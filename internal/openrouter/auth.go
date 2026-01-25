// Package openrouter handles OpenRouter authentication and API interactions.
package openrouter

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/oa-verifier/internal/config"
)

const (
	clerkJSURL = "https://clerk.openrouter.ai/npm/@clerk/clerk-js@5/dist/clerk.browser.js"
	clerkAPI   = "https://clerk.openrouter.ai/v1/client/sessions/%s/tokens"
)

var pages = map[string]string{
	"activity":          "/activity",
	"provisioning_keys": "/settings/provisioning-keys",
}

var actionNameMap = map[string]string{
	"getCurrentUserSA":          "activity",
	"createProvisioningAPIKeySA": "provisioning_keys_create",
	"updateAPIKeySA":            "provisioning_keys_delete",
}

// Auth manages OpenRouter authentication via Clerk cookies.
type Auth struct {
	mu           sync.RWMutex
	clerkParams  map[string]string
	state        map[string]string
	sessionJWT   string
	actionHashes map[string]string
	client       *http.Client
}

// NewAuthFromCookieData creates an Auth instance from cookie dict.
func NewAuthFromCookieData(cookieData map[string]any) (*Auth, error) {
	a := &Auth{
		clerkParams:  make(map[string]string),
		state:        make(map[string]string),
		actionHashes: make(map[string]string),
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}

	// Parse cookie data
	cookies, ok := cookieData["cookies"].([]any)
	if !ok {
		return nil, fmt.Errorf("invalid cookie_data: missing cookies array")
	}

	for _, c := range cookies {
		cookie, ok := c.(map[string]any)
		if !ok {
			continue
		}
		name, _ := cookie["name"].(string)
		value, _ := cookie["value"].(string)
		domain, _ := cookie["domain"].(string)

		switch {
		case name == "__client" && strings.Contains(domain, "clerk"):
			a.state["client_token"] = value
		case name == "__client_uat":
			a.state["client_uat"] = value
		case name == "clerk_active_context":
			parts := strings.Split(value, ":")
			a.state["session_id"] = parts[0]
			a.state["clerk_active_context"] = value
			if len(parts) > 1 && parts[1] != "" {
				a.state["org_id"] = parts[1]
			}
		}
	}

	if a.state["session_id"] == "" || a.state["client_token"] == "" {
		return nil, fmt.Errorf("invalid cookie_data - missing required session data")
	}

	a.fetchClerkVersions()
	if err := a.refreshToken(); err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	a.fetchActionHashes()

	return a, nil
}

func (a *Auth) fetchClerkVersions() {
	resp, err := a.client.Get(clerkJSURL)
	if err != nil || resp.StatusCode != 200 {
		a.clerkParams["__clerk_api_version"] = "2025-11-10"
		a.clerkParams["_clerk_js_version"] = "5.111.0"
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 20000))
	text := string(body)

	jsRe := regexp.MustCompile(`(\d+\.\d+\.\d+)`)
	apiRe := regexp.MustCompile(`["'](\d{4}-\d{2}-\d{2})["']`)

	if m := jsRe.FindStringSubmatch(text); len(m) > 1 {
		a.clerkParams["_clerk_js_version"] = m[1]
	} else {
		a.clerkParams["_clerk_js_version"] = "5.111.0"
	}

	if m := apiRe.FindStringSubmatch(text); len(m) > 1 {
		a.clerkParams["__clerk_api_version"] = m[1]
	} else {
		a.clerkParams["__clerk_api_version"] = "2025-11-10"
	}
}

func (a *Auth) refreshToken() error {
	tokenURL := fmt.Sprintf(clerkAPI, a.state["session_id"])

	data := url.Values{}
	if orgID := a.state["org_id"]; orgID != "" {
		data.Set("organization_id", orgID)
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	q := req.URL.Query()
	for k, v := range a.clerkParams {
		q.Set(k, v)
	}
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Origin", "https://openrouter.ai")
	req.Header.Set("Referer", "https://openrouter.ai/")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	req.AddCookie(&http.Cookie{Name: "__client", Value: a.state["client_token"]})
	req.AddCookie(&http.Cookie{Name: "__client_uat", Value: a.state["client_uat"]})

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("token refresh failed: status %d", resp.StatusCode)
	}

	var result struct {
		JWT string `json:"jwt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	a.mu.Lock()
	a.sessionJWT = result.JWT
	a.mu.Unlock()
	return nil
}

func (a *Auth) fetchActionHashes() {
	cookies := a.GetCookies()
	fetchedChunks := make(map[string]bool)
	actionHashes := make(map[string]string)

	hashRe := regexp.MustCompile(`"([0-9a-f]{40,42})"`)
	chunkRe := regexp.MustCompile(`/_next/static/chunks/([^"']+\.js)`)
	nameRe := regexp.MustCompile(`"([a-zA-Z_]+)"[)\]]`)

	for _, pagePath := range pages {
		req, _ := http.NewRequest("GET", config.BaseURL+pagePath, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}

		resp, err := a.client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		jsChunks := chunkRe.FindAllStringSubmatch(string(body), -1)
		for _, match := range jsChunks {
			chunk := match[1]
			if fetchedChunks[chunk] {
				continue
			}
			fetchedChunks[chunk] = true

			chunkReq, _ := http.NewRequest("GET", config.BaseURL+"/_next/static/chunks/"+chunk, nil)
			for _, c := range cookies {
				chunkReq.AddCookie(c)
			}

			chunkResp, err := a.client.Do(chunkReq)
			if err != nil || chunkResp.StatusCode != 200 {
				continue
			}
			js, _ := io.ReadAll(chunkResp.Body)
			chunkResp.Body.Close()

			jsText := string(js)
			for _, m := range hashRe.FindAllStringSubmatchIndex(jsText, -1) {
				hashVal := jsText[m[2]:m[3]]
				afterStart := m[1]
				afterEnd := min(afterStart+100, len(jsText))
				after := jsText[afterStart:afterEnd]

				if nameMatch := nameRe.FindStringSubmatch(after); len(nameMatch) > 1 {
					actionName := nameMatch[1]
					if key, ok := actionNameMap[actionName]; ok {
						actionHashes[key] = hashVal
					}
				}
			}
		}

		if len(actionHashes) >= len(actionNameMap) {
			break
		}
	}

	a.mu.Lock()
	a.actionHashes = actionHashes
	a.mu.Unlock()
}

// GetCookies returns cookies for HTTP requests.
func (a *Auth) GetCookies() []*http.Cookie {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return []*http.Cookie{
		{Name: "__client_uat", Value: a.state["client_uat"]},
		{Name: "clerk_active_context", Value: a.state["clerk_active_context"]},
		{Name: "__session", Value: a.sessionJWT},
	}
}

// GetActionHash returns the next-action hash for a specific page.
func (a *Auth) GetActionHash(page string) string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.actionHashes[page]
}

// GetAllActionHashes returns all available next-action hashes.
func (a *Auth) GetAllActionHashes() map[string]string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make(map[string]string)
	for k, v := range a.actionHashes {
		result[k] = v
	}
	return result
}
