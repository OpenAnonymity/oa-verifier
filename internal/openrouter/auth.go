// Package openrouter is the verifier's read/query interface to the provider's
// own systems. It is the foundation of the zero-trust architecture for
// oa-chat users.
//
// Zero-trust design:
//
// The verifier audits stations -- the entities that issue ephemeral API keys to
// oa-chat users -- to confirm they are doing a genuine, privacy-compliant
// job. Every piece of verification evidence originates from OpenRouter's own
// systems; the verifier adds zero proprietary truth to the chain.
//
//   - Toggle state: read from OpenRouter's /activity page using the station
//     operator's own authenticated session (cookies). These are OpenRouter's own
//     account settings, not station self-reported claims. Checks occur at
//     cryptographically random intervals, making it impossible for stations to
//     predict when checks happen and cheat by temporarily toggling settings.
//   - Management key: issued by OpenRouter on the station operator's account
//     when the verifier calls POST /settings/management-keys with the operator's
//     cookies. The key lives on OpenRouter; the verifier merely holds a
//     reference to use for subsequent ownership checks.
//   - Key ownership: checked by calling OpenRouter's GET /api/v1/keys/{hash}
//     authenticated with the management key. OpenRouter's own API answers
//     whether a submitted key belongs to the same account.
//     Ref: https://openrouter.ai/docs/api/api-reference/api-keys/get-key
//   - Account identity (email): extracted server-side from the OpenRouter
//     activity response, not from station-supplied text.
//
// Shadow-account attack prevention:
//
// A malicious station could register with a privacy-compliant account (all
// toggles correct) but then issue keys to users from a different shadow account
// that has logging/training enabled. The ownership check defeats this: the
// management key lives on the registered account, so when the verifier asks
// OpenRouter "does this submitted key belong to the same account?", a key from
// a shadow account will fail -- and the station gets banned.
//
// What this means for oa-chat users:
//
//   - Prompts/responses go directly from oa-chat to OpenRouter; the
//     verifier never touches user data.
//   - The verifier's broadcast endpoint tells oa-chat which stations are
//     verified/banned, based entirely on evidence from OpenRouter's own APIs.
//   - Users only need to trust that (1) the verifier code is what it claims
//     (hardware attestation proves this) and (2) OpenRouter's APIs returned the
//     data the verifier reports (the code is open-source and auditable).
//
// Provider trust scope (audit note):
//
// OpenRouter is used as the frontier model provider. Due to OA's unlinkable
// inference layer, even if OpenRouter is malicious, user prompts are still
// unlinkable to the user's identity and unlinkable across sessions. Each
// session uses an ephemeral key issued via blind signatures with no identity
// binding. The verifier adds enforceable accountability on top: verified
// toggle state and shadow-account prevention via ownership checks.
package openrouter

import (
	"context"
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
	"github.com/oa-verifier/internal/netretry"
)

const (
	clerkJSURL                 = "https://clerk.openrouter.ai/npm/@clerk/clerk-js@5/dist/clerk.browser.js"
	clerkAPI                   = "https://clerk.openrouter.ai/v1/client/sessions/%s/tokens"
	managementKeysPagePath     = "/settings/management-keys"
	provisioningKeysLegacyPath = "/settings/provisioning-keys"
)

var pages = map[string]string{
	"activity":                 "/activity",
	"management_keys":          managementKeysPagePath,
	"provisioning_keys_legacy": provisioningKeysLegacyPath,
}

var actionNameMap = map[string]string{
	"getCurrentUserSA":           "activity",
	"createProvisioningAPIKeySA": "provisioning_keys_create",
	"createManagementAPIKeySA":   "provisioning_keys_create",
	"createManagementKeySA":      "provisioning_keys_create",
	"updateAPIKeySA":             "provisioning_keys_delete",
	"updateManagementAPIKeySA":   "provisioning_keys_delete",
	"updateManagementKeySA":      "provisioning_keys_delete",
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
	if err != nil {
		a.clerkParams["__clerk_api_version"] = "2025-11-10"
		a.clerkParams["_clerk_js_version"] = "5.111.0"
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		a.clerkParams["__clerk_api_version"] = "2025-11-10"
		a.clerkParams["_clerk_js_version"] = "5.111.0"
		return
	}

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
	reqBody := data.Encode()

	cfg := netretry.DefaultConfig(4)
	var lastErr error

	for attempt := 1; attempt <= cfg.Attempts; attempt++ {
		req, err := http.NewRequest("POST", tokenURL, strings.NewReader(reqBody))
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
			lastErr = err
			if attempt < cfg.Attempts {
				_ = netretry.Sleep(context.Background(), attempt, cfg)
				continue
			}
			return &RequestResponseError{
				Operation:      "refresh_token",
				Method:         req.Method,
				URL:            req.URL.String(),
				RequestHeaders: flattenHeaders(req.Header),
				RequestBody:    reqBody,
				Err:            err,
			}
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("token refresh failed: status %d", resp.StatusCode)
			if netretry.ShouldRetry(resp.StatusCode, nil) && attempt < cfg.Attempts {
				_ = netretry.Sleep(context.Background(), attempt, cfg)
				continue
			}
			return &RequestResponseError{
				Operation:       "refresh_token",
				Method:          req.Method,
				URL:             req.URL.String(),
				RequestHeaders:  flattenHeaders(req.Header),
				RequestBody:     reqBody,
				ResponseStatus:  resp.StatusCode,
				ResponseHeaders: flattenHeaders(resp.Header),
				ResponseBody:    string(body),
				Err:             lastErr,
			}
		}

		var result struct {
			JWT string `json:"jwt"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			lastErr = err
			if attempt < cfg.Attempts {
				_ = netretry.Sleep(context.Background(), attempt, cfg)
				continue
			}
			return &RequestResponseError{
				Operation:       "refresh_token_parse",
				Method:          req.Method,
				URL:             req.URL.String(),
				RequestHeaders:  flattenHeaders(req.Header),
				RequestBody:     reqBody,
				ResponseStatus:  resp.StatusCode,
				ResponseHeaders: flattenHeaders(resp.Header),
				ResponseBody:    string(body),
				Err:             err,
			}
		}
		if result.JWT == "" {
			lastErr = fmt.Errorf("token refresh failed: empty jwt")
			if attempt < cfg.Attempts {
				_ = netretry.Sleep(context.Background(), attempt, cfg)
				continue
			}
			return &RequestResponseError{
				Operation:       "refresh_token_parse",
				Method:          req.Method,
				URL:             req.URL.String(),
				RequestHeaders:  flattenHeaders(req.Header),
				RequestBody:     reqBody,
				ResponseStatus:  resp.StatusCode,
				ResponseHeaders: flattenHeaders(resp.Header),
				ResponseBody:    string(body),
				Err:             lastErr,
			}
		}

		a.mu.Lock()
		a.sessionJWT = result.JWT
		a.mu.Unlock()
		return nil
	}

	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("token refresh failed after retries")
}

func (a *Auth) fetchActionHashes() {
	cookies := a.GetCookies()
	fetchedChunks := make(map[string]bool)
	actionHashes := make(map[string]string)
	requiredHashes := requiredActionHashCount()

	hashRe := regexp.MustCompile(`"([0-9a-f]{40,42})"`)
	chunkRe := regexp.MustCompile(`/_next/static/chunks/([^"']+\.js)`)
	nameRe := regexp.MustCompile(`"([a-zA-Z0-9_]+)"[)\]]`)

	for _, pagePath := range pages {
		req, _ := http.NewRequest("GET", config.BaseURL+pagePath, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}

		resp, err := a.client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
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
			if err != nil {
				continue
			}
			if chunkResp.StatusCode != 200 {
				chunkResp.Body.Close()
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

		if len(actionHashes) >= requiredHashes {
			break
		}
	}

	a.mu.Lock()
	a.actionHashes = actionHashes
	a.mu.Unlock()
}

func requiredActionHashCount() int {
	unique := make(map[string]struct{})
	for _, key := range actionNameMap {
		unique[key] = struct{}{}
	}
	return len(unique)
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
