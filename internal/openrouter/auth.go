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
//   - Toggle state: read from OpenRouter's authenticated private JSON APIs using
//     the station operator's own session cookies. These are OpenRouter's own
//     account settings, not station self-reported claims. Checks occur at
//     cryptographically random intervals, making it impossible for stations to
//     predict when checks happen and cheat by temporarily toggling settings.
//   - Management key: issued by OpenRouter on the station operator's account
//     through OpenRouter's authenticated management-key API. The key lives on
//     OpenRouter; the verifier merely holds a
//     reference to use for subsequent ownership checks.
//   - Key ownership: checked by calling OpenRouter's GET /api/v1/keys/{hash}
//     authenticated with the management key. OpenRouter's own API answers
//     whether a submitted key belongs to the same account.
//     Ref: https://openrouter.ai/docs/api/api-reference/api-keys/get-key
//   - Account identity (email): read from OpenRouter's current-user response,
//     not from station-supplied text.
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
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/openanonymity/oa-verifier/internal/netretry"
)

var (
	// These are variables so contract tests can use a local Clerk server.
	clerkJSURL = "https://clerk.openrouter.ai/npm/@clerk/clerk-js@5/dist/clerk.browser.js"
	clerkAPI   = "https://clerk.openrouter.ai/v1/client/sessions/%s/tokens"
)

// Auth manages OpenRouter authentication via Clerk cookies.
type Auth struct {
	mu          sync.RWMutex
	clerkParams map[string]string
	state       map[string]string
	sessionJWT  string
	client      *http.Client
}

// NewAuthFromCookieData creates an Auth instance from cookie dict.
func NewAuthFromCookieData(cookieData map[string]any) (*Auth, error) {
	a := &Auth{
		clerkParams: make(map[string]string),
		state:       make(map[string]string),
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
		// Clerk v4: __client on clerk domain
		// Clerk v5: __client_<suffix> on clerk domain (suffix = last 8 chars of publishable key)
		case (name == "__client" || (strings.HasPrefix(name, "__client_") && !strings.HasPrefix(name, "__client_uat"))) && strings.Contains(domain, "clerk"):
			a.state["client_token"] = value
		case name == "__client_uat" || (strings.HasPrefix(name, "__client_uat_") && a.state["client_uat"] == ""):
			a.state["client_uat"] = value
			// Extract Clerk v5 suffix (e.g., "NO6jtgZM" from "__client_uat_NO6jtgZM")
			if suffix := strings.TrimPrefix(name, "__client_uat_"); suffix != name && suffix != "" {
				a.state["clerk_suffix"] = suffix
			}
		case name == "clerk_active_context":
			parts := strings.Split(value, ":")
			a.state["session_id"] = parts[0]
			a.state["clerk_active_context"] = value
			if len(parts) > 1 && parts[1] != "" {
				a.state["org_id"] = parts[1]
			}
		case name == "__session" || strings.HasPrefix(name, "__session_"):
			// Capture the operator's session JWT from registration. Used only
			// as a fallback `expired_token` parameter if Clerk demands one
			// (status 422 missing_expired_token) — never as a current bearer.
			if a.sessionJWT == "" {
				a.sessionJWT = value
			}
		}
	}

	// Clerk v5 fallback: if no __client cookie found on clerk domain,
	// look for __refresh_<suffix> cookies on the openrouter.ai domain.
	// These serve the same role as __client for session token refresh.
	if a.state["client_token"] == "" {
		for _, c := range cookies {
			cookie, ok := c.(map[string]any)
			if !ok {
				continue
			}
			name, _ := cookie["name"].(string)
			value, _ := cookie["value"].(string)
			if strings.HasPrefix(name, "__refresh") && value != "" {
				a.state["client_token"] = value
				break
			}
		}
	}

	if a.state["session_id"] == "" || a.state["client_token"] == "" {
		return nil, fmt.Errorf("invalid cookie_data - missing required session data (session_id=%v, client_token=%v)", a.state["session_id"] != "", a.state["client_token"] != "")
	}

	a.fetchClerkVersions()
	if err := a.refreshToken(); err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	return a, nil
}

// NewAuthFromRawCookieHeader creates an Auth instance from a raw HTTP Cookie header string.
// This is a convenience method for testing/diagnostics. It converts the raw header
// into the structured format expected by NewAuthFromCookieData.
func NewAuthFromRawCookieHeader(rawHeader string) (*Auth, error) {
	var cookieList []any
	for _, pair := range strings.Split(rawHeader, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		eqIdx := strings.Index(pair, "=")
		if eqIdx < 0 {
			continue
		}
		name := strings.TrimSpace(pair[:eqIdx])
		value := strings.TrimSpace(pair[eqIdx+1:])

		// Infer domain for clerk-related cookies
		domain := "openrouter.ai"
		if strings.HasPrefix(name, "__client") && !strings.HasPrefix(name, "__client_uat") {
			domain = "clerk.openrouter.ai"
		}

		cookieList = append(cookieList, map[string]any{
			"name":   name,
			"value":  value,
			"domain": domain,
		})
	}

	return NewAuthFromCookieData(map[string]any{"cookies": cookieList})
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

	buildBody := func(includeExpiredToken bool) string {
		data := url.Values{}
		if orgID := a.state["org_id"]; orgID != "" {
			data.Set("organization_id", orgID)
		}
		if includeExpiredToken {
			a.mu.RLock()
			prevJWT := a.sessionJWT
			a.mu.RUnlock()
			if prevJWT != "" {
				data.Set("expired_token", prevJWT)
			}
		}
		return data.Encode()
	}

	reqBody := buildBody(false)
	expiredTokenRetryUsed := false

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

		// Clerk accepts both __client (v4) and __client_<suffix> (v5) cookies.
		// The token value is what matters, not the cookie name.
		req.AddCookie(&http.Cookie{Name: "__client", Value: a.state["client_token"]})
		if clientUAT := a.state["client_uat"]; clientUAT != "" {
			req.AddCookie(&http.Cookie{Name: "__client_uat", Value: clientUAT})
		}

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
			// Clerk's modern session-refresh path can demand the prior session
			// JWT as `expired_token` (proof-of-possession / anti-replay) for
			// some session states. The error returned is:
			//   422 + body: {"errors":[{"code":"missing_expired_token", ...}]}
			//
			// We don't preemptively send expired_token because Clerk's contract
			// is conditional and always-sending could break the working path.
			// Instead, retry exactly once with expired_token included if we get
			// this specific signal and we have a JWT to submit.
			if resp.StatusCode == 422 && !expiredTokenRetryUsed &&
				strings.Contains(string(body), "missing_expired_token") {
				retryBody := buildBody(true)
				if retryBody != reqBody {
					reqBody = retryBody
					expiredTokenRetryUsed = true
					slog.Info("clerk demanded expired_token, retrying with prior session jwt", "session_id", a.state["session_id"])
					continue
				}
			}

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

// GetCookies returns cookies for HTTP requests.
// Includes both standard and Clerk v5 suffixed cookie names to ensure
// compatibility with OpenRouter's server-side cookie parsing.
func (a *Auth) GetCookies() []*http.Cookie {
	a.mu.RLock()
	defer a.mu.RUnlock()

	cookies := []*http.Cookie{
		{Name: "__client_uat", Value: a.state["client_uat"]},
		{Name: "clerk_active_context", Value: a.state["clerk_active_context"]},
		{Name: "__session", Value: a.sessionJWT},
	}

	// If we detected a Clerk suffix, also send suffixed cookie variants.
	// OpenRouter's server may check either the standard or suffixed names.
	if suffix := a.state["clerk_suffix"]; suffix != "" {
		cookies = append(cookies,
			&http.Cookie{Name: "__client_uat_" + suffix, Value: a.state["client_uat"]},
			&http.Cookie{Name: "__session_" + suffix, Value: a.sessionJWT},
		)
	}

	return cookies
}
