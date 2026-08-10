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
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/openanonymity/oa-verifier/internal/config"
	"github.com/openanonymity/oa-verifier/internal/netretry"
)

const (
	clerkJSURL             = "https://clerk.openrouter.ai/npm/@clerk/clerk-js@5/dist/clerk.browser.js"
	managementKeysPagePath = "/settings/management-keys"
)

// clerkAPI is the URL template for Clerk's session-token endpoint. Defined as
// a var (not const) so tests can substitute an httptest server.
var clerkAPI = "https://clerk.openrouter.ai/v1/client/sessions/%s/tokens"

var pages = map[string]string{
	"activity":        "/activity",
	"management_keys": managementKeysPagePath,
}

// chunkPathRe matches the client-bundle chunk URLs referenced by a page's HTML.
// OpenRouter serves them from a build-specific prefix that has moved before:
// /_next/static/chunks/ until 2026-08, then /_next/static/immutable/chunks/.
// The whole path is captured and reused verbatim for the fetch, so relocating
// the intermediate segment can't silently strand discovery with zero hashes.
var chunkPathRe = regexp.MustCompile(`/_next/static/(?:[A-Za-z0-9._-]+/)*chunks/[A-Za-z0-9._-]+\.js`)

var actionNameMap = map[string]string{
	"getCurrentUserSA":           "activity",
	"createProvisioningAPIKeySA": "provisioning_keys_create",
	"createManagementAPIKeySA":   "provisioning_keys_create",
	"createManagementKeySA":      "provisioning_keys_create",
	"updateAPIKeySA":             "provisioning_keys_delete",
	"updateManagementAPIKeySA":   "provisioning_keys_delete",
	"updateManagementKeySA":      "provisioning_keys_delete",
}

// hashDiscovery records what an action-hash sweep actually saw. Without it an
// empty result surfaces as a bare "map[]", which reads identically whether the
// session is dead, the bundle moved, or the action names were renamed -- three
// failures with three different fixes.
type hashDiscovery struct {
	pagesOK        int
	pagesSignedOut int
	chunksSeen     int
	chunksFetched  int
}

func (d hashDiscovery) String() string {
	return fmt.Sprintf("pages_ok=%d pages_signed_out=%d chunks_seen=%d chunks_fetched=%d",
		d.pagesOK, d.pagesSignedOut, d.chunksSeen, d.chunksFetched)
}

// Auth manages OpenRouter authentication via Clerk cookies.
type Auth struct {
	mu           sync.RWMutex
	clerkParams  map[string]string
	state        map[string]string
	sessionJWT   string
	actionHashes map[string]string
	discovery    hashDiscovery
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
	a.fetchActionHashes()

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

var (
	actionHashRe = regexp.MustCompile(`"([0-9a-f]{40,42})"`)
	actionNameRe = regexp.MustCompile(`"([a-zA-Z0-9_]+)"[)\]]`)
)

// actionNameLookahead is how far past a candidate hash to search for the action
// name. The registration puts the name last, after the callServer/sourcemap
// arguments; ~60 chars in the current bundle, so this leaves headroom.
const actionNameLookahead = 100

// extractActionHashes scans one client-bundle chunk for Next.js server-action
// registrations and records the ones the verifier calls. The live shape is:
//
//	createServerReference("<40-42 hex>",callServer,void 0,findSourceMapURL,"getCurrentUserSA")
//
// Matching is deliberately anchored on the hash rather than on
// createServerReference, since the minified helper name changes between builds.
func extractActionHashes(jsText string, into map[string]string) {
	for _, m := range actionHashRe.FindAllStringSubmatchIndex(jsText, -1) {
		hashVal := jsText[m[2]:m[3]]
		afterEnd := min(m[1]+actionNameLookahead, len(jsText))
		after := jsText[m[1]:afterEnd]

		if nameMatch := actionNameRe.FindStringSubmatch(after); len(nameMatch) > 1 {
			if key, ok := actionNameMap[nameMatch[1]]; ok {
				into[key] = hashVal
			}
		}
	}
}

func (a *Auth) fetchActionHashes() {
	cookies := a.GetCookies()
	fetchedChunks := make(map[string]bool)
	actionHashes := make(map[string]string)
	requiredHashes := requiredActionHashCount()

	var diag hashDiscovery

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

		// An expired session doesn't fail loudly: OpenRouter redirects the
		// auth-gated page to /sign-in, which still returns 200 but carries none
		// of the app's server actions. Record it so a dead cookie is
		// distinguishable from a bundle-layout change.
		if resp.Request != nil && strings.Contains(resp.Request.URL.Path, "/sign-in") {
			diag.pagesSignedOut++
			continue
		}
		diag.pagesOK++

		jsChunks := chunkPathRe.FindAllString(string(body), -1)
		diag.chunksSeen += len(jsChunks)
		for _, chunkPath := range jsChunks {
			if fetchedChunks[chunkPath] {
				continue
			}
			fetchedChunks[chunkPath] = true
			diag.chunksFetched++

			chunkReq, _ := http.NewRequest("GET", config.BaseURL+chunkPath, nil)
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

			extractActionHashes(string(js), actionHashes)
		}

		if len(actionHashes) >= requiredHashes {
			break
		}
	}

	a.mu.Lock()
	a.actionHashes = actionHashes
	a.discovery = diag
	a.mu.Unlock()
}

// DiscoveryDiagnostics summarizes the last action-hash sweep. Callers include it
// when reporting a missing hash so the failure names its own cause.
func (a *Auth) DiscoveryDiagnostics() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.discovery.String()
}

func requiredActionHashCount() int {
	unique := make(map[string]struct{})
	for _, key := range actionNameMap {
		unique[key] = struct{}{}
	}
	return len(unique)
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
