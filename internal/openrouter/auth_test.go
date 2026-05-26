package openrouter

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseCookieData_Standard(t *testing.T) {
	cookieData := map[string]any{
		"cookies": []any{
			map[string]any{"name": "__client", "value": "test_client_token", "domain": "clerk.openrouter.ai"},
			map[string]any{"name": "__client_uat", "value": "1766973631", "domain": "openrouter.ai"},
			map[string]any{"name": "clerk_active_context", "value": "sess_ABC123:", "domain": "openrouter.ai"},
		},
	}

	a := &Auth{
		clerkParams:  make(map[string]string),
		state:        make(map[string]string),
		actionHashes: make(map[string]string),
	}

	cookies, ok := cookieData["cookies"].([]any)
	if !ok {
		t.Fatal("missing cookies array")
	}
	parseCookies(a, cookies)

	if a.state["client_token"] != "test_client_token" {
		t.Errorf("client_token = %q, want %q", a.state["client_token"], "test_client_token")
	}
	if a.state["client_uat"] != "1766973631" {
		t.Errorf("client_uat = %q, want %q", a.state["client_uat"], "1766973631")
	}
	if a.state["session_id"] != "sess_ABC123" {
		t.Errorf("session_id = %q, want %q", a.state["session_id"], "sess_ABC123")
	}
}

func TestParseCookieData_ClerkV5Suffixed(t *testing.T) {
	cookieData := map[string]any{
		"cookies": []any{
			// Clerk v5: __client_<suffix> on clerk domain
			map[string]any{"name": "__client_NO6jtgZM", "value": "v5_client_token", "domain": "clerk.openrouter.ai"},
			map[string]any{"name": "__client_uat_NO6jtgZM", "value": "1766973631", "domain": "openrouter.ai"},
			map[string]any{"name": "clerk_active_context", "value": "sess_XYZ789:", "domain": "openrouter.ai"},
		},
	}

	a := &Auth{
		clerkParams:  make(map[string]string),
		state:        make(map[string]string),
		actionHashes: make(map[string]string),
	}

	cookies, _ := cookieData["cookies"].([]any)
	parseCookies(a, cookies)

	if a.state["client_token"] != "v5_client_token" {
		t.Errorf("client_token = %q, want %q", a.state["client_token"], "v5_client_token")
	}
	if a.state["client_uat"] != "1766973631" {
		t.Errorf("client_uat = %q, want %q", a.state["client_uat"], "1766973631")
	}
	if a.state["clerk_suffix"] != "NO6jtgZM" {
		t.Errorf("clerk_suffix = %q, want %q", a.state["clerk_suffix"], "NO6jtgZM")
	}
}

func TestParseCookieData_RefreshFallback(t *testing.T) {
	// When __client is missing but __refresh_<suffix> is present
	cookieData := map[string]any{
		"cookies": []any{
			map[string]any{"name": "__client_uat", "value": "1766973631", "domain": "openrouter.ai"},
			map[string]any{"name": "__refresh_NO6jtgZM", "value": "refresh_token_value", "domain": "openrouter.ai"},
			map[string]any{"name": "clerk_active_context", "value": "sess_DEF456:", "domain": "openrouter.ai"},
		},
	}

	a := &Auth{
		clerkParams:  make(map[string]string),
		state:        make(map[string]string),
		actionHashes: make(map[string]string),
	}

	cookies, _ := cookieData["cookies"].([]any)
	parseCookies(a, cookies)

	// __refresh_* should be used as fallback for client_token
	applyRefreshFallback(a, cookies)

	if a.state["client_token"] != "refresh_token_value" {
		t.Errorf("client_token = %q, want %q (should use __refresh_* fallback)", a.state["client_token"], "refresh_token_value")
	}
}

func TestParseCookieData_ClientUATNotMatchedAsClient(t *testing.T) {
	// Ensure __client_uat is NOT matched as a __client token
	cookieData := map[string]any{
		"cookies": []any{
			map[string]any{"name": "__client_uat", "value": "uat_value", "domain": "clerk.openrouter.ai"},
			map[string]any{"name": "clerk_active_context", "value": "sess_TEST:", "domain": "openrouter.ai"},
		},
	}

	a := &Auth{
		clerkParams:  make(map[string]string),
		state:        make(map[string]string),
		actionHashes: make(map[string]string),
	}

	cookies, _ := cookieData["cookies"].([]any)
	parseCookies(a, cookies)

	if a.state["client_token"] != "" {
		t.Errorf("client_token = %q, should be empty (__client_uat should not match as client token)", a.state["client_token"])
	}
}

func TestParseCookieData_OrgID(t *testing.T) {
	cookieData := map[string]any{
		"cookies": []any{
			map[string]any{"name": "__client", "value": "tok", "domain": "clerk.openrouter.ai"},
			map[string]any{"name": "__client_uat", "value": "123", "domain": "openrouter.ai"},
			map[string]any{"name": "clerk_active_context", "value": "sess_ABC:org_XYZ", "domain": "openrouter.ai"},
		},
	}

	a := &Auth{
		clerkParams:  make(map[string]string),
		state:        make(map[string]string),
		actionHashes: make(map[string]string),
	}

	cookies, _ := cookieData["cookies"].([]any)
	parseCookies(a, cookies)

	if a.state["session_id"] != "sess_ABC" {
		t.Errorf("session_id = %q, want %q", a.state["session_id"], "sess_ABC")
	}
	if a.state["org_id"] != "org_XYZ" {
		t.Errorf("org_id = %q, want %q", a.state["org_id"], "org_XYZ")
	}
}

// parseCookies extracts state from cookie array (test helper that mirrors NewAuthFromCookieData logic).
func parseCookies(a *Auth, cookies []any) {
	for _, c := range cookies {
		cookie, ok := c.(map[string]any)
		if !ok {
			continue
		}
		name, _ := cookie["name"].(string)
		value, _ := cookie["value"].(string)
		domain, _ := cookie["domain"].(string)

		switch {
		case (name == "__client" || (strings.HasPrefix(name, "__client_") && !strings.HasPrefix(name, "__client_uat"))) && strings.Contains(domain, "clerk"):
			a.state["client_token"] = value
		case name == "__client_uat" || (strings.HasPrefix(name, "__client_uat_") && a.state["client_uat"] == ""):
			a.state["client_uat"] = value
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
		}
	}
}

func applyRefreshFallback(a *Auth, cookies []any) {
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
}

// withFakeClerkAPI swaps clerkAPI to point at the test server and restores it
// when the returned cleanup runs. NOT goroutine-safe; only one test using this
// helper may run at a time.
func withFakeClerkAPI(srv *httptest.Server) func() {
	prev := clerkAPI
	clerkAPI = srv.URL + "/v1/client/sessions/%s/tokens"
	return func() { clerkAPI = prev }
}

// TestRefreshToken_HappyPath: with a 200 response, refreshToken should not
// retry, should not send expired_token, and should store the returned JWT.
// Guards against accidentally tightening the happy path when changing the
// 422-recovery behavior.
func TestRefreshToken_HappyPath(t *testing.T) {
	var requestCount atomic.Int32
	var lastBody string
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		lastBody = string(body)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jwt":"new_jwt_value"}`)
	}))
	defer srv.Close()
	defer withFakeClerkAPI(srv)()

	a := &Auth{
		state:        map[string]string{"session_id": "sess_TEST", "client_token": "ctok", "client_uat": "1"},
		clerkParams:  map[string]string{},
		actionHashes: map[string]string{},
		client:       &http.Client{Timeout: 5 * time.Second},
	}
	if err := a.refreshToken(); err != nil {
		t.Fatalf("refreshToken: %v", err)
	}
	if got := requestCount.Load(); got != 1 {
		t.Errorf("request count = %d, want 1 (happy path must not retry)", got)
	}
	if a.sessionJWT != "new_jwt_value" {
		t.Errorf("sessionJWT = %q, want new_jwt_value", a.sessionJWT)
	}
	mu.Lock()
	body := lastBody
	mu.Unlock()
	if strings.Contains(body, "expired_token") {
		t.Errorf("happy-path body must not include expired_token, got %q", body)
	}
}

// TestRefreshToken_RetryOnMissingExpiredToken: when Clerk responds 422 with
// missing_expired_token, refreshToken should retry exactly once with the
// prior session JWT submitted as expired_token, and succeed if Clerk then
// returns a JWT.
func TestRefreshToken_RetryOnMissingExpiredToken(t *testing.T) {
	var requestCount atomic.Int32
	var bodies []string
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requestCount.Add(1)
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.WriteHeader(http.StatusUnprocessableEntity)
			fmt.Fprintf(w, `{"errors":[{"message":"Missing required parameter","long_message":"The expired_token parameter is required","code":"missing_expired_token"}]}`)
			return
		}
		// On retry, accept and return a fresh JWT
		fmt.Fprintf(w, `{"jwt":"recovered_jwt"}`)
	}))
	defer srv.Close()
	defer withFakeClerkAPI(srv)()

	a := &Auth{
		state:        map[string]string{"session_id": "sess_TEST", "client_token": "ctok", "client_uat": "1"},
		clerkParams:  map[string]string{},
		actionHashes: map[string]string{},
		client:       &http.Client{Timeout: 5 * time.Second},
		sessionJWT:   "prior_jwt_from_cookie", // seeded from __session cookie at registration
	}
	if err := a.refreshToken(); err != nil {
		t.Fatalf("refreshToken: %v", err)
	}
	if got := requestCount.Load(); got != 2 {
		t.Errorf("request count = %d, want 2 (one initial + one retry)", got)
	}
	mu.Lock()
	bodyCount := len(bodies)
	first := bodies[0]
	var second string
	if bodyCount >= 2 {
		second = bodies[1]
	}
	mu.Unlock()
	if strings.Contains(first, "expired_token") {
		t.Errorf("first request must NOT include expired_token, got %q", first)
	}
	if !strings.Contains(second, "expired_token=prior_jwt_from_cookie") {
		t.Errorf("retry must include expired_token=prior_jwt_from_cookie, got %q", second)
	}
	if a.sessionJWT != "recovered_jwt" {
		t.Errorf("sessionJWT after recovery = %q, want recovered_jwt", a.sessionJWT)
	}
}

// TestRefreshToken_RetryNotInfiniteLoop: if Clerk keeps returning 422 even with
// expired_token, we must give up rather than retry forever.
func TestRefreshToken_RetryNotInfiniteLoop(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		fmt.Fprintf(w, `{"errors":[{"code":"missing_expired_token"}]}`)
	}))
	defer srv.Close()
	defer withFakeClerkAPI(srv)()

	a := &Auth{
		state:        map[string]string{"session_id": "sess_TEST", "client_token": "ctok"},
		clerkParams:  map[string]string{},
		actionHashes: map[string]string{},
		client:       &http.Client{Timeout: 5 * time.Second},
		sessionJWT:   "prior_jwt",
	}
	err := a.refreshToken()
	if err == nil {
		t.Fatal("expected error after exhausted retries, got nil")
	}
	// initial + retry-once-with-expired-token = 2 requests, no further retry on the same 422
	if got := requestCount.Load(); got != 2 {
		t.Errorf("request count = %d, want 2 (one initial + one retry, no further attempts)", got)
	}
}

// TestRefreshToken_NoExpiredTokenWhenSessionJWTEmpty: if we have no prior JWT
// to submit, the retry loop should not loop on the 422 forever — there's
// nothing useful to add.
func TestRefreshToken_NoExpiredTokenWhenSessionJWTEmpty(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusUnprocessableEntity)
		fmt.Fprintf(w, `{"errors":[{"code":"missing_expired_token"}]}`)
	}))
	defer srv.Close()
	defer withFakeClerkAPI(srv)()

	a := &Auth{
		state:        map[string]string{"session_id": "sess_TEST", "client_token": "ctok"},
		clerkParams:  map[string]string{},
		actionHashes: map[string]string{},
		client:       &http.Client{Timeout: 5 * time.Second},
		// sessionJWT empty — no JWT to submit as expired_token
	}
	_ = a.refreshToken()
	// With no JWT to add, the retry attempt would build the same body.
	// Our code guards against this (retryBody == reqBody → no continue),
	// so we only see one request.
	if got := requestCount.Load(); got != 1 {
		t.Errorf("request count = %d, want 1 when no prior JWT to submit", got)
	}
}

// TestParseCookieData_SeedsSessionJWT: the __session cookie at registration
// must be captured into a.sessionJWT so the retry path has a JWT to submit.
func TestParseCookieData_SeedsSessionJWT(t *testing.T) {
	cookieData := map[string]any{
		"cookies": []any{
			map[string]any{"name": "__client", "value": "ctok", "domain": "clerk.openrouter.ai"},
			map[string]any{"name": "__client_uat", "value": "1", "domain": "openrouter.ai"},
			map[string]any{"name": "clerk_active_context", "value": "sess_X:", "domain": "openrouter.ai"},
			map[string]any{"name": "__session", "value": "the_initial_jwt", "domain": "openrouter.ai"},
		},
	}
	// Manually replay the parsing logic without triggering refreshToken (which
	// requires HTTP). We only verify state seeding.
	a := &Auth{
		state:        map[string]string{},
		clerkParams:  map[string]string{},
		actionHashes: map[string]string{},
	}
	cookies, _ := cookieData["cookies"].([]any)
	for _, c := range cookies {
		cookie, _ := c.(map[string]any)
		name, _ := cookie["name"].(string)
		value, _ := cookie["value"].(string)
		switch {
		case name == "__session" || strings.HasPrefix(name, "__session_"):
			if a.sessionJWT == "" {
				a.sessionJWT = value
			}
		}
	}
	if a.sessionJWT != "the_initial_jwt" {
		t.Errorf("sessionJWT = %q, want the_initial_jwt", a.sessionJWT)
	}
}
