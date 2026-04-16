package openrouter

import (
	"strings"
	"testing"
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
