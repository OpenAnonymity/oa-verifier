package openrouter

import "testing"

// ---------------------------------------------------------------------------
// Private frontend REST contract
//
// Regression guard for the 2026-08-25 migration: OpenRouter removed the
// getCurrentUserSA server action and moved account state to
// GET /api/frontend/v1/private/users/current. Response bodies below are real
// shapes captured from that endpoint, with identifiers redacted.
// ---------------------------------------------------------------------------

const currentUserOK = `{"data":{
  "email":"test@example.com",
  "clerk_user_id":"REDACTED",
  "enable_training":false,
  "enable_free_model_training":false,
  "enable_free_model_publication":false,
  "enforce_zdr":false,
  "is_broadcast_enabled":false,
  "is_private_logging_enabled":false,
  "lock_privacy_settings":false,
  "subscription_plan":"standard"
}}`

func TestParseCurrentUserResponse_OK(t *testing.T) {
	data, err := parseCurrentUserResponse([]byte(currentUserOK))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["email"] != "test@example.com" {
		t.Errorf("email = %v, want test@example.com", data["email"])
	}
	// Every user-scope required toggle must survive the unwrap as a real bool,
	// since CheckPrivacyToggles treats a missing toggle as not-verified.
	for _, k := range []string{
		"enable_training", "enable_free_model_training", "enable_free_model_publication",
		"enforce_zdr", "is_broadcast_enabled", "is_private_logging_enabled",
	} {
		v, ok := data[k]
		if !ok {
			t.Errorf("toggle %q missing from unwrapped data", k)
			continue
		}
		if _, isBool := v.(bool); !isBool {
			t.Errorf("toggle %q = %T(%v), want bool", k, v, v)
		}
	}
}

func TestParseCurrentUserResponse_Unauthorized(t *testing.T) {
	// Real body observed when the session JWT has expired. Clerk mints
	// 60-second tokens, so this is a live failure mode, not a hypothetical.
	body := `{"error":{"message":"No user or org id found in auth cookie","code":401}}`
	if _, err := parseCurrentUserResponse([]byte(body)); err == nil {
		t.Fatal("expected an error for a 401 envelope, got nil")
	}
}

func TestParseCurrentUserResponse_Rejects(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty data", `{"data":{}}`},
		{"null data", `{"data":null}`},
		{"no envelope", `{}`},
		// A signed-out request can return an HTML page rather than JSON; that
		// must be an error, never an empty-but-successful toggle set.
		{"html sign-in page", `<!DOCTYPE html><html><body>sign in</body></html>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseCurrentUserResponse([]byte(tc.body)); err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}
