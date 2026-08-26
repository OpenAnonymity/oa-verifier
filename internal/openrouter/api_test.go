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

// ---------------------------------------------------------------------------
// Management-key REST contract
//
// Regression guard for the 2026-08-25 migration: createManagementKeySA /
// updateManagementKeySA were removed. Shapes below are real responses from
// /api/frontend/v1/private/management-keys, with hashes redacted.
// ---------------------------------------------------------------------------

func TestParseManagementKeysPage_OK(t *testing.T) {
	body := `{"data":{"keys":[
	  {"hash":"aaa","name":"key-watchdog-v2-station-x","label":"sk-or-v1-2f1...628","expires_at":null,"disabled":false},
	  {"hash":"bbb","name":"other","label":"sk-or-v1-a9a...e37","expires_at":null,"disabled":false}
	],"total_count":164}}`

	keys, total, err := parseManagementKeysPage([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 164 {
		t.Errorf("total_count = %d, want 164", total)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	// CleanupProvisioningKeys matches on "name" and deletes by "hash"; both must
	// survive the parse or cleanup silently no-ops.
	if keys[0]["hash"] != "aaa" || keys[0]["name"] != "key-watchdog-v2-station-x" {
		t.Errorf("first key = %v", keys[0])
	}
}

func TestParseManagementKeysPage_SkipsHashlessEntries(t *testing.T) {
	// A key with no hash cannot be deleted, so it must not enter the list and
	// give cleanup a target it will fail on.
	body := `{"data":{"keys":[{"hash":"","name":"broken"},{"hash":"ccc","name":"ok"}],"total_count":2}}`
	keys, _, err := parseManagementKeysPage([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 || keys[0]["hash"] != "ccc" {
		t.Errorf("got %v, want only the hashed entry", keys)
	}
}

func TestParseManagementKeysPage_Rejects(t *testing.T) {
	cases := []struct{ name, body string }{
		{"error envelope", `{"error":{"message":"Forbidden","code":403}}`},
		{"html", `<!DOCTYPE html><html></html>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseManagementKeysPage([]byte(tc.body)); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

func TestParseManagementKeysPage_EmptyPageTerminatesPaging(t *testing.T) {
	// fetchProvisioningKeysREST stops on an empty page; that must parse cleanly
	// rather than erroring, or pagination would abort mid-listing.
	keys, total, err := parseManagementKeysPage([]byte(`{"data":{"keys":[],"total_count":40}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 0 || total != 40 {
		t.Errorf("keys=%v total=%d", keys, total)
	}
}
