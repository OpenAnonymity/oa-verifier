package openrouter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	testKeyHash       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDeletedHash   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testManagementKey = "sk-or-v1-test-management-key"
)

func newFrontendTestAuth(t *testing.T, handler http.Handler) (*Auth, *httptest.Server) {
	t.Helper()

	server := httptest.NewServer(handler)
	previousBaseURL := frontendBaseURL
	frontendBaseURL = server.URL
	t.Cleanup(func() {
		frontendBaseURL = previousBaseURL
		server.Close()
	})

	return &Auth{
		state: map[string]string{
			"client_uat":           "123",
			"clerk_active_context": "sess_test:org_test",
		},
		sessionJWT: "fresh-session-jwt",
		client:     server.Client(),
	}, server
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func requireFrontendSession(t *testing.T, r *http.Request) {
	t.Helper()
	cookie, err := r.Cookie("__session")
	if err != nil || cookie.Value != "fresh-session-jwt" {
		t.Errorf("request missing refreshed __session cookie")
	}
	if got := r.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q, want application/json", got)
	}
}

func TestFrontendJSONAPIFlow(t *testing.T) {
	requestCounts := make(map[string]int)
	var managementPages []string
	auth, _ := newFrontendTestAuth(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireFrontendSession(t, r)
		requestCounts[r.Method+" "+r.URL.Path]++

		switch {
		case r.Method == http.MethodGet && r.URL.Path == currentUserAPIPath:
			writeJSON(t, w, http.StatusOK, map[string]any{
				"data": map[string]any{
					"email":                         "station@example.invalid",
					"enable_training":               false,
					"enable_free_model_training":    false,
					"enable_free_model_publication": false,
					"enforce_zdr":                   false,
					"is_broadcast_enabled":          false,
					"is_private_logging_enabled":    false,
				},
			})

		case r.Method == http.MethodGet && r.URL.Path == userWorkspacesAPIPath:
			if got := r.URL.Query().Get("scope"); got != "member" {
				t.Errorf("scope = %q, want member", got)
			}
			writeJSON(t, w, http.StatusOK, map[string]any{
				"active_workspace_id":  "ws-active",
				"default_workspace_id": "ws-default",
				"data": []any{
					map[string]any{
						"id":                               "ws-active",
						"slug":                             "active",
						"is_data_discount_logging_enabled": true,
					},
					map[string]any{
						"id":                               "ws-default",
						"slug":                             "custom-default-slug",
						"is_data_discount_logging_enabled": false,
					},
				},
			})

		case r.Method == http.MethodGet && r.URL.Path == managementKeysAPIPath:
			page := r.URL.Query().Get("page")
			managementPages = append(managementPages, page)
			var pageKeys []any
			switch page {
			case "1":
				pageKeys = []any{
					map[string]any{"hash": testKeyHash, "name": "oa-verifier"},
				}
			case "2":
				pageKeys = []any{
					map[string]any{"hash": testDeletedHash, "name": "other"},
				}
			default:
				t.Errorf("management page = %q, want 1 or 2", page)
			}
			writeJSON(t, w, http.StatusOK, map[string]any{
				"data": map[string]any{
					"keys":        pageKeys,
					"total_count": 2,
				},
			})

		case r.Method == http.MethodPost && r.URL.Path == workspaceAPIKeysAPIPath+"/management":
			if got := r.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got)
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode create payload: %v", err)
			}
			if len(payload) != 1 || payload["name"] != "oa-verifier" {
				t.Errorf("create payload = %#v, want name only", payload)
			}
			writeJSON(t, w, http.StatusOK, map[string]any{
				"data": map[string]any{
					"api_key": map[string]any{"hash": testKeyHash},
					"key":     testManagementKey,
				},
			})

		case r.Method == http.MethodPatch && r.URL.Path == workspaceAPIKeysAPIPath+"/"+testKeyHash:
			var payload struct {
				Payload map[string]bool `json:"payload"`
				Opts    map[string]bool `json:"opts"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode delete payload: %v", err)
			}
			if !payload.Payload["deleted"] || !payload.Opts["is_provisioning_key"] {
				t.Errorf("delete payload = %#v", payload)
			}
			writeJSON(t, w, http.StatusOK, map[string]any{
				"data": map[string]any{"hash": testKeyHash, "deleted": true},
			})

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
			writeJSON(t, w, http.StatusNotFound, map[string]string{"error": "unexpected request"})
		}
	}))

	activity, err := FetchActivityData(auth)
	if err != nil {
		t.Fatalf("FetchActivityData: %v", err)
	}
	if activity["email"] != "station@example.invalid" {
		t.Errorf("activity email = %#v", activity["email"])
	}

	workspace, err := FetchWorkspaceData(auth)
	if err != nil {
		t.Fatalf("FetchWorkspaceData: %v", err)
	}
	if workspace["id"] != "ws-default" || workspace["is_data_discount_logging_enabled"] != false {
		t.Errorf("selected wrong workspace: %#v", workspace)
	}

	keys, err := FetchProvisioningKeys(auth)
	if err != nil {
		t.Fatalf("FetchProvisioningKeys: %v", err)
	}
	if len(keys) != 2 || keys[0]["hash"] != testKeyHash || keys[0]["name"] != "oa-verifier" || keys[1]["hash"] != testDeletedHash {
		t.Errorf("keys = %#v", keys)
	}
	if strings.Join(managementPages, ",") != "1,2" {
		t.Errorf("management pages = %v, want [1 2]", managementPages)
	}

	key, err := CreateProvisioningKey(auth, "oa-verifier")
	if err != nil {
		t.Fatalf("CreateProvisioningKey: %v", err)
	}
	if key != testManagementKey {
		t.Errorf("created key = %q", key)
	}

	if err := DeleteProvisioningKey(auth, testKeyHash); err != nil {
		t.Fatalf("DeleteProvisioningKey: %v", err)
	}

	wantCounts := map[string]int{
		http.MethodGet + " " + currentUserAPIPath:                            1,
		http.MethodGet + " " + userWorkspacesAPIPath:                         1,
		http.MethodGet + " " + managementKeysAPIPath:                         2,
		http.MethodPost + " " + workspaceAPIKeysAPIPath + "/management":      1,
		http.MethodPatch + " " + workspaceAPIKeysAPIPath + "/" + testKeyHash: 1,
	}
	for request, want := range wantCounts {
		if got := requestCounts[request]; got != want {
			t.Errorf("%s count = %d, want %d", request, got, want)
		}
	}
}

func TestCreateProvisioningKeyCleansAmbiguousOrphanWithoutRetry(t *testing.T) {
	var createCalls atomic.Int32
	var deleteCalls atomic.Int32
	auth, _ := newFrontendTestAuth(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == workspaceAPIKeysAPIPath+"/management":
			createCalls.Add(1)
			writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{}})
		case r.Method == http.MethodGet && r.URL.Path == managementKeysAPIPath:
			writeJSON(t, w, http.StatusOK, map[string]any{
				"data": map[string]any{
					"keys": []any{
						map[string]any{"hash": testKeyHash, "name": "ambiguous"},
					},
					"total_count": 1,
				},
			})
		case r.Method == http.MethodPatch && r.URL.Path == workspaceAPIKeysAPIPath+"/"+testKeyHash:
			deleteCalls.Add(1)
			writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{"deleted": true}})
		default:
			writeJSON(t, w, http.StatusNotFound, map[string]string{"error": "unexpected request"})
		}
	}))

	_, err := CreateProvisioningKey(auth, "ambiguous")
	if err == nil || !strings.Contains(err.Error(), "cleaned up 1 possible orphan") {
		t.Fatalf("error = %v, want orphan-cleanup error", err)
	}
	if got := createCalls.Load(); got != 1 {
		t.Errorf("create calls = %d, want exactly 1", got)
	}
	if got := deleteCalls.Load(); got != 1 {
		t.Errorf("delete calls = %d, want 1", got)
	}
}

func TestCleanupProvisioningKeysFindsMatchOnLaterPage(t *testing.T) {
	var pages []string
	var deletedHash string
	auth, _ := newFrontendTestAuth(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == managementKeysAPIPath:
			page := r.URL.Query().Get("page")
			pages = append(pages, page)
			var keys []any
			if page == "1" {
				keys = []any{map[string]any{"hash": testKeyHash, "name": "other"}}
			} else if page == "2" {
				keys = []any{map[string]any{"hash": testDeletedHash, "name": "target"}}
			} else {
				t.Errorf("unexpected management page %q", page)
			}
			writeJSON(t, w, http.StatusOK, map[string]any{
				"data": map[string]any{"keys": keys, "total_count": 2},
			})
		case r.Method == http.MethodPatch && r.URL.Path == workspaceAPIKeysAPIPath+"/"+testDeletedHash:
			deletedHash = testDeletedHash
			writeJSON(t, w, http.StatusOK, map[string]any{
				"data": map[string]any{"hash": testDeletedHash, "deleted": true},
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
			writeJSON(t, w, http.StatusNotFound, map[string]string{"error": "unexpected request"})
		}
	}))

	deleted, err := CleanupProvisioningKeys(auth, "target")
	if err != nil {
		t.Fatalf("CleanupProvisioningKeys: %v", err)
	}
	if deleted != 1 || deletedHash != testDeletedHash {
		t.Errorf("deleted=%d hash=%q, want one page-two key", deleted, deletedHash)
	}
	if strings.Join(pages, ",") != "1,2" {
		t.Errorf("pages = %v, want [1 2]", pages)
	}
}

func TestFetchProvisioningKeysRejectsIncompletePagination(t *testing.T) {
	tests := []struct {
		name     string
		pageKeys func(page string) []any
		want     string
	}{
		{
			name: "empty page before total",
			pageKeys: func(page string) []any {
				if page == "1" {
					return []any{map[string]any{"hash": testKeyHash, "name": "first"}}
				}
				return []any{}
			},
			want: "pagination ended after 1 of 2 keys",
		},
		{
			name: "repeated page",
			pageKeys: func(string) []any {
				return []any{map[string]any{"hash": testKeyHash, "name": "first"}}
			},
			want: "page 2 made no progress after 1 of 2 keys",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			auth, _ := newFrontendTestAuth(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(t, w, http.StatusOK, map[string]any{
					"data": map[string]any{
						"keys":        tc.pageKeys(r.URL.Query().Get("page")),
						"total_count": 2,
					},
				})
			}))

			_, err := FetchProvisioningKeys(auth)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseManagementKeysPageRequiresCompleteEnvelope(t *testing.T) {
	for _, body := range []string{
		`{}`,
		`{"data":{}}`,
		`{"data":{"total_count":0}}`,
		`{"data":{"keys":[]}}`,
		`{"data":{"keys":[],"total_count":-1}}`,
	} {
		if _, _, err := parseManagementKeysPage([]byte(body)); err == nil {
			t.Errorf("parseManagementKeysPage(%s) unexpectedly succeeded", body)
		}
	}
}

func TestFrontendAPIErrorContextRedactsCredentialsAndBodies(t *testing.T) {
	auth, _ := newFrontendTestAuth(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "__session=response-secret")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"body-secret"}`)
	}))

	_, err := FetchActivityData(auth)
	if err == nil {
		t.Fatal("expected unauthorized error")
	}
	if !strings.Contains(err.Error(), "session rejected") {
		t.Errorf("error does not distinguish auth failure: %v", err)
	}

	context := ErrorContext(err)
	request := context["openrouter_request"].(map[string]any)
	requestHeaders := request["headers"].(map[string]string)
	if requestHeaders["Cookie"] != "[REDACTED]" {
		t.Errorf("Cookie header was not redacted: %#v", requestHeaders)
	}
	response := context["openrouter_response"].(map[string]any)
	responseHeaders := response["headers"].(map[string]string)
	if responseHeaders["Set-Cookie"] != "[REDACTED]" {
		t.Errorf("Set-Cookie header was not redacted: %#v", responseHeaders)
	}
	contextText := fmt.Sprint(context)
	for _, secret := range []string{"fresh-session-jwt", "response-secret", "body-secret"} {
		if strings.Contains(contextText, secret) {
			t.Errorf("error context leaked %q: %s", secret, contextText)
		}
	}
}

func TestFrontendAPIRejectsSignedOutHTML(t *testing.T) {
	auth, _ := newFrontendTestAuth(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html>sign in</html>")
	}))

	_, err := FetchActivityData(auth)
	if err == nil || !strings.Contains(err.Error(), "unexpected content type") {
		t.Fatalf("error = %v, want signed-out HTML rejection", err)
	}
}

func TestFetchWorkspaceDataRequiresDefaultMembership(t *testing.T) {
	auth, _ := newFrontendTestAuth(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"default_workspace_id": "ws-missing",
			"data": []any{
				map[string]any{"id": "ws-active", "is_data_discount_logging_enabled": false},
			},
		})
	}))

	_, err := FetchWorkspaceData(auth)
	if err == nil || !strings.Contains(err.Error(), "absent from") {
		t.Fatalf("error = %v, want missing-default error", err)
	}
}

func TestDeleteProvisioningKeyRejectsMalformedHash(t *testing.T) {
	var requests atomic.Int32
	auth, _ := newFrontendTestAuth(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		writeJSON(t, w, http.StatusOK, map[string]any{"data": map[string]any{}})
	}))

	if err := DeleteProvisioningKey(auth, "not-a-key-hash"); err == nil {
		t.Fatal("expected invalid hash error")
	}
	if requests.Load() != 0 {
		t.Errorf("made %d requests for malformed hash", requests.Load())
	}
}

func TestDeleteProvisioningKeyRequiresDeletionConfirmation(t *testing.T) {
	responses := map[string]any{
		"false":   map[string]any{"data": map[string]any{"hash": testKeyHash, "deleted": false}},
		"missing": map[string]any{"data": map[string]any{"hash": testKeyHash}},
	}

	for name, response := range responses {
		t.Run(name, func(t *testing.T) {
			auth, _ := newFrontendTestAuth(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeJSON(t, w, http.StatusOK, response)
			}))

			err := DeleteProvisioningKey(auth, testKeyHash)
			if err == nil || !strings.Contains(err.Error(), "did not confirm deletion") {
				t.Fatalf("error = %v, want deletion-confirmation error", err)
			}
		})
	}
}

func TestNewAuthDoesNotFetchOpenRouterBundles(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch {
		case r.URL.Path == "/clerk.js":
			fmt.Fprint(w, `window.clerkVersion="5.111.0";window.apiVersion="2025-11-10";`)
		case strings.Contains(r.URL.Path, "/v1/client/sessions/sess_test/tokens"):
			writeJSON(t, w, http.StatusOK, map[string]string{"jwt": "refreshed-jwt"})
		default:
			t.Errorf("unexpected auth-time request: %s", r.URL.Path)
			writeJSON(t, w, http.StatusNotFound, map[string]string{"error": "unexpected"})
		}
	}))
	defer server.Close()

	previousJSURL := clerkJSURL
	previousAPI := clerkAPI
	clerkJSURL = server.URL + "/clerk.js"
	clerkAPI = server.URL + "/v1/client/sessions/%s/tokens"
	defer func() {
		clerkJSURL = previousJSURL
		clerkAPI = previousAPI
	}()

	_, err := NewAuthFromCookieData(map[string]any{
		"cookies": []any{
			map[string]any{"name": "__client", "value": "client-token", "domain": "clerk.openrouter.ai"},
			map[string]any{"name": "__client_uat", "value": "123", "domain": "openrouter.ai"},
			map[string]any{"name": "clerk_active_context", "value": "sess_test:", "domain": "openrouter.ai"},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthFromCookieData: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("auth made %d requests, want Clerk JS + token only: %v", len(paths), paths)
	}
}
