package certstore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAzure serves an App Service-style MSI endpoint and Key Vault secret API.
type fakeAzure struct {
	t          *testing.T
	mu         sync.Mutex
	secrets    map[string]string
	tokenCalls int
	getCalls   int
	putCalls   int
	identityHd string
	clientID   string
	expiresOn  interface{}
}

func (f *fakeAzure) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/msi/token":
		f.tokenCalls++
		if r.Header.Get("X-IDENTITY-HEADER") != f.identityHd {
			http.Error(w, "missing identity header", http.StatusUnauthorized)
			return
		}
		q := r.URL.Query()
		if q.Get("resource") != KeyVaultResource || q.Get("api-version") != "2019-08-01" || q.Get("client_id") != f.clientID {
			f.t.Errorf("unexpected token query: %s", r.URL.RawQuery)
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok-" + q.Get("resource"), "expires_on": f.expiresOn, "resource": q.Get("resource"), "token_type": "Bearer",
		})
	case strings.HasPrefix(r.URL.Path, "/secrets/"):
		if r.Header.Get("Authorization") != "Bearer tok-"+KeyVaultResource {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]string{"code": "Unauthorized", "message": "bad token"}})
			return
		}
		if r.URL.Query().Get("api-version") != "7.4" {
			http.Error(w, "api-version", http.StatusBadRequest)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/secrets/")
		switch r.Method {
		case http.MethodGet:
			f.getCalls++
			v, ok := f.secrets[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]string{"code": "SecretNotFound", "message": "A secret with (name/id) " + name + " was not found in this key vault."}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": v, "id": "https://kv/secrets/" + name + "/v1", "attributes": map[string]bool{"enabled": true}})
		case http.MethodPut:
			f.putCalls++
			var body kvSecret
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if body.ContentType != "application/json" {
				f.t.Errorf("contentType = %q", body.ContentType)
			}
			f.secrets[name] = body.Value
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": body.Value, "id": "https://kv/secrets/" + name + "/v2"})
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	default:
		http.NotFound(w, r)
	}
}

func newFakeAzure(t *testing.T) (*fakeAzure, *httptest.Server) {
	t.Helper()
	f := &fakeAzure{t: t, secrets: map[string]string{}, identityHd: "hdr-secret", expiresOn: "9999999999"}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	return f, srv
}

func TestKeyVaultSecretStoreRoundtrip(t *testing.T) {
	az, srv := newFakeAzure(t)
	tokens := &MSITokenSource{Endpoint: srv.URL + "/msi/token", Header: az.identityHd}
	kv, err := NewKeyVaultSecretStore(srv.URL, "oa-verifier-tls-bundle", tokens)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := kv.LoadBlob(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing secret: got %v want ErrNotFound", err)
	}
	if err := kv.SaveBlob(ctx, []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	got, err := kv.LoadBlob(ctx)
	if err != nil || string(got) != `{"v":1}` {
		t.Fatalf("load = %q, %v", got, err)
	}
	if az.tokenCalls != 1 {
		t.Fatalf("token should be cached; got %d token calls", az.tokenCalls)
	}
	if az.putCalls != 1 || az.getCalls != 2 {
		t.Fatalf("calls: put=%d get=%d", az.putCalls, az.getCalls)
	}
}

func TestKeyVaultSealedEndToEnd(t *testing.T) {
	az, srv := newFakeAzure(t)
	tokens := &MSITokenSource{Endpoint: srv.URL + "/msi/token", Header: az.identityHd}
	kv, _ := NewKeyVaultSecretStore(srv.URL, "bundle", tokens)
	skr := &fakeSKR{t: t, jwk: rsaJWK(t, "kek"), wantMAA: "maa", wantAKV: "https://kv.vault.azure.net", wantKID: "kek"}
	skrSrv := httptest.NewServer(http.HandlerFunc(skr.handler))
	defer skrSrv.Close()
	st, _ := NewSealedStore(kv, &SKRReleaser{URL: skrSrv.URL + "/key/release", MAAEndpoint: "maa", AKVEndpoint: "https://kv.vault.azure.net", KID: "kek"})

	ctx := context.Background()
	want := testBundle(t, "verifier.example", 90*24*time.Hour)
	if err := st.Save(ctx, want); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(az.secrets["bundle"], "PRIVATE KEY") {
		t.Fatal("vault received plaintext")
	}
	got, err := st.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertBundleEqual(t, got, want)
}

func TestMSITokenSourceIMDSFallbackAndErrors(t *testing.T) {
	var gotMetadata string
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMetadata = r.Header.Get("Metadata")
		gotQuery = r.URL.RawQuery
		if r.URL.Query().Get("client_id") == "boom" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "abc", "expires_in": "3599"})
	}))
	defer srv.Close()

	// Endpoint set but no header -> IMDS style (Metadata: true, 2018-02-01).
	ts := &MSITokenSource{Endpoint: srv.URL, ClientID: "11111111-2222-3333-4444-555555555555"}
	tok, err := ts.Token(context.Background(), KeyVaultResource)
	if err != nil || tok != "abc" {
		t.Fatalf("token = %q, %v", tok, err)
	}
	if gotMetadata != "true" || !strings.Contains(gotQuery, "api-version=2018-02-01") || !strings.Contains(gotQuery, "client_id=11111111") {
		t.Fatalf("unexpected IMDS request: Metadata=%q query=%q", gotMetadata, gotQuery)
	}

	bad := &MSITokenSource{Endpoint: srv.URL, ClientID: "boom"}
	if _, err := bad.Token(context.Background(), KeyVaultResource); err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("expected HTTP 400 error, got %v", err)
	}
}

type tokenRoundTripper func(*http.Request) (*http.Response, error)

func (f tokenRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMSITokenSourceLinuxACIHeaderWithoutEndpoint(t *testing.T) {
	// Linux ACI may inject IDENTITY_HEADER without IDENTITY_ENDPOINT. A fake
	// transport checks the real destination without contacting Azure metadata.
	for _, header := range []string{"", "unpaired-platform-header"} {
		t.Run(header, func(t *testing.T) {
			source := NewMSITokenSourceFromEnv(func(key string) string {
				if key == "IDENTITY_HEADER" {
					return header
				}
				return ""
			}, "staging-identity")
			calls := 0
			source.HTTPClient = &http.Client{Transport: tokenRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Scheme != "http" || r.URL.Host != "169.254.169.254" || r.URL.Path != "/metadata/identity/oauth2/token" {
					t.Fatalf("unexpected metadata destination: %s", r.URL.Redacted())
				}
				q := r.URL.Query()
				if q.Get("resource") != KeyVaultResource || q.Get("client_id") != "staging-identity" || q.Get("api-version") != "2018-02-01" {
					t.Fatal("incorrect IMDS audience, identity, or API version")
				}
				if r.Header.Get("Metadata") != "true" || r.Header.Get("X-IDENTITY-HEADER") != "" {
					t.Fatal("IMDS must use Metadata:true without the unrelated identity header")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"test-token","expires_in":3600}`))}, nil
			})}
			for range 2 {
				if token, err := source.Token(context.Background(), KeyVaultResource); err != nil || token != "test-token" {
					t.Fatalf("token retrieval failed: %v", err)
				}
			}
			if calls != 1 {
				t.Fatalf("expected one request and cached reuse, got %d", calls)
			}
		})
	}
}

func TestMSITokenSourceExplicitIdentityRejectionDoesNotFallBack(t *testing.T) {
	calls := 0
	source := &MSITokenSource{Endpoint: "http://localhost:1234/token", Header: "test-header"}
	source.HTTPClient = &http.Client{Transport: tokenRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Host != "localhost:1234" || r.Header.Get("X-IDENTITY-HEADER") != "test-header" || r.Header.Get("Metadata") != "" {
			t.Fatal("explicit identity request changed destination or protocol")
		}
		return &http.Response{StatusCode: 401, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":"unauthorized"}`))}, nil
	})}
	if _, err := source.Token(context.Background(), KeyVaultResource); err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("expected identity rejection, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("identity rejection must not fall back to another source: %d requests", calls)
	}
}

func TestKeyVaultErrorsSurfaceCode(t *testing.T) {
	az, srv := newFakeAzure(t)
	// Wrong identity header -> token endpoint 401 -> load fails with a clear error.
	tokens := &MSITokenSource{Endpoint: srv.URL + "/msi/token", Header: "wrong"}
	kv, _ := NewKeyVaultSecretStore(srv.URL, "bundle", tokens)
	if _, err := kv.LoadBlob(context.Background()); err == nil || !strings.Contains(err.Error(), "msi token HTTP 401") {
		t.Fatalf("expected msi error, got %v", err)
	}
	_ = az
	// Vault rejects the token -> error message carries the Key Vault code.
	kv2 := &KeyVaultSecretStore{VaultURL: srv.URL, SecretName: "bundle", Tokens: staticToken("nope")}
	if _, err := kv2.LoadBlob(context.Background()); err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("expected Unauthorized, got %v", err)
	}
}

type staticToken string

func (s staticToken) Token(context.Context, string) (string, error) { return string(s), nil }

func TestNormalizeVaultURL(t *testing.T) {
	cases := map[string]string{
		"myvault":                             "https://myvault.vault.azure.net",
		"https://myvault.vault.azure.net/":    "https://myvault.vault.azure.net",
		"myhsm.managedhsm.azure.net":          "https://myhsm.managedhsm.azure.net",
		"http://127.0.0.1:8443":               "http://127.0.0.1:8443",
		" https://x.vault.azure.net ":         "https://x.vault.azure.net",
		"https://kv.vault.azure.net/secrets/": "https://kv.vault.azure.net/secrets",
	}
	for in, want := range cases {
		if got := NormalizeVaultURL(in); got != want {
			t.Errorf("NormalizeVaultURL(%q) = %q, want %q", in, got, want)
		}
	}
}
