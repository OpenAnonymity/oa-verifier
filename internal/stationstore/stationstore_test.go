package stationstore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openanonymity/oa-verifier/internal/certstore"
	"github.com/openanonymity/oa-verifier/internal/models"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func sampleStation(id string) models.Station {
	now := time.Now().UTC().Format(time.RFC3339)
	return models.Station{
		StationID:   id,
		Email:       id + "@example.com",
		DisplayName: "Station " + id,
		CookieData: map[string]any{
			"cookies": []any{
				map[string]any{"name": "__client", "value": "tok-" + id, "domain": "clerk.openrouter.ai", "expires": float64(1.9e9)},
			},
		},
		RegisteredAt:    now,
		LastVerified:    &now,
		ProvisioningKey: "sk-or-mgmt-" + id,
		NextChallengeAt: time.Now().Add(time.Hour),
	}
}

func sampleSnapshot(ids ...string) *Snapshot {
	s := &Snapshot{SavedAt: time.Now().UTC()}
	for i, id := range ids {
		pk := strings.Repeat(string(rune('a'+i)), 64)
		st := sampleStation(id)
		s.Stations = append(s.Stations, RecordFromStation(pk, &st))
	}
	return s
}

func TestMarshalUnmarshalRoundtrip(t *testing.T) {
	want := sampleSnapshot("one", "two")
	data, err := Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != SnapshotVersion || len(got.Stations) != 2 {
		t.Fatalf("got %+v", got)
	}
	g, w := got.Stations[1].ToStation(), want.Stations[1].ToStation()
	if g.StationID != w.StationID || g.Email != w.Email || g.ProvisioningKey != w.ProvisioningKey ||
		g.LastVerified == nil || *g.LastVerified != *w.LastVerified || !g.NextChallengeAt.Equal(w.NextChallengeAt) ||
		g.DisplayName != w.DisplayName || g.RegisteredAt != w.RegisteredAt {
		t.Fatalf("station mismatch:\n got=%+v\nwant=%+v", g, w)
	}
	// Cookie data must survive as the same shape openrouter.NewAuthFromCookieData expects.
	cookies, ok := g.CookieData["cookies"].([]any)
	if !ok || len(cookies) != 1 {
		t.Fatalf("cookies = %#v", g.CookieData["cookies"])
	}
	c := cookies[0].(map[string]any)
	if c["name"] != "__client" || c["value"] != "tok-two" || c["domain"] != "clerk.openrouter.ai" {
		t.Fatalf("cookie = %#v", c)
	}
	if _, present := c["expires"]; present {
		t.Fatal("cookie attributes the verifier never reads must not be persisted")
	}
}

func TestMarshalEmptyAndNil(t *testing.T) {
	data, err := Marshal(&Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"stations":[]`) {
		t.Fatalf("empty snapshot must encode an empty array: %s", data)
	}
	if _, err := Marshal(nil); err == nil {
		t.Fatal("nil snapshot must fail")
	}
	got, err := Unmarshal(data)
	if err != nil || len(got.Stations) != 0 {
		t.Fatalf("got %+v err=%v", got, err)
	}
}

func TestUnmarshalRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"wrong version": `{"v":2,"stations":[]}`,
		"no version":    `{"stations":[]}`,
		"empty pk":      `{"v":1,"stations":[{"public_key":" ","station":{}}]}`,
		"duplicate pk":  `{"v":1,"stations":[{"public_key":"a","station":{}},{"public_key":"a","station":{}}]}`,
		"not json":      `nope`,
	}
	for name, in := range cases {
		if _, err := Unmarshal([]byte(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestMarshalEnforcesSizeBudget(t *testing.T) {
	s := sampleSnapshot("big")
	s.Stations[0].CookieData["blob"] = strings.Repeat("x", MaxEncodedBytes)
	_, err := Marshal(s)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
}

func TestDigestIgnoresVolatileFields(t *testing.T) {
	a := sampleSnapshot("one")
	b := sampleSnapshot("one")
	// Same durable content, different volatile fields.
	b.SavedAt = a.SavedAt.Add(time.Hour)
	b.Stations[0].NextChallengeAt = a.Stations[0].NextChallengeAt.Add(time.Hour)
	later := time.Now().UTC().Add(time.Minute).Format(time.RFC3339)
	b.Stations[0].LastVerified = &later
	b.Stations[0].FailureCount = 7
	if Digest(a) != Digest(b) {
		t.Fatal("digest must ignore next-challenge time, last-verified timestamp and counters")
	}
	// Durable changes must be visible.
	c := sampleSnapshot("one")
	c.Stations[0].ProvisioningKey = "sk-or-mgmt-rotated"
	if Digest(a) == Digest(c) {
		t.Fatal("digest must change with the management key")
	}
	d := sampleSnapshot("one")
	d.Stations[0].LastVerified = nil
	if Digest(a) == Digest(d) {
		t.Fatal("digest must change when a station stops being verified")
	}
	e := sampleSnapshot("one")
	now := time.Now()
	e.Stations[0].FailureFirstAt = &now
	if Digest(a) == Digest(e) {
		t.Fatal("digest must change when a failure window opens")
	}
	f := sampleSnapshot("one")
	f.Stations[0].CookieData["cookies"] = []any{map[string]any{"name": "__client", "value": "fresh"}}
	if Digest(a) == Digest(f) {
		t.Fatal("digest must change with re-supplied cookies")
	}
	if Digest(nil) != "" || Digest(&Snapshot{}) == "" {
		t.Fatal("nil digest must be empty, empty snapshot digest must not")
	}
}

func TestNoopStore(t *testing.T) {
	var st Store = NoopStore{}
	if _, err := st.Load(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if err := st.Save(context.Background(), sampleSnapshot("x")); err != nil {
		t.Fatal(err)
	}
}

func TestFileBackendRoundtrip(t *testing.T) {
	dir := t.TempDir()
	st, desc, err := FromEnv(envMap(map[string]string{EnvStore: "file", EnvStoreDir: dir}))
	if err != nil {
		t.Fatal(err)
	}
	if desc != "file:"+filepath.Join(dir, FileName) {
		t.Fatalf("desc=%q", desc)
	}
	ctx := context.Background()
	if _, err := st.Load(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fresh store must report not found, got %v", err)
	}
	want := sampleSnapshot("one")
	if err := st.Save(ctx, want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %v", info.Mode().Perm())
	}
	got, err := st.Load(ctx)
	if err != nil || len(got.Stations) != 1 || got.Stations[0].ProvisioningKey != "sk-or-mgmt-one" {
		t.Fatalf("got %+v err=%v", got, err)
	}
	// The TLS bundle and the station state share a directory without colliding.
	if _, err := os.Stat(filepath.Join(dir, "tls-bundle.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("station store must not touch the TLS bundle file: %v", err)
	}
}

// --- sealed backend through a fake SKR sidecar -----------------------------

type memBlobs struct {
	mu   sync.Mutex
	data []byte
}

func (m *memBlobs) LoadBlob(context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		return nil, certstore.ErrNotFound
	}
	return append([]byte(nil), m.data...), nil
}

func (m *memBlobs) SaveBlob(_ context.Context, d []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = append([]byte(nil), d...)
	return nil
}

func fakeSKRServer(t *testing.T, jwk []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["kid"] != "kek" || req["akv_endpoint"] != "kv.vault.azure.net" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unexpected request"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"key": string(jwk)})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func octJWK(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{"kty": "oct", "kid": "kek", "k": base64.RawURLEncoding.EncodeToString(k)})
	return b
}

func TestSealedBackendRoundtripAndIsolationFromTLSBundle(t *testing.T) {
	ctx := context.Background()
	jwk := octJWK(t)
	skr := fakeSKRServer(t, jwk)
	blobs := &memBlobs{}
	rel := &certstore.SKRReleaser{URL: skr.URL, MAAEndpoint: "maa", AKVEndpoint: "https://kv.vault.azure.net", KID: "kek"}

	sealed, err := certstore.NewSealedBlobStore(blobs, rel, Purpose)
	if err != nil {
		t.Fatal(err)
	}
	st := NewBlobStore(sealed)
	want := sampleSnapshot("one", "two")
	if err := st.Save(ctx, want); err != nil {
		t.Fatal(err)
	}
	raw, _ := blobs.LoadBlob(ctx)
	for _, secret := range []string{"sk-or-mgmt-one", "tok-two", "one@example.com"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("secret %q leaked into the sealed blob", secret)
		}
	}
	got, err := st.Load(ctx)
	if err != nil || len(got.Stations) != 2 || got.Stations[1].ProvisioningKey != "sk-or-mgmt-two" {
		t.Fatalf("got %+v err=%v", got, err)
	}

	// The certificate store, keyed from the same KEK, must refuse this blob.
	certStore, _ := certstore.NewSealedStore(blobs, rel)
	if _, err := certStore.Load(ctx); err == nil || !strings.Contains(err.Error(), "purpose") {
		t.Fatalf("certificate store must reject a station blob, got %v", err)
	}
}

func TestFromEnvModes(t *testing.T) {
	t.Run("default none", func(t *testing.T) {
		st, desc, err := FromEnv(envMap(nil))
		if err != nil || desc != "none" {
			t.Fatalf("desc=%q err=%v", desc, err)
		}
		if _, ok := st.(NoopStore); !ok {
			t.Fatalf("got %T", st)
		}
	})
	t.Run("keyvault-sealed uses shared TLS_CERT_* variables and its own secret", func(t *testing.T) {
		_, desc, err := FromEnv(envMap(map[string]string{
			EnvStore: "keyvault-sealed", certstore.EnvKEKVault: "kv", certstore.EnvKEKName: "kek", certstore.EnvSecretVault: "kv",
		}))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(desc, "/secrets/"+DefaultSecretName) || !strings.Contains(desc, "kek=https://kv.vault.azure.net/kek") {
			t.Fatalf("desc=%q", desc)
		}
		_, desc, err = FromEnv(envMap(map[string]string{
			EnvStore: "keyvault-sealed", certstore.EnvKEKVault: "kv", certstore.EnvKEKName: "kek", certstore.EnvSecretVault: "kv",
			EnvSecretName: "custom",
		}))
		if err != nil || !strings.Contains(desc, "/secrets/custom") {
			t.Fatalf("desc=%q err=%v", desc, err)
		}
	})
	t.Run("misconfiguration is an error", func(t *testing.T) {
		if _, _, err := FromEnv(envMap(map[string]string{EnvStore: "keyvault-sealed"})); err == nil {
			t.Fatal("sealed without KEK must fail")
		}
		if _, _, err := FromEnv(envMap(map[string]string{EnvStore: "file"})); err == nil || !strings.Contains(err.Error(), EnvStoreDir) {
			t.Fatalf("file without dir must name %s, got %v", EnvStoreDir, err)
		}
		if _, _, err := FromEnv(envMap(map[string]string{EnvStore: "redis"})); err == nil || !strings.Contains(err.Error(), EnvStore) {
			t.Fatalf("unknown mode must name %s, got %v", EnvStore, err)
		}
	})
}

func TestRecordRoundTripAndGoldenFieldNames(t *testing.T) {
	st := sampleStation("one")
	first := time.Now().UTC().Truncate(time.Second)
	st.FailureFirstAt = &first
	st.FailureLastAt = &first
	st.FailureReason = "activity_fetch_failed"
	st.FailureStatus = 503
	st.FailureCount = 2
	rec := RecordFromStation("pk", &st)
	back := rec.ToStation()
	if back.StationID != st.StationID || back.Email != st.Email || back.DisplayName != st.DisplayName ||
		back.RegisteredAt != st.RegisteredAt || back.ProvisioningKey != st.ProvisioningKey ||
		*back.LastVerified != *st.LastVerified || !back.NextChallengeAt.Equal(st.NextChallengeAt) ||
		!back.FailureFirstAt.Equal(*st.FailureFirstAt) || !back.FailureLastAt.Equal(*st.FailureLastAt) ||
		back.FailureReason != st.FailureReason || back.FailureStatus != st.FailureStatus || back.FailureCount != st.FailureCount {
		t.Fatalf("round trip lost data:\n got=%+v\nwant=%+v", back, st)
	}
	// Pointers are copies, not aliases.
	*rec.LastVerified = "changed"
	if *st.LastVerified == "changed" {
		t.Fatal("LastVerified aliased")
	}
	// The wire names are a contract: renaming a Go field must not change them.
	data, _ := json.Marshal(rec)
	var keys map[string]any
	_ = json.Unmarshal(data, &keys)
	for _, k := range []string{"public_key", "station_id", "email", "display_name", "cookie_data", "registered_at",
		"last_verified", "provisioning_key", "next_challenge_at", "failure_first_at", "failure_last_at",
		"failure_reason", "failure_status", "failure_count"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("missing wire field %q in %s", k, data)
		}
	}
	if _, ok := keys["StationID"]; ok {
		t.Fatal("Go field names must not leak into the wire format")
	}
}

func TestTrimCookieDataKeepsOnlyWhatTheVerifierReads(t *testing.T) {
	in := map[string]any{
		"email": "op@example.com",
		"cookies": []any{
			map[string]any{"name": "__client", "value": "c", "domain": "clerk.openrouter.ai", "path": "/", "expires": 1.9e9, "httpOnly": true},
			map[string]any{"name": "__client_uat_NO6jtgZM", "value": "1", "domain": "openrouter.ai"},
			map[string]any{"name": "clerk_active_context", "value": "sess:org", "domain": "openrouter.ai"},
			map[string]any{"name": "__session_NO6jtgZM", "value": "jwt", "domain": "openrouter.ai"},
			map[string]any{"name": "__refresh_NO6jtgZM", "value": "r", "domain": "openrouter.ai"},
			map[string]any{"name": "_ga", "value": "tracking", "domain": "openrouter.ai"},
			map[string]any{"name": "__cf_bm", "value": strings.Repeat("x", 4000), "domain": "openrouter.ai"},
			map[string]any{"name": "__client", "value": "", "domain": "clerk.openrouter.ai"},
			"not a cookie",
		},
	}
	out := TrimCookieData(in)
	if out["email"] != "op@example.com" {
		t.Fatalf("top-level keys must be kept: %v", out)
	}
	cookies := out["cookies"].([]any)
	names := make([]string, 0, len(cookies))
	for _, c := range cookies {
		m := c.(map[string]any)
		names = append(names, m["name"].(string))
		if len(m) > 3 {
			t.Fatalf("cookie must be reduced to name/value/domain: %v", m)
		}
	}
	want := "__client,__client_uat_NO6jtgZM,clerk_active_context,__session_NO6jtgZM,__refresh_NO6jtgZM"
	if strings.Join(names, ",") != want {
		t.Fatalf("kept %v", names)
	}
	// The input is not mutated and nil stays nil.
	if len(in["cookies"].([]any)) != 9 {
		t.Fatal("input mutated")
	}
	if TrimCookieData(nil) != nil {
		t.Fatal("nil must stay nil")
	}
	// A cookie_data without a cookies list is passed through.
	odd := TrimCookieData(map[string]any{"raw": "x"})
	if odd["raw"] != "x" || odd["cookies"] != nil {
		t.Fatalf("odd = %v", odd)
	}
}
