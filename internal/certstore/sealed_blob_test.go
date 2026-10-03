package certstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newSealedBlobForTest(t *testing.T, jwk []byte, purpose string) (*SealedBlobStore, *memBlobs) {
	t.Helper()
	skr := &fakeSKR{t: t, jwk: jwk, wantMAA: "sharedeus.eus.attest.azure.net", wantAKV: "https://kv.vault.azure.net", wantKID: "tls-kek"}
	srv := httptest.NewServer(http.HandlerFunc(skr.handler))
	t.Cleanup(srv.Close)
	blobs := &memBlobs{}
	st, err := NewSealedBlobStore(blobs, &SKRReleaser{
		URL: srv.URL + "/key/release", MAAEndpoint: skr.wantMAA, AKVEndpoint: skr.wantAKV, KID: skr.wantKID,
	}, purpose)
	if err != nil {
		t.Fatal(err)
	}
	return st, blobs
}

func TestSealedBlobStoreRoundtripAndPurposeSeparation(t *testing.T) {
	ctx := context.Background()
	jwk := rsaJWK(t, "tls-kek")
	station, blobs := newSealedBlobForTest(t, jwk, "stationstore")
	payload := []byte(`{"v":1,"stations":[{"public_key":"abc"}]}`)
	if err := station.SaveBlob(ctx, payload); err != nil {
		t.Fatal(err)
	}
	// Ciphertext only in the backing store.
	raw, _ := blobs.LoadBlob(ctx)
	if strings.Contains(string(raw), "abc") {
		t.Fatal("plaintext leaked into the backing store")
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Purpose != "stationstore" || env.KID != "tls-kek" {
		t.Fatalf("envelope = %+v err=%v", env, err)
	}
	got, err := station.LoadBlob(ctx)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("got %q err=%v", got, err)
	}

	// The same key material under a different purpose must not open it, and
	// the mismatch must be reported before any decryption is attempted.
	cert, _ := newSealedBlobForTest(t, jwk, "")
	cert.Blobs = blobs
	if _, err := cert.LoadBlob(ctx); err == nil || !strings.Contains(err.Error(), "purpose") {
		t.Fatalf("expected purpose mismatch, got %v", err)
	}
	other, _ := newSealedBlobForTest(t, jwk, "other")
	other.Blobs = blobs
	if _, err := other.LoadBlob(ctx); err == nil || !strings.Contains(err.Error(), "purpose") {
		t.Fatalf("expected purpose mismatch, got %v", err)
	}

	// Even with the purpose label forged, the derived key differs, so the
	// AEAD check fails.
	env.Purpose = ""
	forged, _ := json.Marshal(env)
	_ = blobs.SaveBlob(ctx, forged)
	if _, err := cert.LoadBlob(ctx); err == nil || !strings.Contains(err.Error(), "unseal") {
		t.Fatalf("expected unseal failure on forged purpose, got %v", err)
	}
}

func TestSealedBlobStoreLegacyEnvelopeStillOpens(t *testing.T) {
	// A bundle sealed by SealedStore (empty purpose, no "purpose" field) must
	// be readable by SealedStore after the refactor.
	ctx := context.Background()
	st, blobs, _ := newSealedForTest(t, rsaJWK(t, "tls-kek"))
	want := testBundle(t, "verifier.example", 100*24*3600e9)
	if err := st.Save(ctx, want); err != nil {
		t.Fatal(err)
	}
	raw, _ := blobs.LoadBlob(ctx)
	if strings.Contains(string(raw), `"purpose"`) {
		t.Fatal("certificate envelope must not carry a purpose field (omitempty)")
	}
	got, err := st.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertBundleEqual(t, got, want)
}

func TestNewSealedBlobStoreRejectsBadPurpose(t *testing.T) {
	if _, err := NewSealedBlobStore(&memBlobs{}, &SKRReleaser{}, "a/b"); err == nil {
		t.Fatal("slash in purpose must be rejected")
	}
	if _, err := NewSealedBlobStore(nil, &SKRReleaser{}, "x"); err == nil {
		t.Fatal("nil blobs must be rejected")
	}
}

func TestFileStoreNamed(t *testing.T) {
	dir := t.TempDir()
	a, err := NewFileStoreNamed(dir, "a.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewFileStoreNamed(dir, "b.json")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := a.SaveBlob(ctx, []byte("A")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.LoadBlob(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("b must be independent of a, got %v", err)
	}
	if err := b.SaveBlob(ctx, []byte("B")); err != nil {
		t.Fatal(err)
	}
	ga, _ := a.LoadBlob(ctx)
	gb, _ := b.LoadBlob(ctx)
	if string(ga) != "A" || string(gb) != "B" {
		t.Fatalf("a=%q b=%q", ga, gb)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	if _, err := NewFileStoreNamed(dir, filepath.Join("sub", "x.json")); err == nil {
		t.Fatal("nested file name must be rejected")
	}
	// Default name is unchanged.
	d, _ := NewFileStore(dir)
	if filepath.Base(d.path()) != bundleFileName {
		t.Fatalf("default path = %s", d.path())
	}
}

func TestBlobStoreFromEnv(t *testing.T) {
	spec := BlobSpec{ModeVar: "X_STORE", DirVar: "X_DIR", FileName: "x.json", SecretName: "x-secret", Purpose: "x"}
	t.Run("none", func(t *testing.T) {
		st, desc, err := BlobStoreFromEnv(envMap(nil), spec)
		if err != nil || st != nil || desc != "none" {
			t.Fatalf("st=%v desc=%q err=%v", st, desc, err)
		}
	})
	t.Run("file", func(t *testing.T) {
		s := spec
		s.Mode, s.Dir = "file", "/data"
		st, desc, err := BlobStoreFromEnv(envMap(nil), s)
		if err != nil || desc != "file:/data/x.json" {
			t.Fatalf("desc=%q err=%v", desc, err)
		}
		if _, ok := st.(*FileStore); !ok {
			t.Fatalf("got %T", st)
		}
		s.Dir = ""
		if _, _, err := BlobStoreFromEnv(envMap(nil), s); err == nil || !strings.Contains(err.Error(), "X_DIR") {
			t.Fatalf("expected X_DIR error, got %v", err)
		}
	})
	t.Run("file-sealed", func(t *testing.T) {
		s := spec
		s.Mode, s.Dir = "file-sealed", "/data"
		st, desc, err := BlobStoreFromEnv(envMap(map[string]string{EnvKEKVault: "kv", EnvKEKName: "kek"}), s)
		if err != nil {
			t.Fatal(err)
		}
		sb := st.(*SealedBlobStore)
		if sb.Purpose != "x" || sb.Releaser.(*SKRReleaser).KID != "kek" || !strings.HasPrefix(desc, "file-sealed:/data/x.json") {
			t.Fatalf("store=%+v desc=%q", sb, desc)
		}
		if _, _, err := BlobStoreFromEnv(envMap(nil), s); err == nil || !strings.Contains(err.Error(), "X_STORE") {
			t.Fatalf("missing kek must name the mode var, got %v", err)
		}
	})
	t.Run("keyvault-sealed", func(t *testing.T) {
		s := spec
		s.Mode = "keyvault-sealed"
		st, desc, err := BlobStoreFromEnv(envMap(map[string]string{
			EnvKEKVault: "kv", EnvKEKName: "kek", EnvSecretVault: "secrets-kv", EnvMSIClientID: "cid",
		}), s)
		if err != nil {
			t.Fatal(err)
		}
		sb := st.(*SealedBlobStore)
		kv := sb.Blobs.(*KeyVaultSecretStore)
		if kv.SecretName != "x-secret" || kv.VaultURL != "https://secrets-kv.vault.azure.net" || kv.Tokens.(*MSITokenSource).ClientID != "cid" {
			t.Fatalf("kv=%+v", kv)
		}
		if !strings.Contains(desc, "keyvault-sealed:https://secrets-kv.vault.azure.net/secrets/x-secret") {
			t.Fatalf("desc=%q", desc)
		}
		s.SecretName = ""
		if _, _, err := BlobStoreFromEnv(envMap(map[string]string{EnvKEKVault: "kv", EnvKEKName: "kek", EnvSecretVault: "v"}), s); err == nil {
			t.Fatal("empty secret name must fail")
		}
	})
	t.Run("unknown", func(t *testing.T) {
		s := spec
		s.Mode = "s3"
		if _, _, err := BlobStoreFromEnv(envMap(nil), s); err == nil || !strings.Contains(err.Error(), "X_STORE") {
			t.Fatalf("got %v", err)
		}
	})
}

type staticTokens struct{ tok, resource string }

func (s *staticTokens) Token(_ context.Context, resource string) (string, error) {
	s.resource = resource
	return s.tok, nil
}

func TestSKRReleaserPassesAccessTokenWhenConfigured(t *testing.T) {
	jwk := rsaJWK(t, "kek")
	var seen map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&seen)
		_ = json.NewEncoder(w).Encode(map[string]string{"key": string(jwk)})
	}))
	defer srv.Close()
	tokens := &staticTokens{tok: "eyJ-token"}
	rel := &SKRReleaser{URL: srv.URL, MAAEndpoint: "maa", AKVEndpoint: "https://kv.vault.azure.net", KID: "kek", Tokens: tokens}
	if _, err := rel.ReleaseKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	if seen["access_token"] != "eyJ-token" || tokens.resource != KeyVaultResource {
		t.Fatalf("request=%v resource=%q", seen, tokens.resource)
	}
	// Managed HSM endpoints get the HSM audience.
	rel.AKVEndpoint = "https://hsm.managedhsm.azure.net"
	_, _ = rel.ReleaseKey(context.Background())
	if tokens.resource != ManagedHSMResource {
		t.Fatalf("resource=%q", tokens.resource)
	}
	// Without Tokens no access_token field is sent (sidecar uses the group identity).
	rel.Tokens = nil
	seen = nil
	_, _ = rel.ReleaseKey(context.Background())
	if _, present := seen["access_token"]; present {
		t.Fatal("access_token must be omitted when no token source is configured")
	}
}

func TestReleaserFromEnvAttachesTokensOnlyWithClientID(t *testing.T) {
	rel, err := ReleaserFromEnv(envMap(map[string]string{EnvKEKVault: "kv", EnvKEKName: "kek"}), "X_STORE")
	if err != nil || rel.Tokens != nil {
		t.Fatalf("rel=%+v err=%v", rel, err)
	}
	rel, err = ReleaserFromEnv(envMap(map[string]string{EnvKEKVault: "kv", EnvKEKName: "kek", EnvMSIClientID: "cid",
		"IDENTITY_ENDPOINT": "http://localhost:1/msi", "IDENTITY_HEADER": "h"}), "X_STORE")
	if err != nil {
		t.Fatal(err)
	}
	ms, ok := rel.Tokens.(*MSITokenSource)
	if !ok || ms.ClientID != "cid" || ms.Endpoint != "http://localhost:1/msi" {
		t.Fatalf("tokens=%+v", rel.Tokens)
	}
}

func TestSKRReleaserSendsBareVaultHost(t *testing.T) {
	jwk := rsaJWK(t, "kek")
	var seen map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&seen)
		_ = json.NewEncoder(w).Encode(map[string]string{"key": string(jwk)})
	}))
	defer srv.Close()
	for _, in := range []string{"https://kv.vault.azure.net", "https://kv.vault.azure.net/", "kv.vault.azure.net"} {
		rel := &SKRReleaser{URL: srv.URL, MAAEndpoint: "sharedeus.eus.attest.azure.net", AKVEndpoint: in, KID: "kek"}
		if _, err := rel.ReleaseKey(context.Background()); err != nil {
			t.Fatal(err)
		}
		if seen["akv_endpoint"] != "kv.vault.azure.net" || seen["maa_endpoint"] != "sharedeus.eus.attest.azure.net" {
			t.Fatalf("request for %q = %v", in, seen)
		}
	}
}

func TestPurposeNamespacesNeverCollideWithCertificate(t *testing.T) {
	if _, err := NewSealedBlobStore(&memBlobs{}, &SKRReleaser{}, "certstore"); err == nil {
		t.Fatal("the certificate purpose name must be reserved")
	}
	if _, err := NewSealedBlobStore(&memBlobs{}, &SKRReleaser{}, "CertStore"); err == nil {
		t.Fatal("the certificate purpose name must be reserved case-insensitively")
	}
	cert := string(hkdfInfo("kek", ""))
	for _, p := range []string{"stationstore", "x", "certstore-"} {
		if string(hkdfInfo("kek", p)) == cert {
			t.Fatalf("purpose %q derives the certificate key", p)
		}
	}
}
