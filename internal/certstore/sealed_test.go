package certstore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// memBlobs is an in-memory BlobStore that records what was written.
type memBlobs struct {
	mu   sync.Mutex
	data []byte
}

func (m *memBlobs) LoadBlob(context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		return nil, ErrNotFound
	}
	return append([]byte(nil), m.data...), nil
}

func (m *memBlobs) SaveBlob(_ context.Context, d []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = append([]byte(nil), d...)
	return nil
}

// fakeSKR mimics the sidecar's POST /key/release. It checks the request
// shape from upstream httpginendpoints.go and returns {"key": "<jwk json>"}.
type fakeSKR struct {
	t         *testing.T
	jwk       []byte
	wantMAA   string
	wantAKV   string
	wantKID   string
	calls     int
	failWith  int
	failError string
}

func (f *fakeSKR) handler(w http.ResponseWriter, r *http.Request) {
	f.calls++
	if r.Method != http.MethodPost || r.URL.Path != "/key/release" {
		http.Error(w, "wrong route", http.StatusNotFound)
		return
	}
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// The sidecar receives bare hosts; the test fixtures may be written as URLs.
	if req["maa_endpoint"] != f.wantMAA || req["akv_endpoint"] != bareHost(f.wantAKV) || req["kid"] != f.wantKID {
		f.t.Errorf("unexpected key release request: %v", req)
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid request format"})
		return
	}
	if f.failWith != 0 {
		w.WriteHeader(f.failWith)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": f.failError})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"key": string(f.jwk)})
}

func rsaJWK(t *testing.T, kid string) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	enc := func(b *big.Int) string { return base64.RawURLEncoding.EncodeToString(b.Bytes()) }
	jwk := map[string]string{
		"kty": "RSA", "kid": kid,
		"n": enc(priv.N), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
		"d": enc(priv.D), "p": enc(priv.Primes[0]), "q": enc(priv.Primes[1]),
		"dp": enc(priv.Precomputed.Dp), "dq": enc(priv.Precomputed.Dq), "qi": enc(priv.Precomputed.Qinv),
	}
	b, _ := json.Marshal(jwk)
	return b
}

func octJWK(t *testing.T, kid string) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{"kty": "oct", "kid": kid, "k": base64.RawURLEncoding.EncodeToString(k)})
	return b
}

func newSealedForTest(t *testing.T, jwk []byte) (*SealedStore, *memBlobs, *fakeSKR) {
	t.Helper()
	skr := &fakeSKR{t: t, jwk: jwk, wantMAA: "sharedeus.eus.attest.azure.net", wantAKV: "https://kv.vault.azure.net", wantKID: "tls-kek"}
	srv := httptest.NewServer(http.HandlerFunc(skr.handler))
	t.Cleanup(srv.Close)
	blobs := &memBlobs{}
	st, err := NewSealedStore(blobs, &SKRReleaser{
		URL: srv.URL + "/key/release", MAAEndpoint: skr.wantMAA, AKVEndpoint: skr.wantAKV, KID: skr.wantKID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return st, blobs, skr
}

func TestSealedStoreRoundtripRSA(t *testing.T) {
	st, blobs, skr := newSealedForTest(t, rsaJWK(t, "https://kv.vault.azure.net/keys/tls-kek/abc"))
	ctx := context.Background()

	if _, err := st.Load(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty: got %v want ErrNotFound", err)
	}
	if skr.calls != 0 {
		t.Fatal("key should not be released when there is nothing to unseal")
	}

	want := testBundle(t, "verifier.example", 90*24*time.Hour)
	if err := st.Save(ctx, want); err != nil {
		t.Fatal(err)
	}

	// Ciphertext must not contain the private key or certificate.
	raw, _ := blobs.LoadBlob(ctx)
	if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "CERTIFICATE") {
		t.Fatal("sealed blob leaks plaintext")
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env.Version != 1 || env.Alg != "A256GCM" || env.KDF != "HKDF-SHA256" || env.KID != "https://kv.vault.azure.net/keys/tls-kek/abc" {
		t.Fatalf("unexpected envelope header: %+v", env)
	}

	got, err := st.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertBundleEqual(t, got, want)
	if skr.calls != 2 {
		t.Fatalf("expected 2 key releases (save+load), got %d", skr.calls)
	}
}

func TestSealedStoreRoundtripOct(t *testing.T) {
	st, _, _ := newSealedForTest(t, octJWK(t, ""))
	ctx := context.Background()
	want := testBundle(t, "verifier.example", 90*24*time.Hour)
	if err := st.Save(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := st.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertBundleEqual(t, got, want)
}

func TestSealedStoreWrongKeyFails(t *testing.T) {
	st, blobs, _ := newSealedForTest(t, rsaJWK(t, "tls-kek"))
	ctx := context.Background()
	if err := st.Save(ctx, testBundle(t, "verifier.example", time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Same kid, different key material: authentication must fail.
	other, _, _ := newSealedForTest(t, rsaJWK(t, "tls-kek"))
	other.Blobs = blobs
	if _, err := other.Load(ctx); err == nil || !strings.Contains(err.Error(), "unseal") {
		t.Fatalf("expected unseal failure, got %v", err)
	}
	// Tampered ciphertext must fail.
	raw, _ := blobs.LoadBlob(ctx)
	var env envelope
	_ = json.Unmarshal(raw, &env)
	ct, _ := base64.StdEncoding.DecodeString(env.Ciphertext)
	ct[len(ct)/2] ^= 0x01
	env.Ciphertext = base64.StdEncoding.EncodeToString(ct)
	tampered, _ := json.Marshal(env)
	_ = blobs.SaveBlob(ctx, tampered)
	if _, err := st.Load(ctx); err == nil {
		t.Fatal("expected tampered ciphertext to fail")
	}
}

func TestSealedStoreKIDMismatch(t *testing.T) {
	st, blobs, _ := newSealedForTest(t, rsaJWK(t, "kek-v1"))
	ctx := context.Background()
	if err := st.Save(ctx, testBundle(t, "verifier.example", time.Hour)); err != nil {
		t.Fatal(err)
	}
	rotated, _, _ := newSealedForTest(t, rsaJWK(t, "kek-v2"))
	rotated.Blobs = blobs
	if _, err := rotated.Load(ctx); err == nil || !strings.Contains(err.Error(), "kid") {
		t.Fatalf("expected kid mismatch error, got %v", err)
	}
}

func TestSKRReleaserErrors(t *testing.T) {
	skr := &fakeSKR{t: t, wantMAA: "maa", wantAKV: "https://kv.vault.azure.net", wantKID: "k", failWith: http.StatusForbidden,
		failError: "secure key release failed: policy not satisfied\nsee docs"}
	srv := httptest.NewServer(http.HandlerFunc(skr.handler))
	defer srv.Close()
	rel := &SKRReleaser{URL: srv.URL + "/key/release", MAAEndpoint: "maa", AKVEndpoint: "https://kv.vault.azure.net", KID: "k"}
	_, err := rel.ReleaseKey(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") || !strings.Contains(err.Error(), "policy not satisfied") || strings.Contains(err.Error(), "see docs") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := (&SKRReleaser{}).ReleaseKey(context.Background()); err == nil {
		t.Fatal("expected configuration error")
	}
}

func TestParseReleasedJWK(t *testing.T) {
	pub, _ := json.Marshal(map[string]string{"kty": "RSA", "n": "AQAB", "e": "AQAB"})
	if _, err := ParseReleasedJWK(pub, "x"); err == nil {
		t.Fatal("public-only JWK must be rejected")
	}
	short, _ := json.Marshal(map[string]string{"kty": "oct", "k": base64.RawURLEncoding.EncodeToString([]byte("short"))})
	if _, err := ParseReleasedJWK(short, "x"); err == nil {
		t.Fatal("short material must be rejected")
	}
	unk, _ := json.Marshal(map[string]string{"kty": "OKP", "d": "AQAB"})
	if _, err := ParseReleasedJWK(unk, "x"); err == nil {
		t.Fatal("unsupported kty must be rejected")
	}
	k, err := ParseReleasedJWK(octJWK(t, ""), "fallback")
	if err != nil || k.KID != "fallback" || k.KeyType != "oct" || len(k.Material) != 32 {
		t.Fatalf("oct parse: %+v %v", k, err)
	}
}

// RFC 5869 Appendix A test case 1.
func TestHKDFSHA256Vector(t *testing.T) {
	ikm := mustHex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHex(t, "000102030405060708090a0b0c")
	info := mustHex(t, "f0f1f2f3f4f5f6f7f8f9")
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	got := hkdfSHA256(ikm, salt, info, 42)
	if h := toHex(got); h != want {
		t.Fatalf("hkdf = %s, want %s", h, want)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte
		for j := 0; j < 2; j++ {
			c := s[2*i+j]
			switch {
			case c >= '0' && c <= '9':
				v = v<<4 | (c - '0')
			case c >= 'a' && c <= 'f':
				v = v<<4 | (c - 'a' + 10)
			default:
				t.Fatalf("bad hex %q", s)
			}
		}
		b[i] = v
	}
	return b
}

func toHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, c := range b {
		out[2*i] = digits[c>>4]
		out[2*i+1] = digits[c&0x0f]
	}
	return string(out)
}
