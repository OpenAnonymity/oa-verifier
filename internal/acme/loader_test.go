package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/lego"

	"github.com/openanonymity/oa-verifier/internal/certstore"
)

const testDomain = "verifier.example.test"

var testNow = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

func fixedNow() time.Time { return testNow }

// makeBundle builds a self-signed bundle for domain valid until notAfter.
func makeBundle(t *testing.T, domain string, notAfter time.Time, caDir string) *certstore.Bundle {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		DNSNames:     []string{domain},
		NotBefore:    testNow.Add(-24 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	acct, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	acctDER, _ := x509.MarshalECPrivateKey(acct)
	return &certstore.Bundle{
		Domain:         domain,
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		AccountKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: acctDER}),
		AccountURI:     "https://acme.test/acct/" + domain,
		CADirURL:       caDir,
		IssuedAt:       testNow.Add(-24 * time.Hour),
		NotAfter:       notAfter,
	}
}

// memStore is an in-memory certstore.Store with fault injection.
type memStore struct {
	mu      sync.Mutex
	bundle  *certstore.Bundle
	loadErr error
	// loadErrTimes > 0 makes loadErr transient: only the first loadErrTimes
	// Load calls fail. Zero means every Load fails.
	loadErrTimes int
	saveErr      error
	saves        int
	loads        int
}

func (m *memStore) Load(context.Context) (*certstore.Bundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loads++
	if m.loadErr != nil {
		if m.loadErrTimes > 0 && m.loads > m.loadErrTimes {
			// transient: succeed after loadErrTimes failures
		} else {
			return nil, m.loadErr
		}
	}
	if m.bundle == nil {
		return nil, certstore.ErrNotFound
	}
	return m.bundle, nil
}

func (m *memStore) Save(_ context.Context, b *certstore.Bundle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saves++
	if m.saveErr != nil {
		return m.saveErr
	}
	m.bundle = b
	return nil
}

// fakeObtainer records calls and returns a scripted result.
type fakeObtainer struct {
	calls    int
	existing []*certstore.Bundle
	result   *certstore.Bundle
	err      error
}

func (f *fakeObtainer) fn(_ context.Context, existing *certstore.Bundle) (*certstore.Bundle, error) {
	f.calls++
	f.existing = append(f.existing, existing)
	return f.result, f.err
}

func prodCfg() *Config {
	return &Config{Domain: testDomain, Email: "ops@example.test", Provider: "cloudflare"}
}

func TestLoadOrObtain_NothingPersisted(t *testing.T) {
	store := &memStore{}
	fresh := makeBundle(t, testDomain, testNow.Add(90*24*time.Hour), lego.LEDirectoryProduction)
	ob := &fakeObtainer{result: fresh}

	got, src, err := LoadOrObtain(context.Background(), prodCfg(), store, ob.fn, fixedNow)
	if err != nil || src != SourceObtained || got != fresh {
		t.Fatalf("got src=%q err=%v", src, err)
	}
	if ob.calls != 1 || ob.existing[0] != nil {
		t.Fatalf("obtainer should be called once without an existing account; calls=%d", ob.calls)
	}
	if store.saves != 1 || store.bundle != fresh {
		t.Fatalf("fresh bundle must be saved; saves=%d", store.saves)
	}
}

func TestLoadOrObtain_ValidPersistedIsReusedWithoutCA(t *testing.T) {
	stored := makeBundle(t, testDomain, testNow.Add(31*24*time.Hour), lego.LEDirectoryProduction)
	store := &memStore{bundle: stored}
	ob := &fakeObtainer{err: errors.New("must not be called")}

	got, src, err := LoadOrObtain(context.Background(), prodCfg(), store, ob.fn, fixedNow)
	if err != nil || src != SourcePersisted || got != stored {
		t.Fatalf("got src=%q err=%v", src, err)
	}
	if ob.calls != 0 {
		t.Fatal("CA must not be contacted when a valid persisted certificate exists")
	}
	if store.saves != 0 {
		t.Fatal("no save expected when reusing")
	}
}

func TestLoadOrObtain_ExpiringPersistedRenewsReusingAccount(t *testing.T) {
	stored := makeBundle(t, testDomain, testNow.Add(29*24*time.Hour), lego.LEDirectoryProduction)
	store := &memStore{bundle: stored}
	fresh := makeBundle(t, testDomain, testNow.Add(90*24*time.Hour), lego.LEDirectoryProduction)
	ob := &fakeObtainer{result: fresh}

	got, src, err := LoadOrObtain(context.Background(), prodCfg(), store, ob.fn, fixedNow)
	if err != nil || src != SourceObtained || got != fresh {
		t.Fatalf("got src=%q err=%v", src, err)
	}
	if ob.calls != 1 || ob.existing[0] != stored {
		t.Fatal("obtainer must receive the stored bundle so the ACME account is reused")
	}
	if store.bundle != fresh {
		t.Fatal("renewed bundle must replace the stored one")
	}
}

func TestLoadOrObtain_ExpiringPersistedServedWhenIssuanceFails(t *testing.T) {
	stored := makeBundle(t, testDomain, testNow.Add(10*24*time.Hour), lego.LEDirectoryProduction)
	store := &memStore{bundle: stored}
	ob := &fakeObtainer{err: errors.New("rate limited")}

	got, src, err := LoadOrObtain(context.Background(), prodCfg(), store, ob.fn, fixedNow)
	if err != nil {
		t.Fatalf("a still-valid persisted certificate must be served, got error %v", err)
	}
	if src != SourcePersistedNearExpiry || got != stored {
		t.Fatalf("src=%q", src)
	}
	if store.saves != 0 {
		t.Fatal("nothing to save")
	}
}

func TestLoadOrObtain_ExpiredPersistedAndIssuanceFails(t *testing.T) {
	stored := makeBundle(t, testDomain, testNow.Add(-time.Hour), lego.LEDirectoryProduction)
	store := &memStore{bundle: stored}
	ob := &fakeObtainer{err: errors.New("rate limited")}

	_, _, err := LoadOrObtain(context.Background(), prodCfg(), store, ob.fn, fixedNow)
	if err == nil || err.Error() != "rate limited" {
		t.Fatalf("expected the issuance error, got %v", err)
	}
	if ob.existing[0] != stored {
		t.Fatal("account of the expired bundle should still be offered for reuse")
	}
}

func TestLoadOrObtain_WrongDomainReissues(t *testing.T) {
	stored := makeBundle(t, "other.example.test", testNow.Add(90*24*time.Hour), lego.LEDirectoryProduction)
	store := &memStore{bundle: stored}
	fresh := makeBundle(t, testDomain, testNow.Add(90*24*time.Hour), lego.LEDirectoryProduction)
	ob := &fakeObtainer{result: fresh}

	got, src, err := LoadOrObtain(context.Background(), prodCfg(), store, ob.fn, fixedNow)
	if err != nil || src != SourceObtained || got != fresh {
		t.Fatalf("src=%q err=%v", src, err)
	}
	if ob.existing[0] != stored {
		t.Fatal("same-CA account should be reused even when the domain changed")
	}
}

func TestLoadOrObtain_WrongDomainNeverServed(t *testing.T) {
	// A persisted certificate for another name must not be served even if
	// issuance fails: the self-signed fallback (caller) is preferable to a
	// certificate that fails hostname verification.
	stored := makeBundle(t, "other.example.test", testNow.Add(90*24*time.Hour), lego.LEDirectoryProduction)
	store := &memStore{bundle: stored}
	ob := &fakeObtainer{err: errors.New("dns failure")}
	if _, _, err := LoadOrObtain(context.Background(), prodCfg(), store, ob.fn, fixedNow); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadOrObtain_CAMismatchDoesNotReuseAccount(t *testing.T) {
	stored := makeBundle(t, testDomain, testNow.Add(90*24*time.Hour), lego.LEDirectoryStaging)
	store := &memStore{bundle: stored}
	fresh := makeBundle(t, testDomain, testNow.Add(90*24*time.Hour), lego.LEDirectoryProduction)
	ob := &fakeObtainer{result: fresh}

	got, src, err := LoadOrObtain(context.Background(), prodCfg(), store, ob.fn, fixedNow)
	if err != nil || src != SourceObtained || got != fresh {
		t.Fatalf("staging certificate must not be served in production; src=%q err=%v", src, err)
	}
	if ob.existing[0] != nil {
		t.Fatal("staging account must not be reused against the production CA")
	}

	// And a staging cert is not a fallback either.
	store2 := &memStore{bundle: stored}
	ob2 := &fakeObtainer{err: errors.New("boom")}
	if _, _, err := LoadOrObtain(context.Background(), prodCfg(), store2, ob2.fn, fixedNow); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadOrObtain_StoreErrorsAreNonFatal(t *testing.T) {
	fresh := makeBundle(t, testDomain, testNow.Add(90*24*time.Hour), lego.LEDirectoryProduction)
	saved := LoadRetryPolicy
	LoadRetryPolicy.Delay = 0
	t.Cleanup(func() { LoadRetryPolicy = saved })

	// Load error (e.g. key release failed) -> obtain without account reuse.
	store := &memStore{loadErr: errors.New("skr: HTTP 403")}
	ob := &fakeObtainer{result: fresh}
	got, src, err := LoadOrObtain(context.Background(), prodCfg(), store, ob.fn, fixedNow)
	if err != nil || src != SourceObtained || got != fresh || ob.existing[0] != nil {
		t.Fatalf("src=%q err=%v", src, err)
	}

	// Save error -> certificate is still served.
	store = &memStore{saveErr: errors.New("vault unavailable")}
	ob = &fakeObtainer{result: fresh}
	got, src, err = LoadOrObtain(context.Background(), prodCfg(), store, ob.fn, fixedNow)
	if err != nil || src != SourceObtained || got != fresh || store.saves != 1 {
		t.Fatalf("src=%q err=%v saves=%d", src, err, store.saves)
	}
}

func TestLoadOrObtain_NilStoreAndUnusableFresh(t *testing.T) {
	fresh := makeBundle(t, testDomain, testNow.Add(90*24*time.Hour), lego.LEDirectoryProduction)
	ob := &fakeObtainer{result: fresh}
	if _, src, err := LoadOrObtain(context.Background(), prodCfg(), nil, ob.fn, fixedNow); err != nil || src != SourceObtained {
		t.Fatalf("nil store must behave as noop; src=%q err=%v", src, err)
	}

	bad := makeBundle(t, "someone.else.test", testNow.Add(90*24*time.Hour), lego.LEDirectoryProduction)
	ob = &fakeObtainer{result: bad}
	if _, _, err := LoadOrObtain(context.Background(), prodCfg(), &memStore{}, ob.fn, fixedNow); err == nil {
		t.Fatal("an obtained certificate for the wrong domain must be rejected")
	}
}

func TestCheckBundle(t *testing.T) {
	ok := makeBundle(t, testDomain, testNow.Add(31*24*time.Hour), lego.LEDirectoryProduction)
	if err := CheckBundle(ok, testDomain, lego.LEDirectoryProduction, testNow, RenewBefore); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
	if err := CheckBundle(ok, testDomain, lego.LEDirectoryProduction, testNow.Add(2*24*time.Hour), RenewBefore); err == nil {
		t.Fatal("bundle with < 30 days left must be rejected for reuse")
	}
	if err := CheckBundle(ok, testDomain, lego.LEDirectoryProduction, testNow.Add(-30*24*time.Hour), 0); err == nil {
		t.Fatal("bundle must be rejected before NotBefore")
	}
	legacy := makeBundle(t, testDomain, testNow.Add(90*24*time.Hour), "")
	if err := CheckBundle(legacy, testDomain, lego.LEDirectoryProduction, testNow, RenewBefore); err != nil {
		t.Fatalf("bundle without CA URL should be accepted: %v", err)
	}
	if err := CheckBundle(nil, testDomain, "", testNow, 0); err == nil {
		t.Fatal("nil bundle")
	}
	broken := makeBundle(t, testDomain, testNow.Add(90*24*time.Hour), "")
	broken.PrivateKeyPEM = ok.PrivateKeyPEM // key of another certificate
	if err := CheckBundle(broken, testDomain, "", testNow, 0); err == nil {
		t.Fatal("mismatched key must be rejected")
	}
}

// --- retry helper -----------------------------------------------------------

type scriptedClient struct {
	fails  int
	result *certstore.Bundle
	calls  int
}

func (s *scriptedClient) ObtainBundle(context.Context) (*certstore.Bundle, error) {
	s.calls++
	if s.calls <= s.fails {
		return nil, errors.New("obtain failed")
	}
	return s.result, nil
}

func TestRetryObtain(t *testing.T) {
	fast := RetryPolicy{RegisterRetries: 3, RegisterDelay: time.Millisecond, ObtainRetries: 3, ObtainDelay: time.Millisecond}
	fresh := makeBundle(t, testDomain, testNow.Add(90*24*time.Hour), "")

	// Registration fails twice, issuance fails once, then succeeds.
	regCalls := 0
	sc := &scriptedClient{fails: 1, result: fresh}
	got, err := retryObtain(context.Background(), fast, func() (bundleObtainer, error) {
		regCalls++
		if regCalls < 3 {
			return nil, errors.New("register failed")
		}
		return sc, nil
	})
	if err != nil || got != fresh || regCalls != 3 || sc.calls != 2 {
		t.Fatalf("err=%v regCalls=%d obtainCalls=%d", err, regCalls, sc.calls)
	}

	// Registration never succeeds -> error after RegisterRetries attempts.
	regCalls = 0
	_, err = retryObtain(context.Background(), fast, func() (bundleObtainer, error) {
		regCalls++
		return nil, errors.New("register failed")
	})
	if err == nil || regCalls != 3 {
		t.Fatalf("err=%v regCalls=%d", err, regCalls)
	}

	// Issuance never succeeds -> error after ObtainRetries attempts.
	sc = &scriptedClient{fails: 100}
	_, err = retryObtain(context.Background(), fast, func() (bundleObtainer, error) { return sc, nil })
	if err == nil || sc.calls != 3 {
		t.Fatalf("err=%v obtainCalls=%d", err, sc.calls)
	}

	// Cancelled context aborts the wait.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	slow := RetryPolicy{RegisterRetries: 2, RegisterDelay: time.Hour, ObtainRetries: 1}
	_, err = retryObtain(ctx, slow, func() (bundleObtainer, error) { return nil, errors.New("register failed") })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestLoadOrObtain_TransientLoadErrorIsRetried(t *testing.T) {
	saved := LoadRetryPolicy
	LoadRetryPolicy = struct {
		Attempts int
		Delay    time.Duration
	}{Attempts: 4, Delay: 0}
	t.Cleanup(func() { LoadRetryPolicy = saved })

	// The SKR sidecar is not up for the first two calls, then the persisted
	// bundle loads: no issuance must happen.
	valid := makeBundle(t, testDomain, testNow.Add(60*24*time.Hour), lego.LEDirectoryProduction)
	store := &memStore{bundle: valid, loadErr: errors.New("dial tcp 127.0.0.1:8080: connection refused"), loadErrTimes: 2}
	ob := &fakeObtainer{err: errors.New("must not be called")}
	got, src, err := LoadOrObtain(context.Background(), prodCfg(), store, ob.fn, fixedNow)
	if err != nil || src != SourcePersisted || got != valid {
		t.Fatalf("src=%q err=%v", src, err)
	}
	if store.loads != 3 || ob.calls != 0 {
		t.Fatalf("loads=%d obtains=%d, want 3 and 0", store.loads, ob.calls)
	}

	// Exhausting the attempts falls through to issuance (old behaviour).
	store = &memStore{bundle: valid, loadErr: errors.New("connection refused")}
	fresh := makeBundle(t, testDomain, testNow.Add(90*24*time.Hour), lego.LEDirectoryProduction)
	ob = &fakeObtainer{result: fresh}
	_, src, err = LoadOrObtain(context.Background(), prodCfg(), store, ob.fn, fixedNow)
	if err != nil || src != SourceObtained || store.loads != 4 || ob.calls != 1 {
		t.Fatalf("src=%q err=%v loads=%d obtains=%d", src, err, store.loads, ob.calls)
	}

	// A cancelled context aborts the retry loop instead of issuing.
	LoadRetryPolicy.Delay = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store = &memStore{bundle: valid, loadErr: errors.New("connection refused")}
	ob = &fakeObtainer{result: fresh}
	if _, _, err := LoadOrObtain(ctx, prodCfg(), store, ob.fn, fixedNow); !errors.Is(err, context.Canceled) || ob.calls != 0 {
		t.Fatalf("err=%v obtains=%d, want context.Canceled and 0", err, ob.calls)
	}
}
