package server

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func okHandler() (http.Handler, *int32) {
	var hits int32
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNoContent)
	}), &hits
}

func doGet(t *testing.T, h http.Handler, remoteAddr, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remoteAddr
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func assertRetryAfter(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rr.Code)
	}
	ra := rr.Header().Get("Retry-After")
	secs, err := strconv.Atoi(ra)
	if err != nil || secs < 1 {
		t.Fatalf("Retry-After = %q, want integer >= 1", ra)
	}
}

func TestAttestationLimiterPerIPBurstThen429(t *testing.T) {
	// Per-IP: 1 rps, burst 3. Global effectively unlimited for this test.
	lim := newAttestationLimiter(1, 3, 1000)
	next, hits := okHandler()
	h := lim.middleware(next)

	for i := 0; i < 3; i++ {
		if rr := doGet(t, h, "203.0.113.1:5000", "/attestation"); rr.Code != http.StatusNoContent {
			t.Fatalf("request %d: status = %d, want 204", i+1, rr.Code)
		}
	}
	rr := doGet(t, h, "203.0.113.1:5001", "/attestation") // same IP, different port
	assertRetryAfter(t, rr)
	if got := atomic.LoadInt32(hits); got != 3 {
		t.Fatalf("handler hits = %d, want 3", got)
	}

	// Another IP has its own bucket and is unaffected.
	if rr := doGet(t, h, "203.0.113.2:5000", "/attestation"); rr.Code != http.StatusNoContent {
		t.Fatalf("other IP status = %d, want 204", rr.Code)
	}
}

func TestAttestationLimiterGlobalCap(t *testing.T) {
	// Per-IP generous; global 2 rps -> burst 2 shared by everyone.
	lim := newAttestationLimiter(1000, 1000, 2)
	next, hits := okHandler()
	h := lim.middleware(next)

	if rr := doGet(t, h, "198.51.100.1:1", "/attestation"); rr.Code != http.StatusNoContent {
		t.Fatalf("first: status = %d", rr.Code)
	}
	if rr := doGet(t, h, "198.51.100.2:1", "/attestation"); rr.Code != http.StatusNoContent {
		t.Fatalf("second: status = %d", rr.Code)
	}
	rr := doGet(t, h, "198.51.100.3:1", "/attestation")
	assertRetryAfter(t, rr)
	if got := atomic.LoadInt32(hits); got != 2 {
		t.Fatalf("handler hits = %d, want 2", got)
	}

	// A global denial must not consume the denied client's per-IP token:
	// its own bucket still holds the full burst.
	ipLim := lim.perIP.getLimiter("198.51.100.3")
	if tokens := ipLim.Tokens(); tokens < 999 {
		t.Fatalf("per-IP tokens after global denial = %v, want ~1000 (reservation cancelled)", tokens)
	}
}

func TestAttestationLimiterRetryAfterReflectsWait(t *testing.T) {
	// 0.25 rps, burst 1: after one request the next token is 4s away.
	lim := newAttestationLimiter(0.25, 1, 1000)
	next, _ := okHandler()
	h := lim.middleware(next)

	if rr := doGet(t, h, "192.0.2.1:1", "/attestation"); rr.Code != http.StatusNoContent {
		t.Fatalf("first: status = %d", rr.Code)
	}
	rr := doGet(t, h, "192.0.2.1:1", "/attestation")
	assertRetryAfter(t, rr)
	secs, _ := strconv.Atoi(rr.Header().Get("Retry-After"))
	if secs < 3 || secs > 4 {
		t.Fatalf("Retry-After = %d, want 3..4 seconds", secs)
	}
}

func TestAttestationLimiterConcurrentNeverExceedsBurst(t *testing.T) {
	const burst = 5
	lim := newAttestationLimiter(0.001, burst, 1000) // effectively no refill during the test
	next, hits := okHandler()
	h := lim.middleware(next)

	var wg sync.WaitGroup
	var denied int32
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := doGet(t, h, "192.0.2.9:1", "/attestation")
			if rr.Code == http.StatusTooManyRequests {
				atomic.AddInt32(&denied, 1)
			}
		}()
	}
	wg.Wait()
	if got := atomic.LoadInt32(hits); got != burst {
		t.Fatalf("handler hits = %d, want exactly %d", got, burst)
	}
	if got := atomic.LoadInt32(&denied); got != 50-burst {
		t.Fatalf("denied = %d, want %d", got, 50-burst)
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	cases := map[time.Duration]int{
		0:                       1,
		10 * time.Millisecond:   1,
		time.Second:             1,
		1001 * time.Millisecond: 2,
		4 * time.Second:         4,
	}
	for d, want := range cases {
		if got := retryAfterSeconds(d); got != want {
			t.Errorf("retryAfterSeconds(%s) = %d, want %d", d, got, want)
		}
	}
}

func TestAttestationLimiterEnvParsing(t *testing.T) {
	t.Setenv("ATTEST_RATE_LIMIT_RPS", "0.5")
	t.Setenv("ATTEST_RATE_LIMIT_BURST", "7")
	t.Setenv("ATTEST_GLOBAL_RPS", "2.5")
	lim := newAttestationLimiterFromEnv()
	ipLim := lim.perIP.getLimiter("x")
	if float64(ipLim.Limit()) != 0.5 || ipLim.Burst() != 7 {
		t.Fatalf("per-IP limiter = %v/%d, want 0.5/7", ipLim.Limit(), ipLim.Burst())
	}
	if float64(lim.global.Limit()) != 2.5 || lim.global.Burst() != 3 {
		t.Fatalf("global limiter = %v/%d, want 2.5/3", lim.global.Limit(), lim.global.Burst())
	}

	// Invalid values fall back to defaults.
	t.Setenv("ATTEST_RATE_LIMIT_RPS", "-1")
	t.Setenv("ATTEST_RATE_LIMIT_BURST", "zero")
	t.Setenv("ATTEST_GLOBAL_RPS", "NaN")
	lim = newAttestationLimiterFromEnv()
	ipLim = lim.perIP.getLimiter("x")
	if float64(ipLim.Limit()) != defaultAttestRateLimitRPS || ipLim.Burst() != defaultAttestRateLimitBurst {
		t.Fatalf("per-IP defaults not applied: %v/%d", ipLim.Limit(), ipLim.Burst())
	}
	if float64(lim.global.Limit()) != defaultAttestGlobalRPS || lim.global.Burst() != 5 {
		t.Fatalf("global defaults not applied: %v/%d", lim.global.Limit(), lim.global.Burst())
	}
}

func TestRateLimiterStoreCleanupDropsStaleEntries(t *testing.T) {
	store := newRateLimiterStore(func() *rate.Limiter { return rate.NewLimiter(1, 1) })
	store.getLimiter("stale")
	store.getLimiter("fresh")
	store.mu.Lock()
	store.limiters["stale"].lastSeen = time.Now().Add(-rateLimiterStaleAfter - time.Minute)
	store.mu.Unlock()

	store.cleanup()

	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.limiters["stale"]; ok {
		t.Fatalf("stale entry survived cleanup")
	}
	if _, ok := store.limiters["fresh"]; !ok {
		t.Fatalf("fresh entry removed by cleanup")
	}
}

// resetGlobalAttestationLimiter forces the process-wide limiter to be rebuilt
// from the current environment on next use, and restores it afterwards.
func resetGlobalAttestationLimiter(t *testing.T) {
	t.Helper()
	reset := func() {
		globalAttestationLimiterMu.Lock()
		defer globalAttestationLimiterMu.Unlock()
		globalAttestationLimiter = nil
	}
	reset()
	t.Cleanup(reset)
}

func TestRouterAppliesAttestationLimiter(t *testing.T) {
	// Stub the SKR sidecar so the handler succeeds without Azure.
	var sidecarCalls int32
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&sidecarCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"eyJ.eyJ.sig"}`))
	}))
	defer sidecar.Close()
	t.Setenv("MAA_ENDPOINT", sidecar.URL)

	t.Setenv("ATTEST_RATE_LIMIT_RPS", "0.001")
	t.Setenv("ATTEST_RATE_LIMIT_BURST", "2")
	t.Setenv("ATTEST_GLOBAL_RPS", "100")
	resetGlobalAttestationLimiter(t)

	router := New(true).Router()

	for i := 0; i < 2; i++ {
		rr := doGet(t, router, "203.0.113.7:4000", "/attestation/raw")
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d body=%s", i+1, rr.Code, rr.Body.String())
		}
	}
	// Third attestation from the same IP is refused before the sidecar is called.
	rr := doGet(t, router, "203.0.113.7:4001", "/attestation")
	assertRetryAfter(t, rr)
	if got := atomic.LoadInt32(&sidecarCalls); got != 2 {
		t.Fatalf("sidecar calls = %d, want 2 (limiter must run before the sidecar call)", got)
	}

	// Non-attestation routes are not subject to the attestation limiter.
	if rr := doGet(t, router, "203.0.113.7:4002", "/health"); rr.Code != http.StatusOK {
		t.Fatalf("/health status = %d, want 200", rr.Code)
	}

	// With attestation disabled the routes are absent entirely.
	if rr := doGet(t, New(false).Router(), "203.0.113.8:1", "/attestation"); rr.Code != http.StatusNotFound {
		t.Fatalf("attestation disabled: status = %d, want 404", rr.Code)
	}
}
