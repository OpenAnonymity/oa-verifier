package server

import (
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/openanonymity/oa-verifier/internal/config"
)

// rateLimiterStore manages per-client IP rate limiters.
type rateLimiterStore struct {
	mu       sync.Mutex
	limiters map[string]*rateLimiterEntry
	// newLimiter builds the limiter for a key seen for the first time.
	newLimiter func() *rate.Limiter
}

type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newRateLimiterStore(newLimiter func() *rate.Limiter) *rateLimiterStore {
	return &rateLimiterStore{
		limiters:   make(map[string]*rateLimiterEntry),
		newLimiter: newLimiter,
	}
}

// globalRateLimiter backs rateLimitMiddleware (all routes). RATE_LIMIT_RPS /
// RATE_LIMIT_BURST are read when a client IP is first seen.
var globalRateLimiter = newRateLimiterStore(func() *rate.Limiter {
	return rate.NewLimiter(rate.Limit(config.RateLimitRPS()), config.RateLimitBurst())
})

// rateLimiterStaleAfter is how long an idle client IP keeps its limiter.
const rateLimiterStaleAfter = 10 * time.Minute

func init() {
	// Cleanup stale entries every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			globalRateLimiter.cleanup()
			// Only sweep the attestation store if a request has already
			// created it; do not force env parsing from the ticker.
			if a := attestationLimiterIfInitialized(); a != nil {
				a.perIP.cleanup()
			}
		}
	}()
}

// getLimiter returns the rate limiter for the given key (client IP), creating one if needed.
func (l *rateLimiterStore) getLimiter(key string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	if entry, exists := l.limiters[key]; exists {
		entry.lastSeen = time.Now()
		return entry.limiter
	}

	limiter := l.newLimiter()
	l.limiters[key] = &rateLimiterEntry{
		limiter:  limiter,
		lastSeen: time.Now(),
	}
	return limiter
}

// cleanup removes stale entries (not seen for rateLimiterStaleAfter).
func (l *rateLimiterStore) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().Add(-rateLimiterStaleAfter)
	for key, entry := range l.limiters {
		if entry.lastSeen.Before(cutoff) {
			delete(l.limiters, key)
		}
	}
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// writeTooManyRequests answers 429 with a Retry-After header (whole seconds, >= 1).
func writeTooManyRequests(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(wait)))
	http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
}

func retryAfterSeconds(wait time.Duration) int {
	secs := int(math.Ceil(wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	return secs
}

// rateLimitMiddleware limits requests per client IP using token bucket algorithm.
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		key := ip
		limiter := globalRateLimiter.getLimiter(key)

		if !limiter.Allow() {
			writeTooManyRequests(w, time.Second)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Attestation rate limiting
//
// GET /attestation and GET /attestation/raw each make the SKR sidecar perform
// an SEV-SNP attestation. The deployed sidecar leaks one /dev/sev-guest file
// descriptor per attestation (confirmed 2026-09-28: 53 requests -> 53 open
// descriptors that never close), so sidecar descriptor consumption is directly
// proportional to attestation request volume. The general limiter (10 rps per
// IP by default) is far too permissive for that, so these routes additionally
// pass through attestationRateLimitMiddleware: a stricter per-IP token bucket
// followed by a global bucket shared by all clients. Denied requests get 429
// with a Retry-After computed from the bucket state.
//
// Environment variables (documented here; all three must be listed in the CCE
// policy's optional_env_vars in .github/workflows/build-and-sign.yml before
// they can be set on the deployed container):
//
//	ATTEST_RATE_LIMIT_RPS    sustained attestation requests per second per
//	                         client IP; decimal allowed, e.g. "0.5" (default 1)
//	ATTEST_RATE_LIMIT_BURST  burst size per client IP, integer >= 1 (default 3)
//	ATTEST_GLOBAL_RPS        sustained attestation requests per second across
//	                         all clients; decimal allowed (default 5). The
//	                         global burst is ceil(ATTEST_GLOBAL_RPS), min 1.
//
// Values are read once, when the limiter is first used.
// ---------------------------------------------------------------------------

const (
	defaultAttestRateLimitRPS   = 1.0
	defaultAttestRateLimitBurst = 3
	defaultAttestGlobalRPS      = 5.0
)

// attestationLimiter combines a per-client-IP limiter store with one global limiter.
type attestationLimiter struct {
	perIP  *rateLimiterStore
	global *rate.Limiter
}

// newAttestationLimiter builds a limiter; non-positive arguments fall back to defaults.
func newAttestationLimiter(perIPRPS float64, perIPBurst int, globalRPS float64) *attestationLimiter {
	if perIPRPS <= 0 {
		perIPRPS = defaultAttestRateLimitRPS
	}
	if perIPBurst < 1 {
		perIPBurst = defaultAttestRateLimitBurst
	}
	if globalRPS <= 0 {
		globalRPS = defaultAttestGlobalRPS
	}
	globalBurst := int(math.Ceil(globalRPS))
	if globalBurst < 1 {
		globalBurst = 1
	}
	return &attestationLimiter{
		perIP: newRateLimiterStore(func() *rate.Limiter {
			return rate.NewLimiter(rate.Limit(perIPRPS), perIPBurst)
		}),
		global: rate.NewLimiter(rate.Limit(globalRPS), globalBurst),
	}
}

func newAttestationLimiterFromEnv() *attestationLimiter {
	return newAttestationLimiter(
		envFloat("ATTEST_RATE_LIMIT_RPS", defaultAttestRateLimitRPS),
		envInt("ATTEST_RATE_LIMIT_BURST", defaultAttestRateLimitBurst),
		envFloat("ATTEST_GLOBAL_RPS", defaultAttestGlobalRPS),
	)
}

// envFloat reads a strictly positive decimal from the environment, else def.
func envFloat(name string, def float64) float64 {
	s := strings.TrimSpace(os.Getenv(name))
	if s == "" {
		return def
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
		slog.Warn("invalid rate limit setting, using default", "var", name, "value", s, "default", def)
		return def
	}
	return v
}

// envInt reads an integer >= 1 from the environment, else def.
func envInt(name string, def int) int {
	s := strings.TrimSpace(os.Getenv(name))
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 1 {
		slog.Warn("invalid rate limit setting, using default", "var", name, "value", s, "default", def)
		return def
	}
	return v
}

// The process-wide attestation limiter is created lazily on first use so
// that ATTEST_* are read after the environment is loaded. A plain mutex
// (rather than sync.Once) lets tests reset it and lets the cleanup ticker
// look without creating it.
var (
	globalAttestationLimiterMu sync.Mutex
	globalAttestationLimiter   *attestationLimiter
)

func getAttestationLimiter() *attestationLimiter {
	globalAttestationLimiterMu.Lock()
	defer globalAttestationLimiterMu.Unlock()
	if globalAttestationLimiter == nil {
		globalAttestationLimiter = newAttestationLimiterFromEnv()
	}
	return globalAttestationLimiter
}

// attestationLimiterIfInitialized returns the process-wide limiter, or nil if
// no attestation request has created it yet.
func attestationLimiterIfInitialized() *attestationLimiter {
	globalAttestationLimiterMu.Lock()
	defer globalAttestationLimiterMu.Unlock()
	return globalAttestationLimiter
}

// allow decides whether one attestation request from ip may proceed now.
// It returns (false, wait) when the request must be rejected, where wait is
// the time until a token becomes available.
//
// The per-IP bucket is checked first so that a single abusive client is
// stopped before it can draw down the shared global bucket. Both reservations
// are taken at the same instant so that a reservation cancelled because the
// other bucket denied the request restores its token exactly.
func (a *attestationLimiter) allow(ip string) (bool, time.Duration) {
	now := time.Now()

	ipRes := a.perIP.getLimiter(ip).ReserveN(now, 1)
	if !ipRes.OK() {
		return false, time.Second
	}
	if wait := ipRes.DelayFrom(now); wait > 0 {
		ipRes.CancelAt(now)
		return false, wait
	}

	gRes := a.global.ReserveN(now, 1)
	if !gRes.OK() {
		ipRes.CancelAt(now)
		return false, time.Second
	}
	if wait := gRes.DelayFrom(now); wait > 0 {
		gRes.CancelAt(now)
		ipRes.CancelAt(now)
		return false, wait
	}
	return true, 0
}

// middleware wraps next with this limiter, answering 429 + Retry-After on denial.
func (a *attestationLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, wait := a.allow(getClientIP(r))
		if !ok {
			writeTooManyRequests(w, wait)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// attestationRateLimitMiddleware applies the process-wide attestation limiter
// (configured from ATTEST_RATE_LIMIT_RPS, ATTEST_RATE_LIMIT_BURST and
// ATTEST_GLOBAL_RPS) to routes that trigger a sidecar attestation.
func attestationRateLimitMiddleware(next http.Handler) http.Handler {
	return getAttestationLimiter().middleware(next)
}

// concurrencyLimiter manages a semaphore for limiting concurrent requests.
type concurrencyLimiter struct {
	sem chan struct{}
}

var globalConcurrencyLimiter *concurrencyLimiter
var concurrencyLimiterOnce sync.Once

func getConcurrencyLimiter() *concurrencyLimiter {
	concurrencyLimiterOnce.Do(func() {
		globalConcurrencyLimiter = &concurrencyLimiter{
			sem: make(chan struct{}, config.MaxConcurrentRequests()),
		}
	})
	return globalConcurrencyLimiter
}

// concurrencyLimitMiddleware limits concurrent request processing.
func concurrencyLimitMiddleware(next http.Handler) http.Handler {
	limiter := getConcurrencyLimiter()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case limiter.sem <- struct{}{}:
			defer func() { <-limiter.sem }()
			next.ServeHTTP(w, r)
		default:
			// Queue is full, return 503 Service Unavailable
			http.Error(w, "Service Temporarily Unavailable", http.StatusServiceUnavailable)
		}
	})
}
