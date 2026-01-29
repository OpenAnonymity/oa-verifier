package server

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/oa-verifier/internal/config"
)

// rateLimiterStore manages per-client (IP+UserAgent) rate limiters.
type rateLimiterStore struct {
	mu       sync.RWMutex
	limiters map[string]*rateLimiterEntry
}

type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var globalRateLimiter = &rateLimiterStore{
	limiters: make(map[string]*rateLimiterEntry),
}

func init() {
	// Cleanup stale entries every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			globalRateLimiter.cleanup()
		}
	}()
}

// getLimiter returns the rate limiter for the given key (IP+UA), creating one if needed.
func (l *rateLimiterStore) getLimiter(key string) *rate.Limiter {
	l.mu.RLock()
	entry, exists := l.limiters[key]
	l.mu.RUnlock()

	if exists {
		l.mu.Lock()
		entry.lastSeen = time.Now()
		l.mu.Unlock()
		return entry.limiter
	}

	// Create new limiter with configured rate and burst
	rps := rate.Limit(config.RateLimitRPS())
	burst := config.RateLimitBurst()
	limiter := rate.NewLimiter(rps, burst)

	l.mu.Lock()
	l.limiters[key] = &rateLimiterEntry{
		limiter:  limiter,
		lastSeen: time.Now(),
	}
	l.mu.Unlock()

	return limiter
}

// cleanup removes stale entries (not seen for 10 minutes).
func (l *rateLimiterStore) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().Add(-10 * time.Minute)
	for key, entry := range l.limiters {
		if entry.lastSeen.Before(cutoff) {
			delete(l.limiters, key)
		}
	}
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (for proxies/load balancers)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		if ip, _, err := net.SplitHostPort(xff); err == nil {
			return ip
		}
		// If no port, use as-is
		if net.ParseIP(xff) != nil {
			return xff
		}
		// Multiple IPs, take first
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// rateLimitMiddleware limits requests per IP+UserAgent using token bucket algorithm.
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)
		ua := r.Header.Get("User-Agent")
		key := ip + "|" + ua
		limiter := globalRateLimiter.getLimiter(key)

		if !limiter.Allow() {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
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
