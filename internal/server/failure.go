package server

import (
	"container/list"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openanonymity/oa-verifier/internal/config"
)

// ---------------------------------------------------------------------------
// Per-station transient failure state
//
// These helpers mutate Failure* fields on a registered models.Station. They are
// naturally bounded: a station must exist in s.stations (registration succeeded)
// before anything is recorded, and unregistering drops the whole entry.
// ---------------------------------------------------------------------------

func (s *Server) markTransientFailure(pk, reason string, statusCode int, detail string) bool {
	graceSeconds := config.StationFailureGraceSeconds()
	graceWindow := time.Duration(graceSeconds) * time.Second
	now := time.Now()

	s.mu.Lock()
	station, ok := s.stations[pk]
	if !ok {
		s.mu.Unlock()
		return false
	}

	if station.FailureFirstAt == nil {
		station.FailureFirstAt = &now
	}
	station.FailureLastAt = &now
	station.FailureReason = reason
	station.FailureDetail = detail
	station.FailureStatus = statusCode
	station.FailureCount++

	first := station.FailureFirstAt
	s.mu.Unlock()

	if graceWindow <= 0 || first == nil {
		return false
	}
	return now.Sub(*first) < graceWindow
}

func (s *Server) clearTransientFailure(pk string) {
	s.mu.Lock()
	if station, ok := s.stations[pk]; ok {
		station.FailureFirstAt = nil
		station.FailureLastAt = nil
		station.FailureReason = ""
		station.FailureDetail = ""
		station.FailureStatus = 0
		station.FailureCount = 0
	}
	s.mu.Unlock()
}

func (s *Server) getFailureCount(pk string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if station, ok := s.stations[pk]; ok {
		return station.FailureCount
	}
	return 0
}

// ---------------------------------------------------------------------------
// Bounded per-identity operation-failure tracker
//
// incOpFailure/clearOpFailure (org_events.go) count consecutive failures per
// "<identity>|<operation>" key so org events can carry consecutive_failure_count.
// The identity is taken from the request (public key or station_id) *before*
// the station is registered, so an unauthenticated caller can create an
// unbounded number of distinct keys with /register calls (measured ~12 MB after
// 100k synthetic identities with the old plain map). This tracker bounds that:
//
//   - at most FAILURE_TRACK_MAX entries (default 10000); when full, the least
//     recently touched entry is evicted (LRU, oldest-first);
//   - entries untouched for FAILURE_TRACK_TTL (default 24h) expire: they are
//     treated as absent on access and removed by an amortized sweep that runs at
//     most once per opFailureSweepInterval from inside inc/clear (no background
//     goroutine, so a Server needs no Close and tests do not leak).
//
// Semantics for a tracked (present, unexpired) key are unchanged: inc returns
// the incremented consecutive count, clear deletes the key and returns the
// previous count (0 if absent).
//
// Environment variables (documented here; both must be listed in the CCE
// policy's optional_env_vars in .github/workflows/build-and-sign.yml before
// they can be set on the deployed container):
//
//	FAILURE_TRACK_MAX  maximum tracked keys, integer >= 1 (default 10000)
//	FAILURE_TRACK_TTL  idle expiry, Go duration ("24h", "90m") or a bare
//	                   integer number of seconds (default 24h)
//
// ---------------------------------------------------------------------------

const (
	defaultFailureTrackMax = 10000
	defaultFailureTrackTTL = 24 * time.Hour
	opFailureSweepInterval = 5 * time.Minute
)

type opFailureEntry struct {
	key      string
	count    int
	lastSeen time.Time
}

// opFailureTracker is a TTL + LRU bounded map of consecutive failure counts.
type opFailureTracker struct {
	mu         sync.Mutex
	maxEntries int
	ttl        time.Duration
	now        func() time.Time
	entries    map[string]*list.Element // key -> element whose Value is *opFailureEntry
	order      *list.List               // front = most recently touched, back = least
	lastSweep  time.Time
}

// newOpFailureTracker creates a tracker; non-positive arguments fall back to defaults.
func newOpFailureTracker(maxEntries int, ttl time.Duration) *opFailureTracker {
	if maxEntries < 1 {
		maxEntries = defaultFailureTrackMax
	}
	if ttl <= 0 {
		ttl = defaultFailureTrackTTL
	}
	return &opFailureTracker{
		maxEntries: maxEntries,
		ttl:        ttl,
		now:        time.Now,
		entries:    make(map[string]*list.Element),
		order:      list.New(),
	}
}

// newOpFailureTrackerFromEnv builds the tracker from FAILURE_TRACK_MAX /
// FAILURE_TRACK_TTL, using defaults for unset or invalid values.
func newOpFailureTrackerFromEnv() *opFailureTracker {
	return newOpFailureTracker(failureTrackMaxFromEnv(), failureTrackTTLFromEnv())
}

func failureTrackMaxFromEnv() int {
	s := strings.TrimSpace(os.Getenv("FAILURE_TRACK_MAX"))
	if s == "" {
		return defaultFailureTrackMax
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 1 {
		slog.Warn("invalid FAILURE_TRACK_MAX, using default", "value", s, "default", defaultFailureTrackMax)
		return defaultFailureTrackMax
	}
	return v
}

func failureTrackTTLFromEnv() time.Duration {
	s := strings.TrimSpace(os.Getenv("FAILURE_TRACK_TTL"))
	if s == "" {
		return defaultFailureTrackTTL
	}
	if secs, err := strconv.Atoi(s); err == nil {
		if secs < 1 {
			slog.Warn("invalid FAILURE_TRACK_TTL, using default", "value", s, "default", defaultFailureTrackTTL.String())
			return defaultFailureTrackTTL
		}
		return time.Duration(secs) * time.Second
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		slog.Warn("invalid FAILURE_TRACK_TTL, using default", "value", s, "default", defaultFailureTrackTTL.String())
		return defaultFailureTrackTTL
	}
	return d
}

func (t *opFailureTracker) expired(e *opFailureEntry, now time.Time) bool {
	return now.Sub(e.lastSeen) >= t.ttl
}

// inc increments and returns the consecutive failure count for key.
// An expired entry restarts at 1. Inserting into a full tracker evicts the
// least recently touched entry.
func (t *opFailureTracker) inc(key string) int {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.maybeSweepLocked(now)

	if el, ok := t.entries[key]; ok {
		e := el.Value.(*opFailureEntry)
		if t.expired(e, now) {
			e.count = 0
		}
		e.count++
		e.lastSeen = now
		t.order.MoveToFront(el)
		return e.count
	}

	for t.order.Len() >= t.maxEntries {
		t.removeLocked(t.order.Back())
	}
	e := &opFailureEntry{key: key, count: 1, lastSeen: now}
	t.entries[key] = t.order.PushFront(e)
	return 1
}

// clear removes key and returns its previous count (0 if absent or expired).
func (t *opFailureTracker) clear(key string) int {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.maybeSweepLocked(now)

	el, ok := t.entries[key]
	if !ok {
		return 0
	}
	e := el.Value.(*opFailureEntry)
	prev := e.count
	if t.expired(e, now) {
		prev = 0
	}
	t.removeLocked(el)
	return prev
}

// get returns the current count without touching recency (0 if absent or expired).
func (t *opFailureTracker) get(key string) int {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	el, ok := t.entries[key]
	if !ok {
		return 0
	}
	e := el.Value.(*opFailureEntry)
	if t.expired(e, now) {
		return 0
	}
	return e.count
}

// len returns the number of stored entries, including not-yet-swept expired ones.
func (t *opFailureTracker) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.order.Len()
}

// sweep removes every expired entry immediately and returns how many it removed.
func (t *opFailureTracker) sweep() int {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sweepLocked(now)
}

func (t *opFailureTracker) maybeSweepLocked(now time.Time) {
	if t.lastSweep.IsZero() {
		t.lastSweep = now
		return
	}
	if now.Sub(t.lastSweep) >= opFailureSweepInterval {
		t.sweepLocked(now)
	}
}

// sweepLocked walks from the least recently touched end and stops at the
// first live entry (recency order implies expiry order). Caller holds t.mu.
func (t *opFailureTracker) sweepLocked(now time.Time) int {
	removed := 0
	for el := t.order.Back(); el != nil; el = t.order.Back() {
		if !t.expired(el.Value.(*opFailureEntry), now) {
			break
		}
		t.removeLocked(el)
		removed++
	}
	t.lastSweep = now
	return removed
}

func (t *opFailureTracker) removeLocked(el *list.Element) {
	if el == nil {
		return
	}
	e := el.Value.(*opFailureEntry)
	delete(t.entries, e.key)
	t.order.Remove(el)
}
