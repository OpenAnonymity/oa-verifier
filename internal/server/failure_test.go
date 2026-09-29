package server

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually advanced clock for deterministic TTL tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestTracker(maxEntries int, ttl time.Duration) (*opFailureTracker, *fakeClock) {
	clk := newFakeClock()
	tr := newOpFailureTracker(maxEntries, ttl)
	tr.now = clk.now
	return tr, clk
}

func TestOpFailureTrackerCountSemantics(t *testing.T) {
	tr, _ := newTestTracker(10, time.Hour)

	if got := tr.inc("a|op"); got != 1 {
		t.Fatalf("first inc = %d, want 1", got)
	}
	if got := tr.inc("a|op"); got != 2 {
		t.Fatalf("second inc = %d, want 2", got)
	}
	if got := tr.inc("a|other"); got != 1 {
		t.Fatalf("different operation inc = %d, want 1", got)
	}
	if got := tr.get("a|op"); got != 2 {
		t.Fatalf("get = %d, want 2", got)
	}
	if got := tr.clear("a|op"); got != 2 {
		t.Fatalf("clear returned %d, want previous count 2", got)
	}
	if got := tr.clear("a|op"); got != 0 {
		t.Fatalf("clear of absent key returned %d, want 0", got)
	}
	if got := tr.inc("a|op"); got != 1 {
		t.Fatalf("inc after clear = %d, want 1", got)
	}
	if got := tr.clear("never"); got != 0 {
		t.Fatalf("clear of never-seen key returned %d, want 0", got)
	}
}

func TestOpFailureTrackerEvictsLeastRecentlyTouched(t *testing.T) {
	tr, _ := newTestTracker(3, time.Hour)

	tr.inc("a")
	tr.inc("b")
	tr.inc("c")
	if tr.len() != 3 {
		t.Fatalf("len = %d, want 3", tr.len())
	}

	// Touch "a" so that "b" becomes the least recently used entry.
	tr.inc("a")

	tr.inc("d") // must evict "b"
	if tr.len() != 3 {
		t.Fatalf("len after eviction = %d, want 3", tr.len())
	}
	if got := tr.get("b"); got != 0 {
		t.Fatalf("evicted key b still has count %d", got)
	}
	if got := tr.get("a"); got != 2 {
		t.Fatalf("recently touched key a has count %d, want 2", got)
	}
	if got := tr.get("c"); got != 1 {
		t.Fatalf("key c has count %d, want 1", got)
	}
	if got := tr.get("d"); got != 1 {
		t.Fatalf("key d has count %d, want 1", got)
	}

	// The map and the list must stay in sync so the bound holds for many keys.
	for i := 0; i < 1000; i++ {
		tr.inc(fmt.Sprintf("k%d", i))
		if tr.len() > 3 {
			t.Fatalf("len exceeded bound: %d", tr.len())
		}
	}
	if len(tr.entries) != tr.order.Len() {
		t.Fatalf("index/list mismatch: %d vs %d", len(tr.entries), tr.order.Len())
	}
}

func TestOpFailureTrackerTTLExpiry(t *testing.T) {
	const ttl = time.Hour
	tr, clk := newTestTracker(100, ttl)

	tr.inc("a")
	tr.inc("a")
	clk.advance(ttl - time.Minute)
	if got := tr.get("a"); got != 2 {
		t.Fatalf("count before expiry = %d, want 2", got)
	}
	// Touching within the TTL extends the idle window.
	if got := tr.inc("a"); got != 3 {
		t.Fatalf("inc before expiry = %d, want 3", got)
	}

	clk.advance(ttl)
	if got := tr.get("a"); got != 0 {
		t.Fatalf("count after expiry = %d, want 0", got)
	}
	// An expired entry restarts from 1 rather than continuing the stale streak.
	if got := tr.inc("a"); got != 1 {
		t.Fatalf("inc after expiry = %d, want 1", got)
	}

	tr.inc("b")
	clk.advance(ttl)
	// clear of an expired entry reports no previous count and drops it.
	if got := tr.clear("b"); got != 0 {
		t.Fatalf("clear of expired key returned %d, want 0", got)
	}
	if got := tr.get("b"); got != 0 {
		t.Fatalf("expired+cleared key b has count %d", got)
	}
}

func TestOpFailureTrackerSweepRemovesOnlyExpired(t *testing.T) {
	const ttl = time.Hour
	tr, clk := newTestTracker(100, ttl)

	tr.inc("old1")
	tr.inc("old2")
	clk.advance(30 * time.Minute)
	tr.inc("fresh")
	clk.advance(31 * time.Minute) // old* are now idle for 61m, fresh for 31m

	if tr.len() != 3 {
		t.Fatalf("len before sweep = %d, want 3", tr.len())
	}
	if removed := tr.sweep(); removed != 2 {
		t.Fatalf("sweep removed %d, want 2", removed)
	}
	if tr.len() != 1 {
		t.Fatalf("len after sweep = %d, want 1", tr.len())
	}
	if got := tr.get("fresh"); got != 1 {
		t.Fatalf("fresh entry lost by sweep, count %d", got)
	}
	if len(tr.entries) != 1 {
		t.Fatalf("index still holds %d entries", len(tr.entries))
	}
}

func TestOpFailureTrackerAmortizedSweepOnAccess(t *testing.T) {
	const ttl = time.Hour
	tr, clk := newTestTracker(100, ttl)

	tr.inc("stale")                // first access records lastSweep
	clk.advance(ttl + time.Minute) // "stale" is expired
	tr.inc("trigger")              // more than opFailureSweepInterval since lastSweep -> sweep
	if got := tr.len(); got != 1 {
		t.Fatalf("len after amortized sweep = %d, want 1 (only trigger)", got)
	}

	// Within the sweep interval no sweep happens, so an expired entry stays
	// stored (but is reported as absent) until the next interval elapses.
	tr2, clk2 := newTestTracker(100, time.Minute)
	tr2.inc("x")
	clk2.advance(2 * time.Minute)
	tr2.inc("y")
	if got := tr2.len(); got != 2 {
		t.Fatalf("len = %d, want 2 (no sweep yet)", got)
	}
	if got := tr2.get("x"); got != 0 {
		t.Fatalf("expired x reported count %d", got)
	}
	clk2.advance(opFailureSweepInterval)
	tr2.inc("z")
	if got := tr2.len(); got != 1 {
		t.Fatalf("len after interval sweep = %d, want 1", got)
	}
}

func TestOpFailureTrackerConcurrentAccessStaysBounded(t *testing.T) {
	const maxEntries = 50
	tr := newOpFailureTracker(maxEntries, time.Hour)

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				key := fmt.Sprintf("id%d|op%d", (g*500+i)%200, i%3)
				switch i % 5 {
				case 0:
					tr.clear(key)
				case 1:
					tr.get(key)
				default:
					if got := tr.inc(key); got < 1 {
						t.Errorf("inc returned %d", got)
					}
				}
				if tr.len() > maxEntries {
					t.Errorf("len %d exceeded bound %d", tr.len(), maxEntries)
				}
			}
		}(g)
	}
	wg.Wait()

	if tr.len() > maxEntries {
		t.Fatalf("final len %d exceeded bound %d", tr.len(), maxEntries)
	}
	if len(tr.entries) != tr.order.Len() {
		t.Fatalf("index/list mismatch: %d vs %d", len(tr.entries), tr.order.Len())
	}
}

func TestOpFailureTrackerServerIntegration(t *testing.T) {
	t.Setenv("FAILURE_TRACK_MAX", "2")
	t.Setenv("FAILURE_TRACK_TTL", "1h")
	s := New(false)

	if got := s.incOpFailure("pk1", "cookie_auth"); got != 1 {
		t.Fatalf("incOpFailure = %d, want 1", got)
	}
	if got := s.incOpFailure("pk1", "cookie_auth"); got != 2 {
		t.Fatalf("incOpFailure = %d, want 2", got)
	}
	s.incOpFailure("pk2", "cookie_auth")
	s.incOpFailure("pk3", "cookie_auth") // evicts pk1 (max 2)
	if got := s.clearOpFailure("pk1", "cookie_auth"); got != 0 {
		t.Fatalf("clearOpFailure of evicted identity = %d, want 0", got)
	}
	if got := s.clearOpFailure("pk3", "cookie_auth"); got != 1 {
		t.Fatalf("clearOpFailure = %d, want 1", got)
	}
	if s.opFailures.maxEntries != 2 || s.opFailures.ttl != time.Hour {
		t.Fatalf("env not applied: max=%d ttl=%s", s.opFailures.maxEntries, s.opFailures.ttl)
	}
}

func TestFailureTrackEnvParsing(t *testing.T) {
	cases := []struct {
		max, ttl string
		wantMax  int
		wantTTL  time.Duration
	}{
		{"", "", defaultFailureTrackMax, defaultFailureTrackTTL},
		{"500", "90m", 500, 90 * time.Minute},
		{"500", "3600", 500, time.Hour}, // bare seconds
		{"0", "0", defaultFailureTrackMax, defaultFailureTrackTTL},
		{"-1", "-5m", defaultFailureTrackMax, defaultFailureTrackTTL},
		{"abc", "soon", defaultFailureTrackMax, defaultFailureTrackTTL},
		{" 42 ", " 2h ", 42, 2 * time.Hour},
	}
	for _, tc := range cases {
		t.Setenv("FAILURE_TRACK_MAX", tc.max)
		t.Setenv("FAILURE_TRACK_TTL", tc.ttl)
		tr := newOpFailureTrackerFromEnv()
		if tr.maxEntries != tc.wantMax || tr.ttl != tc.wantTTL {
			t.Errorf("MAX=%q TTL=%q -> max=%d ttl=%s, want max=%d ttl=%s",
				tc.max, tc.ttl, tr.maxEntries, tr.ttl, tc.wantMax, tc.wantTTL)
		}
	}
}
