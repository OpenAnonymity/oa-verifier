package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openanonymity/oa-verifier/internal/stationstore"
)

var errUnreadable = errors.New("sealed blob cannot be opened by this build")

func submitFor(t *testing.T, s *Server, stationID string) (int, map[string]any, http.Header) {
	t.Helper()
	body := `{"station_id":"` + stationID + `","api_key":"sk-or-v1-x","expires_at":4102444800,"station_signature":"00","org_signature":"00"}`
	rec := httptest.NewRecorder()
	s.handleSubmitKey(rec, httptest.NewRequest(http.MethodPost, "/submit_key", strings.NewReader(body)))
	var data map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &data)
	return rec.Code, data, rec.Header()
}

func submitUnknown(t *testing.T, s *Server) (int, map[string]any, http.Header) {
	return submitFor(t, s, "station-unknown")
}

func broadcastOf(t *testing.T, s *Server) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleBroadcast(rec, httptest.NewRequest(http.MethodGet, "/broadcast", nil))
	var data map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	return data
}

func broadcastReady(t *testing.T, s *Server) (bool, map[string]any) {
	t.Helper()
	data := broadcastOf(t, s)
	ready, _ := data["registry_ready"].(bool)
	return ready, data
}

func TestBroadcastRegistrationTimeDoesNotRenewOnRestoreOrBackgroundCheck(t *testing.T) {
	store := &memStore{}
	first := newTestServer(t, store)
	pk := addStation(first, "a")
	registered := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	first.stations[pk].RegisteredAt = registered
	first.stations[pk].LastVerified = &registered
	if err := first.persistOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := newTestServer(t, store)
	second.loadStationState(context.Background())
	for i := 0; i < 2; i++ {
		rows := broadcastOf(t, second)["verified_stations"].([]any)
		if len(rows) != 1 || rows[0].(map[string]any)["registered_at"] != registered {
			t.Fatal("restoring or observing a station renewed its registration time")
		}
		now := utcNow()
		second.stations[pk].LastVerified = &now
	}
	// Only a successful new registration replaces RegisteredAt.
	newRegistration := utcNow()
	second.stations[pk].RegisteredAt = newRegistration
	rows := broadcastOf(t, second)["verified_stations"].([]any)
	if rows[0].(map[string]any)["registered_at"] != newRegistration {
		t.Fatal("new registration time missing from broadcast")
	}
}

func setWarmupSince(s *Server, at time.Time) {
	s.state.mu.Lock()
	s.state.warmupSince = at
	s.state.mu.Unlock()
}

func jsonText(m map[string]any) string {
	b, _ := json.Marshal(m)
	return string(b)
}

func TestRegistryNotReadyDuringWarmupWithoutPersistence(t *testing.T) {
	t.Setenv("BANNED_STATIONS_FILE", filepath.Join(t.TempDir(), "banned.json"))
	t.Setenv("REGISTRY_WARMUP_SECONDS", "3600")
	s := New(false)

	ready, reason := s.registryReadiness()
	if ready || reason != "warming" {
		t.Fatalf("fresh server must be warming, got ready=%v reason=%q", ready, reason)
	}

	// Unknown station: "not yet", not "no".
	code, data, hdr := submitUnknown(t, s)
	if code != http.StatusServiceUnavailable || data["status"] != "unavailable" || data["detail"] != "registry_warming" {
		t.Fatalf("code=%d body=%v", code, data)
	}
	if hdr.Get("Retry-After") == "" {
		t.Fatal("503 must carry Retry-After")
	}
	if _, ok := data["registry"].(map[string]any); !ok {
		t.Fatalf("503 must carry the registry status block: %v", data)
	}
	// Nothing in the body may look like a hard failure to the client's classifier.
	text := strings.ToLower(jsonText(data))
	for _, bad := range []string{"expired", "invalid key", "invalid signature", "privacy", "logging", "training", "banned", "ownership", "signature mismatch"} {
		if strings.Contains(text, bad) {
			t.Fatalf("503 body must not contain %q: %s", bad, text)
		}
	}

	// Broadcast says so too, with the status block and an (empty) removed list.
	readyFlag, bc := broadcastReady(t, s)
	if readyFlag {
		t.Fatal("broadcast must report registry_ready=false while warming")
	}
	status := bc["registry"].(map[string]any)
	if status["reason"] != "warming" || status["warmup_seconds"].(float64) != 3600 || status["ready"] != false {
		t.Fatalf("registry status = %v", status)
	}
	if _, ok := bc["removed_stations"].([]any); !ok {
		t.Fatalf("not-ready broadcast must carry removed_stations: %v", bc)
	}

	// Once the warm-up has elapsed the historical answers return.
	setWarmupSince(s, time.Now().Add(-2*time.Hour))
	if ready, reason := s.registryReadiness(); !ready || reason != "warmup_elapsed" {
		t.Fatalf("got ready=%v reason=%q", ready, reason)
	}
	if code, _, _ := submitUnknown(t, s); code != http.StatusNotFound {
		t.Fatalf("after warm-up an unknown station must be 404, got %d", code)
	}
	readyFlag, bc = broadcastReady(t, s)
	if !readyFlag {
		t.Fatal("broadcast must report ready after warm-up")
	}
	if _, present := bc["removed_stations"]; present {
		t.Fatal("ready broadcast is authoritative and must not carry removed_stations")
	}
}

func TestWarmupZeroKeepsHistoricalBehaviour(t *testing.T) {
	t.Setenv("BANNED_STATIONS_FILE", filepath.Join(t.TempDir(), "banned.json"))
	t.Setenv("REGISTRY_WARMUP_SECONDS", "0")
	s := New(false)
	if ready, reason := s.registryReadiness(); !ready || reason != "warmup_elapsed" {
		t.Fatalf("warm-up 0 must be ready at once, got %v %q", ready, reason)
	}
	if code, _, _ := submitUnknown(t, s); code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", code)
	}
}

func TestWarmupIsCappedAtSevenDays(t *testing.T) {
	t.Setenv("BANNED_STATIONS_FILE", filepath.Join(t.TempDir(), "banned.json"))
	t.Setenv("REGISTRY_WARMUP_SECONDS", "99999999")
	s := New(false)
	if got := s.registryStatus()["warmup_seconds"]; got != 604800 {
		t.Fatalf("warm-up must be capped at 604800, got %v", got)
	}
}

func TestDefaultWarmupIsSevenDays(t *testing.T) {
	t.Setenv("REGISTRY_WARMUP_SECONDS", "")
	t.Setenv("BANNED_STATIONS_FILE", filepath.Join(t.TempDir(), "banned.json"))
	s := New(false)
	if got := s.registryStatus()["warmup_seconds"]; got != 604800 {
		t.Fatalf("default warm-up = %v, want 604800 (7 days)", got)
	}
	setWarmupSince(s, time.Now().Add(-6*24*time.Hour-23*time.Hour))
	if ready, _ := s.registryReadiness(); ready {
		t.Fatal("must still be warming after 6 days 23 hours")
	}
	setWarmupSince(s, time.Now().Add(-7*24*time.Hour-time.Minute))
	if ready, _ := s.registryReadiness(); !ready {
		t.Fatal("must be ready after 7 days")
	}
}

func TestBannedStationGetsAVerdictWhileWarming(t *testing.T) {
	t.Setenv("BANNED_STATIONS_FILE", filepath.Join(t.TempDir(), "banned.json"))
	t.Setenv("REGISTRY_WARMUP_SECONDS", "3600")
	s := New(false)
	pk := addStation(s, "evil")
	s.banned.Ban("station-evil", pk, "evil@example.com", "privacy_toggles_invalid")
	s.mu.Lock()
	delete(s.stations, pk)
	delete(s.stationIDToPK, "station-evil")
	s.mu.Unlock()

	code, data, _ := submitFor(t, s, "station-evil")
	if code != http.StatusForbidden || data["status"] != "banned" {
		t.Fatalf("banned station must be refused while warming: code=%d body=%v", code, data)
	}
	if b, ok := data["banned_station"].(map[string]any); !ok || b["station_id"] != "station-evil" {
		t.Fatalf("banned_station block = %v", data["banned_station"])
	}
}

func TestDeliberatelyRemovedStationGetsAVerdictAndIsPublished(t *testing.T) {
	t.Setenv("BANNED_STATIONS_FILE", filepath.Join(t.TempDir(), "banned.json"))
	t.Setenv("REGISTRY_WARMUP_SECONDS", "3600")
	s := New(false)
	pk := addStation(s, "gone")
	s.unregisterStation("station-gone", pk, "gone@example.com", "activity_fetch_failed", 503, "", "activity_fetch", 3, false)

	if code, _, _ := submitFor(t, s, "station-gone"); code != http.StatusNotFound {
		t.Fatalf("removed station must get 404 even while warming, got %d", code)
	}
	if code, _, _ := submitUnknown(t, s); code != http.StatusServiceUnavailable {
		t.Fatalf("other unknown stations still get 503 while warming, got %d", code)
	}
	bc := broadcastOf(t, s)
	removed, _ := bc["removed_stations"].([]any)
	if len(removed) != 1 {
		t.Fatalf("removed_stations = %v", bc["removed_stations"])
	}
	r := removed[0].(map[string]any)
	if r["station_id"] != "station-gone" || r["public_key"] != pk || r["reason"] != "activity_fetch_failed" {
		t.Fatalf("removed entry = %v", r)
	}

	// Registering again clears the tombstone (handleRegister deletes it on success).
	s.mu.Lock()
	s.stations[pk] = testStation("gone")
	s.stationIDToPK["station-gone"] = pk
	delete(s.removed, "station-gone")
	s.mu.Unlock()
	if s.wasRemoved("station-gone") {
		t.Fatal("tombstone must clear on re-registration")
	}
}

func TestTombstonesAreBounded(t *testing.T) {
	t.Setenv("BANNED_STATIONS_FILE", filepath.Join(t.TempDir(), "banned.json"))
	s := New(false)
	s.mu.Lock()
	for i := 0; i < maxRemovedTombstones+50; i++ {
		s.recordRemovedLocked("station-"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+time.Duration(i).String(), "pk", "r")
	}
	n := len(s.removed)
	s.mu.Unlock()
	if n != maxRemovedTombstones {
		t.Fatalf("tombstones = %d, want cap %d", n, maxRemovedTombstones)
	}
}

func TestSnapshotSavedWhileWarmingIsNotTreatedAsComplete(t *testing.T) {
	// Regression: a list saved during warm-up (only the stations that
	// re-registered since) used to be restored as "ready", and the org then
	// replaced its key set with that subset.
	shortPersistTimers(t)
	t.Setenv("REGISTRY_WARMUP_SECONDS", "3600")
	store := &memStore{}

	first := newTestServer(t, store)
	firstStart := time.Now().Add(-30 * time.Minute)
	first.startedAt = firstStart
	setWarmupSince(first, firstStart)
	ctx1, cancel1 := context.WithCancel(context.Background())
	first.loadStationState(ctx1)
	go first.persistLoop(ctx1)
	addStation(first, "a")
	waitFor(t, "write", func() bool { _, n := store.counts(); return n >= 1 })
	stopLoop(cancel1, first)

	store.mu.Lock()
	saved := *store.snap
	store.mu.Unlock()
	if saved.Complete || saved.WarmupSince.IsZero() {
		t.Fatalf("snapshot written while warming must be incomplete with a warm-up start: %+v", saved)
	}

	second := newTestServer(t, store)
	second.loadStationState(context.Background())
	if ready, reason := second.registryReadiness(); ready || reason != "warming" {
		t.Fatalf("incomplete snapshot must keep warming, got %v %q", ready, reason)
	}
	// The warm-up continues from the first start, not the restart.
	status := second.registryStatus()
	since, _ := time.Parse(time.RFC3339, status["warmup_since"].(string))
	if since.After(firstStart.Add(time.Second)) {
		t.Fatalf("restart extended the warm-up: warmup_since=%v, first start %v", since, firstStart)
	}
	if ready, _ := broadcastReady(t, second); ready {
		t.Fatal("broadcast must stay not-ready")
	}
	second.mu.RLock()
	_, ok := second.stations[pkFor("a")]
	second.mu.RUnlock()
	if !ok {
		t.Fatal("station not restored")
	}

	// Had the warm-up started long enough ago, the restart is ready at once.
	store.mu.Lock()
	store.snap.WarmupSince = time.Now().Add(-2 * time.Hour)
	store.mu.Unlock()
	third := newTestServer(t, store)
	third.loadStationState(context.Background())
	if ready, reason := third.registryReadiness(); !ready || reason != "warmup_elapsed" {
		t.Fatalf("warm-up that began before the restart must count, got %v %q", ready, reason)
	}
}

func TestCompleteSnapshotIsReadyImmediately(t *testing.T) {
	shortPersistTimers(t)
	store := &memStore{}

	// A previous process that WAS ready saved its registry.
	t.Setenv("REGISTRY_WARMUP_SECONDS", "0")
	first := newTestServer(t, store)
	ctx1, cancel1 := context.WithCancel(context.Background())
	first.loadStationState(ctx1)
	go first.persistLoop(ctx1)
	addStation(first, "a")
	waitFor(t, "write", func() bool { _, n := store.counts(); return n == 1 })
	stopLoop(cancel1, first)
	store.mu.Lock()
	complete := store.snap.Complete
	store.mu.Unlock()
	if !complete {
		t.Fatal("snapshot written while ready must be complete")
	}

	t.Setenv("REGISTRY_WARMUP_SECONDS", "3600")
	second := newTestServer(t, store)
	if ready, _ := second.registryReadiness(); ready {
		t.Fatal("must not be ready before the snapshot is loaded")
	}
	second.loadStationState(context.Background())
	if ready, reason := second.registryReadiness(); !ready || reason != "snapshot_restored" {
		t.Fatalf("complete snapshot must make the registry ready at once, got %v %q", ready, reason)
	}
	if code, _, _ := submitUnknown(t, second); code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown station after restore, got %d", code)
	}
	if readyFlag, _ := broadcastReady(t, second); !readyFlag {
		t.Fatal("broadcast must report ready after restore")
	}
}

func TestEmptySnapshotReadinessFollowsItsCompleteFlag(t *testing.T) {
	shortPersistTimers(t)
	t.Setenv("REGISTRY_WARMUP_SECONDS", "3600")

	complete := &memStore{snap: &stationstore.Snapshot{SavedAt: time.Now(), Complete: true}}
	s := newTestServer(t, complete)
	s.loadStationState(context.Background())
	if ready, reason := s.registryReadiness(); !ready || reason != "snapshot_restored" {
		t.Fatalf("legitimately empty complete registry: got %v %q", ready, reason)
	}

	// An empty INCOMPLETE snapshot (e.g. the shutdown flush of a warming
	// verifier nobody could register with) must not wipe the org.
	incomplete := &memStore{snap: &stationstore.Snapshot{SavedAt: time.Now(), WarmupSince: time.Now()}}
	s2 := newTestServer(t, incomplete)
	s2.loadStationState(context.Background())
	if ready, reason := s2.registryReadiness(); ready || reason != "warming" {
		t.Fatalf("empty incomplete snapshot: got %v %q", ready, reason)
	}
}

func TestPeriodicCheckWritesCompleteWhenWarmupEnds(t *testing.T) {
	shortPersistTimers(t)
	oldTick := statePeriodicCheck
	statePeriodicCheck = 20 * time.Millisecond
	t.Cleanup(func() { statePeriodicCheck = oldTick })
	t.Setenv("REGISTRY_WARMUP_SECONDS", "3600")

	store := &memStore{}
	s := newTestServer(t, store)
	ctx, cancel := context.WithCancel(context.Background())
	s.loadStationState(ctx)
	go s.persistLoop(ctx)
	defer stopLoop(cancel, s)

	addStation(s, "a")
	waitFor(t, "incomplete write", func() bool { _, n := store.counts(); return n == 1 })
	store.mu.Lock()
	firstComplete := store.snap.Complete
	store.mu.Unlock()
	if firstComplete {
		t.Fatal("first write must be incomplete")
	}

	// The warm-up ends with no registry change: the periodic check must
	// write Complete=true by itself.
	setWarmupSince(s, time.Now().Add(-2*time.Hour))
	waitFor(t, "complete write", func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		return store.snap != nil && store.snap.Complete
	})
}

func TestPeriodicCheckRetriesFailedStartupLoad(t *testing.T) {
	shortPersistTimers(t)
	oldTick, oldAttempts := statePeriodicCheck, stateLoadAttempts
	statePeriodicCheck, stateLoadAttempts = 20*time.Millisecond, 1
	t.Cleanup(func() { statePeriodicCheck, stateLoadAttempts = oldTick, oldAttempts })
	t.Setenv("REGISTRY_WARMUP_SECONDS", "3600")

	saved := &stationstore.Snapshot{SavedAt: time.Now(), Complete: true,
		Stations: []stationstore.Record{stationstore.RecordFromStation(pkFor("old"), testStation("old"))}}
	store := &memStore{snap: saved, loadErr: errUnreadable}
	s := newTestServer(t, store)
	ctx, cancel := context.WithCancel(context.Background())
	s.loadStationState(ctx)
	go s.persistLoop(ctx)
	defer stopLoop(cancel, s)
	if ready, reason := s.registryReadiness(); ready || reason != "state_not_loaded" {
		t.Fatalf("got %v %q", ready, reason)
	}

	// No registration happens; the store becomes readable on its own.
	store.mu.Lock()
	store.loadErr = nil
	store.mu.Unlock()
	waitFor(t, "late load", func() bool { ready, _ := s.registryReadiness(); return ready })
	s.mu.RLock()
	_, ok := s.stations[pkFor("old")]
	s.mu.RUnlock()
	if !ok {
		t.Fatal("late-loaded station missing")
	}
}

func TestUnreadableSnapshotKeepsNotReadyPastWarmup(t *testing.T) {
	shortPersistTimers(t)
	oldAttempts := stateLoadAttempts
	stateLoadAttempts = 1
	t.Cleanup(func() { stateLoadAttempts = oldAttempts })
	t.Setenv("REGISTRY_WARMUP_SECONDS", "0")
	store := &memStore{snap: &stationstore.Snapshot{}, loadErr: errUnreadable}
	s := newTestServer(t, store)
	s.loadStationState(context.Background())
	if ready, reason := s.registryReadiness(); ready || reason != "state_not_loaded" {
		t.Fatalf("configured-but-unreadable store must keep the verifier not-ready, got %v %q", ready, reason)
	}
	if code, _, _ := submitUnknown(t, s); code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 while state is unreadable, got %d", code)
	}
	recH := httptest.NewRecorder()
	s.handleHealth(recH, httptest.NewRequest(http.MethodGet, "/health", nil))
	var h map[string]any
	_ = json.Unmarshal(recH.Body.Bytes(), &h)
	if h["registry_ready"] != false {
		t.Fatalf("health = %v", h)
	}
}
