package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openanonymity/oa-verifier/internal/models"
	"github.com/openanonymity/oa-verifier/internal/stationstore"
)

// memStore is an in-memory stationstore.Store that counts and can fail.
type memStore struct {
	mu       sync.Mutex
	snap     *stationstore.Snapshot
	loads    int
	saves    int
	loadErr  error // returned by Load while set
	saveErr  error // returned by Save while set
	lastSave []byte
}

func (m *memStore) Load(context.Context) (*stationstore.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loads++
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	if m.snap == nil {
		return nil, stationstore.ErrNotFound
	}
	data, _ := stationstore.Marshal(m.snap)
	return stationstore.Unmarshal(data)
}

func (m *memStore) Save(_ context.Context, s *stationstore.Snapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	data, err := stationstore.Marshal(s)
	if err != nil {
		return err
	}
	snap, err := stationstore.Unmarshal(data)
	if err != nil {
		return err
	}
	m.snap = snap
	m.lastSave = data
	m.saves++
	return nil
}

func (m *memStore) counts() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loads, m.saves
}

func testStation(id string) *models.Station {
	now := utcNow()
	return &models.Station{
		StationID:       "station-" + id,
		Email:           id + "@example.com",
		DisplayName:     id,
		CookieData:      map[string]any{"cookies": []any{map[string]any{"name": "__client", "value": "tok-" + id, "domain": "clerk.openrouter.ai"}}},
		RegisteredAt:    now,
		LastVerified:    &now,
		ProvisioningKey: "sk-or-mgmt-" + id,
		NextChallengeAt: time.Now().Add(time.Hour),
	}
}

func pkFor(id string) string {
	// 64 hex chars, distinct per id.
	b := []byte(id + "000000000000000000000000000000000000000000000000000000000000000")
	out := make([]byte, 64)
	for i := range out {
		out[i] = "0123456789abcdef"[int(b[i%len(b)])%16]
	}
	return string(out)
}

// addStation inserts directly into the registry the way handleRegister does.
func addStation(s *Server, id string) string {
	pk := pkFor(id)
	st := testStation(id)
	s.mu.Lock()
	s.stations[pk] = st
	s.emailToPK[st.Email] = pk
	s.stationIDToPK[st.StationID] = pk
	s.mu.Unlock()
	s.requestPersist()
	return pk
}

func newTestServer(t *testing.T, store stationstore.Store) *Server {
	t.Helper()
	t.Setenv("BANNED_STATIONS_FILE", filepath.Join(t.TempDir(), "banned.json"))
	s := New(false)
	s.SetStationStateStore(store, "mem")
	return s
}

func shortPersistTimers(t *testing.T) {
	t.Helper()
	oldDebounce, oldRetry, oldLoadDelay, oldWindow := statePersistDebounce, statePersistRetry, stateLoadDelay, stateRestoreChallengeWindow
	statePersistDebounce = 10 * time.Millisecond
	statePersistRetry = 20 * time.Millisecond
	stateLoadDelay = 5 * time.Millisecond
	stateRestoreChallengeWindow = 50 * time.Millisecond
	t.Cleanup(func() {
		statePersistDebounce, statePersistRetry, stateLoadDelay, stateRestoreChallengeWindow = oldDebounce, oldRetry, oldLoadDelay, oldWindow
	})
}

// stopLoop cancels a server's context and waits for its persist loop to exit,
// so a test's cleanup never races the loop's reads of the timer variables.
func stopLoop(cancel context.CancelFunc, s *Server) {
	cancel()
	<-s.state.done
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestNewServerDefaultsToNoopPersistence(t *testing.T) {
	t.Setenv("BANNED_STATIONS_FILE", filepath.Join(t.TempDir(), "banned.json"))
	s := New(false)
	if s.StationStateDescription() != "none" {
		t.Fatalf("desc = %q", s.StationStateDescription())
	}
	// Must be safe to call without InitStationState.
	addStation(s, "a")
	h := s.stationStateHealth()
	if h["store"] != "none" {
		t.Fatalf("health = %v", h)
	}
}

func TestPersistLoopWritesOnChangeAndSkipsUnchanged(t *testing.T) {
	shortPersistTimers(t)
	store := &memStore{}
	s := newTestServer(t, store)
	ctx, cancel := context.WithCancel(context.Background())
	s.loadStationState(ctx)
	go s.persistLoop(ctx)
	defer stopLoop(cancel, s)

	addStation(s, "a")
	waitFor(t, "first write", func() bool { _, n := store.counts(); return n == 1 })
	if len(store.snap.Stations) != 1 || store.snap.Stations[0].ProvisioningKey != "sk-or-mgmt-a" {
		t.Fatalf("saved %+v", store.snap)
	}

	// Volatile-only changes (next challenge, counters) must not cause a write.
	s.mu.Lock()
	s.stations[pkFor("a")].NextChallengeAt = time.Now().Add(2 * time.Hour)
	s.stations[pkFor("a")].FailureCount = 3
	s.mu.Unlock()
	s.requestPersist()
	time.Sleep(6 * statePersistDebounce)
	if _, n := store.counts(); n != 1 {
		t.Fatalf("volatile change caused a write: saves=%d", n)
	}

	// A burst of changes coalesces into one write.
	addStation(s, "b")
	addStation(s, "c")
	waitFor(t, "second write", func() bool { _, n := store.counts(); return n == 2 })
	time.Sleep(6 * statePersistDebounce)
	if _, n := store.counts(); n != 2 {
		t.Fatalf("burst was not coalesced: saves=%d", n)
	}
	if len(store.snap.Stations) != 3 {
		t.Fatalf("saved %d stations", len(store.snap.Stations))
	}

	// Removing a station is durable.
	s.unregisterStation("station-b", pkFor("b"), "b@example.com", "test", 0, "", "test", 0, false)
	waitFor(t, "third write", func() bool { _, n := store.counts(); return n == 3 })
	if len(store.snap.Stations) != 2 {
		t.Fatalf("after unregister saved %d stations", len(store.snap.Stations))
	}
}

func TestPersistLoopRetriesFailedWrites(t *testing.T) {
	shortPersistTimers(t)
	store := &memStore{saveErr: errors.New("vault unavailable")}
	s := newTestServer(t, store)
	ctx, cancel := context.WithCancel(context.Background())
	s.loadStationState(ctx)
	go s.persistLoop(ctx)
	defer stopLoop(cancel, s)

	addStation(s, "a")
	time.Sleep(4 * statePersistRetry)
	if _, n := store.counts(); n != 0 {
		t.Fatalf("write should have failed, saves=%d", n)
	}
	store.mu.Lock()
	store.saveErr = nil
	store.mu.Unlock()
	waitFor(t, "retry to succeed", func() bool { _, n := store.counts(); return n == 1 })
}

func TestRestartRestoresRegistryAndBroadcast(t *testing.T) {
	shortPersistTimers(t)
	store := &memStore{}

	// First process: two stations register, one is unverified.
	first := newTestServer(t, store)
	ctx1, cancel1 := context.WithCancel(context.Background())
	first.loadStationState(ctx1)
	go first.persistLoop(ctx1)
	addStation(first, "a")
	pkB := addStation(first, "b")
	first.mu.Lock()
	first.stations[pkB].LastVerified = nil
	first.mu.Unlock()
	first.requestPersist()
	waitFor(t, "write", func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		return store.snap != nil && len(store.snap.Stations) == 2 && store.snap.Stations[1].LastVerified == nil
	})
	_, savesByFirst := store.counts()
	stopLoop(cancel1, first) // "container stops"

	// Second process: nothing registered, the snapshot is loaded.
	second := newTestServer(t, store)
	ctx2, cancel2 := context.WithCancel(context.Background())
	before := time.Now()
	second.loadStationState(ctx2)

	second.mu.RLock()
	a, okA := second.stations[pkFor("a")]
	b, okB := second.stations[pkB]
	emailA := second.emailToPK["a@example.com"]
	idA := second.stationIDToPK["station-a"]
	second.mu.RUnlock()
	if !okA || !okB {
		t.Fatalf("stations not restored: a=%v b=%v", okA, okB)
	}
	if a.ProvisioningKey != "sk-or-mgmt-a" || a.LastVerified == nil || b.LastVerified != nil {
		t.Fatalf("restored state wrong: a=%+v b=%+v", a, b)
	}
	if emailA != pkFor("a") || idA != pkFor("a") {
		t.Fatalf("index maps not rebuilt: email=%q id=%q", emailA, idA)
	}
	// Restored stations are re-checked soon, not at their old far-future time.
	if a.NextChallengeAt.After(before.Add(stateRestoreChallengeWindow + time.Second)) {
		t.Fatalf("restored station not scheduled for a prompt re-check: %v", a.NextChallengeAt)
	}
	// The cookie data is usable by the OpenRouter auth parser's shape check.
	if _, ok := a.CookieData["cookies"].([]any); !ok {
		t.Fatalf("cookie data shape lost: %#v", a.CookieData)
	}

	// /broadcast lists the verified one immediately, so the org keeps its key.
	rec := httptest.NewRecorder()
	second.handleBroadcast(rec, httptest.NewRequest(http.MethodGet, "/broadcast", nil))
	var body struct {
		Verified []map[string]any `json:"verified_stations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Verified) != 1 || body.Verified[0]["public_key"] != pkFor("a") {
		t.Fatalf("broadcast = %s", rec.Body.String())
	}

	// /health reports stations and the persistence mode, nothing secret.
	rec = httptest.NewRecorder()
	second.handleHealth(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	var health map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &health)
	if health["stations"].(float64) != 2 {
		t.Fatalf("health = %v", health)
	}
	p := health["persistence"].(map[string]any)
	if p["store"] != "mem" || p["loaded"] != true {
		t.Fatalf("persistence health = %v", p)
	}

	// Nothing changed durably, so the restored process does not rewrite.
	go second.persistLoop(ctx2)
	defer stopLoop(cancel2, second)
	second.requestPersist()
	time.Sleep(6 * statePersistDebounce)
	if _, n := store.counts(); n != savesByFirst {
		t.Fatalf("restore caused a redundant write: saves=%d (first process wrote %d)", n, savesByFirst)
	}
}

func TestRestoreSkipsBannedAndKeepsLiveBindings(t *testing.T) {
	shortPersistTimers(t)
	store := &memStore{}
	s := newTestServer(t, store)

	snap := &stationstore.Snapshot{SavedAt: time.Now()}
	for _, id := range []string{"a", "b", "c", "d"} {
		snap.Stations = append(snap.Stations, stationstore.RecordFromStation(pkFor(id), testStation(id)))
	}
	// "b" was banned after the snapshot was written.
	s.banned.Ban("station-b", pkFor("b"), "b@example.com", "test_ban")
	// "c" registered again under a NEW key while we were down (same email).
	newPK := pkFor("c2")
	stC := testStation("c")
	stC.ProvisioningKey = "" // registered but still without a key (MFA blocked)
	s.mu.Lock()
	s.stations[newPK] = stC
	s.emailToPK[stC.Email] = newPK
	s.stationIDToPK[stC.StationID] = newPK
	s.mu.Unlock()
	// "a" is live with the SAME key but lost its management key.
	stA := testStation("a")
	stA.ProvisioningKey = ""
	s.mu.Lock()
	s.stations[pkFor("a")] = stA
	s.emailToPK[stA.Email] = pkFor("a")
	s.mu.Unlock()
	// "d"'s station id is now live under a different key AND a different email.
	stD := testStation("d")
	stD.Email = "d-new@example.com"
	newD := pkFor("d2")
	s.mu.Lock()
	s.stations[newD] = stD
	s.emailToPK[stD.Email] = newD
	s.stationIDToPK[stD.StationID] = newD
	s.mu.Unlock()

	restored, skipped := s.restoreSnapshot(snap)
	if restored != 0 || skipped != 1 {
		t.Fatalf("restored=%d skipped=%d", restored, skipped)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.stations[pkFor("b")]; ok {
		t.Fatal("banned station must not be restored")
	}
	if _, ok := s.stations[pkFor("c")]; ok {
		t.Fatal("stale record for an email now bound to another key must not be restored")
	}
	if s.emailToPK["c@example.com"] != newPK {
		t.Fatal("live email binding must win")
	}
	if s.stations[pkFor("a")].ProvisioningKey != "sk-or-mgmt-a" {
		t.Fatal("a saved management key must fill an empty live one")
	}
	if s.stations[pkFor("a")].CookieData["cookies"].([]any)[0].(map[string]any)["value"] != "tok-a" {
		t.Fatal("live record must keep its own cookies")
	}
	if _, ok := s.stations[pkFor("d")]; ok || s.stationIDToPK["station-d"] != newD {
		t.Fatal("a saved record whose station id is live under another key must not be restored")
	}
}

func TestShutdownFlushesPendingWrite(t *testing.T) {
	shortPersistTimers(t)
	store := &memStore{}
	s := newTestServer(t, store)
	ctx, cancel := context.WithCancel(context.Background())
	s.loadStationState(ctx)
	go s.persistLoop(ctx)

	// Register and immediately "receive SIGTERM", well inside the debounce.
	addStation(s, "a")
	stopLoop(cancel, s)
	if _, n := store.counts(); n != 1 {
		t.Fatalf("pending change lost on shutdown: saves=%d", n)
	}
	if len(store.snap.Stations) != 1 {
		t.Fatalf("flushed snapshot has %d stations", len(store.snap.Stations))
	}
	// WaitStationState returns promptly once the loop is done.
	done := make(chan struct{})
	go func() { s.WaitStationState(time.Second); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WaitStationState did not return")
	}
}

func TestTooLargeSnapshotIsReportedNotRetriedBlindly(t *testing.T) {
	shortPersistTimers(t)
	store := &memStore{}
	s := newTestServer(t, store)
	ctx, cancel := context.WithCancel(context.Background())
	s.loadStationState(ctx)
	go s.persistLoop(ctx)
	defer stopLoop(cancel, s)

	pk := addStation(s, "a")
	waitFor(t, "first write", func() bool { _, n := store.counts(); return n == 1 })

	// A station whose relevant cookie is absurdly large: cannot be persisted.
	s.mu.Lock()
	s.stations[pk].CookieData = map[string]any{"cookies": []any{map[string]any{"name": "__client", "value": strings.Repeat("x", stationstore.MaxEncodedBytes)}}}
	s.mu.Unlock()
	s.requestPersist()
	waitFor(t, "save error on /health", func() bool { return s.stationStateHealth()["save_error"] == true })
	if _, n := store.counts(); n != 1 {
		t.Fatalf("oversized snapshot must not be written: saves=%d", n)
	}
	// Shrinking it again recovers.
	s.mu.Lock()
	s.stations[pk].CookieData = testStation("a").CookieData
	s.stations[pk].DisplayName = "renamed"
	s.mu.Unlock()
	s.requestPersist()
	waitFor(t, "recovery write", func() bool { _, n := store.counts(); return n == 2 })
	if h := s.stationStateHealth(); h["save_error"] != nil {
		t.Fatalf("save_error must clear after a successful write: %v", h)
	}
}

func TestStartupLoadHonoursOverallDeadline(t *testing.T) {
	shortPersistTimers(t)
	oldDeadline, oldAttempts := stateLoadDeadline, stateLoadAttempts
	stateLoadDeadline, stateLoadAttempts = 30*time.Millisecond, 1000
	t.Cleanup(func() { stateLoadDeadline, stateLoadAttempts = oldDeadline, oldAttempts })

	store := &memStore{loadErr: errors.New("sidecar hung")}
	s := newTestServer(t, store)
	start := time.Now()
	s.loadStationState(context.Background())
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("start-up load ran for %v despite the deadline", elapsed)
	}
	if h := s.stationStateHealth(); h["loaded"] != false || h["load_error"] != true {
		t.Fatalf("health = %v", h)
	}
}

func TestFailedLoadNeverClobbersSnapshot(t *testing.T) {
	shortPersistTimers(t)
	oldAttempts := stateLoadAttempts
	stateLoadAttempts = 2
	t.Cleanup(func() { stateLoadAttempts = oldAttempts })

	// A snapshot exists but the store is unreadable at start-up.
	saved := &stationstore.Snapshot{SavedAt: time.Now(), Stations: []stationstore.Record{stationstore.RecordFromStation(pkFor("old"), testStation("old"))}}
	store := &memStore{snap: saved, loadErr: errors.New("sidecar not ready")}
	s := newTestServer(t, store)
	ctx, cancel := context.WithCancel(context.Background())
	s.loadStationState(ctx)
	if loads, _ := store.counts(); loads != 2 {
		t.Fatalf("expected %d load attempts, got %d", 2, loads)
	}
	if h := s.stationStateHealth(); h["loaded"] != false || h["load_error"] != true {
		t.Fatalf("health = %v", h)
	}
	go s.persistLoop(ctx)
	defer stopLoop(cancel, s)

	// A station registers while the store is still unreadable: no write may
	// happen, because it would replace the snapshot we could not read.
	addStation(s, "new")
	time.Sleep(4 * statePersistRetry)
	if _, saves := store.counts(); saves != 0 {
		t.Fatalf("wrote over an unread snapshot: saves=%d", saves)
	}
	store.mu.Lock()
	if len(store.snap.Stations) != 1 || store.snap.Stations[0].PublicKey != pkFor("old") {
		store.mu.Unlock()
		t.Fatal("stored snapshot was modified")
	}
	store.loadErr = nil
	store.mu.Unlock()

	// Once readable, the old record is merged and the union is written.
	waitFor(t, "merge and write", func() bool { _, saves := store.counts(); return saves == 1 })
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.snap.Stations) != 2 {
		t.Fatalf("expected merged snapshot with 2 stations, got %d", len(store.snap.Stations))
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.stations[pkFor("old")]; !ok {
		t.Fatal("late-loaded station not merged into the registry")
	}
	if h := s.stationStateHealth(); h["loaded"] != true {
		t.Fatalf("health = %v", h)
	}
}

func TestInitStationStateFromEnvFileBackend(t *testing.T) {
	shortPersistTimers(t)
	dir := t.TempDir()
	t.Setenv(stationstore.EnvStore, "file")
	t.Setenv(stationstore.EnvStoreDir, dir)
	t.Setenv("BANNED_STATIONS_FILE", filepath.Join(dir, "banned.json"))

	ctx1, cancel1 := context.WithCancel(context.Background())
	first := New(false)
	if err := first.InitStationState(ctx1); err != nil {
		t.Fatal(err)
	}
	if first.StationStateDescription() != "file:"+filepath.Join(dir, stationstore.FileName) {
		t.Fatalf("desc = %q", first.StationStateDescription())
	}
	addStation(first, "a")
	waitFor(t, "file write", func() bool {
		first.state.mu.Lock()
		defer first.state.mu.Unlock()
		return first.state.writes == 1
	})
	stopLoop(cancel1, first)

	second := New(false)
	ctx2, cancel2 := context.WithCancel(context.Background())
	if err := second.InitStationState(ctx2); err != nil {
		t.Fatal(err)
	}
	defer stopLoop(cancel2, second)
	second.mu.RLock()
	defer second.mu.RUnlock()
	if st, ok := second.stations[pkFor("a")]; !ok || st.ProvisioningKey != "sk-or-mgmt-a" {
		t.Fatalf("not restored from file: %+v", st)
	}
}

func TestInitStationStateRejectsMisconfiguration(t *testing.T) {
	t.Setenv(stationstore.EnvStore, "keyvault-sealed") // no KEK, no vault
	t.Setenv("BANNED_STATIONS_FILE", filepath.Join(t.TempDir(), "banned.json"))
	s := New(false)
	if err := s.InitStationState(context.Background()); err == nil {
		t.Fatal("misconfigured store must fail start-up")
	}
}
