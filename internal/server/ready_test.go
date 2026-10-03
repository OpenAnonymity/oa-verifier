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

func submitUnknown(t *testing.T, s *Server) (int, map[string]any, http.Header) {
	t.Helper()
	body := `{"station_id":"station-unknown","api_key":"sk-or-v1-x","expires_at":4102444800,"station_signature":"00","org_signature":"00"}`
	rec := httptest.NewRecorder()
	s.handleSubmitKey(rec, httptest.NewRequest(http.MethodPost, "/submit_key", strings.NewReader(body)))
	var data map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &data)
	return rec.Code, data, rec.Header()
}

func broadcastReady(t *testing.T, s *Server) (bool, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleBroadcast(rec, httptest.NewRequest(http.MethodGet, "/broadcast", nil))
	var data map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	ready, _ := data["registry_ready"].(bool)
	return ready, data
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
	// Nothing in the body may look like a hard failure to the client's classifier.
	text := strings.ToLower(rec(data))
	for _, bad := range []string{"expired", "invalid key", "invalid signature", "privacy", "logging", "training", "banned", "ownership"} {
		if strings.Contains(text, bad) {
			t.Fatalf("503 body must not contain %q: %s", bad, text)
		}
	}

	// Broadcast says so too, with the status block.
	readyFlag, bc := broadcastReady(t, s)
	if readyFlag {
		t.Fatal("broadcast must report registry_ready=false while warming")
	}
	status := bc["registry"].(map[string]any)
	if status["reason"] != "warming" || status["warmup_seconds"].(float64) != 3600 {
		t.Fatalf("registry status = %v", status)
	}

	// Once the warm-up has elapsed the historical answers return.
	s.startedAt = time.Now().Add(-2 * time.Hour)
	if ready, reason := s.registryReadiness(); !ready || reason != "warmup_elapsed" {
		t.Fatalf("got ready=%v reason=%q", ready, reason)
	}
	code, _, _ = submitUnknown(t, s)
	if code != http.StatusNotFound {
		t.Fatalf("after warm-up an unknown station must be 404, got %d", code)
	}
	if readyFlag, _ := broadcastReady(t, s); !readyFlag {
		t.Fatal("broadcast must report ready after warm-up")
	}
}

func rec(m map[string]any) string {
	b, _ := json.Marshal(m)
	return string(b)
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

func TestRestoredSnapshotIsReadyImmediately(t *testing.T) {
	shortPersistTimers(t)
	t.Setenv("REGISTRY_WARMUP_SECONDS", "3600")
	store := &memStore{}
	// A previous process saved one station.
	first := newTestServer(t, store)
	ctx1, cancel1 := context.WithCancel(context.Background())
	first.loadStationState(ctx1)
	go first.persistLoop(ctx1)
	addStation(first, "a")
	waitFor(t, "write", func() bool { _, n := store.counts(); return n == 1 })
	stopLoop(cancel1, first)

	second := newTestServer(t, store)
	if ready, _ := second.registryReadiness(); ready {
		t.Fatal("must not be ready before the snapshot is loaded")
	}
	second.loadStationState(context.Background())
	if ready, reason := second.registryReadiness(); !ready || reason != "snapshot_restored" {
		t.Fatalf("restored registry must be ready at once, got %v %q", ready, reason)
	}
	// Known station → normal path (gets past the registry lookup); unknown → 404.
	if code, _, _ := submitUnknown(t, second); code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown station after restore, got %d", code)
	}
	if readyFlag, _ := broadcastReady(t, second); !readyFlag {
		t.Fatal("broadcast must report ready after restore")
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
	// Health exposes the flag without secrets.
	recH := httptest.NewRecorder()
	s.handleHealth(recH, httptest.NewRequest(http.MethodGet, "/health", nil))
	var h map[string]any
	_ = json.Unmarshal(recH.Body.Bytes(), &h)
	if h["registry_ready"] != false {
		t.Fatalf("health = %v", h)
	}
}

func TestEmptySnapshotCountsAsComplete(t *testing.T) {
	// A verifier whose saved registry is legitimately empty is complete, not warming.
	shortPersistTimers(t)
	t.Setenv("REGISTRY_WARMUP_SECONDS", "3600")
	store := &memStore{snap: &stationstore.Snapshot{SavedAt: time.Now()}}
	s := newTestServer(t, store)
	s.loadStationState(context.Background())
	if ready, reason := s.registryReadiness(); !ready || reason != "snapshot_restored" {
		t.Fatalf("got %v %q", ready, reason)
	}
}

func TestDefaultWarmupIsSevenDays(t *testing.T) {
	t.Setenv("REGISTRY_WARMUP_SECONDS", "")
	t.Setenv("BANNED_STATIONS_FILE", filepath.Join(t.TempDir(), "banned.json"))
	s := New(false)
	if got := s.registryStatus()["warmup_seconds"]; got != 604800 {
		t.Fatalf("default warm-up = %v, want 604800 (7 days)", got)
	}
	s.startedAt = time.Now().Add(-6*24*time.Hour - 23*time.Hour)
	if ready, _ := s.registryReadiness(); ready {
		t.Fatal("must still be warming after 6 days 23 hours")
	}
	s.startedAt = time.Now().Add(-7*24*time.Hour - time.Minute)
	if ready, _ := s.registryReadiness(); !ready {
		t.Fatal("must be ready after 7 days")
	}
}
