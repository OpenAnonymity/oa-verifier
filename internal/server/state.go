package server

// Docstream:
//
// Purpose:
//   - Keep the station registry across container restarts so that an
//     unattended restart does not force every station to register again
//     (which now needs a human: see internal/stationstore).
//
// Behaviour:
//   - At start-up the snapshot is loaded (with retries, because the SKR
//     sidecar that releases the sealing key can be slow to come up) and its
//     stations are put back into the registry. Banned stations are skipped.
//     Restored stations are re-challenged within a minute, so stale
//     verification state is corrected quickly and the org is notified exactly
//     as it would be for a live station.
//   - Every code path that changes the registry calls requestPersist(). A
//     single background goroutine coalesces those requests, takes a snapshot
//     under the read lock, and writes it only when the durable content
//     (identity, credentials, verified/failing state) differs from what was
//     last written — the next-challenge timer and per-check counters never
//     trigger a write on their own.
//   - A failed write is retried; a failed start-up load is retried before the
//     first write, and a snapshot that could not be read is never overwritten
//     with a smaller one (a late successful load is merged instead).
//
// Trust boundary:
//   - No verification decision changes. The store holds station-operator
//     governance data only, sealed to the attested image when a sealed
//     backend is configured (docs/STATION_STATE.md).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openanonymity/oa-verifier/internal/stationstore"
)

// stationState is the server's persistence bookkeeping.
type stationState struct {
	store   stationstore.Store
	desc    string        // full description for logs (may name the vault and key)
	mode    string        // backend name only, safe for the public /health
	changed chan struct{} // buffered(1); a pending-write flag
	done    chan struct{} // closed when persistLoop returns

	mu              sync.Mutex
	loaded          bool   // Load succeeded or found nothing: saving is allowed
	lastLoadErr     error  // last non-NotFound load error, for /health and logs
	lastSaveErr     error  // last failed write (cleared by the next success), for /health
	lastSavedDigest string // Digest of the snapshot last written
	writes          int    // successful writes, for tests and /health
}

// Tunables, variables so tests can shorten them.
var (
	// stateLoadAttempts / stateLoadDelay bound the start-up load retries.
	// Six tries ten seconds apart mirrors acme.LoadRetryPolicy: the SKR
	// sidecar can take a little while to answer after a cold start.
	stateLoadAttempts = 6
	stateLoadDelay    = 10 * time.Second
	// stateLoadDeadline caps the whole start-up load, whatever the per-call
	// timeouts add up to, so a hung sidecar cannot hold :443 closed past the
	// liveness probe's patience. After it the server starts empty and keeps
	// retrying the load before its first write.
	stateLoadDeadline = 2 * time.Minute
	// stateFlushTimeout bounds the final write attempted on shutdown.
	stateFlushTimeout = 10 * time.Second
	// statePersistDebounce coalesces bursts of registry changes into one write.
	statePersistDebounce = 2 * time.Second
	// statePersistRetry is the delay after a failed write (or a failed late load).
	statePersistRetry = 30 * time.Second
	// stateRestoreChallengeWindow spreads the first re-check of restored
	// stations over this window after start-up.
	stateRestoreChallengeWindow = 60 * time.Second
)

func newStationState(store stationstore.Store, desc string) *stationState {
	mode := desc
	if i := strings.IndexByte(mode, ':'); i >= 0 {
		mode = mode[:i]
	}
	return &stationState{store: store, desc: desc, mode: mode, changed: make(chan struct{}, 1), done: make(chan struct{})}
}

// InitStationState configures persistence from the environment, restores the
// saved registry and starts the background writer. It must run before the
// server starts answering requests. A misconfigured store is an error (the
// process should not start half-configured); a store that cannot be read yet
// is not: the server starts empty, keeps retrying the load before its first
// write, and logs the condition.
func (s *Server) InitStationState(ctx context.Context) error {
	store, desc, err := stationstore.FromEnv(os.Getenv)
	if err != nil {
		return err
	}
	s.SetStationStateStore(store, desc)
	s.loadStationState(ctx)
	go s.persistLoop(ctx)
	return nil
}

// SetStationStateStore installs a store without touching the environment
// (tests, and InitStationState).
func (s *Server) SetStationStateStore(store stationstore.Store, desc string) {
	if store == nil {
		store = stationstore.NoopStore{}
		desc = "none"
	}
	s.state = newStationState(store, desc)
}

// StationStateDescription reports the configured backend, for logs and /health.
func (s *Server) StationStateDescription() string {
	if s.state == nil {
		return "none"
	}
	return s.state.desc
}

// loadStationState restores the saved registry at start-up.
func (s *Server) loadStationState(ctx context.Context) {
	if _, isNoop := s.state.store.(stationstore.NoopStore); isNoop {
		s.state.mu.Lock()
		s.state.loaded = true
		s.state.mu.Unlock()
		slog.Info("station registry persistence disabled", "store", s.state.desc)
		return
	}
	slog.Info("loading persisted station registry", "store", s.state.desc)
	loadCtx, cancel := context.WithTimeout(ctx, stateLoadDeadline)
	defer cancel()
	var snap *stationstore.Snapshot
	var err error
	for attempt := 1; attempt <= stateLoadAttempts; attempt++ {
		snap, err = s.state.store.Load(loadCtx)
		if err == nil || errors.Is(err, stationstore.ErrNotFound) || loadCtx.Err() != nil {
			break
		}
		slog.Warn("loading persisted station registry failed, retrying",
			"attempt", attempt, "max_attempts", stateLoadAttempts, "error", err)
		if attempt < stateLoadAttempts {
			select {
			case <-loadCtx.Done():
			case <-time.After(stateLoadDelay):
			}
		}
	}
	if ctx.Err() != nil {
		return // shutting down
	}
	if loadCtx.Err() != nil && err != nil && !errors.Is(err, stationstore.ErrNotFound) {
		err = fmt.Errorf("gave up after %s: %w", stateLoadDeadline, err)
	}
	switch {
	case err == nil:
		restored, skipped := s.restoreSnapshot(snap)
		s.state.mu.Lock()
		s.state.loaded = true
		s.state.lastLoadErr = nil
		s.state.lastSavedDigest = stationstore.Digest(s.snapshot())
		s.state.mu.Unlock()
		slog.Info("station registry restored", "stations", restored, "skipped_banned", skipped,
			"saved_at", snap.SavedAt.UTC().Format(time.RFC3339), "store", s.state.desc)
	case errors.Is(err, stationstore.ErrNotFound):
		s.state.mu.Lock()
		s.state.loaded = true
		s.state.lastLoadErr = nil
		s.state.mu.Unlock()
		slog.Info("no persisted station registry yet", "store", s.state.desc)
	default:
		// Start empty, but remember that something may be stored: persistOnce
		// retries the load and merges before it is allowed to write.
		s.state.mu.Lock()
		s.state.loaded = false
		s.state.lastLoadErr = err
		s.state.mu.Unlock()
		slog.Error("persisted station registry could not be loaded; starting empty and retrying before any write",
			"error", err, "store", s.state.desc)
	}
}

// restoreSnapshot puts saved stations back into the registry. Existing
// entries win over saved ones (a station that registered during a slow load
// has fresher cookies), except that a saved management key fills an empty
// one. Banned stations are not restored. Returns (restored, skippedBanned).
func (s *Server) restoreSnapshot(snap *stationstore.Snapshot) (int, int) {
	if snap == nil {
		return 0, 0
	}
	now := time.Now()
	restored, skipped := 0, 0
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rec := range snap.Stations {
		pk := rec.PublicKey
		st := rec.ToStation()
		if s.banned.IsBanned(st.StationID, pk) {
			skipped++
			continue
		}
		if current, exists := s.stations[pk]; exists {
			if current.ProvisioningKey == "" && st.ProvisioningKey != "" {
				current.ProvisioningKey = st.ProvisioningKey
				slog.Info("restored management key for already-registered station", "station_id", current.StationID)
			}
			continue
		}
		// A live registration that already owns this email or station id wins;
		// the saved record is stale (the station re-registered under a new key
		// while we were down) and is dropped.
		if st.Email != "" {
			if otherPK, taken := s.emailToPK[st.Email]; taken && otherPK != pk {
				continue
			}
		}
		if st.StationID != "" {
			if otherPK, taken := s.stationIDToPK[st.StationID]; taken && otherPK != pk {
				continue
			}
		}
		// Re-check soon, spread out so restored stations do not all hit
		// OpenRouter in the same second.
		st.NextChallengeAt = now.Add(time.Duration(rand.Int63n(int64(stateRestoreChallengeWindow))))
		cp := st
		s.stations[pk] = &cp
		if st.Email != "" {
			s.emailToPK[st.Email] = pk
		}
		if st.StationID != "" {
			s.stationIDToPK[st.StationID] = pk
		}
		restored++
	}
	return restored, skipped
}

// snapshot copies the registry into a Snapshot sorted by public key.
func (s *Server) snapshot() *stationstore.Snapshot {
	s.mu.RLock()
	recs := make([]stationstore.Record, 0, len(s.stations))
	for pk, st := range s.stations {
		recs = append(recs, stationstore.RecordFromStation(pk, st))
	}
	s.mu.RUnlock()
	sort.Slice(recs, func(i, j int) bool { return recs[i].PublicKey < recs[j].PublicKey })
	return &stationstore.Snapshot{Version: stationstore.SnapshotVersion, SavedAt: time.Now().UTC(), Stations: recs}
}

// requestPersist flags that the registry changed. It never blocks: the flag
// is a one-slot channel and the writer drains it.
func (s *Server) requestPersist() {
	if s.state == nil {
		return
	}
	select {
	case s.state.changed <- struct{}{}:
	default:
	}
}

// persistLoop is the single writer. It coalesces change notifications,
// retries failures, and exits with the context.
func (s *Server) persistLoop(ctx context.Context) {
	if s.state == nil {
		return
	}
	defer close(s.state.done)
	if _, isNoop := s.state.store.(stationstore.NoopStore); isNoop {
		return
	}
	var retry <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			s.flushOnShutdown()
			return
		case <-s.state.changed:
			// Debounce: let a burst of changes (register + first check) settle.
			select {
			case <-ctx.Done():
				s.flushOnShutdown()
				return
			case <-time.After(statePersistDebounce):
			}
		case <-retry:
			retry = nil
		}
		// Drain anything that arrived during the debounce.
		select {
		case <-s.state.changed:
		default:
		}
		if err := s.persistOnce(ctx); err != nil {
			if ctx.Err() != nil {
				s.flushOnShutdown()
				return
			}
			if errors.Is(err, stationstore.ErrTooLarge) {
				// Not transient: nothing will change until the registry does.
				// Logged at error level and visible on /health (save_error).
				slog.Error("station registry snapshot too large to persist; persistence is stalled until the registry shrinks", "error", err)
			} else {
				slog.Warn("persisting station registry failed; will retry", "error", err, "retry_in", statePersistRetry)
			}
			retry = time.After(statePersistRetry)
		}
	}
}

// flushOnShutdown makes one last attempt to write a pending change with a
// fresh, bounded context, so a registration made seconds before a SIGTERM
// (a platform repair, a redeploy) is not lost. Failures are logged only.
func (s *Server) flushOnShutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), stateFlushTimeout)
	defer cancel()
	if err := s.persistOnce(ctx); err != nil {
		slog.Warn("final station registry write on shutdown failed", "error", err)
	}
}

// WaitStationState blocks until the persistence goroutine has finished its
// shutdown flush, or timeout elapses. main calls it after the HTTP server has
// stopped so the process does not exit with a write in flight.
func (s *Server) WaitStationState(timeout time.Duration) {
	if s.state == nil {
		return
	}
	select {
	case <-s.state.done:
	case <-time.After(timeout):
		slog.Warn("timed out waiting for the station registry writer to finish")
	}
}

// persistOnce writes the registry if its durable content changed. If the
// start-up load failed it first retries the load and merges the result, so a
// snapshot that was merely unreadable for a while is never clobbered.
func (s *Server) persistOnce(ctx context.Context) error {
	s.state.mu.Lock()
	loaded := s.state.loaded
	s.state.mu.Unlock()

	if !loaded {
		snap, err := s.state.store.Load(ctx)
		switch {
		case err == nil:
			restored, skipped := s.restoreSnapshot(snap)
			slog.Info("late load of persisted station registry succeeded", "merged", restored, "skipped_banned", skipped)
		case errors.Is(err, stationstore.ErrNotFound):
		default:
			s.state.mu.Lock()
			s.state.lastLoadErr = err
			s.state.mu.Unlock()
			return err
		}
		s.state.mu.Lock()
		s.state.loaded = true
		s.state.lastLoadErr = nil
		s.state.mu.Unlock()
	}

	snap := s.snapshot()
	digest := stationstore.Digest(snap)

	s.state.mu.Lock()
	unchanged := digest == s.state.lastSavedDigest
	s.state.mu.Unlock()
	if unchanged {
		return nil
	}
	if err := s.state.store.Save(ctx, snap); err != nil {
		s.state.mu.Lock()
		s.state.lastSaveErr = err
		s.state.mu.Unlock()
		return err
	}
	s.state.mu.Lock()
	s.state.lastSavedDigest = digest
	s.state.lastSaveErr = nil
	s.state.writes++
	s.state.mu.Unlock()
	slog.Info("station registry persisted", "stations", len(snap.Stations), "store", s.state.desc)
	return nil
}

// stationStateHealth summarises persistence for /health.
func (s *Server) stationStateHealth() map[string]any {
	if s.state == nil {
		return map[string]any{"store": "none"}
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	out := map[string]any{
		"store":  s.state.mode,
		"loaded": s.state.loaded,
	}
	if s.state.lastLoadErr != nil {
		out["load_error"] = true
	}
	if s.state.lastSaveErr != nil {
		out["save_error"] = true
	}
	return out
}
