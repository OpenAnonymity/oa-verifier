package server

// Docstream:
//
// Purpose:
//   - Let the verifier say "I cannot judge yet" instead of "no" while its
//     station registry may be incomplete after a start, so the org and the
//     client can fall back to their existing degraded-verifier handling for a
//     bounded time instead of treating an amnesiac verifier as authoritative.
//
// When the registry is "ready":
//   - A snapshot saved while ready (Complete) was restored (state.go): the
//     registry is authoritative as of its save, so ready at once.
//   - Otherwise REGISTRY_WARMUP_SECONDS (capped at 7 days in code) after the
//     warm-up began, provided the state store is loaded. The warm-up begins at
//     this start, or earlier if an incomplete snapshot says a warm-up was
//     already running, so restarts cannot extend it. A store that is
//     configured but unreadable keeps the verifier not-ready; the org's grace
//     window bounds how long that is tolerated.
//
// What not-ready changes, and what it does not:
//   - /broadcast carries registry_ready=false, so the org merges the listed
//     stations instead of replacing its set, and keeps the rest for its grace
//     window. Bans are still published and still applied.
//   - /broadcast also lists removed_stations: stations this process
//     deliberately unregistered, so the org drops their keys even though it
//     is not replacing its set.
//   - /submit_key answers 503 {"status":"unavailable","detail":"registry_warming"}
//     for a station it does not know, which the client treats as a verifier
//     outage (bounded retries, outage policy) rather than a verdict. Banned
//     stations (403) and removed stations (404) still get a verdict.
//   - Nothing is ever marked verified without evidence. Known stations are
//     checked exactly as before; unknown stations get "not yet", never "yes".

import (
	"time"

	"github.com/openanonymity/oa-verifier/internal/config"
)

// removedStation is a tombstone for a station unregistered by this process.
type removedStation struct {
	PublicKey string
	Reason    string
	At        time.Time
}

// maxRemovedTombstones bounds the tombstone map; the oldest entry is evicted.
const maxRemovedTombstones = 1000

// recordRemovedLocked adds a tombstone. Caller holds s.mu.
func (s *Server) recordRemovedLocked(stationID, publicKey, reason string) {
	if s.removed == nil {
		s.removed = make(map[string]removedStation)
	}
	if _, exists := s.removed[stationID]; !exists && len(s.removed) >= maxRemovedTombstones {
		var oldestID string
		var oldest time.Time
		for id, r := range s.removed {
			if oldestID == "" || r.At.Before(oldest) {
				oldestID, oldest = id, r.At
			}
		}
		delete(s.removed, oldestID)
	}
	s.removed[stationID] = removedStation{PublicKey: publicKey, Reason: reason, At: time.Now()}
}

// wasRemoved reports whether this process unregistered stationID (and it has
// not registered again since).
func (s *Server) wasRemoved(stationID string) bool {
	if stationID == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.removed[stationID]
	return ok
}

// removedList is the removed_stations block of /broadcast.
func (s *Server) removedList() []map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]map[string]string, 0, len(s.removed))
	for id, r := range s.removed {
		out = append(out, map[string]string{
			"station_id": id,
			"public_key": r.PublicKey,
			"reason":     r.Reason,
			"removed_at": r.At.UTC().Format(time.RFC3339),
		})
	}
	return out
}

// bannedEntry returns the public ban record for stationID, if banned.
func (s *Server) bannedEntry(stationID string) (map[string]string, bool) {
	if stationID == "" || !s.banned.IsBanned(stationID, "") {
		return nil, false
	}
	for _, b := range s.banned.GetAll() {
		if b["station_id"] == stationID {
			return b, true
		}
	}
	return map[string]string{"station_id": stationID}, true
}

// registryReady reports whether the registry can be treated as complete.
func (s *Server) registryReady() bool {
	ready, _ := s.registryReadiness()
	return ready
}

// registryReadiness returns the readiness flag and the reason behind it.
func (s *Server) registryReadiness() (bool, string) {
	loaded, complete, since := true, false, s.startedAt
	if s.state != nil {
		s.state.mu.Lock()
		loaded, complete, since = s.state.loaded, s.state.snapshotComplete, s.state.warmupSince
		s.state.mu.Unlock()
	}
	if complete {
		return true, "snapshot_restored"
	}
	if !loaded {
		return false, "state_not_loaded"
	}
	warmup := time.Duration(config.RegistryWarmupSeconds()) * time.Second
	if time.Since(since) >= warmup {
		return true, "warmup_elapsed"
	}
	return false, "warming"
}

// registryStatus is the readiness block published on /broadcast and /health.
func (s *Server) registryStatus() map[string]any {
	ready, reason := s.registryReadiness()
	since := s.startedAt
	if s.state != nil {
		s.state.mu.Lock()
		since = s.state.warmupSince
		s.state.mu.Unlock()
	}
	return map[string]any{
		"ready":          ready,
		"reason":         reason,
		"started_at":     s.startedAt.UTC().Format(time.RFC3339),
		"warmup_since":   since.UTC().Format(time.RFC3339),
		"uptime_seconds": int(time.Since(s.startedAt).Seconds()),
		"warmup_seconds": config.RegistryWarmupSeconds(),
	}
}
