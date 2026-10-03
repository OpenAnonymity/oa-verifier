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
//   - A persisted snapshot was restored (state.go): the registry is complete
//     as of its save, so ready at once.
//   - Otherwise after REGISTRY_WARMUP_SECONDS of uptime, provided the state
//     store is loaded (a store that is configured but still unreadable keeps
//     the verifier not-ready; the org's grace window bounds how long that is
//     tolerated).
//
// What not-ready changes, and what it does not:
//   - /broadcast carries registry_ready=false, so the org merges the listed
//     stations instead of replacing its set, and keeps the rest for its grace
//     window. Bans are still published and still applied.
//   - /submit_key answers 503 {"status":"unavailable","detail":"registry_warming"}
//     for a station it does not know, which the client treats as a verifier
//     outage (bounded retries, outage policy) rather than a verdict.
//   - Nothing is ever marked verified without evidence. Known stations are
//     checked exactly as before; unknown stations get "not yet", never "yes".

import (
	"time"

	"github.com/openanonymity/oa-verifier/internal/config"
)

// registryReady reports whether the registry can be treated as complete.
func (s *Server) registryReady() bool {
	ready, _ := s.registryReadiness()
	return ready
}

// registryReadiness returns the readiness flag and the reason behind it.
func (s *Server) registryReadiness() (bool, string) {
	loaded, snapshotLoaded := true, false
	if s.state != nil {
		s.state.mu.Lock()
		loaded, snapshotLoaded = s.state.loaded, s.state.snapshotLoaded
		s.state.mu.Unlock()
	}
	if snapshotLoaded {
		return true, "snapshot_restored"
	}
	warmup := time.Duration(config.RegistryWarmupSeconds()) * time.Second
	if !loaded {
		return false, "state_not_loaded"
	}
	if time.Since(s.startedAt) >= warmup {
		return true, "warmup_elapsed"
	}
	return false, "warming"
}

// registryStatus is the readiness block published on /broadcast and /health.
func (s *Server) registryStatus() map[string]any {
	ready, reason := s.registryReadiness()
	return map[string]any{
		"ready":          ready,
		"reason":         reason,
		"started_at":     s.startedAt.UTC().Format(time.RFC3339),
		"uptime_seconds": int(time.Since(s.startedAt).Seconds()),
		"warmup_seconds": config.RegistryWarmupSeconds(),
	}
}
