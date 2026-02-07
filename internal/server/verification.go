package server

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/oa-verifier/internal/challenge"
	"github.com/oa-verifier/internal/config"
	"github.com/oa-verifier/internal/models"
	"github.com/oa-verifier/internal/openrouter"
)

// verificationLoop runs in a dedicated goroutine, completely independent
// from HTTP request handlers. This ensures true parallelism - thousands of
// /submit_key requests will never slow down the toggle checking loop.
func (s *Server) verificationLoop(ctx context.Context) {
	slog.Info("verification loop started",
		"min_interval", config.ChallengeMinInterval(),
		"max_interval", config.ChallengeMaxInterval())

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("verification loop stopped")
			return
		case <-ticker.C:
			s.checkDueStations(ctx)
		}
	}
}

// checkDueStations finds stations due for challenge and challenges them concurrently.
func (s *Server) checkDueStations(ctx context.Context) {
	now := time.Now()

	type stationEntry struct {
		pk   string
		data models.Station
	}
	var stationsDue []stationEntry

	s.mu.RLock()
	for pk, data := range s.stations {
		if now.After(data.NextChallengeAt) || now.Equal(data.NextChallengeAt) {
			stationsDue = append(stationsDue, stationEntry{pk: pk, data: *data})
		}
	}
	s.mu.RUnlock()

	if len(stationsDue) == 0 {
		return
	}

	// Each station gets its own goroutine for true parallel verification.
	// No semaphore - all stations due are checked simultaneously.
	var wg sync.WaitGroup
	for _, entry := range stationsDue {
		wg.Add(1)
		go func(pk string, station models.Station) {
			defer wg.Done()
			s.challengeOneStation(ctx, pk, station)
		}(entry.pk, entry.data)
	}
	wg.Wait()
}

// challengeOneStation challenges a single station by checking privacy toggles.
// Runs in its own goroutine, fully concurrent with other challenges and HTTP handlers.
func (s *Server) challengeOneStation(ctx context.Context, pk string, station models.Station) {
	stationID := station.StationID
	if stationID == "" {
		stationID = pk[:16]
	}
	stationEmail := station.Email

	// Skip if banned
	if s.banned.IsBanned(stationID, pk) {
		s.mu.Lock()
		if _, exists := s.stations[pk]; exists {
			delete(s.stations, pk)
			if stationEmail != "" {
				delete(s.emailToPK, stationEmail)
			}
			if station.StationID != "" {
				delete(s.stationIDToPK, station.StationID)
			}
			slog.Info("removed banned station from registry", "station_id", stationID)
		}
		s.mu.Unlock()
		return
	}

	slog.Info("checking privacy toggles", "station_id", stationID)

	// Check privacy toggles
	passed := false
	reason := ""
	unregister := false
	unregisterReason := ""
	unregisterDetail := ""
	transientFailure := false
	withinGrace := false

	if station.CookieData == nil {
		reason = "no_cookie_data"
		transientFailure = true
		unregisterReason = "no_cookie_data"
		unregisterDetail = "missing_cookie_data"
	} else {
		auth, err := openrouter.NewAuthFromCookieData(station.CookieData)
		if err != nil {
			reason = "auth_error"
			transientFailure = true
			unregisterReason = "auth_error"
			unregisterDetail = err.Error()
		} else {
			activityData, err := openrouter.FetchActivityData(auth)
			if err != nil || activityData == nil {
				reason = "activity_fetch_failed"
				transientFailure = true
				unregisterReason = "activity_fetch_failed"
				if err != nil {
					unregisterDetail = err.Error()
				}
			} else {
				toggleResult, toggleDetails := challenge.CheckPrivacyToggles(activityData)
				switch toggleResult {
				case challenge.ToggleOK:
					passed = true
				case challenge.ToggleInvalid:
					reason = fmt.Sprintf("privacy_toggles_invalid:[%s]", strings.Join(toggleDetails, ","))
					slog.Error("station failed privacy toggle check", "station_id", stationID, "toggles", toggleDetails)
				case challenge.ToggleMissing:
					reason = fmt.Sprintf("privacy_toggles_missing:[%s]", strings.Join(toggleDetails, ","))
					transientFailure = true
					unregisterReason = "privacy_toggles_missing"
					unregisterDetail = strings.Join(toggleDetails, ",")
				case challenge.ToggleUnparseable:
					reason = fmt.Sprintf("privacy_toggles_unparseable:[%s]", strings.Join(toggleDetails, ","))
					transientFailure = true
					unregisterReason = "privacy_toggles_unparseable"
					unregisterDetail = strings.Join(toggleDetails, ",")
				}
			}
		}
	}

	if transientFailure {
		withinGrace = s.markTransientFailure(pk, unregisterReason, 0, unregisterDetail)
		if !withinGrace {
			unregister = true
		}
	}

	if unregister {
		slog.Warn("unregistering station due to verification failure", "station_id", stationID, "reason", unregisterReason)
		s.unregisterStation(station.StationID, pk, stationEmail, unregisterReason, 0, unregisterDetail)
		return
	}

	// Update station state
	s.mu.Lock()
	if current, exists := s.stations[pk]; exists {
		// Schedule next challenge (independent per station)
		current.NextChallengeAt = s.getNextChallengeTime()

		if passed {
			now := utcNow()
			current.LastVerified = &now
			slog.Info("privacy toggles OK", "station_id", stationID)
			current.FailureFirstAt = nil
			current.FailureLastAt = nil
			current.FailureReason = ""
			current.FailureDetail = ""
			current.FailureStatus = 0
			current.FailureCount = 0
		} else {
			if !transientFailure || !withinGrace {
				current.LastVerified = nil
			}
			slog.Warn("verification FAILED", "station_id", stationID, "reason", reason, "grace", withinGrace)
		}
	}
	s.mu.Unlock()

	// Ban if necessary (outside lock)
	if !passed && challenge.ShouldBan(reason) {
		s.banned.Ban(station.StationID, pk, stationEmail, reason)
	}
}
