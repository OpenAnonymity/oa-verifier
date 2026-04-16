// Docstream:
//
// Purpose:
// - This loop is the core station-compliance enforcement path for privacy toggles.
//
// Enforcement behavior:
//   - It continuously re-checks station operator account-state against
//     `OpenRouterRequiredToggles` and updates verification outcomes
//     (verified, transiently unverified, banned/unregistered).
//   - Check intervals are cryptographically random (see challenge.GetRandomInterval),
//     making it impossible for stations to predict when checks occur and cheat
//     by temporarily toggling settings.
//   - Checks use provider-exposed account metadata fetched by verifier; station
//     self-assertions are not accepted as sufficient evidence.
//
// Data-path boundary:
//   - End-user prompts/responses do not transit this loop; it only consumes station
//     governance metadata (cookie-authenticated provider account state).
//   - This loop operates exclusively on station-operator account data. It never
//     receives, processes, or stores any end-user identity material.
//
// Trust chain (runtime view):
//   - Attested verifier runtime -> enforced toggle checks -> station verification-state updates
//     -> client key acceptance/rejection behavior.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/openanonymity/oa-verifier/internal/challenge"
	"github.com/openanonymity/oa-verifier/internal/config"
	"github.com/openanonymity/oa-verifier/internal/models"
	"github.com/openanonymity/oa-verifier/internal/openrouter"
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
func (s *Server) challengeOneStation(_ context.Context, pk string, station models.Station) {
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
	unregisterOperation := ""
	transientFailure := false
	withinGrace := false
	transientEvent := ""
	transientOperation := ""
	transientStatusCode := 0
	transientDetails := map[string]any{}

	if station.CookieData == nil {
		reason = "no_cookie_data"
		transientFailure = true
		unregisterReason = "no_cookie_data"
		unregisterDetail = "missing_cookie_data"
		unregisterOperation = "cookie_auth"
		transientEvent = "verification_no_cookie_data"
		transientOperation = "cookie_auth"
	} else {
		auth, err := openrouter.NewAuthFromCookieData(station.CookieData)
		if err != nil {
			reason = "auth_error"
			transientFailure = true
			unregisterReason = "auth_error"
			unregisterDetail = err.Error()
			unregisterOperation = "cookie_auth"
			transientEvent = "verification_cookie_auth_failed"
			transientOperation = "cookie_auth"
			transientStatusCode = 401
			transientDetails = openrouterErrorDetails(err)
		} else {
			activityData, err := openrouter.FetchActivityData(auth)
			if err != nil || activityData == nil {
				reason = "activity_fetch_failed"
				transientFailure = true
				unregisterReason = "activity_fetch_failed"
				unregisterOperation = "activity_fetch"
				transientEvent = "verification_activity_fetch_failed"
				transientOperation = "activity_fetch"
				if err != nil {
					unregisterDetail = err.Error()
					transientDetails = openrouterErrorDetails(err)
				}
			} else {
				// Merge workspace data into activity data for toggle checking.
				// Workspace-level toggles (e.g. is_data_discount_logging_enabled)
				// are only available from the workspace settings endpoint.
				wsData, wsErr := openrouter.FetchWorkspaceData(auth)
				if wsErr != nil {
					slog.Warn("workspace data fetch failed, checking with user data only", "station_id", stationID, "error", wsErr)
				}
				mergedData := mergeToggleData(activityData, wsData)

				toggleResult, toggleDetails := challenge.CheckPrivacyToggles(mergedData)
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
					unregisterOperation = "privacy_toggle_check"
					transientEvent = "verification_privacy_toggles_missing"
					transientOperation = "privacy_toggle_check"
				case challenge.ToggleUnparseable:
					reason = fmt.Sprintf("privacy_toggles_unparseable:[%s]", strings.Join(toggleDetails, ","))
					transientFailure = true
					unregisterReason = "privacy_toggles_unparseable"
					unregisterDetail = strings.Join(toggleDetails, ",")
					unregisterOperation = "privacy_toggle_check"
					transientEvent = "verification_privacy_toggles_unparseable"
					transientOperation = "privacy_toggle_check"
				}
			}
		}
	}

	failureCount := 0
	if transientFailure {
		withinGrace = s.markTransientFailure(pk, unregisterReason, transientStatusCode, unregisterDetail)
		failureCount = s.getFailureCount(pk)
		s.notifyOrgEvent(orgEvent{
			event:                   transientEvent,
			stationID:               stationID,
			publicKey:               pk,
			email:                   stationEmail,
			reason:                  unregisterReason,
			statusCode:              transientStatusCode,
			errorDetail:             unregisterDetail,
			operation:               transientOperation,
			consecutiveFailureCount: failureCount,
			withinGrace:             withinGrace,
			withinGraceSet:          true,
			details:                 transientDetails,
		})
		if failureCount == 1 {
			s.notifyOrgEvent(orgEvent{
				event:                   "transient_failure_started",
				stationID:               stationID,
				publicKey:               pk,
				email:                   stationEmail,
				reason:                  unregisterReason,
				statusCode:              transientStatusCode,
				errorDetail:             unregisterDetail,
				operation:               transientOperation,
				consecutiveFailureCount: failureCount,
				withinGrace:             withinGrace,
				withinGraceSet:          true,
				details:                 transientDetails,
			})
		}
		if !withinGrace {
			unregister = true
		}
	}

	if unregister {
		slog.Warn("unregistering station due to verification failure", "station_id", stationID, "reason", unregisterReason)
		s.unregisterStation(station.StationID, pk, stationEmail, unregisterReason, transientStatusCode, unregisterDetail, unregisterOperation, failureCount, false)
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
		s.notifyOrgEvent(orgEvent{
			event:       "station_banned",
			stationID:   station.StationID,
			publicKey:   pk,
			email:       stationEmail,
			reason:      reason,
			statusCode:  403,
			errorDetail: reason,
			operation:   "privacy_toggle_check",
		})
	}
}
