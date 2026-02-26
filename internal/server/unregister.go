package server

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/openanonymity/oa-verifier/internal/openrouter"
)

func (s *Server) unregisterStation(stationID, publicKey, email, reason string, statusCode int, errorDetail, operation string, consecutiveFailureCount int, withinGrace bool) {
	s.mu.Lock()
	if publicKey != "" {
		delete(s.stations, publicKey)
	}
	if email != "" {
		delete(s.emailToPK, email)
	}
	if stationID != "" {
		delete(s.stationIDToPK, stationID)
	}
	s.mu.Unlock()

	s.notifyOrgEvent(orgEvent{
		event:                   "station_unregistered",
		stationID:               stationID,
		publicKey:               publicKey,
		email:                   email,
		reason:                  reason,
		statusCode:              statusCode,
		errorDetail:             errorDetail,
		operation:               operation,
		consecutiveFailureCount: consecutiveFailureCount,
		withinGrace:             withinGrace,
		withinGraceSet:          true,
	})
}

func (s *Server) refreshProvisioningKey(stationID, publicKey, email string, cookieData map[string]any) (string, error) {
	if cookieData == nil {
		return "", fmt.Errorf("missing cookie data")
	}

	auth, err := openrouter.NewAuthFromCookieData(cookieData)
	if err != nil {
		return "", err
	}

	label := generateProvLabel(stationID)
	if _, cleanupErr := openrouter.CleanupProvisioningKeys(auth, label); cleanupErr != nil {
		s.notifyOrgEvent(orgEvent{
			event:       "submit_key_refresh_cleanup_failed",
			stationID:   stationID,
			publicKey:   publicKey,
			email:       email,
			reason:      "management_key_cleanup_failed",
			statusCode:  http.StatusBadGateway,
			errorDetail: cleanupErr.Error(),
			operation:   "management_key_cleanup",
			details:     openrouterErrorDetails(cleanupErr),
		})
		slog.Warn("failed cleanup before provisioning key refresh", "station_id", stationID, "label", label, "error", cleanupErr)
	}
	key, err := openrouter.CreateProvisioningKey(auth, label)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	if current, ok := s.stations[publicKey]; ok {
		current.ProvisioningKey = key
	}
	s.mu.Unlock()

	return key, nil
}
