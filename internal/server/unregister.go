package server

import (
	"fmt"
	"log/slog"

	"github.com/oa-verifier/internal/openrouter"
)

func (s *Server) unregisterStation(stationID, publicKey, email, reason string, statusCode int, errorDetail string) {
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

	update := openrouter.OrgUpdate{
		StationID:   stationID,
		PublicKey:   publicKey,
		Email:       email,
		Reason:      reason,
		StatusCode:  statusCode,
		ErrorDetail: errorDetail,
		Event:       "station_unregistered",
		OccurredAt:  utcNow(),
		Source:      "oa-verifier",
	}

	go func() {
		if err := openrouter.NotifyOrgUpdate(update); err != nil {
			slog.Warn("failed to notify org update", "station_id", stationID, "error", err)
		}
	}()
}

func (s *Server) refreshProvisioningKey(stationID, publicKey string, cookieData map[string]any) (string, error) {
	if cookieData == nil {
		return "", fmt.Errorf("missing cookie data")
	}

	auth, err := openrouter.NewAuthFromCookieData(cookieData)
	if err != nil {
		return "", err
	}

	label := generateProvLabel(stationID)
	if _, cleanupErr := openrouter.CleanupProvisioningKeys(auth, label); cleanupErr != nil {
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
