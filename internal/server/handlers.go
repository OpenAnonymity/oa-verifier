package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/oa-verifier/internal/challenge"
	"github.com/oa-verifier/internal/config"
	"github.com/oa-verifier/internal/models"
	"github.com/oa-verifier/internal/openrouter"
	"github.com/oa-verifier/internal/registry"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]string{"detail": detail})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	slog.Info("registration request received",
		"public_key", req.PublicKey,
		"display_name", req.DisplayName)

	if !validatePublicKey(req.PublicKey) {
		slog.Warn("registration rejected: invalid public key format", "pk", req.PublicKey[:min(16, len(req.PublicKey))])
		writeError(w, http.StatusBadRequest, "Invalid Ed25519 public key (need 64 hex chars)")
		return
	}

	// Check if already banned by public key
	if s.banned.IsBanned("", req.PublicKey) {
		bannedID := s.banned.GetStationIDByPK(req.PublicKey)
		if bannedID == "" {
			bannedID = "pk:" + req.PublicKey[:16]
		}
		slog.Warn("registration rejected: station is BANNED", "station_id", bannedID)
		go func() { _ = openrouter.NotifyOrgBanned(bannedID, "banned_reregister_attempt") }()
		writeError(w, http.StatusForbidden, "Station is banned")
		return
	}

	// Verify cookie and get account data
	auth, err := openrouter.NewAuthFromCookieData(req.CookieData)
	if err != nil {
		slog.Warn("registration rejected: failed to verify cookie",
			"pk", req.PublicKey[:16],
			"display_name", req.DisplayName,
			"error", err)
		writeError(w, http.StatusUnauthorized, "Failed to verify cookie")
		return
	}

	data, err := openrouter.FetchActivityData(auth)
	if err != nil || data == nil {
		slog.Warn("registration rejected: failed to fetch activity data",
			"pk", req.PublicKey[:16],
			"display_name", req.DisplayName)
		writeError(w, http.StatusUnauthorized, "Failed to verify cookie")
		return
	}

	email := extractEmail(data)
	if email == "" {
		slog.Warn("registration rejected: could not extract email",
			"pk", req.PublicKey[:16],
			"display_name", req.DisplayName)
		writeError(w, http.StatusUnauthorized, "Could not extract email from account")
		return
	}

	slog.Info("registration: cookie verified",
		"email", email,
		"public_key", req.PublicKey,
		"display_name", req.DisplayName)

	// Validate against station registry - REQUIRED
	registryStations, err := registry.FetchStations()
	if err != nil {
		slog.Error("registration rejected: failed to fetch registry",
			"email", email,
			"public_key", req.PublicKey,
			"display_name", req.DisplayName,
			"error", err)
		writeError(w, http.StatusServiceUnavailable, "Failed to connect to station registry")
		return
	}
	if len(registryStations) == 0 {
		slog.Error("registration rejected: registry not configured or returned no stations",
			"email", email,
			"public_key", req.PublicKey,
			"display_name", req.DisplayName)
		writeError(w, http.StatusServiceUnavailable, "Station registry not configured or unavailable")
		return
	}

	// Find station by email
	var registryEntry map[string]any
	for _, st := range registryStations {
		if st["or_account_email"] == email {
			registryEntry = st
			break
		}
	}
	if registryEntry == nil {
		slog.Error("no station registered for email in registry",
			"email", email,
			"public_key", req.PublicKey,
			"display_name", req.DisplayName)
		writeError(w, http.StatusNotFound, "No station registered for this email in registry")
		return
	}

	stationID, _ := registryEntry["station_id"].(string)
	if stationID == "" {
		slog.Error("registration rejected: station_id is empty in registry entry",
			"email", email,
			"public_key", req.PublicKey,
			"display_name", req.DisplayName)
		writeError(w, http.StatusBadRequest, "Station entry in registry has no station_id")
		return
	}

	if s.banned.IsBanned(stationID, "") {
		slog.Warn("registration rejected: station is BANNED", "station_id", stationID)
		go func() { _ = openrouter.NotifyOrgBanned(stationID, "banned_reregister_attempt") }()
		writeError(w, http.StatusForbidden, "Station is banned")
		return
	}

	slog.Info("three-way binding established",
		"station_id", stationID,
		"email", email,
		"public_key", req.PublicKey,
		"display_name", req.DisplayName)

	// Verify privacy toggles immediately
	privacyOK, invalidToggles := challenge.CheckPrivacyToggles(data)
	if !privacyOK {
		reason := fmt.Sprintf("privacy_toggles_invalid_on_register:[%s]", strings.Join(invalidToggles, ","))
		slog.Error("registration rejected: FAILED privacy toggle check - BANNING", "station_id", stationID, "toggles", invalidToggles)
		effectiveStationID := stationID
		if effectiveStationID == "" {
			effectiveStationID = "unknown"
		}
		s.banned.Ban(effectiveStationID, req.PublicKey, email, reason)
		writeError(w, http.StatusForbidden, "Privacy toggles not properly configured. Station banned.")
		return
	}

	now := utcNow()

	// Check for existing provisioning key
	var existingProvKey string
	s.mu.RLock()
	if station, ok := s.stations[req.PublicKey]; ok {
		existingProvKey = station.ProvisioningKey
	} else if oldPK, ok := s.emailToPK[email]; ok {
		if station, ok := s.stations[oldPK]; ok {
			existingProvKey = station.ProvisioningKey
		}
	}
	s.mu.RUnlock()

	// Create provisioning key if needed (station_id is always set at this point)
	provisioningKey := existingProvKey
	if provisioningKey == "" {
		label := generateProvLabel(stationID)
		// Cleanup any existing keys with this label
		cleanedUp, _ := openrouter.CleanupProvisioningKeys(auth, label)
		if cleanedUp > 0 {
			slog.Info("cleaned up existing provisioning keys", "station_id", stationID, "label", label, "count", cleanedUp)
		}
		key, err := openrouter.CreateProvisioningKey(auth, label)
		if err != nil {
			slog.Error("failed to create provisioning key",
				"station_id", stationID,
				"label", label,
				"error", err)
			writeError(w, http.StatusInternalServerError, "Failed to create provisioning key")
			return
		}
		provisioningKey = key
		slog.Info("created provisioning key",
			"station_id", stationID,
			"label", label,
			"key_prefix", provisioningKey[:min(20, len(provisioningKey))])
	} else {
		slog.Info("using existing provisioning key", "station_id", stationID)
	}

	s.mu.Lock()
	// Identity migration: if email already registered, remove old entry
	if oldPK, ok := s.emailToPK[email]; ok && oldPK != req.PublicKey {
		if oldStation, ok := s.stations[oldPK]; ok {
			delete(s.stations, oldPK)
			if oldStation.StationID != "" {
				delete(s.stationIDToPK, oldStation.StationID)
			}
		}
	}

	nowPtr := now
	s.stations[req.PublicKey] = &models.Station{
		StationID:       stationID,
		Email:           email,
		DisplayName:     req.DisplayName,
		CookieData:      req.CookieData,
		RegisteredAt:    now,
		LastVerified:    &nowPtr,
		ProvisioningKey: provisioningKey,
		NextChallengeAt: s.getNextChallengeTime(),
	}
	s.emailToPK[email] = req.PublicKey
	if stationID != "" {
		s.stationIDToPK[stationID] = req.PublicKey
	}
	s.mu.Unlock()

	slog.Info("station registered successfully",
		"station_id", stationID,
		"email", email,
		"public_key", req.PublicKey,
		"display_name", req.DisplayName,
		"has_provisioning_key", provisioningKey != "")

	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "registered",
		"station_id": stationID,
		"public_key": req.PublicKey,
		"email":      email,
		"verified":   true,
	})
}

func (s *Server) handleSubmitKey(w http.ResponseWriter, r *http.Request) {
	var req models.SubmitKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Look up station data
	s.mu.RLock()
	publicKey := s.stationIDToPK[req.StationID]
	var stationData *models.Station
	if publicKey != "" {
		if st, ok := s.stations[publicKey]; ok {
			// Copy for use outside lock
			copy := *st
			stationData = &copy
		}
	}
	s.mu.RUnlock()

	if publicKey == "" || stationData == nil {
		writeError(w, http.StatusNotFound, "Station not registered")
		return
	}

	// Check if banned FIRST - no need to do anything else if banned
	if s.banned.IsBanned(req.StationID, publicKey) {
		slog.Debug("submit_key rejected: station is banned", "station_id", req.StationID)
		writeError(w, http.StatusForbidden, "Station is banned")
		return
	}

	provisioningKey := stationData.ProvisioningKey
	stationEmail := stationData.Email

	if provisioningKey == "" {
		writeError(w, http.StatusBadRequest, "Station has no provisioning key")
		return
	}

	// Verify inner signature (station): message = "station_id|api_key|key_valid_till"
	innerMessage := fmt.Sprintf("%s|%s|%d", req.StationID, req.APIKey, req.KeyValidTill)
	if !verifyEd25519Signature(publicKey, innerMessage, req.StationSignature) {
		slog.Warn("invalid station signature for key submission", "station_id", req.StationID)
		writeError(w, http.StatusUnauthorized, "Invalid station signature")
		return
	}

	// Verify outer signature (org)
	orgPublicKey, err := s.getOrgPublicKey()
	if err != nil || orgPublicKey == "" {
		writeError(w, http.StatusServiceUnavailable, "Could not fetch org public key")
		return
	}

	outerMessage := fmt.Sprintf("%s|%s|%d|%s", req.StationID, req.APIKey, req.KeyValidTill, req.StationSignature)
	if !verifyEd25519Signature(orgPublicKey, outerMessage, req.OrgSignature) {
		slog.Warn("invalid org signature for key submission", "station_id", req.StationID)
		writeError(w, http.StatusUnauthorized, "Invalid org signature")
		return
	}

	// Check key hasn't already expired
	now := time.Now().Unix()
	if req.KeyValidTill <= now {
		writeError(w, http.StatusBadRequest, "Key already expired")
		return
	}

	// Verify key ownership via OpenRouter API
	keyHash := computeKeyHash(req.APIKey)
	owned, err := openrouter.VerifyKeyOwnership(provisioningKey, keyHash)
	if err != nil || !owned {
		// Key doesn't belong to station - BAN immediately
		reason := "issued_api_key_not_owned_by_registered_or_account"
		bannedAt := utcNow()
		slog.Error("key not owned by station - BANNING (potential shadow account)", "hash", keyHash[:16], "station_id", req.StationID)
		s.banned.Ban(req.StationID, publicKey, stationEmail, reason)

		// Remove from active stations
		s.mu.Lock()
		delete(s.stations, publicKey)
		if stationEmail != "" {
			delete(s.emailToPK, stationEmail)
		}
		delete(s.stationIDToPK, req.StationID)
		s.mu.Unlock()

		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":  "Key not owned by station account. Station banned.",
			"status": "banned",
			"banned_station": map[string]string{
				"station_id": req.StationID,
				"public_key": publicKey,
				"reason":     reason,
				"banned_at":  bannedAt,
			},
		})
		return
	}

	slog.Info("key ownership verified", "station_id", req.StationID, "hash", keyHash[:16])
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "verified",
		"station_id": req.StationID,
		"key_hash":   keyHash[:16],
	})
}

func (s *Server) getOrgPublicKey() (string, error) {
	s.orgPKMu.RLock()
	if s.orgPK != "" && time.Since(s.orgPKFetched) < orgPKTTL {
		pk := s.orgPK
		s.orgPKMu.RUnlock()
		return pk, nil
	}
	cachedPK := s.orgPK
	s.orgPKMu.RUnlock()

	pk, err := openrouter.FetchOrgPublicKey()
	if err != nil {
		// Fallback to cached key if fetch fails
		if cachedPK != "" {
			slog.Warn("org public key fetch failed, using cached", "error", err)
			return cachedPK, nil
		}
		return "", err
	}

	s.orgPKMu.Lock()
	s.orgPK = pk
	s.orgPKFetched = time.Now()
	s.orgPKMu.Unlock()

	return pk, nil
}

func (s *Server) handleGetStation(w http.ResponseWriter, r *http.Request) {
	publicKey := chi.URLParam(r, "public_key")

	s.mu.RLock()
	station, ok := s.stations[publicKey]
	s.mu.RUnlock()

	if !ok {
		writeError(w, http.StatusNotFound, "Station not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"station_id":   station.StationID,
		"public_key":   publicKey,
		"display_name": station.DisplayName,
	})
}

func (s *Server) handleBroadcast(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	verified := make([]map[string]any, 0) // Initialize as empty slice, not nil
	for pk, data := range s.stations {
		if data.LastVerified != nil {
			verified = append(verified, map[string]any{
				"station_id":   data.StationID,
				"public_key":   pk,
				"display_name": data.DisplayName,
			})
		}
	}
	s.mu.RUnlock()

	banned := s.banned.GetAll()

	writeJSON(w, http.StatusOK, map[string]any{
		"verified_stations": verified,
		"banned_stations":   banned,
	})
}

func (s *Server) handleBannedStations(w http.ResponseWriter, r *http.Request) {
	banned := s.banned.GetAll()
	writeJSON(w, http.StatusOK, map[string]any{
		"banned_stations": banned,
		"count":           len(banned),
	})
}

func (s *Server) handleReloadConfig(w http.ResponseWriter, r *http.Request) {
	registrySecret := config.RegistrySecret()
	if registrySecret == "" {
		writeError(w, http.StatusServiceUnavailable, "Registry secret not configured")
		return
	}

	auth := r.Header.Get("Authorization")
	expected := "Bearer " + registrySecret
	if auth != expected {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	config.Reload()
	slog.Info("configuration reloaded from .env")

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "reloaded",
		"challenge_interval": map[string]int{
			"min_seconds": config.ChallengeMinInterval(),
			"max_seconds": config.ChallengeMaxInterval(),
		},
	})
}


