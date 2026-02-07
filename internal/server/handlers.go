package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/oa-verifier/internal/challenge"
	"github.com/oa-verifier/internal/config"
	"github.com/oa-verifier/internal/models"
	"github.com/oa-verifier/internal/openrouter"
	"github.com/oa-verifier/internal/registry"
)

// ACI Confidential Containers attestation endpoint (SKR sidecar)
const (
	defaultMAAEndpoint    = "http://localhost:8080/attest/maa"
	defaultMAAProviderURL = "sharedeus.eus.attest.azure.net"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]string{"detail": detail})
}

func writeUnregisteredError(w http.ResponseWriter) {
	writeError(w, http.StatusConflict, "Station credentials fetch failed; treat station as unregistered.")
}

func (s *Server) banStationForKeyNotOwned(w http.ResponseWriter, stationID, publicKey, stationEmail, keyHashFull string) {
	reason := "issued_api_key_not_owned_by_registered_or_account"
	bannedAt := utcNow()
	slog.Error("key not owned by station - BANNING (potential shadow account)", "hash", keyHashFull[:16], "station_id", stationID)
	s.banned.Ban(stationID, publicKey, stationEmail, reason)

	// Remove from active stations
	s.mu.Lock()
	delete(s.stations, publicKey)
	if stationEmail != "" {
		delete(s.emailToPK, stationEmail)
	}
	delete(s.stationIDToPK, stationID)
	s.mu.Unlock()

	writeJSON(w, http.StatusForbidden, map[string]any{
		"error":  "Key not owned by station account. Station banned.",
		"status": "banned",
		"banned_station": map[string]string{
			"station_id": stationID,
			"public_key": publicKey,
			"reason":     reason,
			"banned_at":  bannedAt,
		},
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	stationCount := len(s.stations)
	s.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "healthy",
		"stations": stationCount,
	})
}

// maxRequestBodySize limits incoming request body to 1MB to prevent memory exhaustion
const maxRequestBodySize = 1 << 20 // 1MB

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
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

	// Early return if already registered with same public key
	s.mu.RLock()
	if existing, ok := s.stations[req.PublicKey]; ok {
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"status":     "already_registered",
			"station_id": existing.StationID,
			"public_key": req.PublicKey,
		})
		return
	}
	s.mu.RUnlock()

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
	toggleResult, toggleDetails := challenge.CheckPrivacyToggles(data)
	switch toggleResult {
	case challenge.ToggleInvalid:
		reason := fmt.Sprintf("privacy_toggles_invalid_on_register:[%s]", strings.Join(toggleDetails, ","))
		slog.Error("registration rejected: FAILED privacy toggle check - BANNING", "station_id", stationID, "toggles", toggleDetails)
		effectiveStationID := stationID
		if effectiveStationID == "" {
			effectiveStationID = "unknown"
		}
		s.banned.Ban(effectiveStationID, req.PublicKey, email, reason)
		writeError(w, http.StatusForbidden, "Privacy toggles not properly configured. Station banned.")
		return
	case challenge.ToggleMissing, challenge.ToggleUnparseable:
		slog.Warn("registration rejected: unable to verify privacy toggles", "station_id", stationID, "result", toggleResult, "details", toggleDetails)
		writeError(w, http.StatusServiceUnavailable, "Unable to verify privacy toggles; try again.")
		return
	case challenge.ToggleOK:
		// continue
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
		cleanedUp, cleanupErr := openrouter.CleanupProvisioningKeys(auth, label)
		if cleanupErr != nil {
			slog.Warn("failed cleanup of existing provisioning keys", "station_id", stationID, "label", label, "error", cleanupErr)
		}
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
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
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

	secondsLeft := req.KeyValidTill - now
	graceSeconds := int64(config.SubmitKeyOwnershipGraceSeconds())
	nearExpiry := secondsLeft <= graceSeconds

	// Verify key ownership via OpenRouter API
	keyHashFull := computeKeyHash(req.APIKey)
	retryBase := 250 * time.Millisecond
	maxJitter := 200 * time.Millisecond
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	refreshed := false

	sleepBackoff := func(attempt int) {
		backoff := retryBase * time.Duration(1<<uint(attempt-1))
		jitter := time.Duration(rng.Int63n(int64(maxJitter)))
		time.Sleep(backoff + jitter)
	}

	for attempt := 1; attempt <= 3; attempt++ {
		result, err := openrouter.VerifyKeyOwnership(provisioningKey, keyHashFull)
		if result.StatusCode == 0 || (result.StatusCode == 200 && err != nil) {
			if attempt < 3 {
				sleepBackoff(attempt)
				continue
			}
			break
		}

		switch result.StatusCode {
		case http.StatusOK:
			if result.Owned {
				slog.Info("key ownership verified", "station_id", req.StationID, "hash", keyHashFull[:16])
				writeJSON(w, http.StatusOK, map[string]any{
					"status":     "verified",
					"station_id": req.StationID,
					"key_hash":   keyHashFull[:16],
				})
				return
			}
			if result.NotOwned {
				if nearExpiry {
					writeJSON(w, http.StatusOK, map[string]any{
						"status":     "unverified",
						"station_id": req.StationID,
						"key_hash":   keyHashFull[:16],
						"detail":     "key_near_expiry_not_owned",
						"retryable":  false,
					})
					return
				}
				s.banStationForKeyNotOwned(w, req.StationID, publicKey, stationEmail, keyHashFull)
				return
			}
		case http.StatusNotFound:
			if nearExpiry {
				writeJSON(w, http.StatusOK, map[string]any{
					"status":     "unverified",
					"station_id": req.StationID,
					"key_hash":   keyHashFull[:16],
					"detail":     "key_near_expiry_not_owned",
					"retryable":  false,
				})
				return
			}
			s.banStationForKeyNotOwned(w, req.StationID, publicKey, stationEmail, keyHashFull)
			return
		case http.StatusUnauthorized:
			if !refreshed {
				newKey, refreshErr := s.refreshProvisioningKey(req.StationID, publicKey, stationData.CookieData)
				if refreshErr != nil {
					withinGrace := s.markTransientFailure(publicKey, "provisioning_key_refresh_failed", result.StatusCode, refreshErr.Error())
					if withinGrace {
						writeJSON(w, http.StatusServiceUnavailable, map[string]any{
							"status":     "unverified",
							"station_id": req.StationID,
							"key_hash":   keyHashFull[:16],
							"detail":     "auth_refresh_failed",
							"retryable":  true,
						})
						return
					}
					s.unregisterStation(req.StationID, publicKey, stationEmail, "provisioning_key_refresh_failed", result.StatusCode, refreshErr.Error())
					writeUnregisteredError(w)
					return
				}
				s.clearTransientFailure(publicKey)
				provisioningKey = newKey
				refreshed = true
				continue
			}
			if attempt < 3 {
				sleepBackoff(attempt)
				continue
			}
			writeError(w, http.StatusUnauthorized, "Unauthorized Error (OpenRouter)")
			return
		case http.StatusForbidden:
			if attempt < 3 {
				sleepBackoff(attempt)
				continue
			}
			writeError(w, http.StatusForbidden, "Forbidden Error (OpenRouter)")
			return
		case http.StatusTooManyRequests:
			writeError(w, http.StatusTooManyRequests, "Too Many Requests Error (OpenRouter)")
			return
		default:
			if attempt < 3 {
				sleepBackoff(attempt)
				continue
			}
		}
	}

	writeJSON(w, http.StatusServiceUnavailable, map[string]any{
		"status":     "unverified",
		"station_id": req.StationID,
		"key_hash":   keyHashFull[:16],
		"detail":     "ownership_check_error",
		"retryable":  true,
	})
	return
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

func (s *Server) handleUnbanStation(w http.ResponseWriter, r *http.Request) {
	// Require admin auth
	if !s.checkAdminAuth(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	stationID := chi.URLParam(r, "station_id")
	if stationID == "" {
		writeError(w, http.StatusBadRequest, "station_id required")
		return
	}

	if s.banned.Unban(stationID) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":     "unbanned",
			"station_id": stationID,
		})
	} else {
		writeError(w, http.StatusNotFound, "Station not found in banned list")
	}
}

func (s *Server) handleClearBanned(w http.ResponseWriter, r *http.Request) {
	// Require admin auth
	if !s.checkAdminAuth(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	count := s.banned.Clear()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "cleared",
		"removed": count,
	})
}

func (s *Server) checkAdminAuth(r *http.Request) bool {
	registrySecret := config.RegistrySecret()
	if registrySecret == "" {
		return false
	}
	auth := r.Header.Get("Authorization")
	return auth == "Bearer "+registrySecret
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

// decodeJWTPayload decodes JWT payload without verification (for display only).
func decodeJWTPayload(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	payload := parts[1]
	// Add padding if needed
	if pad := len(payload) % 4; pad != 0 {
		payload += strings.Repeat("=", 4-pad)
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil
	}
	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil
	}
	return claims
}

// maaAttestRequest is the request payload for the SKR sidecar /attest/maa endpoint.
type maaAttestRequest struct {
	MAAEndpoint string `json:"maa_endpoint"`
	RuntimeData string `json:"runtime_data"` // base64-encoded nonce data
}

// getAttestationToken calls the ACI MAA sidecar to get an attestation token.
// tlsHash is the SHA256 hash of the TLS public key for channel binding.
func getAttestationToken(nonce, tlsHash string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get MAA endpoint from env or use default
	maaEndpoint := os.Getenv("MAA_ENDPOINT")
	if maaEndpoint == "" {
		maaEndpoint = defaultMAAEndpoint
	}

	maaProvider := os.Getenv("MAA_PROVIDER_URL")
	if maaProvider == "" {
		maaProvider = defaultMAAProviderURL
	}

	// Ensure nonce is not empty - required by the sidecar
	if nonce == "" {
		nonce = "default-nonce"
	}

	// runtime_data must be valid JSON for MAA
	// Include both nonce (freshness) and tls_hash (channel binding)
	runtimeJSON := map[string]string{"nonce": nonce}
	if tlsHash != "" {
		runtimeJSON["tls_hash"] = tlsHash
	}
	runtimeBytes, _ := json.Marshal(runtimeJSON)
	runtimeData := base64.StdEncoding.EncodeToString(runtimeBytes)

	reqBody := maaAttestRequest{
		MAAEndpoint: maaProvider,
		RuntimeData: runtimeData,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", maaEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Use configured HTTP client with timeout
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call MAA sidecar: %w", err)
	}
	defer resp.Body.Close()

	// Read body once for both error handling and parsing
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("MAA sidecar returned %d: %s", resp.StatusCode, string(body))
	}

	// Try parsing as JSON first
	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		// Try reading as plain text token
		token := strings.TrimSpace(string(body))
		if token != "" && strings.Contains(token, ".") {
			return token, nil
		}
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if result.Token == "" {
		return "", fmt.Errorf("empty token in response")
	}

	return result.Token, nil
}

func (s *Server) handleAttestation(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("nonce")

	// Pass TLS public key hash for channel binding
	token, err := getAttestationToken(nonce, s.tlsPubKeyHash)
	if err != nil {
		slog.Error("attestation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "Attestation failed: "+err.Error())
		return
	}

	claims := decodeJWTPayload(token)
	if claims == nil {
		writeError(w, http.StatusInternalServerError, "Failed to decode attestation token")
		return
	}

	// Build summary for SEV-SNP (ACI Confidential Containers)
	summary := map[string]any{
		"issuer": claims["iss"],
	}

	// SEV-SNP specific claims
	if attestationType, ok := claims["x-ms-attestation-type"].(string); ok {
		summary["attestation_type"] = attestationType
	}
	if complianceStatus, ok := claims["x-ms-compliance-status"].(string); ok {
		summary["compliance_status"] = complianceStatus
	}

	// HOST_DATA contains the CCE policy hash - this is the critical field
	// It proves which container image is running
	if hostData, ok := claims["x-ms-sevsnpvm-hostdata"].(string); ok {
		summary["host_data"] = hostData
		summary["cce_policy_hash"] = hostData // alias for clarity
	}

	// Runtime data contains the nonce we provided
	if runtimeData, ok := claims["x-ms-runtime"].(map[string]any); ok {
		if clientPayload, ok := runtimeData["client-payload"].(map[string]any); ok {
			summary["runtime_data"] = clientPayload
		}
	}

	// Debug/security status
	if isDebuggable, ok := claims["x-ms-sevsnpvm-is-debuggable"].(bool); ok {
		summary["debug_disabled"] = !isDebuggable
	}

	// VM ID if available
	if vmID, ok := claims["x-ms-sevsnpvm-vmpl"].(float64); ok {
		summary["vmpl"] = int(vmID)
	}

	issuer, _ := claims["iss"].(string)

	// Include TLS hash in summary for channel binding verification
	if s.tlsPubKeyHash != "" {
		summary["tls_pubkey_hash"] = s.tlsPubKeyHash
	}

	// Get CCE policy from environment (set at deployment time)
	// This allows users to verify: sha256(policy) == summary.cce_policy_hash
	policyB64 := os.Getenv("CCE_POLICY_B64")
	var policyDecoded string
	if policyB64 != "" {
		if decoded, err := base64.StdEncoding.DecodeString(policyB64); err == nil {
			policyDecoded = string(decoded)
		}
	}

	// Build policy response - enables zero-trust verification without registry access
	policyResponse := map[string]any{
		"available": policyB64 != "",
	}
	if policyB64 != "" {
		policyResponse["base64"] = policyB64
		policyResponse["decoded"] = policyDecoded
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":     token,
		"timestamp": utcNow(),
		"nonce":     nonce,
		"summary":   summary,
		"policy":    policyResponse,
		"verify_at": issuer + "/certs",
		"verification": map[string]any{
			"how_to_verify": []string{
				"1. Verify JWT signature using keys from verify_at URL (must be *.attest.azure.net)",
				"2. Compute sha256(policy.decoded) - must equal summary.cce_policy_hash",
				"3. Policy is now VERIFIED by hardware - audit it to see what's running",
				"4. (Optional) Check tls_pubkey_hash matches server's TLS cert for channel binding",
			},
			"what_policy_proves":      "The exact CCE policy enforced by Azure hardware - contains layers, command, env vars, capabilities",
			"what_host_data_proves":   "SHA256 hash of CCE policy - proves which container is allowed to run",
			"what_tls_hash_proves":    "SHA256 hash of TLS public key - proves you're talking directly to the enclave",
			"zero_trust_verification": "sha256(policy.decoded) == summary.cce_policy_hash proves policy authenticity",
		},
	})
}

func (s *Server) handleAttestationRaw(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("nonce")

	// Pass TLS public key hash for channel binding
	token, err := getAttestationToken(nonce, s.tlsPubKeyHash)
	if err != nil {
		slog.Error("attestation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "Attestation failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}
