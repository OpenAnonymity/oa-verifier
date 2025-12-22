// Package banned provides persistent banned station management.
package banned

import (
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/oa-verifier/internal/config"
	"github.com/oa-verifier/internal/models"
	"github.com/oa-verifier/internal/openrouter"
)

// Manager handles banned station storage.
type Manager struct {
	mu       sync.RWMutex
	filepath string
	stations []models.BannedStation
}

// NewManager creates a new BannedStationManager.
func NewManager() *Manager {
	m := &Manager{
		filepath: config.BannedStationsFile(),
		stations: make([]models.BannedStation, 0),
	}
	m.loadSync()
	return m
}

func (m *Manager) loadSync() {
	data, err := os.ReadFile(m.filepath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Error("failed to load banned stations", "error", err)
		}
		return
	}

	var stations []models.BannedStation
	if err := json.Unmarshal(data, &stations); err != nil {
		slog.Error("failed to parse banned stations", "error", err)
		return
	}

	m.stations = stations
	slog.Info("loaded banned stations", "count", len(m.stations), "file", m.filepath)
}

func (m *Manager) save() {
	data, err := json.MarshalIndent(m.stations, "", "  ")
	if err != nil {
		slog.Error("failed to marshal banned stations", "error", err)
		return
	}

	if err := os.WriteFile(m.filepath, data, 0644); err != nil {
		slog.Error("failed to save banned stations", "error", err)
	}
}

// Ban adds a station to the banned list and notifies org.
func (m *Manager) Ban(stationID, publicKey, email, reason string) {
	m.mu.Lock()

	// Check if already banned
	for _, s := range m.stations {
		if s.StationID == stationID && s.PublicKey == publicKey {
			m.mu.Unlock()
			return
		}
	}

	banned := models.BannedStation{
		StationID: stationID,
		PublicKey: publicKey,
		Email:     email,
		Reason:    reason,
		BannedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	m.stations = append(m.stations, banned)
	m.save()
	m.mu.Unlock()

	slog.Warn("banned station", "station_id", stationID, "reason", reason)

	// Notify org (outside lock, in goroutine for non-blocking)
	go func() {
		_ = openrouter.NotifyOrgBanned(stationID, reason)
	}()
}

// GetAll returns all banned stations (no email exposed).
func (m *Manager) GetAll() []map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]map[string]string, 0, len(m.stations)) // Always return [], never null
	for _, s := range m.stations {
		result = append(result, s.ToPublicDict())
	}
	return result
}

// IsBanned checks if a station is banned by station_id or public_key.
func (m *Manager) IsBanned(stationID, publicKey string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, s := range m.stations {
		if stationID != "" && s.StationID == stationID {
			return true
		}
		if publicKey != "" && s.PublicKey == publicKey {
			return true
		}
	}
	return false
}

// GetStationIDByPK gets station_id for a banned public key.
func (m *Manager) GetStationIDByPK(publicKey string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, s := range m.stations {
		if s.PublicKey == publicKey {
			return s.StationID
		}
	}
	return ""
}




