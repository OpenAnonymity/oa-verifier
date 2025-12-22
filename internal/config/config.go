// Package config provides hot-reloadable configuration.
package config

import (
	"os"
	"strconv"
	"sync"

	"github.com/joho/godotenv"
)

// Hardcoded constants (proved with attestation)
const (
	BaseURL          = "https://openrouter.ai"
	OpenRouterAPIURL = "https://openrouter.ai/api/v1"
)

// RequiredToggles - privacy toggles that MUST be false (security-critical)
var RequiredToggles = map[string]bool{
	"enable_logging":              false,
	"enable_training":             false,
	"enable_free_model_training":  false,
	"enable_free_model_publication": false,
	"enforce_zdr":                 false,
	"always_enforce_allowed":      false,
	"is_broadcast_enabled":        false,
}

var (
	once sync.Once
	mu   sync.RWMutex
)

func init() {
	once.Do(func() {
		_ = godotenv.Load()
	})
}

// Reload forces reload of .env file.
func Reload() {
	mu.Lock()
	defer mu.Unlock()
	_ = godotenv.Overload()
}

// RegistryURL returns STATION_REGISTRY_URL.
func RegistryURL() string {
	mu.RLock()
	defer mu.RUnlock()
	return os.Getenv("STATION_REGISTRY_URL")
}

// RegistrySecret returns STATION_REGISTRY_SECRET.
func RegistrySecret() string {
	mu.RLock()
	defer mu.RUnlock()
	return os.Getenv("STATION_REGISTRY_SECRET")
}

// ProvisioningKeySalt returns PROVISIONING_KEY_SALT as bytes.
func ProvisioningKeySalt() []byte {
	mu.RLock()
	defer mu.RUnlock()
	salt := os.Getenv("PROVISIONING_KEY_SALT")
	if salt == "" {
		return []byte("default_dev_salt")
	}
	return []byte(salt)
}

// ChallengeMinInterval returns CHALLENGE_MIN_INTERVAL (default 300).
func ChallengeMinInterval() int {
	mu.RLock()
	defer mu.RUnlock()
	s := os.Getenv("CHALLENGE_MIN_INTERVAL")
	if s == "" {
		return 300
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return 300
	}
	return v
}

// ChallengeMaxInterval returns CHALLENGE_MAX_INTERVAL (default 600).
func ChallengeMaxInterval() int {
	mu.RLock()
	defer mu.RUnlock()
	s := os.Getenv("CHALLENGE_MAX_INTERVAL")
	if s == "" {
		return 600
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return 600
	}
	return v
}

// BannedStationsFile returns BANNED_STATIONS_FILE (default "banned_stations.json").
func BannedStationsFile() string {
	mu.RLock()
	defer mu.RUnlock()
	f := os.Getenv("BANNED_STATIONS_FILE")
	if f == "" {
		return "banned_stations.json"
	}
	return f
}




