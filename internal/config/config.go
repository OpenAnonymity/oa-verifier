// Package config provides hot-reloadable configuration.
package config

import (
	"os"
	"strconv"
	"sync"

	"github.com/joho/godotenv"
)

// ---------------------------------------------------------------------------
// OpenRouter station config
//
// These constants and toggles are specific to OpenRouter-type stations. The
// verifier is generic; future station types (other providers, enclave proxies,
// etc.) would add their own section here.
// ---------------------------------------------------------------------------

// OpenRouter base URLs (hardcoded; proved correct via attestation).
const (
	BaseURL          = "https://openrouter.ai"
	OpenRouterAPIURL = "https://openrouter.ai/api/v1"
)

// OpenRouterRequiredToggles defines account-state fields on an OpenRouter
// station operator's account that must remain false for the station to stay
// verifier-eligible.
//
// These values are read from the station operator's OpenRouter account metadata
// (via authenticated session cookies), not from station self-reported claims.
// This is an anti-forgery compliance check on provider-exposed policy state; it
// does not, by itself, attest provider-internal storage/logging implementation.
//
// Toggle definitions (all must be false):
//
//   - enable_training: Whether to allow routing to providers that may train on
//     data (paid models). When false, OpenRouter will not route to providers
//     that train on prompts.
//     Ref: https://openrouter.ai/docs/guides/privacy/logging
//
//   - enable_free_model_training: Same as enable_training but for free-tier
//     models. OpenRouter has separate settings for paid and free models.
//     Ref: https://openrouter.ai/docs/guides/privacy/logging
//
//   - enable_free_model_publication: Controls whether free model interaction
//     data can be published/shared. Must be false to prevent publication of
//     user interaction data.
//
//   - enforce_zdr: Zero Data Retention routing filter. When true, OpenRouter
//     blocks routing to endpoints without a ZDR policy. ZDR is a property of
//     the endpoint/provider -- if an endpoint supports ZDR, data is not
//     retained regardless of this toggle. Whether data is retained at the
//     provider level depends on which model the user chooses and whether that
//     model's endpoint has a ZDR policy. This is a routing preference, not a
//     privacy-critical toggle; the logging/training toggles above are what
//     protect user data at the OpenRouter layer.
//     Ref: https://openrouter.ai/docs/guides/features/zdr
//
//   - always_enforce_allowed: Allowed-model enforcement toggle. Must be false
//     to prevent the account from restricting to a model allowlist that could
//     interfere with station operation.
//
//   - is_broadcast_enabled: OpenRouter Broadcast feature. When true, all API
//     request traces (prompts, completions, token counts, timing) are sent to
//     configured external observability platforms (Langfuse, Datadog, etc.).
//     Must be false so the station operator is not broadcasting user request
//     traces to third parties.
//     Ref: https://openrouter.ai/docs/guides/features/broadcast/overview
//
//   - is_private_logging_enabled: OpenRouter IO Logging feature. When true,
//     input/output data for API requests is logged to the account's
//     observability dashboard. Must be false so the station operator is not
//     storing user prompts and completions.
//     Ref: https://openrouter.ai/docs/guides/privacy/data-collection
//
//   - is_data_discount_logging_enabled: OpenRouter data discount opt-in.
//     When true, OpenRouter may use prompt/completion data for product
//     improvement in exchange for a 1% usage discount. Must be false so
//     user data is not used for training or product enhancement. This
//     replaced the former enable_logging field. Note: this is a workspace-
//     level setting fetched from workspace data, not from getCurrentUserSA.
//     Ref: https://openrouter.ai/docs/guides/privacy/data-collection

// UserRequiredToggles are checked against getCurrentUserSA response.
var UserRequiredToggles = map[string]bool{
	"enable_training":               false,
	"enable_free_model_training":    false,
	"enable_free_model_publication": false,
	"enforce_zdr":                   false,
	"always_enforce_allowed":        false,
	"is_broadcast_enabled":          false,
	"is_private_logging_enabled":    false,
}

// WorkspaceRequiredToggles are checked against workspace settings data.
var WorkspaceRequiredToggles = map[string]bool{
	"is_data_discount_logging_enabled": false,
}

// OpenRouterRequiredToggles is the combined set of all required toggles.
// Used by CheckPrivacyToggles which searches any data map for matching keys.
var OpenRouterRequiredToggles = func() map[string]bool {
	merged := make(map[string]bool)
	for k, v := range UserRequiredToggles {
		merged[k] = v
	}
	for k, v := range WorkspaceRequiredToggles {
		merged[k] = v
	}
	return merged
}()

// ---------------------------------------------------------------------------
// Generic verifier config
// ---------------------------------------------------------------------------

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

// SubmitKeyOwnershipGraceSeconds returns SUBMIT_KEY_OWNERSHIP_GRACE_SECONDS.
// When a submitted key is near expiry, ownership checks are skipped to avoid false bans.
func SubmitKeyOwnershipGraceSeconds() int {
	mu.RLock()
	defer mu.RUnlock()
	s := os.Getenv("SUBMIT_KEY_OWNERSHIP_GRACE_SECONDS")
	if s == "" {
		return 300
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return 300
	}
	return v
}

// StationFailureGraceSeconds returns STATION_FAILURE_GRACE_SECONDS.
// Grace window before unregistering on transient failures (default 600).
func StationFailureGraceSeconds() int {
	mu.RLock()
	defer mu.RUnlock()
	s := os.Getenv("STATION_FAILURE_GRACE_SECONDS")
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

// MaxConcurrentRequests returns MAX_CONCURRENT_REQUESTS (default 20).
// Controls max concurrent HTTP request handlers for CPU-heavy endpoints.
func MaxConcurrentRequests() int {
	mu.RLock()
	defer mu.RUnlock()
	s := os.Getenv("MAX_CONCURRENT_REQUESTS")
	if s == "" {
		return 20
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 1 {
		return 20
	}
	return v
}

// RateLimitRPS returns RATE_LIMIT_RPS (default 10).
// Controls requests per second per IP.
func RateLimitRPS() int {
	mu.RLock()
	defer mu.RUnlock()
	s := os.Getenv("RATE_LIMIT_RPS")
	if s == "" {
		return 10
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 1 {
		return 10
	}
	return v
}

// RateLimitBurst returns RATE_LIMIT_BURST (default 20).
// Controls burst size per IP for rate limiting.
func RateLimitBurst() int {
	mu.RLock()
	defer mu.RUnlock()
	s := os.Getenv("RATE_LIMIT_BURST")
	if s == "" {
		return 20
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 1 {
		return 20
	}
	return v
}
