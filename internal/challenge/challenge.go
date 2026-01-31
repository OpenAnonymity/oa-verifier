// Package challenge provides privacy toggle verification helpers.
package challenge

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/oa-verifier/internal/config"
)

// CheckPrivacyToggles checks if all privacy toggles are correctly set.
// Returns (ok, invalidToggles).
func CheckPrivacyToggles(data map[string]any) (bool, []string) {
	var invalid []string
	for key, requiredVal := range config.RequiredToggles {
		actualVal, exists := data[key]
		if !exists || actualVal != requiredVal {
			invalid = append(invalid, fmt.Sprintf("%s=%v(expected=%v)", key, actualVal, requiredVal))
		}
	}
	return len(invalid) == 0, invalid
}

// GetRandomInterval returns a cryptographically secure random interval between challenges.
func GetRandomInterval() float64 {
	minInterval := config.ChallengeMinInterval()
	maxInterval := config.ChallengeMaxInterval()
	rangeSize := maxInterval - minInterval
	if rangeSize <= 0 {
		return float64(minInterval)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(rangeSize+1)))
	if err != nil {
		return float64(minInterval)
	}
	return float64(minInterval) + float64(n.Int64())
}

// ShouldBan checks if a failure reason should result in banning.
func ShouldBan(reason string) bool {
	banPrefixes := []string{
		"privacy_toggles_invalid",
		"issued_api_key_not_owned",
	}
	for _, prefix := range banPrefixes {
		if strings.HasPrefix(reason, prefix) {
			return true
		}
	}
	return false
}
