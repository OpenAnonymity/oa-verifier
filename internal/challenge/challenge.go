// Package challenge provides privacy toggle verification helpers.
//
// Docstream:
//
// Purpose:
//   - `CheckPrivacyToggles` is the toggle-evaluation core used by handler/loop
//     enforcement.
//
// Result model:
//   - It classifies provider-exposed account-state into deterministic outcomes:
//     ok, invalid, missing, unparseable.
//   - `ToggleInvalid` indicates policy violation and can drive ban/not-verified
//     decisions in caller policy.
//
// Input boundary:
//   - Checks run on provider-exposed account metadata fetched by verifier, not
//     station self-reported claims.
//   - This package validates exposed account metadata; it does not attest
//     provider-internal systems beyond those exposed fields.
package challenge

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/openanonymity/oa-verifier/internal/config"
)

// ToggleCheckResult describes the outcome of the privacy toggle check.
type ToggleCheckResult int

const (
	ToggleOK ToggleCheckResult = iota
	ToggleInvalid
	ToggleMissing
	ToggleUnparseable
)

func (r ToggleCheckResult) String() string {
	switch r {
	case ToggleOK:
		return "ok"
	case ToggleInvalid:
		return "invalid"
	case ToggleMissing:
		return "missing"
	case ToggleUnparseable:
		return "unparseable"
	default:
		return "unknown"
	}
}

type candidate struct {
	key  string
	path string
	val  any
}

// CheckPrivacyToggles checks whether required privacy toggles are correctly set
// in provider-exposed account-state data.
// Returns (result, details).
func CheckPrivacyToggles(data map[string]any) (ToggleCheckResult, []string) {
	if data == nil {
		return ToggleMissing, []string{"<all_required_toggles_missing>"}
	}

	var candidates []candidate
	collectCandidates(data, "", &candidates)

	required := make(map[string]bool)
	for k, v := range config.OpenRouterRequiredToggles {
		required[strings.ToLower(k)] = v
	}

	found := make(map[string][]candidate)
	for _, c := range candidates {
		keyLower := strings.ToLower(c.key)
		pathLower := strings.ToLower(c.path)
		for reqKey := range required {
			if keyLower == reqKey || pathLower == reqKey || strings.HasSuffix(pathLower, "."+reqKey) {
				found[reqKey] = append(found[reqKey], c)
			}
		}
	}

	var invalid []string
	var missing []string
	var unparseable []string

	for reqKey, requiredVal := range required {
		cands := found[reqKey]
		if len(cands) == 0 {
			missing = append(missing, reqKey)
			continue
		}

		hasParsed := false
		hasMatch := false
		hasMismatch := false
		for _, c := range cands {
			parsed, ok := normalizeBool(c.val)
			if !ok {
				continue
			}
			hasParsed = true
			if parsed != requiredVal {
				hasMismatch = true
				invalid = append(invalid, fmt.Sprintf("%s=%v(expected=%v)", c.path, c.val, requiredVal))
			} else {
				hasMatch = true
			}
		}

		if hasMismatch {
			continue
		}
		if hasParsed && hasMatch {
			continue
		}
		unparseable = append(unparseable, reqKey)
	}

	if len(invalid) > 0 {
		return ToggleInvalid, invalid
	}
	if len(unparseable) > 0 {
		return ToggleUnparseable, unparseable
	}
	if len(missing) > 0 {
		return ToggleMissing, missing
	}
	return ToggleOK, nil
}

func collectCandidates(v any, path string, out *[]candidate) {
	switch t := v.(type) {
	case map[string]any:
		for k, v2 := range t {
			nextPath := k
			if path != "" {
				nextPath = path + "." + k
			}
			*out = append(*out, candidate{key: k, path: nextPath, val: v2})
			collectCandidates(v2, nextPath, out)
		}
	case []any:
		for i, v2 := range t {
			idx := fmt.Sprintf("%d", i)
			nextPath := idx
			if path != "" {
				nextPath = path + "." + idx
			}
			collectCandidates(v2, nextPath, out)
		}
	}
}

func normalizeBool(v any) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		s := strings.ToLower(strings.TrimSpace(t))
		if s == "true" {
			return true, true
		}
		if s == "false" {
			return false, true
		}
	case float64:
		if t == 0 {
			return false, true
		}
		if t == 1 {
			return true, true
		}
	case int:
		if t == 0 {
			return false, true
		}
		if t == 1 {
			return true, true
		}
	case int64:
		if t == 0 {
			return false, true
		}
		if t == 1 {
			return true, true
		}
	case uint:
		if t == 0 {
			return false, true
		}
		if t == 1 {
			return true, true
		}
	case json.Number:
		if i, err := t.Int64(); err == nil {
			if i == 0 {
				return false, true
			}
			if i == 1 {
				return true, true
			}
		} else if f, err := t.Float64(); err == nil {
			if f == 0 {
				return false, true
			}
			if f == 1 {
				return true, true
			}
		}
	}
	return false, false
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
