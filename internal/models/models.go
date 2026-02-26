// Package models contains verifier data structures.
//
// Docstream:
//
// Actor boundary:
//   - `Station` represents station-operator governance state.
//   - `Email` and `CookieData` belong to station operator accounts and are used for
//     registration binding + periodic compliance checks.
//   - These fields are verifier evidence for station governance, not end-user
//     prompt/chat identity data.
package models

import "time"

// BannedStation represents a banned station.
type BannedStation struct {
	StationID string `json:"station_id"`
	PublicKey string `json:"public_key"`
	Email     string `json:"email"`
	Reason    string `json:"reason"`
	BannedAt  string `json:"banned_at"`
}

// ToPublicDict returns a copy without email (for API responses).
func (b *BannedStation) ToPublicDict() map[string]string {
	return map[string]string{
		"station_id": b.StationID,
		"public_key": b.PublicKey,
		"reason":     b.Reason,
		"banned_at":  b.BannedAt,
	}
}

// RegisterRequest is the payload for POST /register.
type RegisterRequest struct {
	CookieData  map[string]any `json:"cookie_data"`
	PublicKey   string         `json:"public_key"`
	DisplayName string         `json:"display_name"`
}

// SubmitKeyRequest is the payload for POST /submit_key.
type SubmitKeyRequest struct {
	StationID        string `json:"station_id"`
	APIKey           string `json:"api_key"`
	KeyValidTill     int64  `json:"key_valid_till"`
	StationSignature string `json:"station_signature"`
	OrgSignature     string `json:"org_signature"`
}

// Station represents a registered station operator's governance state.
//
// All fields (CookieData, Email, etc.) are station-operator credentials used
// for compliance checks against the provider's account-state APIs:
// 1. Independent provider-state checks (re-auth and activity fetch)
// 2. Three-way binding integrity (station_id <-> email <-> public_key)
// 3. Provisioning key lifecycle management
//
// These are not end-user data and have no bearing on user privacy or
// unlinkability. The verifier never receives, stores, or processes any
// end-user identity material.
type Station struct {
	StationID       string
	Email           string
	DisplayName     string
	CookieData      map[string]any
	RegisteredAt    string
	LastVerified    *string // nil if not verified
	ProvisioningKey string
	NextChallengeAt time.Time
	FailureFirstAt  *time.Time
	FailureLastAt   *time.Time
	FailureReason   string
	FailureDetail   string
	FailureStatus   int
	FailureCount    int
}

// Cookie represents a browser cookie.
type Cookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain,omitempty"`
}
