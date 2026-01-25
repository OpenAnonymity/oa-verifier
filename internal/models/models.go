// Package models contains data structures for the verifier.
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

// Station represents a registered station in memory.
type Station struct {
	StationID       string
	Email           string
	DisplayName     string
	CookieData      map[string]any
	RegisteredAt    string
	LastVerified    *string // nil if not verified
	ProvisioningKey string
	NextChallengeAt time.Time
}

// Cookie represents a browser cookie.
type Cookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain,omitempty"`
}
