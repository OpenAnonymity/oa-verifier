// Package stationstore persists the verifier's station registry across
// restarts.
//
// Docstream:
//
// Why this exists:
//   - The registry (internal/server: stations, emailToPK, stationIDToPK) lives
//     in process memory. Every container start therefore began with zero
//     stations, and each station had to register again.
//   - Re-registration makes the verifier ask OpenRouter to issue a fresh
//     management key on the operator's account. OpenRouter now gates that
//     call behind a recent multi-factor login ("strict_mfa", within ten
//     minutes), so an unattended restart could not complete it and the
//     station stayed unregistered until a person logged in.
//   - Everything the verifier does with a key it already holds (ownership
//     checks via /api/v1/keys, privacy-toggle reads with the operator's
//     session) is unaffected by that gate. Keeping the registry across
//     restarts removes the only step that needed a person.
//
// What is stored:
//   - A Snapshot of every registered station: public key, station id, email,
//     display name, the OpenRouter session cookies the operator supplied, the
//     OpenRouter-issued management key, verification timestamps and failure
//     state — i.e. models.Station as the server holds it.
//   - Station-operator governance data only. End-user prompts, identities and
//     API keys never enter the registry and so never enter the snapshot.
//
// How it is stored:
//   - Through the same backends as the TLS certificate bundle
//     (internal/certstore): a file, a sealed file, or a sealed Key Vault
//     secret. "Sealed" means AES-256-GCM under a key derived from a Key Vault
//     key that the SKR sidecar releases only to an enclave whose attestation
//     matches the key's release policy. Outside the enclave only ciphertext
//     exists; a different image (different CCE policy hash) cannot unseal it.
//   - The sealing purpose "stationstore" separates this blob from the TLS
//     bundle even though both use one Key Vault key: the derived AES keys
//     differ and each store refuses the other's envelope.
//
// Trust boundary:
//   - Nothing here changes what the verifier verifies or how. A restored
//     station is re-challenged shortly after start-up like any other, and a
//     station that fails is unregistered or banned exactly as before.
//   - The snapshot does not create or rotate provider credentials. It only
//     keeps the ones OpenRouter issued to the verifier during registration.
package stationstore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openanonymity/oa-verifier/internal/certstore"
	"github.com/openanonymity/oa-verifier/internal/models"
)

// Environment variables understood by FromEnv. Every one of them must be
// listed in the CCE policy's optional_env_vars (build-and-sign.yml, "Generate
// CCE policy" step) or the confidential container will refuse to start. The
// vault, KEK, SKR endpoint and managed identity are the shared TLS_CERT_*
// variables from internal/certstore so one Key Vault setup serves both blobs.
const (
	// EnvStore selects the backend: none (default) | file | file-sealed | keyvault-sealed.
	EnvStore = "STATION_STATE_STORE"
	// EnvStoreDir is the directory for file and file-sealed.
	EnvStoreDir = "STATION_STATE_STORE_DIR"
	// EnvSecretName is the Key Vault secret for keyvault-sealed (default DefaultSecretName).
	EnvSecretName = "STATION_STATE_SECRET_NAME"
)

// DefaultSecretName is used when STATION_STATE_SECRET_NAME is unset.
const DefaultSecretName = "oa-verifier-station-state"

// Purpose is the sealing domain for the station registry (see certstore.SealedBlobStore).
const Purpose = "stationstore"

// FileName is the file used by the file backends.
const FileName = "station-state.json"

// SnapshotVersion is the current on-the-wire format.
const SnapshotVersion = 1

// MaxEncodedBytes is the largest snapshot a store should be asked to hold.
// Key Vault secrets are capped at 25 KB; the sealed envelope adds roughly a
// third (base64) plus a few hundred bytes, so the plaintext budget is lower.
// A station record with a typical Clerk session is 2–5 KB, which comfortably
// fits the handful of stations one verifier serves. Save refuses larger
// snapshots instead of letting Key Vault reject them half-way.
const MaxEncodedBytes = 17 * 1024

// ErrNotFound is returned by Load when nothing has been saved yet.
var ErrNotFound = certstore.ErrNotFound

// ErrTooLarge is returned by Save when the snapshot exceeds MaxEncodedBytes.
var ErrTooLarge = errors.New("stationstore: snapshot exceeds the store size budget")

// Record is one registered station: its public key (the registry's map key)
// and the server's view of it, with explicit JSON names so the on-the-wire
// format does not depend on Go field names in models.Station.
type Record struct {
	PublicKey       string         `json:"public_key"`
	StationID       string         `json:"station_id"`
	Email           string         `json:"email"`
	DisplayName     string         `json:"display_name"`
	CookieData      map[string]any `json:"cookie_data,omitempty"`
	RegisteredAt    string         `json:"registered_at"`
	LastVerified    *string        `json:"last_verified,omitempty"`
	ProvisioningKey string         `json:"provisioning_key,omitempty"`
	NextChallengeAt time.Time      `json:"next_challenge_at"`
	FailureFirstAt  *time.Time     `json:"failure_first_at,omitempty"`
	FailureLastAt   *time.Time     `json:"failure_last_at,omitempty"`
	FailureReason   string         `json:"failure_reason,omitempty"`
	FailureDetail   string         `json:"failure_detail,omitempty"`
	FailureStatus   int            `json:"failure_status,omitempty"`
	FailureCount    int            `json:"failure_count,omitempty"`
}

// RecordFromStation converts a live registry entry into its persisted form.
// Pointer fields are copied, and the cookie data is reduced to the cookies
// the verifier actually reads (see TrimCookieData), which both bounds the
// snapshot size and avoids persisting cookies that serve no purpose here.
func RecordFromStation(publicKey string, st *models.Station) Record {
	r := Record{
		PublicKey:       publicKey,
		StationID:       st.StationID,
		Email:           st.Email,
		DisplayName:     st.DisplayName,
		CookieData:      TrimCookieData(st.CookieData),
		RegisteredAt:    st.RegisteredAt,
		ProvisioningKey: st.ProvisioningKey,
		NextChallengeAt: st.NextChallengeAt,
		FailureReason:   st.FailureReason,
		FailureDetail:   st.FailureDetail,
		FailureStatus:   st.FailureStatus,
		FailureCount:    st.FailureCount,
	}
	if st.LastVerified != nil {
		v := *st.LastVerified
		r.LastVerified = &v
	}
	if st.FailureFirstAt != nil {
		v := *st.FailureFirstAt
		r.FailureFirstAt = &v
	}
	if st.FailureLastAt != nil {
		v := *st.FailureLastAt
		r.FailureLastAt = &v
	}
	return r
}

// ToStation converts a persisted record back into a registry entry.
func (r Record) ToStation() models.Station {
	st := models.Station{
		StationID:       r.StationID,
		Email:           r.Email,
		DisplayName:     r.DisplayName,
		CookieData:      r.CookieData,
		RegisteredAt:    r.RegisteredAt,
		ProvisioningKey: r.ProvisioningKey,
		NextChallengeAt: r.NextChallengeAt,
		FailureReason:   r.FailureReason,
		FailureDetail:   r.FailureDetail,
		FailureStatus:   r.FailureStatus,
		FailureCount:    r.FailureCount,
	}
	if r.LastVerified != nil {
		v := *r.LastVerified
		st.LastVerified = &v
	}
	if r.FailureFirstAt != nil {
		v := *r.FailureFirstAt
		st.FailureFirstAt = &v
	}
	if r.FailureLastAt != nil {
		v := *r.FailureLastAt
		st.FailureLastAt = &v
	}
	return st
}

// relevantCookie reports whether openrouter.NewAuthFromCookieData reads a
// cookie of this name: the Clerk client/refresh credentials, the client_uat
// marker, the active-context cookie and the session JWT (used only as the
// expired_token hint). Everything else is dead weight in the snapshot.
func relevantCookie(name string) bool {
	switch {
	case name == "clerk_active_context":
		return true
	case strings.HasPrefix(name, "__client"), strings.HasPrefix(name, "__session"), strings.HasPrefix(name, "__refresh"):
		return true
	}
	return false
}

// TrimCookieData returns a copy of cookieData whose "cookies" list keeps only
// the cookies the verifier uses, each reduced to its name, value and domain.
// Other top-level keys are kept as they are. A nil input stays nil.
func TrimCookieData(cookieData map[string]any) map[string]any {
	if cookieData == nil {
		return nil
	}
	out := make(map[string]any, len(cookieData))
	for k, v := range cookieData {
		if k != "cookies" {
			out[k] = v
		}
	}
	cookies, ok := cookieData["cookies"].([]any)
	if !ok {
		return out
	}
	kept := make([]any, 0, len(cookies))
	for _, c := range cookies {
		cookie, ok := c.(map[string]any)
		if !ok {
			continue
		}
		name, _ := cookie["name"].(string)
		value, _ := cookie["value"].(string)
		if !relevantCookie(name) || value == "" {
			continue
		}
		slim := map[string]any{"name": name, "value": value}
		if domain, ok := cookie["domain"].(string); ok && domain != "" {
			slim["domain"] = domain
		}
		kept = append(kept, slim)
	}
	out["cookies"] = kept
	return out
}

// Snapshot is the persisted form of the station registry.
type Snapshot struct {
	Version  int       `json:"v"`
	SavedAt  time.Time `json:"saved_at"`
	Stations []Record  `json:"stations"`
}

// Store persists a Snapshot.
type Store interface {
	// Load returns the saved snapshot or ErrNotFound.
	Load(ctx context.Context) (*Snapshot, error)
	// Save atomically replaces the saved snapshot.
	Save(ctx context.Context, s *Snapshot) error
}

// NoopStore never finds anything and discards saves. It reproduces the
// pre-persistence behaviour exactly and is the default.
type NoopStore struct{}

// Load implements Store.
func (NoopStore) Load(context.Context) (*Snapshot, error) { return nil, ErrNotFound }

// Save implements Store.
func (NoopStore) Save(context.Context, *Snapshot) error { return nil }

// Marshal encodes a snapshot, stamping the current version.
func Marshal(s *Snapshot) ([]byte, error) {
	if s == nil {
		return nil, errors.New("stationstore: nil snapshot")
	}
	out := *s
	out.Version = SnapshotVersion
	if out.Stations == nil {
		out.Stations = []Record{}
	}
	data, err := json.Marshal(&out)
	if err != nil {
		return nil, fmt.Errorf("stationstore: encode snapshot: %w", err)
	}
	if len(data) > MaxEncodedBytes {
		return nil, fmt.Errorf("%w: %d bytes for %d stations (limit %d)", ErrTooLarge, len(data), len(out.Stations), MaxEncodedBytes)
	}
	return data, nil
}

// Unmarshal decodes a snapshot and checks its version and basic integrity.
func Unmarshal(data []byte) (*Snapshot, error) {
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("stationstore: decode snapshot: %w", err)
	}
	if s.Version != SnapshotVersion {
		return nil, fmt.Errorf("stationstore: unsupported snapshot version %d (want %d)", s.Version, SnapshotVersion)
	}
	seen := make(map[string]struct{}, len(s.Stations))
	for i, r := range s.Stations {
		if strings.TrimSpace(r.PublicKey) == "" {
			return nil, fmt.Errorf("stationstore: record %d has no public key", i)
		}
		if _, dup := seen[r.PublicKey]; dup {
			return nil, fmt.Errorf("stationstore: duplicate public key in snapshot")
		}
		seen[r.PublicKey] = struct{}{}
	}
	if s.Stations == nil {
		s.Stations = []Record{}
	}
	return &s, nil
}

// blobStore adapts a certstore.BlobStore (plain or sealed) to Store.
type blobStore struct{ blobs certstore.BlobStore }

// NewBlobStore wraps any BlobStore — a FileStore, a KeyVaultSecretStore, or a
// SealedBlobStore around either — as a snapshot Store.
func NewBlobStore(blobs certstore.BlobStore) Store { return &blobStore{blobs: blobs} }

// Load implements Store.
func (s *blobStore) Load(ctx context.Context) (*Snapshot, error) {
	raw, err := s.blobs.LoadBlob(ctx)
	if err != nil {
		return nil, err
	}
	return Unmarshal(raw)
}

// Save implements Store.
func (s *blobStore) Save(ctx context.Context, snap *Snapshot) error {
	raw, err := Marshal(snap)
	if err != nil {
		return err
	}
	return s.blobs.SaveBlob(ctx, raw)
}

// FromEnv builds the Store selected by STATION_STATE_STORE. An empty or
// "none" value returns NoopStore, i.e. exactly the pre-persistence behaviour.
// The returned string describes the configuration for logging.
// Misconfiguration (a mode without its required variables) is an error so
// that it is caught at start-up instead of silently running without state.
func FromEnv(getenv func(string) string) (Store, string, error) {
	secret := getenv(EnvSecretName)
	if secret == "" {
		secret = DefaultSecretName
	}
	blobs, desc, err := certstore.BlobStoreFromEnv(getenv, certstore.BlobSpec{
		ModeVar:    EnvStore,
		Mode:       getenv(EnvStore),
		Dir:        getenv(EnvStoreDir),
		DirVar:     EnvStoreDir,
		FileName:   FileName,
		SecretName: secret,
		Purpose:    Purpose,
	})
	if err != nil {
		return nil, "", err
	}
	if blobs == nil {
		return NoopStore{}, desc, nil
	}
	return NewBlobStore(blobs), desc, nil
}

// Digest returns a stable fingerprint of the parts of a snapshot worth a
// write: identity, credentials, and whether a station is currently verified
// or in a failure window. Fields that change on every check (the next
// challenge time, failure timestamps, counters) are left out so that the
// server can call for a save freely and the store only writes when the
// durable content differs. See server.persistLoop.
func Digest(s *Snapshot) string {
	if s == nil {
		return ""
	}
	type durable struct {
		PublicKey       string         `json:"pk"`
		StationID       string         `json:"sid"`
		Email           string         `json:"email"`
		DisplayName     string         `json:"name"`
		CookieData      map[string]any `json:"cookies"`
		RegisteredAt    string         `json:"registered_at"`
		ProvisioningKey string         `json:"prov_key"`
		Verified        bool           `json:"verified"`
		Failing         bool           `json:"failing"`
		FailureReason   string         `json:"failure_reason"`
	}
	items := make([]durable, 0, len(s.Stations))
	for _, r := range s.Stations {
		items = append(items, durable{
			PublicKey:       r.PublicKey,
			StationID:       r.StationID,
			Email:           r.Email,
			DisplayName:     r.DisplayName,
			CookieData:      r.CookieData,
			RegisteredAt:    r.RegisteredAt,
			ProvisioningKey: r.ProvisioningKey,
			Verified:        r.LastVerified != nil,
			Failing:         r.FailureFirstAt != nil,
			FailureReason:   r.FailureReason,
		})
	}
	// Order is part of the fingerprint; callers sort records by public key.
	data, err := json.Marshal(items)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}
