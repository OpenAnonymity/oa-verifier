package certstore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// KeyReleaser returns the raw key-encryption-key material. In production this
// is the SKR sidecar, which only hands the key out after Azure Key Vault has
// verified an attestation token for this enclave against the key's release
// policy.
type KeyReleaser interface {
	ReleaseKey(ctx context.Context) (*ReleasedKey, error)
}

// ReleasedKey is the parsed JSON Web Key returned by the sidecar.
type ReleasedKey struct {
	KID string
	// Material is the secret part of the JWK: "k" for oct keys, "d" for RSA
	// and EC keys. It is only ever fed to HKDF, never used directly.
	Material []byte
	KeyType  string
}

// envelope is the sealed on-disk / in-vault format. Ciphertext is the
// AES-256-GCM encryption of the JSON bundle; AAD binds version and kid so a
// blob cannot be silently re-labelled.
type envelope struct {
	Version    int    `json:"v"`
	Alg        string `json:"alg"`
	KDF        string `json:"kdf"`
	KID        string `json:"kid"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

const (
	envelopeVersion = 1
	envelopeAlg     = "A256GCM"
	envelopeKDF     = "HKDF-SHA256"
	hkdfSalt        = "oa-verifier/certstore/kek/v1"
	hkdfInfoPrefix  = "oa-verifier/certstore/aes-256-gcm/"
)

// SealedStore encrypts bundles before handing them to an untrusted BlobStore.
type SealedStore struct {
	Blobs    BlobStore
	Releaser KeyReleaser
}

// NewSealedStore wraps blobs with AES-256-GCM sealing keyed from releaser.
func NewSealedStore(blobs BlobStore, releaser KeyReleaser) (*SealedStore, error) {
	if blobs == nil || releaser == nil {
		return nil, errors.New("certstore: sealed store needs a blob store and a key releaser")
	}
	return &SealedStore{Blobs: blobs, Releaser: releaser}, nil
}

// Load implements Store.
func (s *SealedStore) Load(ctx context.Context) (*Bundle, error) {
	raw, err := s.Blobs.LoadBlob(ctx)
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("certstore: decode sealed envelope: %w", err)
	}
	if env.Version != envelopeVersion || env.Alg != envelopeAlg || env.KDF != envelopeKDF {
		return nil, fmt.Errorf("certstore: unsupported envelope v=%d alg=%q kdf=%q", env.Version, env.Alg, env.KDF)
	}
	key, err := s.Releaser.ReleaseKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("certstore: key release: %w", err)
	}
	if env.KID != "" && key.KID != "" && env.KID != key.KID {
		return nil, fmt.Errorf("certstore: envelope sealed under kid %q but released key is %q", env.KID, key.KID)
	}
	aead, err := aeadFor(key)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("certstore: decode nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("certstore: decode ciphertext: %w", err)
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("certstore: bad nonce length")
	}
	plain, err := aead.Open(nil, nonce, ct, aad(env.KID))
	if err != nil {
		return nil, fmt.Errorf("certstore: unseal bundle: %w", err)
	}
	return Unmarshal(plain)
}

// Save implements Store.
func (s *SealedStore) Save(ctx context.Context, b *Bundle) error {
	plain, err := Marshal(b)
	if err != nil {
		return err
	}
	key, err := s.Releaser.ReleaseKey(ctx)
	if err != nil {
		return fmt.Errorf("certstore: key release: %w", err)
	}
	aead, err := aeadFor(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("certstore: nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plain, aad(key.KID))
	env := envelope{
		Version:    envelopeVersion,
		Alg:        envelopeAlg,
		KDF:        envelopeKDF,
		KID:        key.KID,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("certstore: encode envelope: %w", err)
	}
	return s.Blobs.SaveBlob(ctx, raw)
}

func aad(kid string) []byte {
	return []byte(fmt.Sprintf("%s/v%d/%s", envelopeAlg, envelopeVersion, kid))
}

// aeadFor derives the 256-bit AES key from the released material with
// HKDF-SHA256. The released JWK is an asymmetric or symmetric key whose raw
// secret is not shaped like an AES key, so it is treated as HKDF input keying
// material rather than used directly.
func aeadFor(key *ReleasedKey) (cipher.AEAD, error) {
	if key == nil || len(key.Material) == 0 {
		return nil, errors.New("certstore: released key has no secret material")
	}
	aesKey := hkdfSHA256(key.Material, []byte(hkdfSalt), []byte(hkdfInfoPrefix+key.KID), 32)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("certstore: aes: %w", err)
	}
	return cipher.NewGCM(block)
}

// hkdfSHA256 implements RFC 5869 extract-then-expand with HMAC-SHA256. It is
// implemented here (about twenty lines) so the module keeps go 1.22 and does
// not take a direct dependency on golang.org/x/crypto.
func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	ext := hmac.New(sha256.New, salt)
	ext.Write(ikm)
	prk := ext.Sum(nil)

	var out []byte
	var prev []byte
	for counter := byte(1); len(out) < length; counter++ {
		exp := hmac.New(sha256.New, prk)
		exp.Write(prev)
		exp.Write(info)
		exp.Write([]byte{counter})
		prev = exp.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

// ---------------------------------------------------------------------------
// SKR sidecar key release
// ---------------------------------------------------------------------------

// DefaultSKRReleaseURL is where the Microsoft SKR sidecar listens inside the
// container group (see deploy/aci-template.json).
const DefaultSKRReleaseURL = "http://localhost:8080/key/release"

// SKRReleaser asks the confidential sidecar to release a Key Vault key.
//
// Request/response shapes follow the upstream sidecar
// (internal/httpginendpoints/httpginendpoints.go, PostKeyRelease):
//
//	POST /key/release
//	{"maa_endpoint": "...", "akv_endpoint": "...", "kid": "...", "access_token": "..."(optional)}
//	200 {"key": "<JWK as a JSON string>"}
//	4xx/5xx {"error": "..."}
type SKRReleaser struct {
	// URL of the sidecar endpoint; DefaultSKRReleaseURL when empty.
	URL string
	// MAAEndpoint is the attestation authority named in the key's release
	// policy (MAA_PROVIDER_URL, e.g. sharedeus.eus.attest.azure.net).
	MAAEndpoint string
	// AKVEndpoint is the vault or managed HSM hosting the key
	// (e.g. https://myvault.vault.azure.net).
	AKVEndpoint string
	// KID is the key name.
	KID string
	// HTTPClient defaults to a client with a 60s timeout.
	HTTPClient *http.Client
}

type skrRequest struct {
	MAAEndpoint string `json:"maa_endpoint"`
	AKVEndpoint string `json:"akv_endpoint"`
	KID         string `json:"kid"`
}

type skrResponse struct {
	Key   string `json:"key"`
	Error string `json:"error"`
}

// ReleaseKey implements KeyReleaser.
func (r *SKRReleaser) ReleaseKey(ctx context.Context) (*ReleasedKey, error) {
	if r.MAAEndpoint == "" || r.AKVEndpoint == "" || r.KID == "" {
		return nil, errors.New("certstore: skr releaser needs maa endpoint, akv endpoint and kid")
	}
	url := r.URL
	if url == "" {
		url = DefaultSKRReleaseURL
	}
	client := r.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	body, err := json.Marshal(skrRequest{MAAEndpoint: r.MAAEndpoint, AKVEndpoint: r.AKVEndpoint, KID: r.KID})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certstore: skr request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("certstore: read skr response: %w", err)
	}
	var out skrResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("certstore: skr returned HTTP %d with non-JSON body", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(out.Error)
		if msg == "" {
			msg = "no error message"
		}
		return nil, fmt.Errorf("certstore: skr HTTP %d: %s", resp.StatusCode, firstLine(msg))
	}
	if out.Key == "" {
		return nil, errors.New("certstore: skr response has no key")
	}
	return ParseReleasedJWK([]byte(out.Key), r.KID)
}

// ParseReleasedJWK extracts the secret material from a JWK. Supported types:
// "oct" (k), "RSA" (d) and "EC" (d). Public-only JWKs are rejected. The key
// name passed as fallbackKID is used when the JWK has no kid of its own.
func ParseReleasedJWK(jwk []byte, fallbackKID string) (*ReleasedKey, error) {
	var k struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		K   string `json:"k"`
		D   string `json:"d"`
	}
	if err := json.Unmarshal(jwk, &k); err != nil {
		return nil, fmt.Errorf("certstore: decode released jwk: %w", err)
	}
	var secret string
	switch k.Kty {
	case "oct":
		secret = k.K
	case "RSA", "EC":
		secret = k.D
	default:
		return nil, fmt.Errorf("certstore: unsupported released key type %q", k.Kty)
	}
	if secret == "" {
		return nil, fmt.Errorf("certstore: released %s jwk carries no private material", k.Kty)
	}
	material, err := decodeB64URL(secret)
	if err != nil {
		return nil, fmt.Errorf("certstore: decode jwk material: %w", err)
	}
	if len(material) < 32 {
		return nil, errors.New("certstore: released key material is shorter than 256 bits")
	}
	kid := k.Kid
	if kid == "" {
		kid = fallbackKID
	}
	return &ReleasedKey{KID: kid, Material: material, KeyType: k.Kty}, nil
}

func decodeB64URL(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
