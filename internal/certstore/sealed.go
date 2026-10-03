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
// AES-256-GCM encryption of the JSON payload; AAD binds version, kid and
// purpose so a blob cannot be silently re-labelled or replayed into a store
// with a different purpose.
type envelope struct {
	Version    int    `json:"v"`
	Alg        string `json:"alg"`
	KDF        string `json:"kdf"`
	KID        string `json:"kid"`
	Purpose    string `json:"purpose,omitempty"`
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

// SealedBlobStore seals arbitrary payloads before handing them to an
// untrusted BlobStore, and unseals them on the way back.
//
// Purpose is a short label naming what the blob holds ("" for the TLS
// certificate bundle, "stationstore" for the station registry, ...). It is
// mixed into the HKDF info string and into the AEAD associated data, so two
// stores sharing one Key Vault key still use unrelated AES keys, and a blob
// saved by one store is rejected by the other instead of being decrypted and
// misinterpreted. The empty purpose keeps the exact pre-existing derivation
// and AAD, so bundles sealed before this field existed still open.
type SealedBlobStore struct {
	Blobs    BlobStore
	Releaser KeyReleaser
	Purpose  string
}

// NewSealedBlobStore wraps blobs with AES-256-GCM sealing keyed from releaser
// and domain-separated by purpose.
func NewSealedBlobStore(blobs BlobStore, releaser KeyReleaser, purpose string) (*SealedBlobStore, error) {
	if blobs == nil || releaser == nil {
		return nil, errors.New("certstore: sealed store needs a blob store and a key releaser")
	}
	if strings.ContainsAny(purpose, "/ \t\r\n") || strings.EqualFold(purpose, "certstore") {
		// "/" and whitespace would blur the HKDF info / AAD strings; "certstore"
		// is the name of the empty (TLS bundle) purpose and is reserved.
		return nil, fmt.Errorf("certstore: invalid sealing purpose %q", purpose)
	}
	return &SealedBlobStore{Blobs: blobs, Releaser: releaser, Purpose: purpose}, nil
}

// LoadBlob implements BlobStore: it loads the sealed envelope from the
// underlying store and returns the decrypted payload.
func (s *SealedBlobStore) LoadBlob(ctx context.Context) ([]byte, error) {
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
	if env.Purpose != s.Purpose {
		return nil, fmt.Errorf("certstore: envelope sealed for purpose %q, this store is %q", env.Purpose, s.Purpose)
	}
	key, err := s.Releaser.ReleaseKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("certstore: key release: %w", err)
	}
	if env.KID != "" && key.KID != "" && env.KID != key.KID {
		return nil, fmt.Errorf("certstore: envelope sealed under kid %q but released key is %q", env.KID, key.KID)
	}
	aead, err := aeadFor(key, s.Purpose)
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
	plain, err := aead.Open(nil, nonce, ct, aad(env.KID, s.Purpose))
	if err != nil {
		return nil, fmt.Errorf("certstore: unseal bundle: %w", err)
	}
	return plain, nil
}

// SaveBlob implements BlobStore: it seals plain and stores the envelope.
func (s *SealedBlobStore) SaveBlob(ctx context.Context, plain []byte) error {
	key, err := s.Releaser.ReleaseKey(ctx)
	if err != nil {
		return fmt.Errorf("certstore: key release: %w", err)
	}
	aead, err := aeadFor(key, s.Purpose)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("certstore: nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plain, aad(key.KID, s.Purpose))
	env := envelope{
		Version:    envelopeVersion,
		Alg:        envelopeAlg,
		KDF:        envelopeKDF,
		KID:        key.KID,
		Purpose:    s.Purpose,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("certstore: encode envelope: %w", err)
	}
	return s.Blobs.SaveBlob(ctx, raw)
}

// SealedStore encrypts certificate bundles before handing them to an
// untrusted BlobStore. It is SealedBlobStore with the empty (certificate)
// purpose plus Bundle encoding.
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

func (s *SealedStore) sealed() *SealedBlobStore {
	return &SealedBlobStore{Blobs: s.Blobs, Releaser: s.Releaser}
}

// Load implements Store.
func (s *SealedStore) Load(ctx context.Context) (*Bundle, error) {
	plain, err := s.sealed().LoadBlob(ctx)
	if err != nil {
		return nil, err
	}
	return Unmarshal(plain)
}

// Save implements Store.
func (s *SealedStore) Save(ctx context.Context, b *Bundle) error {
	plain, err := Marshal(b)
	if err != nil {
		return err
	}
	return s.sealed().SaveBlob(ctx, plain)
}

func aad(kid, purpose string) []byte {
	if purpose == "" {
		return []byte(fmt.Sprintf("%s/v%d/%s", envelopeAlg, envelopeVersion, kid))
	}
	return []byte(fmt.Sprintf("%s/v%d/%s/%s", envelopeAlg, envelopeVersion, kid, purpose))
}

// hkdfInfo is the HKDF info string for a purpose. The empty purpose keeps the
// historical certificate string; any other purpose gets its own namespace
// ("oa-verifier/purpose/<p>/...", which no value of <p> can turn into the
// certificate string) so the derived AES keys are independent.
func hkdfInfo(kid, purpose string) []byte {
	if purpose == "" {
		return []byte(hkdfInfoPrefix + kid)
	}
	return []byte("oa-verifier/purpose/" + purpose + "/aes-256-gcm/" + kid)
}

// aeadFor derives the 256-bit AES key from the released material with
// HKDF-SHA256. The released JWK is an asymmetric or symmetric key whose raw
// secret is not shaped like an AES key, so it is treated as HKDF input keying
// material rather than used directly.
func aeadFor(key *ReleasedKey, purpose string) (cipher.AEAD, error) {
	if key == nil || len(key.Material) == 0 {
		return nil, errors.New("certstore: released key has no secret material")
	}
	aesKey := hkdfSHA256(key.Material, []byte(hkdfSalt), hkdfInfo(key.KID, purpose), 32)
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
	// Tokens, when set, supplies the Key Vault access token that is passed to
	// the sidecar as "access_token". The sidecar then uses it instead of
	// fetching one itself, which pins the call to a specific user-assigned
	// identity (TLS_CERT_MSI_CLIENT_ID). When nil the sidecar uses the
	// group's identity on its own, exactly as before.
	Tokens TokenSource
	// HTTPClient defaults to a client with a 60s timeout.
	HTTPClient *http.Client
}

type skrRequest struct {
	MAAEndpoint string `json:"maa_endpoint"`
	AKVEndpoint string `json:"akv_endpoint"`
	KID         string `json:"kid"`
	AccessToken string `json:"access_token,omitempty"`
}

// ManagedHSMResource is the token audience for Azure Managed HSM (public cloud).
const ManagedHSMResource = "https://managedhsm.azure.net"

// vaultResourceFor picks the token audience for a vault or managed HSM URL.
func vaultResourceFor(akvEndpoint string) string {
	if strings.Contains(strings.ToLower(akvEndpoint), ".managedhsm.") {
		return ManagedHSMResource
	}
	return KeyVaultResource
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
	// The sidecar wants bare hosts ("mykv.vault.azure.net"), exactly like
	// maa_endpoint; it prepends https:// itself. AKVEndpoint is kept as a URL
	// for logging and token-audience selection.
	reqBody := skrRequest{MAAEndpoint: r.MAAEndpoint, AKVEndpoint: bareHost(r.AKVEndpoint), KID: r.KID}
	if r.Tokens != nil {
		tok, err := r.Tokens.Token(ctx, vaultResourceFor(r.AKVEndpoint))
		if err != nil {
			return nil, fmt.Errorf("certstore: key vault token for skr: %w", err)
		}
		reqBody.AccessToken = tok
	}
	body, err := json.Marshal(reqBody)
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

// bareHost strips the scheme and any trailing slash from a vault URL.
func bareHost(endpoint string) string {
	e := strings.TrimSpace(endpoint)
	e = strings.TrimPrefix(e, "https://")
	e = strings.TrimPrefix(e, "http://")
	return strings.TrimRight(e, "/")
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
