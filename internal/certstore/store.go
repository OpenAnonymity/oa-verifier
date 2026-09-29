// Package certstore persists the verifier's TLS material (certificate chain,
// private key, ACME account) across container restarts.
//
// Azure recreates the Confidential ACI group on every platform repair; without
// persistence each start requested a brand-new Let's Encrypt certificate and
// quickly hit the duplicate-certificate rate limit (5 per week), after which
// the server fell back to a self-signed certificate.
//
// Trust model (see docs/CERT_PERSISTENCE.md): TLS terminates inside the
// enclave and the private key must never leave the enclave in plaintext. The
// only backend that writes outside the enclave is SealedStore, which encrypts
// the bundle with AES-256-GCM under a key that Azure Key Vault releases only
// to an attested enclave (secure key release through the SKR sidecar).
package certstore

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// ErrNotFound is returned by Store.Load when no bundle has been saved yet.
var ErrNotFound = errors.New("certstore: no bundle found")

// Bundle is everything needed to resume TLS service and ACME account
// operations without contacting the CA again.
type Bundle struct {
	// Domain the certificate was issued for (TLS_DOMAIN at issue time).
	Domain string `json:"domain"`
	// CertificatePEM is the full PEM chain (leaf first).
	CertificatePEM []byte `json:"certificate_pem"`
	// PrivateKeyPEM is the PEM-encoded certificate private key.
	PrivateKeyPEM []byte `json:"private_key_pem"`
	// AccountKeyPEM is the PEM-encoded ACME account private key.
	AccountKeyPEM []byte `json:"account_key_pem,omitempty"`
	// AccountURI is the ACME account registration URI (kid).
	AccountURI string `json:"account_uri,omitempty"`
	// CADirURL identifies the ACME directory the account belongs to
	// (production vs staging); an account key is only valid at one CA.
	CADirURL string `json:"ca_dir_url,omitempty"`
	// IssuedAt is when the certificate was obtained by this service.
	IssuedAt time.Time `json:"issued_at"`
	// NotAfter is the leaf certificate expiry, copied for cheap inspection.
	NotAfter time.Time `json:"not_after"`
}

// Store persists a Bundle.
type Store interface {
	// Load returns the saved bundle or ErrNotFound.
	Load(ctx context.Context) (*Bundle, error)
	// Save atomically replaces the saved bundle.
	Save(ctx context.Context, b *Bundle) error
}

// BlobStore persists an opaque byte slice. SealedStore uses it as the backing
// store for ciphertext; FileStore and KeyVaultSecretStore implement it.
type BlobStore interface {
	LoadBlob(ctx context.Context) ([]byte, error)
	SaveBlob(ctx context.Context, data []byte) error
}

// NoopStore never finds anything and discards saves. It reproduces the
// pre-persistence behaviour exactly and is the default.
type NoopStore struct{}

func (NoopStore) Load(context.Context) (*Bundle, error) { return nil, ErrNotFound }
func (NoopStore) Save(context.Context, *Bundle) error   { return nil }

// Marshal encodes a bundle as JSON.
func Marshal(b *Bundle) ([]byte, error) {
	if b == nil {
		return nil, errors.New("certstore: nil bundle")
	}
	return json.Marshal(b)
}

// Unmarshal decodes a bundle from JSON and rejects bundles without a
// certificate or key.
func Unmarshal(data []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("certstore: decode bundle: %w", err)
	}
	if len(b.CertificatePEM) == 0 || len(b.PrivateKeyPEM) == 0 {
		return nil, errors.New("certstore: bundle is missing certificate or private key")
	}
	return &b, nil
}

// Leaf parses and returns the first certificate of the chain.
func (b *Bundle) Leaf() (*x509.Certificate, error) {
	if b == nil {
		return nil, errors.New("certstore: nil bundle")
	}
	block, _ := pem.Decode(b.CertificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("certstore: certificate PEM has no CERTIFICATE block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certstore: parse leaf certificate: %w", err)
	}
	return leaf, nil
}

// TLSCertificate builds a tls.Certificate (with Leaf populated) and returns
// the SHA-256 hash of the leaf's SubjectPublicKeyInfo, which the attestation
// endpoint uses for channel binding.
func (b *Bundle) TLSCertificate() (tls.Certificate, string, error) {
	if b == nil {
		return tls.Certificate{}, "", errors.New("certstore: nil bundle")
	}
	cert, err := tls.X509KeyPair(b.CertificatePEM, b.PrivateKeyPEM)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("certstore: certificate/key mismatch: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("certstore: parse leaf certificate: %w", err)
	}
	cert.Leaf = leaf
	pub, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("certstore: marshal public key: %w", err)
	}
	sum := sha256.Sum256(pub)
	return cert, hex.EncodeToString(sum[:]), nil
}

// blobBundleStore adapts a BlobStore holding plaintext JSON to a Store.
type blobBundleStore struct{ blobs BlobStore }

// NewBlobBundleStore returns a Store that keeps the JSON-encoded bundle in
// plaintext in the given BlobStore. Only use it with storage that never
// leaves the enclave (e.g. an in-memory or emptyDir FileStore).
func NewBlobBundleStore(blobs BlobStore) Store { return &blobBundleStore{blobs: blobs} }

func (s *blobBundleStore) Load(ctx context.Context) (*Bundle, error) {
	data, err := s.blobs.LoadBlob(ctx)
	if err != nil {
		return nil, err
	}
	return Unmarshal(data)
}

func (s *blobBundleStore) Save(ctx context.Context, b *Bundle) error {
	data, err := Marshal(b)
	if err != nil {
		return err
	}
	return s.blobs.SaveBlob(ctx, data)
}
