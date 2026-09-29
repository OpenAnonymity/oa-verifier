// Package acme provides ACME DNS-01 certificate management for Let's Encrypt.
package acme

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"

	"github.com/openanonymity/oa-verifier/internal/certstore"
)

// Config holds ACME configuration from environment variables.
type Config struct {
	Domain   string // TLS_DOMAIN
	Email    string // ACME_EMAIL
	Provider string // ACME_DNS_PROVIDER (cloudflare, etc.)
	Staging  bool   // ACME_STAGING=true
}

// LoadConfig reads ACME configuration from environment.
func LoadConfig() *Config {
	return &Config{
		Domain:   os.Getenv("TLS_DOMAIN"),
		Email:    os.Getenv("ACME_EMAIL"),
		Provider: os.Getenv("ACME_DNS_PROVIDER"),
		Staging:  os.Getenv("ACME_STAGING") == "true",
	}
}

// IsEnabled returns true if ACME is properly configured.
func (c *Config) IsEnabled() bool {
	return c.Domain != "" && c.Email != "" && c.Provider != ""
}

// CADirURL returns the ACME directory this configuration talks to. Account
// keys and certificates are only meaningful at the CA that issued them, so
// the value is persisted alongside the bundle.
func (c *Config) CADirURL() string {
	if c.Staging {
		return lego.LEDirectoryStaging
	}
	return lego.LEDirectoryProduction
}

// User implements acme.User for lego.
type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *User) GetEmail() string                        { return u.Email }
func (u *User) GetRegistration() *registration.Resource { return u.Registration }
func (u *User) GetPrivateKey() crypto.PrivateKey        { return u.key }

// Client holds a registered ACME client that can be reused across retries.
type Client struct {
	client *lego.Client
	user   *User
	cfg    *Config
}

// NewClient creates an ACME client with a fresh account key and registers it.
// Prefer NewClientWithAccount when a persisted account exists: re-registering
// on every start is what exhausted the CA's rate limits.
func NewClient(cfg *Config) (*Client, error) {
	return NewClientWithAccount(cfg, nil, "")
}

// NewClientWithAccount creates an ACME client. When accountKeyPEM is given the
// key is reused and the existing account is resolved by key
// (registration.ResolveAccountByKey) instead of creating a new one; if the CA
// does not know the key, a registration is created for it. accountURI is
// informational (the CA is authoritative) and logged.
func NewClientWithAccount(cfg *Config, accountKeyPEM []byte, accountURI string) (*Client, error) {
	var privateKey crypto.PrivateKey
	var err error
	reused := false
	if len(accountKeyPEM) > 0 {
		privateKey, err = certcrypto.ParsePEMPrivateKey(accountKeyPEM)
		if err != nil {
			slog.Warn("persisted ACME account key is unreadable, generating a new one", "error", err)
		} else {
			reused = true
		}
	}
	if privateKey == nil {
		privateKey, err = certcrypto.GeneratePrivateKey(certcrypto.EC256)
		if err != nil {
			return nil, fmt.Errorf("failed to generate account key: %w", err)
		}
	}

	user := &User{
		Email: cfg.Email,
		key:   privateKey,
	}

	config := lego.NewConfig(user)
	config.Certificate.KeyType = certcrypto.EC256
	config.CADirURL = cfg.CADirURL()
	if cfg.Staging {
		slog.Info("using Let's Encrypt staging environment")
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME client: %w", err)
	}

	provider, err := getDNSProvider(cfg.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS provider: %w", err)
	}

	err = client.Challenge.SetDNS01Provider(provider, dns01.AddRecursiveNameservers([]string{"1.1.1.1:53", "8.8.8.8:53"}))
	if err != nil {
		return nil, fmt.Errorf("failed to set DNS provider: %w", err)
	}

	if reused {
		reg, rerr := client.Registration.ResolveAccountByKey()
		if rerr == nil {
			user.Registration = reg
			if accountURI != "" && accountURI != reg.URI {
				slog.Warn("ACME account URI changed", "persisted", accountURI, "resolved", reg.URI)
			}
			slog.Info("reusing persisted ACME account", "account", reg.URI)
			return &Client{client: client, user: user, cfg: cfg}, nil
		}
		slog.Warn("persisted ACME account key not known to CA, registering it", "error", rerr, "persisted_uri", accountURI)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("failed to register with ACME: %w", err)
	}
	user.Registration = reg
	slog.Info("registered with ACME server", "account", reg.URI)

	return &Client{client: client, user: user, cfg: cfg}, nil
}

// AccountKeyPEM returns the PEM-encoded account private key.
func (ac *Client) AccountKeyPEM() []byte { return certcrypto.PEMEncode(ac.user.key) }

// AccountURI returns the account's registration URI, if registered.
func (ac *Client) AccountURI() string {
	if ac.user.Registration == nil {
		return ""
	}
	return ac.user.Registration.URI
}

// ObtainBundle obtains a certificate via DNS-01 challenge using an
// already-registered ACME client and returns it together with the account
// material as a persistable bundle. Does not re-register.
func (ac *Client) ObtainBundle(ctx context.Context) (*certstore.Bundle, error) {
	slog.Info("requesting ACME certificate", "domain", ac.cfg.Domain)

	request := certificate.ObtainRequest{
		Domains: []string{ac.cfg.Domain},
		Bundle:  true,
	}

	certificates, err := ac.client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate: %w", err)
	}

	b := &certstore.Bundle{
		Domain:         ac.cfg.Domain,
		CertificatePEM: certificates.Certificate,
		PrivateKeyPEM:  certificates.PrivateKey,
		AccountKeyPEM:  ac.AccountKeyPEM(),
		AccountURI:     ac.AccountURI(),
		CADirURL:       ac.cfg.CADirURL(),
		IssuedAt:       time.Now().UTC(),
	}
	leaf, err := b.Leaf()
	if err != nil {
		return nil, fmt.Errorf("failed to parse obtained certificate: %w", err)
	}
	b.NotAfter = leaf.NotAfter
	if _, _, err := b.TLSCertificate(); err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	slog.Info("certificate obtained successfully", "domain", ac.cfg.Domain, "not_after", leaf.NotAfter.UTC().Format(time.RFC3339))
	return b, nil
}

// ObtainCertificate obtains a certificate via DNS-01 challenge using
// an already-registered ACME client. Does not re-register.
func (ac *Client) ObtainCertificate(ctx context.Context) (tls.Certificate, string, error) {
	b, err := ac.ObtainBundle(ctx)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return b.TLSCertificate()
}

// ObtainCertificate is a convenience wrapper that creates a new client,
// registers, and obtains a certificate in one call. Use NewClient +
// Client.ObtainCertificate separately if you need to retry without re-registering.
func ObtainCertificate(ctx context.Context, cfg *Config) (tls.Certificate, string, error) {
	slog.Info("obtaining ACME certificate", "domain", cfg.Domain, "provider", cfg.Provider)

	ac, err := NewClient(cfg)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	return ac.ObtainCertificate(ctx)
}

// getDNSProvider returns the appropriate DNS provider based on name.
func getDNSProvider(name string) (*cloudflare.DNSProvider, error) {
	switch name {
	case "cloudflare":
		// Cloudflare provider expects CF_DNS_API_TOKEN (optionally CF_ZONE_API_TOKEN).
		// Legacy email/key auth is also supported by lego via CF_API_EMAIL + CF_API_KEY.
		return cloudflare.NewDNSProvider()
	default:
		return nil, fmt.Errorf("unsupported DNS provider: %s (supported: cloudflare)", name)
	}
}

// computePubKeyHash computes SHA256 hash of the certificate's public key.
func computePubKeyHash(cert *tls.Certificate) string {
	if len(cert.Certificate) == 0 {
		return ""
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return ""
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(pubKeyBytes)
	return hex.EncodeToString(hash[:])
}

// RenewBefore is how long before expiry a certificate is renewed, and the
// minimum remaining validity a persisted certificate needs to be reused.
const RenewBefore = 30 * 24 * time.Hour

// StartRenewalLoop starts a background goroutine that renews the certificate
// in bundle before expiry, persists the new bundle to store and calls
// updateCert with the new certificate and public key hash. The ACME client is
// created lazily at renewal time from the bundle's persisted account key, so
// no new account is registered.
func StartRenewalLoop(ctx context.Context, cfg *Config, store certstore.Store, bundle *certstore.Bundle, updateCert func(tls.Certificate, string)) {
	if store == nil {
		store = certstore.NoopStore{}
	}
	leaf, err := bundle.Leaf()
	if err != nil || leaf.NotAfter.IsZero() {
		slog.Warn("could not determine certificate expiry, renewal loop will not run", "error", err)
		return
	}
	notAfter := leaf.NotAfter
	current := bundle

	go func() {
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				remaining := time.Until(notAfter)
				slog.Info("certificate renewal check", "domain", cfg.Domain, "expires_in", remaining.Round(time.Hour))

				if remaining > RenewBefore {
					continue
				}

				slog.Info("certificate expiring soon, renewing", "domain", cfg.Domain, "expires_in", remaining.Round(time.Hour))
				client, err := NewClientWithAccount(cfg, current.AccountKeyPEM, current.AccountURI)
				if err != nil {
					slog.Error("certificate renewal failed: ACME client", "domain", cfg.Domain, "error", err)
					continue
				}
				newBundle, err := client.ObtainBundle(ctx)
				if err != nil {
					slog.Error("certificate renewal failed", "domain", cfg.Domain, "error", err)
					continue
				}
				newCert, newHash, err := newBundle.TLSCertificate()
				if err != nil {
					slog.Error("certificate renewal produced an unusable bundle", "domain", cfg.Domain, "error", err)
					continue
				}
				if err := store.Save(ctx, newBundle); err != nil {
					slog.Error("failed to persist renewed certificate; it will be re-issued on next restart", "domain", cfg.Domain, "error", err)
				} else {
					slog.Info("renewed certificate persisted", "domain", cfg.Domain)
				}

				current = newBundle
				notAfter = newBundle.NotAfter
				slog.Info("certificate renewed", "domain", cfg.Domain, "new_hash", newHash, "not_after", notAfter.UTC().Format(time.RFC3339))
				updateCert(newCert, newHash)
			}
		}
	}()
}

// errNoBundle is used internally when nothing usable could be produced.
var errNoBundle = errors.New("acme: no certificate available")
