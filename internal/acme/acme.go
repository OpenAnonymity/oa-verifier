// Package acme provides ACME DNS-01 certificate management for Let's Encrypt.
package acme

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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
)

// Config holds ACME configuration from environment variables.
type Config struct {
	Domain   string // TLS_DOMAIN
	Email    string // ACME_EMAIL
	Provider string // ACME_DNS_PROVIDER (cloudflare, etc.)
}

// LoadConfig reads ACME configuration from environment.
func LoadConfig() *Config {
	return &Config{
		Domain:   os.Getenv("TLS_DOMAIN"),
		Email:    os.Getenv("ACME_EMAIL"),
		Provider: os.Getenv("ACME_DNS_PROVIDER"),
	}
}

// IsEnabled returns true if ACME is properly configured.
func (c *Config) IsEnabled() bool {
	return c.Domain != "" && c.Email != "" && c.Provider != ""
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

// NewClient creates an ACME client, generates an account key, and registers
// with the ACME server. The returned Client can be reused for multiple
// ObtainCertificate calls without re-registering (avoiding rate limits).
func NewClient(cfg *Config) (*Client, error) {
	privateKey, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate account key: %w", err)
	}

	user := &User{
		Email: cfg.Email,
		key:   privateKey,
	}

	config := lego.NewConfig(user)
	config.Certificate.KeyType = certcrypto.EC256

	if os.Getenv("ACME_STAGING") == "true" {
		config.CADirURL = lego.LEDirectoryStaging
		slog.Info("using Let's Encrypt staging environment")
	} else {
		config.CADirURL = lego.LEDirectoryProduction
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

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("failed to register with ACME: %w", err)
	}
	user.Registration = reg
	slog.Info("registered with ACME server")

	return &Client{client: client, user: user, cfg: cfg}, nil
}

// ObtainCertificate obtains a certificate via DNS-01 challenge using
// an already-registered ACME client. Does not re-register.
func (ac *Client) ObtainCertificate(ctx context.Context) (tls.Certificate, string, error) {
	slog.Info("requesting ACME certificate", "domain", ac.cfg.Domain)

	request := certificate.ObtainRequest{
		Domains: []string{ac.cfg.Domain},
		Bundle:  true,
	}

	certificates, err := ac.client.Certificate.Obtain(request)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to obtain certificate: %w", err)
	}

	slog.Info("certificate obtained successfully", "domain", ac.cfg.Domain)

	cert, err := tls.X509KeyPair(certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	pubKeyHash := computePubKeyHash(&cert)
	return cert, pubKeyHash, nil
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

// StartRenewalLoop starts a background goroutine that renews the certificate
// before expiry and calls updateCert with the new certificate and public key hash.
// It uses the provided Client to avoid re-registering with the ACME server.
func StartRenewalLoop(ctx context.Context, cfg *Config, acmeClient *Client, cert tls.Certificate, updateCert func(tls.Certificate, string)) {
	// Parse leaf to get expiry time.
	var notAfter time.Time
	if len(cert.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			notAfter = leaf.NotAfter
		}
	}
	if notAfter.IsZero() {
		slog.Warn("could not determine certificate expiry, renewal loop will not run")
		return
	}

	go func() {
		const renewBefore = 30 * 24 * time.Hour // renew 30 days before expiry
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				remaining := time.Until(notAfter)
				slog.Info("certificate renewal check", "domain", cfg.Domain, "expires_in", remaining.Round(time.Hour))

				if remaining > renewBefore {
					continue
				}

				slog.Info("certificate expiring soon, renewing", "domain", cfg.Domain, "expires_in", remaining.Round(time.Hour))
				newCert, newHash, err := acmeClient.ObtainCertificate(ctx)
				if err != nil {
					slog.Error("certificate renewal failed", "domain", cfg.Domain, "error", err)
					continue
				}

				// Update expiry for next check.
				if len(newCert.Certificate) > 0 {
					if leaf, err := x509.ParseCertificate(newCert.Certificate[0]); err == nil {
						notAfter = leaf.NotAfter
					}
				}

				slog.Info("certificate renewed", "domain", cfg.Domain, "new_hash", newHash)
				updateCert(newCert, newHash)
			}
		}
	}()
}
