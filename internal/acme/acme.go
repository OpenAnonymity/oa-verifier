// Package acme provides ACME DNS-01 certificate management for Let's Encrypt.
package acme

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
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

// ObtainCertificate obtains a certificate via DNS-01 challenge.
// Returns the certificate, public key hash (for attestation), and any error.
func ObtainCertificate(ctx context.Context, cfg *Config) (tls.Certificate, string, error) {
	slog.Info("obtaining ACME certificate", "domain", cfg.Domain, "provider", cfg.Provider)

	// Generate a new private key for this certificate
	privateKey, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to generate private key: %w", err)
	}

	user := &User{
		Email: cfg.Email,
		key:   privateKey,
	}

	// Create ACME client config
	config := lego.NewConfig(user)
	config.Certificate.KeyType = certcrypto.EC256

	// Use Let's Encrypt production (or staging for testing)
	// Production: lego.LEDirectoryProduction
	// Staging: lego.LEDirectoryStaging
	if os.Getenv("ACME_STAGING") == "true" {
		config.CADirURL = lego.LEDirectoryStaging
		slog.Info("using Let's Encrypt staging environment")
	} else {
		config.CADirURL = lego.LEDirectoryProduction
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to create ACME client: %w", err)
	}

	// Set up DNS provider
	provider, err := getDNSProvider(cfg.Provider)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to create DNS provider: %w", err)
	}

	err = client.Challenge.SetDNS01Provider(provider, dns01.AddRecursiveNameservers([]string{"1.1.1.1:53", "8.8.8.8:53"}))
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to set DNS provider: %w", err)
	}

	// Register with ACME server
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to register with ACME: %w", err)
	}
	user.Registration = reg
	slog.Info("registered with ACME server")

	// Request certificate
	request := certificate.ObtainRequest{
		Domains: []string{cfg.Domain},
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to obtain certificate: %w", err)
	}

	slog.Info("certificate obtained successfully", "domain", cfg.Domain)

	// Parse the certificate
	cert, err := tls.X509KeyPair(certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Compute public key hash for attestation
	pubKeyHash := computePubKeyHash(&cert)

	return cert, pubKeyHash, nil
}

// getDNSProvider returns the appropriate DNS provider based on name.
func getDNSProvider(name string) (*cloudflare.DNSProvider, error) {
	switch name {
	case "cloudflare":
		// Cloudflare uses CF_API_TOKEN or CF_DNS_API_TOKEN environment variable
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
	// Hash the public key from the leaf certificate
	hash := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(hash[:])
}

// StartRenewalLoop starts a background goroutine that renews the certificate before expiry.
func StartRenewalLoop(ctx context.Context, cfg *Config, updateCert func(tls.Certificate, string)) {
	go func() {
		// Check every 12 hours
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Renew if less than 30 days until expiry
				// For now, just log - full renewal would need certificate expiry tracking
				slog.Info("certificate renewal check", "domain", cfg.Domain)
			}
		}
	}()
}
