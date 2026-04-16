// Package server provides the HTTP server and handlers.
package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/openanonymity/oa-verifier/internal/acme"
	"github.com/openanonymity/oa-verifier/internal/banned"
	"github.com/openanonymity/oa-verifier/internal/challenge"
	"github.com/openanonymity/oa-verifier/internal/models"
)

// Server holds all server state.
type Server struct {
	mu            sync.RWMutex
	stations      map[string]*models.Station // pk -> Station
	emailToPK     map[string]string          // email -> pk
	stationIDToPK map[string]string          // station_id -> pk
	opFailureMu   sync.Mutex
	opFailure     map[string]int // "<identity>|<operation>" -> consecutive failures

	banned *banned.Manager

	// Cached org public key (TTL-based)
	orgPKMu      sync.RWMutex
	orgPK        string
	orgPKFetched time.Time

	attestationEnabled bool

	// TLS certificate and public key hash, swappable for ACME renewal.
	tlsCertMu     sync.RWMutex
	tlsCert       *tls.Certificate
	tlsPubKeyHash string
}

const orgPKTTL = 10 * time.Minute

// New creates a new Server.
func New(attestationEnabled bool) *Server {
	return &Server{
		stations:           make(map[string]*models.Station),
		emailToPK:          make(map[string]string),
		stationIDToPK:      make(map[string]string),
		opFailure:          make(map[string]int),
		banned:             banned.NewManager(),
		attestationEnabled: attestationEnabled,
	}
}

// Router returns the chi router with all routes.
func (s *Server) Router() chi.Router {
	r := chi.NewRouter()

	// Middleware (order matters)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(corsMiddleware)
	r.Use(rateLimitMiddleware) // Rate limit all routes including /health

	// CPU-heavy endpoints get additional concurrency limiting
	r.With(concurrencyLimitMiddleware).Post("/register", s.handleRegister)
	r.With(concurrencyLimitMiddleware).Post("/submit_key", s.handleSubmitKey)

	// Other routes
	r.Get("/health", s.handleHealth)
	r.Get("/station/{public_key}", s.handleGetStation)
	r.Get("/broadcast", s.handleBroadcast)
	r.Get("/banned-stations", s.handleBannedStations)
	r.Delete("/banned-stations/{station_id}", s.handleUnbanStation)
	r.Delete("/banned-stations", s.handleClearBanned)
	r.Post("/reload-config", s.handleReloadConfig)

	// Attestation endpoints - prove this runs in a Confidential VM
	if s.attestationEnabled {
		r.Get("/attestation", s.handleAttestation)
		r.Get("/attestation/raw", s.handleAttestationRaw)
	}

	return r
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Run starts the HTTP server.
func (s *Server) Run(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Router(),
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Start verification loop in separate goroutine
	go s.verificationLoop(ctx)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	slog.Info("starting server", "addr", addr)
	return srv.ListenAndServe()
}

// RunTLS starts HTTPS.
// If ACME is configured (TLS_DOMAIN, ACME_EMAIL, ACME_DNS_PROVIDER), obtains a Let's Encrypt certificate.
// Otherwise, generates a self-signed certificate.
// TLS terminates at this server (inside the enclave), not at Azure.
func (s *Server) RunTLS(ctx context.Context, addr string) error {
	var cert tls.Certificate
	var pubKeyHash string
	var err error
	var certType string

	// Try ACME first if configured
	acmeCfg := acme.LoadConfig()
	if acmeCfg.IsEnabled() {
		slog.Info("ACME configured, obtaining Let's Encrypt certificate",
			"domain", acmeCfg.Domain,
			"provider", acmeCfg.Provider)

		// Register once with ACME server (avoids rate limit on re-registration).
		const maxRegRetries = 10
		const regRetryDelay = 3 * time.Minute
		var acmeClient *acme.Client
		for attempt := 1; ; attempt++ {
			acmeClient, err = acme.NewClient(acmeCfg)
			if err == nil {
				break
			}
			if attempt >= maxRegRetries {
				slog.Error("ACME registration failed after all retries",
					"attempts", maxRegRetries, "error", err)
				break
			}
			slog.Warn("ACME registration failed, retrying",
				"attempt", attempt, "max_retries", maxRegRetries, "error", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(regRetryDelay):
			}
		}

		if acmeClient != nil {
			// Obtain certificate (retries don't re-register).
			const maxCertRetries = 5
			const certRetryDelay = 15 * time.Second
			for attempt := 1; ; attempt++ {
				cert, pubKeyHash, err = acmeClient.ObtainCertificate(ctx)
				if err == nil {
					break
				}
				if attempt >= maxCertRetries {
					slog.Error("ACME certificate failed after all retries",
						"attempts", maxCertRetries, "error", err)
					break
				}
				slog.Warn("ACME certificate attempt failed, retrying",
					"attempt", attempt, "max_retries", maxCertRetries, "error", err)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(certRetryDelay):
				}
			}
		}

		if err != nil {
			slog.Error("ACME certificate failed, falling back to self-signed", "error", err)
			cert, pubKeyHash, err = generateSelfSignedCert()
			if err != nil {
				return err
			}
			certType = "self-signed (ACME fallback)"
		} else {
			certType = "Let's Encrypt"
			// Start renewal loop — callback swaps the live cert under a mutex.
			acme.StartRenewalLoop(ctx, acmeCfg, acmeClient, cert, func(newCert tls.Certificate, newHash string) {
				s.tlsCertMu.Lock()
				s.tlsCert = &newCert
				s.tlsPubKeyHash = newHash
				s.tlsCertMu.Unlock()
			})
		}
	} else {
		cert, pubKeyHash, err = generateSelfSignedCert()
		if err != nil {
			return err
		}
		certType = "self-signed"
	}

	// Store initial certificate behind mutex for hot-reload support.
	s.tlsCertMu.Lock()
	s.tlsCert = &cert
	s.tlsPubKeyHash = pubKeyHash
	s.tlsCertMu.Unlock()

	customDomain := os.Getenv("TLS_DOMAIN")
	slog.Info("TLS certificate ready",
		"type", certType,
		"pubkey_hash", pubKeyHash,
		"domain", customDomain)

	tlsSrv := &http.Server{
		Addr:              addr,
		Handler:           s.Router(),
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				s.tlsCertMu.RLock()
				defer s.tlsCertMu.RUnlock()
				return s.tlsCert, nil
			},
			MinVersion: tls.VersionTLS12,
		},
	}

	go s.verificationLoop(ctx)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tlsSrv.Shutdown(shutdownCtx)
	}()

	slog.Info("starting HTTPS server", "addr", addr, "cert_type", certType)
	return tlsSrv.ListenAndServeTLS("", "")
}

// generateSelfSignedCert creates a self-signed TLS certificate valid for 1 year.
// Returns the certificate and the SHA256 hash of the public key (for channel binding).
func generateSelfSignedCert() (tls.Certificate, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}

	// Get custom domain from environment, or use defaults
	dnsNames := []string{
		"localhost",
		"*.azurecontainer.io",
	}
	if customDomain := os.Getenv("TLS_DOMAIN"); customDomain != "" {
		dnsNames = append(dnsNames, customDomain)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"OA Verifier Enclave"},
			CommonName:   "Confidential Enclave",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	// Compute SHA256 hash of the public key for TLS channel binding
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	pubKeyHash := sha256.Sum256(pubKeyBytes)
	pubKeyHashHex := hex.EncodeToString(pubKeyHash[:])

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, pubKeyHashHex, nil
}

// getTLSPubKeyHash returns the current TLS public key hash (thread-safe).
func (s *Server) getTLSPubKeyHash() string {
	s.tlsCertMu.RLock()
	defer s.tlsCertMu.RUnlock()
	return s.tlsPubKeyHash
}

// Helper functions

func (s *Server) getNextChallengeTime() time.Time {
	return time.Now().Add(time.Duration(challenge.GetRandomInterval()) * time.Second)
}

func utcNow() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func validatePublicKey(pkHex string) bool {
	if len(pkHex) != 64 {
		return false
	}
	_, err := hex.DecodeString(pkHex)
	return err == nil
}

func generateProvLabel(stationID string) string {
	sum := sha256.Sum256([]byte(stationID))
	return hex.EncodeToString(sum[:])[:16]
}

func extractEmail(data map[string]any) string {
	if email, ok := data["email"].(string); ok {
		return email
	}
	return ""
}

// mergeToggleData combines user data and workspace data into a single map
// for privacy toggle checking. Workspace-level toggles (like
// is_data_discount_logging_enabled) are only in workspace data.
func mergeToggleData(userData, workspaceData map[string]any) map[string]any {
	merged := make(map[string]any, len(userData)+len(workspaceData))
	for k, v := range userData {
		merged[k] = v
	}
	for k, v := range workspaceData {
		if _, exists := merged[k]; !exists {
			merged[k] = v
		}
	}
	return merged
}

func verifyEd25519Signature(publicKeyHex, message, signatureHex string) bool {
	pubKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return false
	}

	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}

	return ed25519.Verify(pubKeyBytes, []byte(message), sigBytes)
}

func computeKeyHash(apiKey string) string {
	h := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(h[:])
}
