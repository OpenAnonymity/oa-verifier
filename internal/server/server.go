// Package server provides the HTTP server and handlers.
package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/crypto/ed25519"

	"github.com/oa-verifier/internal/banned"
	"github.com/oa-verifier/internal/challenge"
	"github.com/oa-verifier/internal/config"
	"github.com/oa-verifier/internal/models"
)

// Server holds all server state.
type Server struct {
	mu            sync.RWMutex
	stations      map[string]*models.Station // pk -> Station
	emailToPK     map[string]string          // email -> pk
	stationIDToPK map[string]string          // station_id -> pk

	banned *banned.Manager

	// Cached org public key (TTL-based)
	orgPKMu      sync.RWMutex
	orgPK        string
	orgPKFetched time.Time
}

const orgPKTTL = 10 * time.Minute

// New creates a new Server.
func New() *Server {
	return &Server{
		stations:      make(map[string]*models.Station),
		emailToPK:     make(map[string]string),
		stationIDToPK: make(map[string]string),
		banned:        banned.NewManager(),
	}
}

// Router returns the chi router with all routes.
func (s *Server) Router() chi.Router {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(corsMiddleware)

	// Routes
	r.Post("/register", s.handleRegister)
	r.Post("/submit_key", s.handleSubmitKey)
	r.Get("/station/{public_key}", s.handleGetStation)
	r.Get("/broadcast", s.handleBroadcast)
	r.Get("/banned-stations", s.handleBannedStations)
	r.Post("/reload-config", s.handleReloadConfig)

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
		Addr:    addr,
		Handler: s.Router(),
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
	mac := hmac.New(sha256.New, config.ProvisioningKeySalt())
	mac.Write([]byte(stationID))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

func extractEmail(data map[string]any) string {
	if email, ok := data["email"].(string); ok {
		return email
	}
	return ""
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




