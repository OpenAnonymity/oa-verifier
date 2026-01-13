// Enclave Verifier - Secure station verification with key-based identity.
//
// Endpoints:
//
//	POST /register - Register station with Ed25519 public key and cookie
//	POST /submit_key - Submit double-signed API key for ownership verification
//	GET /station/{public_key} - Get station info
//	GET /broadcast - Get all verified stations
//
// Security:
//   - Three-way binding: station_id (registry) <-> email (cookie) <-> public_key (station)
//   - Anti-Squatting: Email extracted server-side from cookie
//   - Identity Migration: Same email can move to new key (device recovery)
//   - DoS Protection: Verification runs internally, not via public endpoint
//   - No /update endpoint: Cookie changes require re-registration to re-verify binding
//
// Concurrency:
//   - HTTP handlers run in separate goroutines (net/http)
//   - Verification loop runs in a dedicated goroutine
//   - True parallelism: thousands of /submit_key requests won't slow down verification
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/oa-verifier/internal/server"
)

func main() {
	// Parse command-line flags
	attestation := flag.Bool("attestation", true, "Enable attestation endpoints (requires Azure CC sidecar)")
	flag.Parse()

	// Setup structured logging
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	// Create server
	srv := server.New(*attestation)

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	// Run server with TLS on port 443
	// TLS terminates inside the enclave (not at Azure)
	slog.Info("starting Enclave Verifier with TLS", "port", 443, "attestation", *attestation)
	err := srv.RunTLS(ctx)

	if err != nil && err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}

	slog.Info("server stopped")
}




