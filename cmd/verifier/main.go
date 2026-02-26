// Enclave Verifier - Secure station verification with key-based identity.
//
// Docstream:
//
// Endpoints:
// - POST /register: Register station with Ed25519 public key and cookie.
// - POST /submit_key: Submit double-signed API key for ownership verification.
// - GET /station/{public_key}: Get station info.
// - GET /broadcast: Get all verified stations.
//
// Security & Verification Flow:
//   - Registration input includes station public key + OpenRouter session cookie.
//   - Verifier fetches provider account-state using the cookie and extracts email
//     server-side (not from station self-assertion), then enforces:
//     station_id <-> email <-> public_key.
//   - Verifier requests OpenRouter to issue a management key (called provisioning
//     key in code) on the station operator's account for ownership checks.
//     This key is hosted by OpenRouter, not the verifier; station does not
//     provide this key.
//   - Required privacy toggles are enforced as false on provider account-state:
//     enable_logging, enable_training, enable_free_model_training,
//     enable_free_model_publication, enforce_zdr, always_enforce_allowed,
//     is_broadcast_enabled.
//   - `/submit_key` validates station+org signatures as anti-forgery binding inputs,
//     then verifies submitted key ownership against provider account state via
//     OpenRouter API:
//     https://openrouter.ai/docs/api/api-reference/api-keys/get-key
//   - Broadcast toggle reference:
//     https://openrouter.ai/docs/guides/features/broadcast/overview#enabling-broadcast
//   - No public challenge trigger endpoint: periodic verification is internal.
//   - No /update endpoint: Cookie changes require re-registration to re-verify binding.
//
// Trust Model:
//   - Verifier role: station compliance enforcement, not end-user prompt transport.
//   - End-user prompt/response traffic is client -> provider (`oa-fastchat` ->
//     OpenRouter), and does not transit verifier handlers.
//   - Verifier independently checks provider account-state and
//     key ownership/signature constraints; station/org inputs are validated as
//     anti-forgery evidence, not blindly trusted.
//   - To avoid trusting submitter assertions, verifier cross-checks anti-forgery
//     evidence from registry records, org signature/public-key material, and
//     provider-exposed account-state APIs.
//   - These are verification evidence inputs, not blind-trust authorities.
//
// Scope:
// - This entrypoint wires runtime mode and lifecycle only.
// - Enforcement logic lives in `internal/server` and `internal/challenge`.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/openanonymity/oa-verifier/internal/server"
)

func main() {
	// Parse command-line flags
	attestation := flag.Bool("attestation", true, "Enable attestation endpoints (requires Azure CC sidecar)")
	httpMode := flag.Bool("http", false, "Run in HTTP mode instead of HTTPS (for local development)")
	port := flag.String("port", "", "Port to listen on (default: 8080 for HTTP, 443 for HTTPS)")
	local := flag.Bool("local", false, "Local development mode (implies -http -attestation=false)")
	flag.Parse()

	// Local mode overrides
	if *local {
		*httpMode = true
		*attestation = false
	}

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

	// Determine address
	addr := *port
	if addr == "" {
		if *httpMode {
			addr = ":8080"
		} else {
			addr = ":443"
		}
	} else {
		addr = ":" + addr
	}

	// Run server
	var err error
	if *httpMode {
		slog.Info("starting Enclave Verifier with HTTP", "addr", addr, "attestation", *attestation)
		err = srv.Run(ctx, addr)
	} else {
		// TLS terminates inside the enclave (not at Azure)
		slog.Info("starting Enclave Verifier with TLS", "addr", addr, "attestation", *attestation)
		err = srv.RunTLS(ctx, addr)
	}

	if err != nil && err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}

	slog.Info("server stopped")
}
