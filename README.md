# OA-Verifier

A station verification service for enforcing station compliance and proving runtime integrity in confidential runtimes (Azure ACI Confidential Containers).

## What It Does

OA-Verifier provides verifier-side evidence and enforcement for station governance:

- **The exact runtime policy measured** - via attested CCE policy hash
- **No runtime tampering of measured policy path** - via AMD SEV-SNP attestation
- **Station compliance enforcement** - via toggle checks and ownership/signature verification

## Trust Model

- Verifier role: station compliance enforcer, not prompt/response transport.
- Prompt/response path: end user client -> provider.
- Governance path: station registration, signature checks, toggle checks.
- Required anti-forgery verification inputs: registry station authorization,
  org signature/public-key path, provider account-state APIs.

See:

- [Trust Model](docs/TRUST_MODEL.md)

### Supported Station Types

| Station Type | Verification |
|-------------|--------------|
| **OpenRouter Stations** | Privacy toggles, API key ownership, account binding |
| *Future Station Types* | Planned extension for other provider/enclave-based services |

## Verification

Anyone can verify the service is running expected code:

### Quick Verification

```bash
# Fetch attestation from live service
curl -sS "https://verifier.openanonymity.ai/attestation?nonce=$(date +%s)" | jq .summary

# Returns hardware-signed proof including:
# - cce_policy_hash: SHA256 of the container policy (what code can run)
# - attestation_type: sevsnpvm (AMD SEV-SNP)
# - debug_disabled: true (no debugging possible)
```

### Full Verification (Zero-Trust)

```bash
# Clone and run local verification script
git clone https://github.com/openanonymity/oa-verifier
cd oa-verifier
./scripts/verify-local.sh https://verifier.openanonymity.ai
```

This rebuilds the container locally with Nix and compares the policy hash against what Azure hardware attests.
For strict zero-trust conclusions, also verify the JWT signature using the `verify_at` key endpoint returned by `/attestation`.

### Recheck the shared deployment without restarting it

Run **Verify Attestation (Source → Deployed)** (`verify-attestation.yml`) manually
with `source_revision` set to the full commit SHA used by the deployment. Select
the branch containing the verification workflow you want to run; the source is
checked out separately at the supplied revision. Do not rerun **Build, Sign, and
Deploy** merely to repeat verification: that workflow can replace the live group.

The verification workflow targets the shared `oa-verifier-2` group only. It uses
the existing Azure and registry credentials to read the deployed immutable image
reference and pull identity, rebuild the specified source, compare Docker image
IDs, regenerate the deployment policy, and compare its hash to the signed Azure
attestation claim after checking the signature, nonce, issuer, and validity time.
It never creates, deletes, or restarts Azure resources. This does not test
OpenRouter login or station registration.

Post-deployment verification calls this same workflow. It no longer passes image
references through cross-job outputs, which GitHub can suppress when values
match a secret. Missing or unexpected deployment metadata fails verification;
there is no fallback to a registry's `latest` tag. The daily check uses the
current main commit, so a deployment that lags main can report a mismatch.
The previous arbitrary `service_url` input is removed because other deployments
can have different policies and need their own verification configuration.

## Trust Chain

```
Source Code (this repo)
    ↓ [Nix reproducible build]
Container Image (deterministic hash)
    ↓ [CCE policy generated from image]
Policy Hash (SHA256 of allowed container config)
    ↓ [Measured by AMD SEV-SNP hardware]
Attestation JWT (signed by Azure MAA)
    ↓ [Verifiable by anyone]
Proof: "This exact code is running in an isolated enclave"
```

## API

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/attestation` | GET | Hardware attestation JWT with policy hash |
| `/attestation/raw` | GET | JSON response containing `token` |
| `/broadcast` | GET | List of verified and banned stations |

### Station Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/register` | POST | Register station with Ed25519 public key |
| `/submit_key` | POST | Submit double-signed API key for verification |
| `/station/{public_key}` | GET | Get station info by public key |
| `/banned-stations` | GET | List banned stations |

## Security Model

| Layer | Protection | Verification |
|-------|------------|--------------|
| **Source** | Public, auditable | You read it |
| **Build** | Nix reproducible | Rebuild locally |
| **Image** | Sigstore signed | `cosign verify` |
| **Runtime** | AMD SEV-SNP enclave | MAA attestation |
| **Network** | TLS terminates in enclave | Channel binding hash |

### What The Enclave Guarantees

- **Memory isolation**: Hypervisor cannot read enclave memory
- **No stdio**: Container cannot write to stdout/stderr (policy enforced)
- **No debugging**: Debug mode disabled in hardware
- **Measured boot**: Only the attested container can run
- **TLS channel binding**: The TLS certificate is generated inside the enclave and its public key hash is included in the hardware attestation. This means MITM is impossible -- you can verify the TLS public key hash from `/attestation` matches the certificate presented by the server, proving your connection terminates inside the attested enclave

## Development

Toolchain: `go.mod` declares Go 1.22.0 as the minimum language version.
This rollout retains the existing nixos-24.05 lock and toolchain. The Go 1.24
upgrade is deferred to a separate change with a generated, committed lock
and a verified container build; this does not resolve the older toolchain's
support status.

```bash
# Build server
go build -o oa-verifier ./cmd/verifier

# Test (the race detector covers the failure tracker and rate limiters)
go vet ./... && go test -race ./...

# Run locally (without attestation)
./oa-verifier -local

# Run with attestation (requires Azure environment)
./oa-verifier -attestation
```

### Reproducible Build (Nix)

`flake.nix` and `flake.lock` agree on nixpkgs `nixos-24.05`; the lock pins
its exact revision. CI uses `--no-update-lock-file` for both development
shells and builds so an inconsistent lock fails instead of silently floating.
Change the input and regenerate/commit the lock together when upgrading.
`vendorHash` covers the vendored module tree (derived from `go.mod`/`go.sum`),
not the toolchain, so it only changes when dependencies change; on a mismatch
the build fails and prints the expected hash.

```bash
# Build container with deterministic hash
nix build --no-update-lock-file .#container

# Load and inspect
docker load < result
docker inspect oa-verifier:latest
```

## Deployment

See [deploy/README.md](deploy/README.md) for details.

## Configuration

| Variable | Description |
|----------|-------------|
| `MAA_ENDPOINT` | Azure MAA sidecar endpoint |
| `STATION_REGISTRY_URL` | Station registry service |
| `STATION_REGISTRY_SECRET` | Registry auth secret |
| `TLS_DOMAIN` | Custom domain for Let's Encrypt |
| `CHALLENGE_MIN_INTERVAL` | Min seconds between privacy checks |
| `CHALLENGE_MAX_INTERVAL` | Max seconds between privacy checks |
| `SUBMIT_KEY_OWNERSHIP_GRACE_SECONDS` | Grace window for ownership checks |
| `STATION_FAILURE_GRACE_SECONDS` | Grace window before unregistering on transient failures |
| `RATE_LIMIT_RPS` / `RATE_LIMIT_BURST` | General per-IP rate limit, all routes (default 10 rps, burst 20) |
| `MAX_CONCURRENT_REQUESTS` | Concurrent `/register` + `/submit_key` handlers (default 20) |
| `ATTEST_RATE_LIMIT_RPS` / `ATTEST_RATE_LIMIT_BURST` | Per-IP limit for `/attestation*` (default 1 rps, burst 3); each request costs a sidecar attestation |
| `ATTEST_GLOBAL_RPS` | Global limit for `/attestation*` across all clients (default 5 rps) |
| `FAILURE_TRACK_MAX` | Max tracked `<identity>\|<operation>` consecutive-failure counters (default 10000, LRU eviction) |
| `FAILURE_TRACK_TTL` | Idle expiry of those counters, Go duration or seconds (default `24h`) |

Every variable the container reads must also appear in `required_env_vars` or
`optional_env_vars` of the "Generate CCE policy" step in
`.github/workflows/build-and-sign.yml`; the confidential-computing policy rejects
any other environment variable and the container will not start.

## Documentation

- [Trust Model](docs/TRUST_MODEL.md) - Role boundaries, data flow, guarantees/non-goals, unlinkability model
- [Attestation Deep Dive](docs/ATTESTATION.md) - How zero-trust verification works
- [Deployment Guide](deploy/README.md) - CI/CD and Azure setup

## License

GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).
