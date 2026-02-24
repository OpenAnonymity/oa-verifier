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
| **Proxy Stations** | Enclave attestation proving no-logging guarantees |
| *Future* | Extensible for other enclave-based services |

## Verification

Anyone can verify the service is running expected code:

### Quick Verification

```bash
# Fetch attestation from live service
curl -sk https://oa-verifier.eastus.azurecontainer.io/attestation | jq .summary

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
./scripts/verify-local.sh https://oa-verifier.eastus.azurecontainer.io
```

This rebuilds the container locally with Nix and compares the policy hash against what Azure hardware attests.

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
| `/attestation/raw` | GET | Raw JWT token only |
| `/broadcast` | GET | List of verified and banned stations |

### Station Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/register` | POST | Register station with Ed25519 public key |
| `/submit_key` | POST | Submit double-signed API key for verification |
| `/station/{pk}` | GET | Get station info by public key |
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

## Development

```bash
# Build server
go build -o oa-verifier ./cmd/verifier

# Run locally (without attestation)
./oa-verifier -local

# Run with attestation (requires Azure environment)
./oa-verifier -attestation
```

### Reproducible Build (Nix)

```bash
# Build container with deterministic hash
nix build .#container

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

## Documentation

- [Trust Model](docs/TRUST_MODEL.md) - Role boundaries, data flow, guarantees/non-goals, unlinkability model
- [Attestation Deep Dive](docs/ATTESTATION.md) - How zero-trust verification works
- [Deployment Guide](deploy/README.md) - CI/CD and Azure setup

## License

GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).
