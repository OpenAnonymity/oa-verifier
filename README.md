# OA-Verifier

Zero-trust verification service running in Azure Confidential Containers with AMD SEV-SNP hardware attestation.

## Features

- **Hardware-backed attestation**: Runs in AMD SEV-SNP enclave with Microsoft Azure Attestation
- **Zero-trust verification**: Users can cryptographically verify the running code
- **Sigstore provenance**: Container images are signed with GitHub Actions OIDC
- **Reproducible builds**: Nix flake for bit-for-bit reproducible builds

## Verification

Users can verify the service is running the expected code using two paths:

### Fast Path (Sigstore)

For users who trust GitHub Actions:

```bash
# Install the verifier
cargo install --git https://github.com/openanonymity/oa-verifier oa-verify

# Verify the service
oa-verify --url https://oa-verifier.eastus.azurecontainer.io
# Or use the web interface
# https://openanonymity.github.io/oa-verifier/
```

### Paranoid Path (Nix)

For users who trust only the source code:

```bash
# Build from source (produces identical hash)
nix build .#container

# Compare hash to attestation
# The policy hash in the attestation should match
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TRUST CHAIN                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Source Code (GitHub)                                                       │
│      ↓                                                                       │
│  GitHub Actions Build (Sigstore signed)                                      │
│      ↓                                                                       │
│  Container Image (GHCR + ACR)                                                │
│      ↓                                                                       │
│  CCE Policy (specifies allowed container)                                    │
│      ↓                                                                       │
│  Policy Hash (measured by AMD SEV-SNP)                                       │
│      ↓                                                                       │
│  Azure MAA Attestation (signed JWT)                                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/attestation` | GET | Get hardware attestation (JWT from Azure MAA) |
| `/register` | POST | Register station with Ed25519 public key |
| `/submit_key` | POST | Submit double-signed API key |
| `/broadcast` | GET | Get verified and banned stations |
| `/banned-stations` | GET | Get banned station list |

## Development

### Prerequisites

```bash
# Go 1.22+
go version

# Rust (for verifier)
rustc --version

# Or use Nix
nix develop
```

### Build

```bash
# Server
go build -o verifier ./cmd/verifier

# Verifier CLI
cd verifier && cargo build --release
```

### With Nix (Reproducible)

```bash
# Build everything
nix build .#server     # Go server
nix build .#container  # Docker image

# Development shell
nix develop
```

## Deployment

The service is deployed via GitHub Actions:

1. Push to `main` triggers build
2. Container is built and signed with Sigstore
3. Pushed to GHCR and ACR
4. Manual trigger deploys to Azure ACI

See [deploy/README.md](deploy/README.md) for details.

## Security Model

| What | Who Controls | Verification |
|------|--------------|--------------|
| Source Code | Public (GitHub) | You audit it |
| Build Process | GitHub Actions | Sigstore signature |
| Container | GHCR/ACR | Same digest |
| Runtime | Azure SEV-SNP | MAA attestation |

## Module Structure

| Path | Purpose |
|------|---------|
| `cmd/verifier/` | Server entry point |
| `internal/` | Core packages (server, config, models, banned, challenge, registry, openrouter) |
| `verifier/` | Rust verifier CLI + WASM |
| `deploy/` | Azure deployment templates |
| `.github/workflows/` | CI/CD pipelines |

## License

MIT
