# Zero-Trust Attestation & Verification Guide

This document explains how to verify that OA-Verifier is running exactly the code
published in this repository using zero-trust verification (verify evidence, do not
blindly trust operators).

## Table of Contents

- [Overview](#overview)
- [Key Concepts](#key-concepts)
- [Parties Involved](#parties-involved)
- [Hash Types](#hash-types)
- [The Trust Chain](#the-trust-chain)
- [Complete Zero-Trust Verification](#complete-zero-trust-verification)
- [Quick Verification](#quick-verification)
- [What The Attestation Proves](#what-the-attestation-proves)
- [FAQ](#faq)

---

## Overview

The OA-Verifier runs inside an **Azure Confidential Container** using AMD SEV-SNP hardware. The `/attestation` endpoint returns:

1. **JWT Token** - Signed by Azure Attestation Service, contains hardware measurements
2. **CCE Policy** - The exact policy enforced by hardware (what containers can run)
3. **Summary** - Key claims extracted for convenience

The hardware measures the policy at boot and stores its hash in a tamper-proof register. This hash (`host_data`) proves exactly which container configuration is running.

---

## Boundary Scope (Attestation vs Trust Model)

Attestation evidence in this file proves runtime/policy integrity properties of verifier deployment.
It does not by itself prove all operational governance semantics or external system claims.

Use these alongside this guide:

- [Trust Model](TRUST_MODEL.md)

Boundary notes:

1. Attestation summary decode is not full cryptographic verification by itself.
2. Governance/control decisions still use required anti-forgery verification inputs
   (registry/org/provider APIs) to prevent forged/misattributed key submissions that
   could wrongly penalize a genuine station.
3. Ticket unlinkability claims are external system context and are not verifier-runtime-only claims.

---

## Key Concepts

| Term | Definition |
|------|------------|
| **AMD SEV-SNP** | Hardware security feature that isolates container memory from the host |
| **CCE Policy** | Confidential Compute Enforcement policy - a Rego file defining allowed containers |
| **host_data** | Hardware-measured SHA256 hash of the CCE policy |
| **Manifest Digest** | SHA256 of container manifest (used by registries like GHCR) |
| **Image ID** | SHA256 of container config (used locally by Docker) |
| **Attestation JWT** | Cryptographic proof signed by Azure containing hardware measurements |

---

## Parties Involved

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              PARTIES                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  GITHUB                 Source code repository                              │
│  └─ Actions             Builds container with Nix (reproducible)            │
│                                                                              │
│  GHCR                   GitHub Container Registry                           │
│  └─ Stores              Container images with manifest digests              │
│                                                                              │
│  AZURE                                                                       │
│  ├─ Container Instances Runs the container in TEE                          │
│  ├─ Attestation Service Signs the JWT with hardware measurements           │
│  └─ AMD SEV-SNP         Hardware that measures and enforces policy         │
│                                                                              │
│  YOU (Verifier)         Builds locally + verifies attestation               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Hash Types

Understanding the different hashes is crucial for verification:

| Hash | What It Is | Example | Used For |
|------|-----------|---------|----------|
| **Policy Hash** | SHA256 of CCE policy | `2d01833fd5aa6aed...` | Hardware verification |
| **Manifest Digest** | SHA256 of image manifest | `0a91cf7a6db5f1c0d88bcda...` | Registry addressing |
| **Image ID** | SHA256 of image config | `13351c8408a18dda...` | Local Docker identification |
| **Layer Hash** | SHA256 of compressed layer | `eee2cb9809bdf33ce...` | Content verification |

**Important**: Manifest Digest and Image ID are different hashes of the **same image**. They both refer to identical content but are computed differently.

```
Docker Image
├── manifest.json  ───► SHA256 = Manifest Digest (used in ghcr.io/...@sha256:XXX)
├── config.json    ───► SHA256 = Image ID (what `docker inspect` shows)
└── layers/        ───► SHA256 = Layer Hashes
```

---

## The Trust Chain

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TRUST CHAIN                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   1. SOURCE CODE (GitHub)                                                    │
│        │ You can audit this                                                  │
│        ▼                                                                     │
│   2. NIX BUILD (Reproducible)                                                │
│        │ Same source → same image digest                                     │
│        ▼                                                                     │
│   3. CONTAINER IMAGE                                                         │
│        │ Manifest Digest: sha256:0a91cf7a...                                │
│        │ Image ID: sha256:13351c8408a18...                                  │
│        ▼                                                                     │
│   4. CCE POLICY (Rego file)                                                  │
│        │ Contains: image reference, layers, commands, env vars              │
│        │ Policy Hash: sha256(policy) = 2d01833fd5aa...                      │
│        ▼                                                                     │
│   5. HARDWARE MEASUREMENT (AMD SEV-SNP)                                      │
│        │ Stores policy hash in tamper-proof register                        │
│        │ This becomes "host_data" in attestation                            │
│        ▼                                                                     │
│   6. ATTESTATION JWT (Signed by Azure)                                       │
│        │ Contains: host_data, nonce, hardware claims                        │
│        ▼                                                                     │
│   7. YOUR VERIFICATION                                                       │
│        │ sha256(policy) == host_data? ✓                                     │
│        │ policy.image_digest == local_build_digest? ✓                       │
│        ▼                                                                     │
│   ✅ VERIFIED: Enclave runs your audited code                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Complete Zero-Trust Verification

This is the full verification procedure for strong zero-trust assurance: conclusions
come from cryptographic checks plus required anti-forgery verification inputs, not
blind trust.

### Prerequisites

- Linux x86_64 machine (for reproducible builds)
- Docker installed
- Nix installed with flakes enabled

```bash
# Enable Nix flakes (if not already)
mkdir -p ~/.config/nix
echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf
```

### Step 1: Clone and Build Locally

```bash
# Clone the repository
git clone https://github.com/openanonymity/oa-verifier
cd oa-verifier

# Build with Nix (reproducible build)
nix build .#container

# Load into Docker
docker load < result
```

### Step 2: Get Your Local Build's Digest

```bash
# Start a temporary local registry
docker run -d -p 5000:5000 --name registry registry:2

# Push your local build to get the manifest digest
docker tag oa-verifier:latest localhost:5000/oa-verifier:latest
docker push localhost:5000/oa-verifier:latest
# Output shows: digest: sha256:XXXXXXXX

# Or capture it:
LOCAL_DIGEST=$(docker inspect localhost:5000/oa-verifier:latest --format='{{index .RepoDigests 0}}' | cut -d'@' -f2)
echo "Local build digest: $LOCAL_DIGEST"

# Cleanup
docker stop registry && docker rm registry
```

### Step 3: Fetch Attestation

```bash
# Generate a nonce for freshness
NONCE=$(date +%s)

# Fetch attestation from the service
curl -sk "https://oa-verifier.eastus.azurecontainer.io/attestation?nonce=$NONCE" > attestation.json

# Pretty print to inspect
cat attestation.json | jq
```

### Step 4: Verify Policy Authenticity (Hardware Verification)

```bash
# Compute SHA256 of the policy
COMPUTED_HASH=$(jq -r '.policy.base64' attestation.json | base64 -d | sha256sum | cut -d' ' -f1)

# Get the hardware-measured hash
HARDWARE_HASH=$(jq -r '.summary.host_data' attestation.json)

echo "Computed policy hash: $COMPUTED_HASH"
echo "Hardware host_data:   $HARDWARE_HASH"

if [ "$COMPUTED_HASH" = "$HARDWARE_HASH" ]; then
  echo "✅ Policy verified by hardware!"
else
  echo "❌ VERIFICATION FAILED - Policy tampered!"
  exit 1
fi
```

### Step 5: Verify Image Digest Matches Policy

```bash
# Extract the image digest from the verified policy
POLICY_DIGEST=$(jq -r '.policy.decoded' attestation.json | grep -oP '"id":"ghcr.io/[^"]+' | head -1 | cut -d'@' -f2)

echo "Policy allows digest: $POLICY_DIGEST"
echo "Your local digest:    $LOCAL_DIGEST"

if [ "$POLICY_DIGEST" = "$LOCAL_DIGEST" ]; then
  echo "✅ VERIFIED! Your local build matches the running container!"
else
  echo "❌ Digest mismatch - different code!"
  exit 1
fi
```

### Step 6: Verify JWT Signature (Required for strict zero-trust conclusions)

```bash
# Get Azure's public keys
VERIFY_URL=$(jq -r '.verify_at' attestation.json)
curl -s "$VERIFY_URL" | jq

# The JWT must be verified using these keys.
# The "kid" in the JWT header identifies which key to use.
```

Without Step 6, you only have partial/integrity-level evidence from decoded fields.
Strict cryptographic conclusions require successful JWT signature verification.

### Script (Hash + Digest checks only; not strict by itself)

```bash
#!/bin/bash
set -e

echo "=== Attestation Integrity Check (non-strict) ==="

# Step 1: Fetch attestation
NONCE=$(date +%s)
curl -sk "https://oa-verifier.eastus.azurecontainer.io/attestation?nonce=$NONCE" > attestation.json

# Step 2: Verify policy hash (hardware verification)
COMPUTED=$(jq -r '.policy.base64' attestation.json | base64 -d | sha256sum | cut -d' ' -f1)
HARDWARE=$(jq -r '.summary.host_data' attestation.json)

echo "Policy hash computed: $COMPUTED"
echo "Hardware host_data:   $HARDWARE"

if [ "$COMPUTED" != "$HARDWARE" ]; then
  echo "❌ FAILED: Policy hash mismatch!"
  exit 1
fi
echo "✅ Policy verified by hardware"

# Step 3: Extract policy details
echo ""
echo "=== Policy Contents ==="
POLICY_IMAGE=$(jq -r '.policy.decoded' attestation.json | grep -oP '"id":"[^"]+' | head -1 | cut -d'"' -f4)
POLICY_COMMAND=$(jq -r '.policy.decoded' attestation.json | grep -oP '"command":\[[^\]]+\]' | head -1)
POLICY_LAYERS=$(jq -r '.policy.decoded' attestation.json | grep -oP '"layers":\[[^\]]+\]' | head -1)

echo "Image:   $POLICY_IMAGE"
echo "Command: $POLICY_COMMAND"
echo "Layers:  $POLICY_LAYERS"

# Step 4: Compare with local build (if available)
if docker inspect oa-verifier:latest &>/dev/null; then
  LOCAL_ID=$(docker inspect oa-verifier:latest --format='{{.Id}}')
  echo ""
  echo "=== Local Build Comparison ==="
  echo "Local Image ID: $LOCAL_ID"
  echo ""
  echo "To verify digest match, push to a local registry:"
  echo "  docker run -d -p 5000:5000 --name registry registry:2"
  echo "  docker tag oa-verifier:latest localhost:5000/oa-verifier:latest"
  echo "  docker push localhost:5000/oa-verifier:latest"
  echo "  # Compare the digest with: $(echo $POLICY_IMAGE | cut -d'@' -f2)"
fi

echo ""
echo "=== Verification Complete (signature verification not included in this script) ==="
```

---

## Quick Verification

If you trust GitHub Actions built the image correctly (don't need full zero-trust):

```bash
# Fetch and verify policy hash only
curl -sk "https://oa-verifier.eastus.azurecontainer.io/attestation?nonce=$(date +%s)" | \
  jq '{
    policy_verified: (.summary.host_data == (.policy.base64 | @base64d | @text | gsub("[\\n]"; "") | .)),
    image: (.policy.decoded | capture("\"id\":\"(?<img>[^\"]+)\"") | .img),
    hardware: .summary.host_data,
    debug_disabled: .summary.debug_disabled,
    attestation_type: .summary.attestation_type
  }'
```

---

## What The Attestation Proves

| Claim | Field | Meaning |
|-------|-------|---------|
| **Hardware Type** | `attestation_type: sevsnpvm` | Running in AMD SEV-SNP enclave |
| **Policy Hash** | `host_data` | SHA256 of CCE policy (hardware-measured) |
| **Debug Disabled** | `debug_disabled: true` | No debugger can attach |
| **Compliance** | `compliance_status` | Azure security compliance |
| **Freshness** | `nonce` | Your nonce proves this isn't a replay |
| **TLS Binding** | `tls_pubkey_hash` | Hash of TLS cert (channel binding) |

---

## What The Policy Contains

The CCE policy (returned in `policy.decoded`) defines:

```rego
containers := [{
  "id": "ghcr.io/erikchi/oa-verifier@sha256:...",  # Exact image allowed
  "command": ["/bin/oa-verifier"],                  # Exact command
  "layers": ["eee2cb9809bdf33ce..."],               # Layer hashes
  "env_rules": [...],                               # Allowed environment variables
  "capabilities": {...},                            # Linux capabilities
  "working_dir": "/app",                            # Working directory
  "mounts": [...]                                   # Allowed mounts
}]
```

**Any change** to the image, command, environment variables, or capabilities would change the policy hash, causing verification to fail.

---

## FAQ

### Q: Can the operator fake the attestation?

**No.** The policy hash is measured by AMD SEV-SNP hardware into a register that software cannot modify. The attestation JWT is signed by Azure Attestation Service using keys you can verify.

### Q: Why are Manifest Digest and Image ID different?

They're different hashes of the same image:
- **Manifest Digest** = SHA256 of the registry manifest (includes metadata)
- **Image ID** = SHA256 of the image config JSON (content only)

Both refer to identical container content.

### Q: What if my local build digest doesn't match?

Ensure you're:
1. On **x86_64 Linux** (not ARM/Mac)
2. Using the **same commit** as deployed
3. Using **Nix** for reproducible builds

### Q: Do I need to rebuild from source?

Only for **full zero-trust**. If you trust GitHub Actions, you can verify the policy hash matches what CI computed and check the image digest in the policy.

### Q: What about the sidecar container?

The CCE policy includes ALL containers:
1. `oa-verifier` - Your application
2. `skr-sidecar` - Microsoft's SKR container for attestation
3. `pause-container` - Kubernetes pause container

All are measured in the policy hash.

### Q: Can environment variables be modified?

Only environment variables explicitly allowed in `env_rules` can be set. The policy uses:
- `strategy: "string"` - Exact match required
- `strategy: "re2"` - Regex pattern match

Any unauthorized env var would violate the policy.

---

## Security Guarantees

If verification passes:

| Guarantee | How It's Proven |
|-----------|----------------|
| **Code Integrity** | Policy hash matches → exact image running |
| **Memory Isolation** | AMD SEV-SNP encrypts memory from host |
| **Tamper Evidence** | Any code change → different policy hash |
| **Freshness** | Your nonce in attestation → not replayed |
| **No Debug Access** | `debug_disabled: true` → no debugger |

---

## Reference

- **Attestation Endpoint**: `https://oa-verifier.eastus.azurecontainer.io/attestation?nonce=<your-nonce>`
- **Azure Keys**: `https://sharedeus.eus.attest.azure.net/certs`
- **Source Code**: `https://github.com/openanonymity/oa-verifier`
