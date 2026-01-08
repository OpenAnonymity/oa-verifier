# Attestation & Code Verification Guide

This document explains how the oa-verifier uses Azure Confidential Containers to provide cryptographic proof that the server is running exactly the code published in this repository.

## Overview

The oa-verifier runs inside an **Azure Container Instance (ACI) with Confidential Containers**, which uses AMD SEV-SNP hardware to create an isolated, encrypted environment. The `/attestation` endpoint returns a hardware-signed proof of what code is running.

## How It Works

### The Trust Chain

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TRUST CHAIN                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   1. SOURCE CODE (GitHub)                                                   │
│        │                                                                     │
│        ▼                                                                     │
│   2. CONTAINER IMAGE (Dockerfile → sha256:abc123...)                        │
│        │                                                                     │
│        ▼                                                                     │
│   3. CCE POLICY (az confcom acipolicygen → lists allowed container digest)  │
│        │                                                                     │
│        ▼                                                                     │
│   4. AZURE DEPLOYMENT (policy hash measured by AMD SEV-SNP hardware)        │
│        │                                                                     │
│        ▼                                                                     │
│   5. ATTESTATION TOKEN (hardware-signed JWT with policy hash)               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | What It Is | Who Controls It |
|-----------|------------|-----------------|
| Source Code | This GitHub repository | Public, auditable |
| Container Image | Built from Dockerfile | Deterministic from source |
| CCE Policy | Specifies allowed container digest | Generated from container |
| Policy Hash | SHA256 of CCE policy | Hardware-measured, unforgeable |
| Attestation Token | Signed JWT from Azure | Azure Attestation Service |

### What Makes This Unforgeable?

1. **The CCE Policy contains the full container identity** - not just a hash we type in, but cryptographic hashes of every layer of the container image.

2. **Hardware enforcement** - Azure's Utility VM (UVM), which is itself measured by AMD SEV-SNP, validates that the container layers match what's specified in the policy before allowing execution.

3. **The policy hash is hardware-measured** - The `host_data` field in the attestation is computed by AMD SEV-SNP hardware, not software. It cannot be spoofed.

4. **The attestation is signed by Azure** - The JWT is signed by Azure Attestation Service keys, which you can independently verify.

## Attestation Response Explained

When you call `/attestation?nonce=your-random-value`, you get:

```json
{
  "summary": {
    "attestation_type": "sevsnpvm",
    "cce_policy_hash": "bb4ce8d9e736e60acb2e74b6e20db6c947088f6feea0a4918b23e00881c288b5",
    "host_data": "bb4ce8d9e736e60acb2e74b6e20db6c947088f6feea0a4918b23e00881c288b5",
    "debug_disabled": true,
    "compliance_status": "azure-compliant-uvm",
    "issuer": "https://sharedeus.eus.attest.azure.net"
  },
  "token": "eyJhbGciOiJSUzI1NiI...",
  "verify_at": "https://sharedeus.eus.attest.azure.net/certs",
  "nonce": "your-random-value"
}
```

### Field Meanings

| Field | Meaning | Trust Level |
|-------|---------|-------------|
| `attestation_type: sevsnpvm` | Running in AMD SEV-SNP enclave | Hardware-guaranteed |
| `cce_policy_hash` / `host_data` | SHA256 of the CCE policy | **Critical** - proves which container is allowed |
| `debug_disabled: true` | No debugger can attach | Security requirement |
| `compliance_status: azure-compliant-uvm` | Running in compliant environment | Azure attestation |
| `token` | Full JWT with all claims | Cryptographically signed |
| `verify_at` | URL to get signing keys | For JWT verification |
| `nonce` | Your random value (echoed back) | Proves freshness |

## How to Verify (Step by Step)

### Prerequisites

```bash
# Install required tools
az extension add --name confcom
# Docker must be installed and running
```

### Step 1: Get the Attestation

```bash
# Generate a random nonce
NONCE=$(openssl rand -hex 16)

# Get attestation from the running service
ATTESTATION=$(curl -s "https://oa-verifier.eastus.azurecontainer.io:8000/attestation?nonce=$NONCE")

# Extract the policy hash
POLICY_HASH=$(echo "$ATTESTATION" | jq -r '.summary.cce_policy_hash')
echo "Policy Hash from attestation: $POLICY_HASH"

# Verify nonce was echoed back (proves freshness)
RETURNED_NONCE=$(echo "$ATTESTATION" | jq -r '.nonce')
if [ "$RETURNED_NONCE" != "$NONCE" ]; then
  echo "ERROR: Nonce mismatch - possible replay attack!"
  exit 1
fi
```

### Step 2: Build Container from Source

```bash
# Clone the repository
git clone https://github.com/openanonymity/oa-verifier.git
cd oa-verifier

# Build the container (produces deterministic image)
docker build -t oa-verifier-local .

# Get the image digest (content hash)
IMAGE_DIGEST=$(docker inspect oa-verifier-local --format='{{.Id}}')
echo "Your built image digest: $IMAGE_DIGEST"
```

### Step 3: Generate CCE Policy from Your Build

```bash
# Create a test ARM template with your local image
cat > /tmp/verify-template.json << 'EOF'
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [{
    "type": "Microsoft.ContainerInstance/containerGroups",
    "apiVersion": "2023-05-01",
    "name": "verify-test",
    "location": "eastus",
    "properties": {
      "sku": "Confidential",
      "containers": [{
        "name": "oa-verifier",
        "properties": {
          "image": "oa-verifier-local",
          "resources": {"requests": {"cpu": 1, "memoryInGB": 1}}
        }
      }],
      "confidentialComputeProperties": {"ccePolicy": ""},
      "osType": "Linux"
    }
  }]
}
EOF

# Generate policy (this hashes your local image)
az confcom acipolicygen -a /tmp/verify-template.json --print-policy --outraw > /tmp/policy.txt

# Compute policy hash
YOUR_POLICY_HASH=$(sha256sum /tmp/policy.txt | cut -d' ' -f1)
echo "Your computed policy hash: $YOUR_POLICY_HASH"
```

### Step 4: Compare the Hashes

```bash
if [ "$POLICY_HASH" = "$YOUR_POLICY_HASH" ]; then
  echo "✅ VERIFIED: The running container matches the source code!"
else
  echo "❌ MISMATCH: Policy hashes differ"
  echo "   Expected (from source): $YOUR_POLICY_HASH"
  echo "   Actual (from attestation): $POLICY_HASH"
fi
```

### Step 5: Verify JWT Signature (Optional, Maximum Security)

```python
#!/usr/bin/env python3
"""Verify the attestation JWT signature."""
import requests
import jwt
from cryptography.x509 import load_pem_x509_certificate
import base64
import json

# Get attestation
resp = requests.get("https://oa-verifier.eastus.azurecontainer.io:8000/attestation")
data = resp.json()
token = data["token"]
verify_url = data["verify_at"]

# Get Azure signing keys
jwks = requests.get(verify_url).json()

# Decode JWT header
header = json.loads(base64.urlsafe_b64decode(token.split('.')[0] + '=='))
kid = header["kid"]

# Find matching key
for key in jwks.get("keys", []):
    if key.get("kid") == kid:
        cert_data = base64.b64decode(key["x5c"][0])
        cert = load_pem_x509_certificate(
            b"-----BEGIN CERTIFICATE-----\n" + 
            base64.b64encode(cert_data) + 
            b"\n-----END CERTIFICATE-----"
        )
        public_key = cert.public_key()
        
        # Verify signature and decode
        claims = jwt.decode(token, public_key, algorithms=["RS256"],
                          options={"verify_aud": False})
        
        print("✅ JWT signature verified!")
        print(f"   Issuer: {claims['iss']}")
        print(f"   Host Data: {claims.get('x-ms-sevsnpvm-hostdata', 'N/A')}")
        break
```

## Understanding the CCE Policy

The CCE policy is a Rego document that specifies exactly what can run. You can decode and inspect it:

```bash
# Get the policy from the ARM template
POLICY_B64=$(cat deploy/aci-template.json | jq -r '.resources[0].properties.confidentialComputeProperties.ccePolicy')

# Decode it
echo "$POLICY_B64" | base64 -d > /tmp/policy.rego

# View the container specifications
cat /tmp/policy.rego | grep -A5 '"id":'
```

You'll see something like:
```
"id": "oaverifieracr.azurecr.io/oa-verifier@sha256:dd547f4905b35fe57eab3d389348723547fcffbb56128433aee302f90260db91"
"layers": [
  "6f937bc4d3707c87d1207acd64290d97ec90c8b87a7785cb307808afa49ff892",
  "1e471b94030a28739317d0a2ba4055ed74cffe8541c42c69a7936d10c6e2a534",
  ...
]
```

The `layers` array contains SHA256 hashes of each Docker layer. This is what makes it unforgeable - you can't change the code without changing these hashes.

## Current Deployment Details

| Property | Value |
|----------|-------|
| **Service URL** | `http://oa-verifier.eastus.azurecontainer.io:8000` |
| **Container Image** | `oaverifieracr.azurecr.io/oa-verifier@sha256:dd547f4905b35fe57eab3d389348723547fcffbb56128433aee302f90260db91` |
| **CCE Policy Hash** | `bb4ce8d9e736e60acb2e74b6e20db6c947088f6feea0a4918b23e00881c288b5` |
| **Attestation Type** | AMD SEV-SNP |
| **Azure Region** | East US |

## Quick Verification Script

Save this as `verify-attestation.sh`:

```bash
#!/bin/bash
set -e

EXPECTED_POLICY_HASH="bb4ce8d9e736e60acb2e74b6e20db6c947088f6feea0a4918b23e00881c288b5"
SERVICE_URL="http://oa-verifier.eastus.azurecontainer.io:8000"

# Generate nonce
NONCE=$(openssl rand -hex 16)

# Get attestation
echo "Fetching attestation..."
ATTESTATION=$(curl -s "${SERVICE_URL}/attestation?nonce=${NONCE}")

# Extract values
POLICY_HASH=$(echo "$ATTESTATION" | jq -r '.summary.cce_policy_hash')
RETURNED_NONCE=$(echo "$ATTESTATION" | jq -r '.summary.runtime_data.nonce // .nonce')
ATTESTATION_TYPE=$(echo "$ATTESTATION" | jq -r '.summary.attestation_type')
DEBUG_DISABLED=$(echo "$ATTESTATION" | jq -r '.summary.debug_disabled')

echo ""
echo "=== Attestation Results ==="
echo "Attestation Type: $ATTESTATION_TYPE"
echo "Debug Disabled:   $DEBUG_DISABLED"
echo "Policy Hash:      $POLICY_HASH"
echo ""

# Verify
PASSED=true

if [ "$ATTESTATION_TYPE" != "sevsnpvm" ]; then
  echo "❌ FAIL: Not running in SEV-SNP enclave"
  PASSED=false
fi

if [ "$DEBUG_DISABLED" != "true" ]; then
  echo "❌ FAIL: Debug is enabled (security risk)"
  PASSED=false
fi

if [ "$POLICY_HASH" != "$EXPECTED_POLICY_HASH" ]; then
  echo "❌ FAIL: Policy hash mismatch"
  echo "   Expected: $EXPECTED_POLICY_HASH"
  echo "   Got:      $POLICY_HASH"
  PASSED=false
fi

if [ "$PASSED" = true ]; then
  echo "✅ VERIFIED: All checks passed!"
  echo "   The server is running the expected code in a secure enclave."
else
  echo ""
  echo "⚠️  Verification failed. Do not trust this service."
  exit 1
fi
```

## FAQ

### Q: Can the operator fake the policy hash?

**No.** The policy hash is computed by AMD SEV-SNP hardware when the container boots. The operator provides the policy document, but if the actual container doesn't match the policy, the boot fails. If they deploy a different container, the policy hash changes.

### Q: What if the operator runs the correct container but modifies it at runtime?

**Not possible.** The container runs in encrypted memory (AMD SEV-SNP). The operator cannot read or modify the memory without the enclave detecting it.

### Q: Why do I need to build from source?

To complete the verification chain. You need to confirm that the container digest in the policy corresponds to the source code you've audited.

### Q: What if the attestation service is compromised?

The attestation is signed by Azure's Attestation Service keys. To fake it, an attacker would need to compromise Azure's signing infrastructure, which is protected by HSMs.

### Q: Is the container image publicly available?

The container is hosted on Azure Container Registry. For full verification, you should build from source (ensures reproducibility) rather than pulling a pre-built image.

## Building from Source

```bash
# Clone
git clone https://github.com/openanonymity/oa-verifier.git
cd oa-verifier

# Build (reproducible)
docker build -t oa-verifier .

# The Dockerfile uses specific flags for reproducibility:
# - CGO_ENABLED=0
# - -trimpath
# - -ldflags="-s -w -buildid="
```

## Deep Dive: Concepts Explained

### Q: What is the relationship between Source Code, Binary, and Container Image?

```
┌─────────────────┐     go build      ┌─────────────────┐
│   SOURCE CODE   │ ─────────────────▶│     BINARY      │
│   (.go files)   │                   │   (verifier)    │
└─────────────────┘                   └─────────────────┘
                                              │
                                              │ docker build
                                              ▼
                                      ┌─────────────────┐
                                      │ CONTAINER IMAGE │
                                      │  (layered tar)  │
                                      └─────────────────┘
```

| Concept | What It Is | Example |
|---------|------------|---------|
| **Source Code** | Human-readable text files | `handlers.go`, `server.go` |
| **Binary** | Compiled machine code | `verifier` (one executable file) |
| **Container Image** | Binary + OS + dependencies, packaged as layers | Alpine Linux + ca-certificates + `verifier` binary |

### Q: What exactly is a Container Image?

A container image is like a **zip file of a filesystem**, stored as layers:

```
Container Image: oaverifieracr.azurecr.io/oa-verifier@sha256:dd547f...
│
├── Layer 1: Alpine Linux base (sha256:6f937bc4d370...)
│   └── /bin, /lib, /usr, etc.
│
├── Layer 2: ca-certificates package (sha256:1e471b9403...)
│   └── /etc/ssl/certs/
│
├── Layer 3: tzdata package (sha256:3ac2beaa8cc9...)
│   └── /usr/share/zoneinfo/
│
├── Layer 4: Create user "appuser" (sha256:3e85bb18a20...)
│   └── /etc/passwd, /home/appuser/
│
├── Layer 5: Copy binary (sha256:1bb9fb2552c8...)
│   └── /app/verifier  ◄── YOUR COMPILED GO CODE
│
└── Layer 6: Set permissions (sha256:5548c43d9ac1...)
    └── chown appuser:appuser /app
```

Each layer has a **SHA256 hash** of its contents. This makes the image **content-addressable** - if you change one byte, the hash changes.

### Q: What is the CCE Policy and what's in it?

The **Confidential Computing Enforcement (CCE) Policy** is a document that tells Azure's hardware: **"Only allow THIS specific container to run."**

The policy is written in **Rego** (a policy language). Here's the key structure:

```rego
containers := [
  {
    "id": "oaverifieracr.azurecr.io/oa-verifier@sha256:dd547f4905b35fe...",
    
    "command": ["/app/verifier"],   # What command runs
    
    "layers": [                      # THE CRITICAL PART
      "6f937bc4d3707c87d1207acd64290d97ec90c8b87a7785cb307808afa49ff892",
      "1e471b94030a28739317d0a2ba4055ed74cffe8541c42c69a7936d10c6e2a534",
      "3ac2beaa8cc9fd7bb936a15a04b1a5f1a8493ad51934a3a0d20d898ece7ebd26",
      "3e85bb18a2012a038bb8d4278e2d4f54526926a2ae648dc4b4645d3b68c2a150",
      "1bb9fb2552c89192ab20cc6463dcfbd12623553726bbf9bfe1c49e74c055e6f46",
      "5548c43d9ac19b918b5531df8759db7e0193de6a260f1893025db4d5cc0180cb"
    ],
    
    "env_rules": [                   # Allowed environment variables
      {"pattern": "PORT=8000", ...},
      {"pattern": "MAA_ENDPOINT=...", ...}
    ],
    
    "user": {"user_idname": {"pattern": "appuser", ...}}
  }
]
```

**Key Insight**: The `layers` array contains **the exact SHA256 hashes of each Docker layer**. This is what makes the policy unforgeable:

- If you change ONE byte of source code → the binary changes
- If the binary changes → the layer hash changes  
- If the layer hash changes → the policy no longer matches
- If the policy doesn't match → **hardware refuses to boot the container**

### Q: How does the attestation work with the policy, container, and code?

#### At Deployment Time (You do this once)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        DEPLOYMENT TIME                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. You build container from source                                 │
│     └── docker build → sha256:dd547f...                             │
│                                                                      │
│  2. You generate CCE policy                                         │
│     └── az confcom acipolicygen                                     │
│     └── Tool downloads image, extracts layer hashes                 │
│     └── Creates policy document with those hashes                   │
│                                                                      │
│  3. You deploy to Azure                                             │
│     └── az deployment group create --template-file aci-template.json│
│     └── Template includes the policy                                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

#### At Boot Time (Hardware does this automatically)

```
┌─────────────────────────────────────────────────────────────────────┐
│                          BOOT TIME                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. Azure starts AMD SEV-SNP enclave                                │
│                                                                      │
│  2. Microsoft's Utility VM (UVM) boots inside enclave               │
│     └── UVM is itself measured by hardware                          │
│                                                                      │
│  3. UVM reads the CCE policy you provided                           │
│     └── Computes SHA256 of policy → "bb4ce8d9..."                  │
│     └── Stores this hash in hardware register (HOST_DATA)           │
│                                                                      │
│  4. UVM tries to start your container                               │
│     └── Downloads container image                                    │
│     └── Extracts each layer                                          │
│     └── Computes SHA256 of each layer                               │
│     └── COMPARES against policy's "layers" array                    │
│                                                                      │
│  5. If ALL layers match → container starts                          │
│     If ANY layer differs → BOOT FAILS, container never runs         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

#### At Attestation Time (User verification)

```
┌─────────────────────────────────────────────────────────────────────┐
│                      ATTESTATION TIME                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. User calls: GET /attestation?nonce=abc123                       │
│                                                                      │
│  2. Your Go code calls the SKR sidecar                              │
│     └── POST http://localhost:8080/attest/maa                       │
│     └── Body: {"maa_endpoint": "...", "runtime_data": "abc123"}     │
│                                                                      │
│  3. SKR sidecar asks AMD hardware for attestation report            │
│     └── Hardware reads its registers (HOST_DATA, etc.)              │
│     └── Creates a report signed by AMD's hardware key               │
│                                                                      │
│  4. SKR sends report to Azure Attestation Service (MAA)             │
│     └── MAA verifies the hardware signature                         │
│     └── MAA creates a JWT signed by Azure's keys                    │
│     └── JWT contains all the hardware measurements                  │
│                                                                      │
│  5. Your Go code returns the JWT to user                            │
│                                                                      │
│  6. User verifies:                                                  │
│     a. JWT signature is from Azure (not faked)                      │
│     b. host_data matches expected policy hash                       │
│     c. Policy hash corresponds to policy with their container       │
│     d. Container was built from the source they audited             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Q: How do all the pieces relate to each other?

```
                    ┌─────────────────┐
                    │   SOURCE CODE   │
                    │   (GitHub)      │
                    └────────┬────────┘
                             │ go build
                             ▼
                    ┌─────────────────┐
                    │     BINARY      │
                    │   (/app/verifier)│
                    └────────┬────────┘
                             │ docker build
                             ▼
                    ┌─────────────────┐
                    │ CONTAINER IMAGE │◄─────────────────────┐
                    │ sha256:dd547f...│                      │
                    └────────┬────────┘                      │
                             │                               │
                             │ az confcom acipolicygen       │
                             ▼                               │
                    ┌─────────────────┐                      │
                    │   CCE POLICY    │                      │
                    │ (lists layer    │──────────────────────┘
                    │  hashes)        │    "This policy allows
                    └────────┬────────┘     this container"
                             │
                             │ SHA256
                             ▼
                    ┌─────────────────┐
                    │  POLICY HASH    │
                    │ bb4ce8d9...     │
                    └────────┬────────┘
                             │
                             │ Measured by AMD SEV-SNP
                             ▼
                    ┌─────────────────┐
                    │   HOST_DATA     │
                    │ (hardware reg)  │
                    └────────┬────────┘
                             │
                             │ Included in attestation
                             ▼
                    ┌─────────────────┐
                    │ ATTESTATION JWT │
                    │ (signed by Azure)│
                    └────────┬────────┘
                             │
                             │ User verifies
                             ▼
                    ┌─────────────────┐
                    │  TRUST: Code in │
                    │  enclave matches│
                    │  source on GitHub│
                    └─────────────────┘
```

### Summary Table

| Question | Answer |
|----------|--------|
| **What is a container image?** | Your compiled binary + OS + dependencies, packaged as content-addressed layers |
| **What is the CCE policy?** | A document listing the exact layer hashes of allowed containers |
| **What does hardware measure?** | The SHA256 hash of the CCE policy → stored in `HOST_DATA` |
| **What does attestation prove?** | That `HOST_DATA` was set by real AMD hardware, not software |
| **How does user verify?** | Compare `HOST_DATA` in attestation → to policy hash they compute → to container they build from source |

**The Unforgeable Chain**: If you change the source → binary changes → layer hash changes → policy must change → HOST_DATA changes → attestation reveals different hash → user verification fails.

## References

- [Azure Confidential Containers Documentation](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-confidential-overview)
- [AMD SEV-SNP Technical Documentation](https://www.amd.com/en/developer/sev.html)
- [Azure Attestation Service](https://learn.microsoft.com/en-us/azure/attestation/)
- [Confidential Sidecar Containers](https://github.com/microsoft/confidential-sidecar-containers)

