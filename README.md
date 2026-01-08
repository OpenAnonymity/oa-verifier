# OpenRouter Enclave Verifier

Lightweight verification service for OpenRouter stations. Runs in **Azure Container Instances (ACI) Confidential Containers** with AMD SEV-SNP hardware protection.

## Build & Run

### Local Development

```bash
go build -o verifier ./cmd/verifier
./verifier

# Or directly
go run ./cmd/verifier
```

### Container Build

```bash
docker build -t oa-verifier .
docker run -p 8000:8000 oa-verifier
```

### Deploy to ACI Confidential

```bash
cd deploy
./deploy.sh \
  --acr-name youracr \
  --resource-group your-rg \
  --registry-url "https://your-registry" \
  --registry-secret "secret" \
  --salt "your-salt"
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/register` | POST | Register station with Ed25519 public key and cookie |
| `/submit_key` | POST | Submit double-signed API key for ownership verification |
| `/station/{public_key}` | GET | Get station info |
| `/broadcast` | GET | Get all verified stations and banned list |
| `/banned-stations` | GET | Get list of banned stations |
| `/reload-config` | POST | Hot-reload config from .env (requires auth) |
| `/attestation` | GET | Get SEV-SNP attestation proof with policy hash |
| `/attestation/raw` | GET | Get raw JWT attestation token |

## Module Structure

| Path | Purpose |
|------|---------|
| `cmd/verifier/main.go` | Entry point |
| `internal/server/` | HTTP server, handlers, verification loop |
| `internal/config/` | Hot-reloadable configuration |
| `internal/models/` | Data models |
| `internal/openrouter/` | OpenRouter auth & API interactions |
| `internal/banned/` | Banned station tracking |
| `internal/challenge/` | Privacy toggle verification |
| `internal/registry/` | Station registry fetch |
| `deploy/` | ACI deployment scripts and ARM templates |

## Security

- Three-way binding: station_id (registry) <-> email (cookie) <-> public_key (station)
- Cookie data stored in memory only (never persisted)
- Background verification loop randomly challenges stations
- Runs in AMD SEV-SNP Trusted Execution Environment
- No SSH access possible (ACI serverless)

## Attestation & Code Verification

This verifier runs inside **Azure Container Instances (ACI) Confidential Containers** with AMD SEV-SNP hardware protection. The `/attestation` endpoint provides cryptographic proof that:

1. The container is running in a genuine hardware-isolated enclave
2. The CCE policy hash matches what we publish (proving which container runs)
3. The container digest can be verified against this source code

### How ACI Confidential Attestation Works

```
AMD SEV-SNP Hardware
       │
       ▼ (enforces CCE policy at boot)
Microsoft Utility VM (measured by hardware)
       │
       ▼ (only runs containers matching policy)
Your Container (digest verified against policy)
       │
       ▼ (attestation contains policy hash)
Azure Attestation Service (signs the report)
       │
       ▼ (user verifies signature + policy hash)
TRUST ESTABLISHED
```

### Current Expected Values

**Container Digest:**
```
sha256:<DEPLOY_AND_UPDATE_THIS>
```

**CCE Policy Hash (HOST_DATA):**
```
<DEPLOY_AND_UPDATE_THIS>
```

### How to Verify

1. **Get the attestation:**
   ```bash
   curl https://verifier.openanonymity.ai/attestation | jq .
   ```

2. **Check the `cce_policy_hash` in the response**

3. **Verify it matches by building from source:**
   ```bash
   # Clone and build
   git clone https://github.com/openanonymity/oa-verifier
   cd oa-verifier
   docker build -t verifier .
   
   # Get the digest
   docker inspect verifier --format='{{.Id}}'
   ```

4. **Verify the CCE policy** pins this digest (see `deploy/arm-template.json`)

### What Each Field Means

| Field | Meaning | Trust Level |
|-------|---------|-------------|
| `cce_policy_hash` / `host_data` | Hash of CCE policy | **Critical** - proves which container is allowed |
| `attestation_type: sevsnpvm` | Running in AMD SEV-SNP enclave | Hardware-backed |
| `debug_disabled: true` | Cannot attach debugger | Required for security |
| `compliance_status` | Azure CVM compliance | Cloud attestation |

### Quick Verification Script

```bash
#!/bin/bash
# Update these with published values
EXPECTED_POLICY_HASH="<your-expected-policy-hash>"

ACTUAL_HASH=$(curl -s https://verifier.openanonymity.ai/attestation | jq -r '.summary.cce_policy_hash')

if [ "$ACTUAL_HASH" = "$EXPECTED_POLICY_HASH" ]; then
    echo "VERIFIED: Container is running with expected policy"
else
    echo "FAILED: Policy hash mismatch!"
    echo "Expected: $EXPECTED_POLICY_HASH"
    echo "Actual:   $ACTUAL_HASH"
    exit 1
fi
```

### Full Verification (Build from Source)

For maximum trust, verify the entire chain yourself:

```bash
#!/bin/bash
set -e

echo "=== Full Verification ==="

# 1. Clone the source
git clone https://github.com/openanonymity/oa-verifier /tmp/oa-verifier
cd /tmp/oa-verifier

# 2. Build the container
echo "Building container..."
docker build -t verify-test .
LOCAL_DIGEST=$(docker inspect verify-test --format='{{.Id}}' | cut -d: -f2)
echo "Local digest: sha256:${LOCAL_DIGEST:0:12}..."

# 3. Get attestation from running service
echo "Getting attestation..."
ATTESTATION=$(curl -s https://verifier.openanonymity.ai/attestation)
POLICY_HASH=$(echo "$ATTESTATION" | jq -r '.summary.cce_policy_hash')
CLAIMED_DIGEST=$(echo "$ATTESTATION" | jq -r '.verification.expected_container_digest')

echo "Remote policy hash: ${POLICY_HASH:0:16}..."
echo "Claimed digest: ${CLAIMED_DIGEST:0:24}..."

# 4. Verify JWT signature (requires Azure public keys)
VERIFY_URL=$(echo "$ATTESTATION" | jq -r '.verify_at')
echo "Verify JWT at: $VERIFY_URL"

# 5. Compare digests
if [[ "$CLAIMED_DIGEST" == *"$LOCAL_DIGEST"* ]]; then
    echo ""
    echo "SUCCESS: Container digest matches source code!"
    echo "The service is running exactly the code from GitHub."
else
    echo ""
    echo "WARNING: Digest mismatch - investigate before trusting"
fi

# Cleanup
rm -rf /tmp/oa-verifier
```

### Understanding the Trust Chain

```
GitHub Source Code
       │
       ▼ (user builds locally)
Container Image (sha256:ABC123)
       │
       ▼ (CCE policy pins this digest)
CCE Policy Hash (in HOST_DATA)
       │
       ▼ (hardware-signed attestation)
Azure Attestation Service
       │
       ▼ (user verifies signature)
VERIFIED: Service runs GitHub code
```

**Why this is secure:**
- AMD SEV-SNP hardware enforces the CCE policy
- Policy specifies exact container digest (content-addressed hash)
- You cannot run a different container - hardware blocks it
- Attestation is signed by Azure, not the container
- User computes expected values from source (doesn't trust publisher)

### Security Model

| Entity | Trust Required |
|--------|----------------|
| AMD SEV-SNP | Hardware measures correctly |
| Microsoft Utility VM | Enforces CCE policy |
| Azure Attestation | Signs reports honestly |
| Container Registry | Content-addressed (digest = hash) |
| **Us (operators)** | **NOT TRUSTED** - verify yourself! |

The attestation proves what's running. Users verify by building from source.
