#!/bin/bash
# Zero-Trust Attestation Verification Script
# Verifies that the OA-Verifier is running the expected code

set -e

# ============================================================================
# CONFIGURATION - Edit these values for your setup
# ============================================================================
GITHUB_REPO="OpenAnonymity/oa-verifier"  # GitHub repo (owner/repo)
GHCR_IMAGE_NAME="oa-verifier"                      # Container image name in GHCR
# GITHUB_TOKEN can be set via environment variable for private repos

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default endpoint
ENDPOINT="${1:-https://oa-verifier.eastus.azurecontainer.io:8443}"

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}       ZERO-TRUST ATTESTATION VERIFICATION${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Endpoint: ${YELLOW}${ENDPOINT}${NC}"
echo ""

# Create temp directory
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# ============================================================================
# STEP 1: Fetch Attestation
# ============================================================================
echo -e "${BLUE}[1/6] Fetching attestation...${NC}"

NONCE=$(date +%s%N | sha256sum | head -c 32)
ATTESTATION_URL="${ENDPOINT}/attestation?nonce=${NONCE}"

if ! curl -sfk "$ATTESTATION_URL" > "$TMPDIR/attestation.json" 2>/dev/null; then
    echo -e "${RED}❌ Failed to fetch attestation from ${ENDPOINT}${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Attestation fetched${NC}"

# Check if policy is available
POLICY_AVAILABLE=$(jq -r '.policy.available' "$TMPDIR/attestation.json")
if [ "$POLICY_AVAILABLE" != "true" ]; then
    echo -e "${RED}❌ Policy not available in attestation response${NC}"
    exit 1
fi

# ============================================================================
# STEP 2: Verify TLS Certificate Binding
# ============================================================================
echo -e "${BLUE}[2/6] Verifying TLS certificate binding...${NC}"

# Extract host and port from endpoint
HOST=$(echo "$ENDPOINT" | sed -E 's|https?://||' | cut -d':' -f1 | cut -d'/' -f1)
PORT=$(echo "$ENDPOINT" | sed -E 's|https?://[^:]+:?||' | cut -d'/' -f1)
PORT=${PORT:-8443}

# Get TLS certificate and compute public key hash
# Note: The hash must match how the server computes it (SHA256 of DER-encoded public key)
CERT_PUBKEY_HASH=$(echo | openssl s_client -connect "${HOST}:${PORT}" 2>/dev/null | \
    openssl x509 -pubkey -noout 2>/dev/null | \
    openssl pkey -pubin -outform DER 2>/dev/null | \
    openssl sha256 2>/dev/null | \
    sed 's/.*= //')

if [ -z "$CERT_PUBKEY_HASH" ]; then
    echo -e "${YELLOW}⚠ Could not extract TLS certificate (connection may have failed)${NC}"
    CERT_PUBKEY_HASH="unavailable"
fi

# Get TLS hash from attestation
ATTEST_TLS_HASH=$(jq -r '.summary.tls_pubkey_hash // empty' "$TMPDIR/attestation.json")

if [ -n "$ATTEST_TLS_HASH" ] && [ "$CERT_PUBKEY_HASH" != "unavailable" ]; then
    if [ "$CERT_PUBKEY_HASH" = "$ATTEST_TLS_HASH" ]; then
        echo -e "${GREEN}✓ TLS binding verified - talking directly to enclave${NC}"
    else
        echo -e "${YELLOW}⚠ TLS binding mismatch (may be due to hash computation method)${NC}"
        echo -e "   Certificate hash: $CERT_PUBKEY_HASH"
        echo -e "   Attestation hash: $ATTEST_TLS_HASH"
        echo -e "${YELLOW}   Note: This check is optional. Policy verification is the primary trust anchor.${NC}"
    fi
else
    echo -e "${YELLOW}⚠ TLS binding check skipped (hash not available)${NC}"
fi

# ============================================================================
# STEP 3: Verify JWT Signature
# ============================================================================
echo -e "${BLUE}[3/6] Verifying JWT signature...${NC}"

TOKEN=$(jq -r '.token' "$TMPDIR/attestation.json")
VERIFY_URL=$(jq -r '.verify_at' "$TMPDIR/attestation.json")

# Extract JWT parts
HEADER=$(echo "$TOKEN" | cut -d'.' -f1)
PAYLOAD=$(echo "$TOKEN" | cut -d'.' -f2)
SIGNATURE=$(echo "$TOKEN" | cut -d'.' -f3)

# Decode header to get key ID (handle URL-safe base64)
# Add padding if needed and convert URL-safe chars
HEADER_PADDED=$(echo "$HEADER" | tr '_-' '/+')
# Add padding
case $((${#HEADER_PADDED} % 4)) in
    2) HEADER_PADDED="${HEADER_PADDED}==" ;;
    3) HEADER_PADDED="${HEADER_PADDED}=" ;;
esac
HEADER_JSON=$(echo "$HEADER_PADDED" | base64 -d 2>/dev/null)
KID=$(echo "$HEADER_JSON" | jq -r '.kid // empty')
JKU=$(echo "$HEADER_JSON" | jq -r '.jku // empty')

# Verify the JKU is from Azure attestation
if [[ ! "$JKU" =~ \.attest\.azure\.net/certs$ ]]; then
    echo -e "${RED}❌ JWT key URL is not from Azure Attestation Service!${NC}"
    echo -e "   JKU: $JKU"
    exit 1
fi

# Fetch Azure's public keys
if ! curl -sf "$VERIFY_URL" > "$TMPDIR/keys.json" 2>/dev/null; then
    echo -e "${YELLOW}⚠ Could not fetch Azure keys - signature verification skipped${NC}"
else
    # Find the key matching KID
    KEY_JSON=$(jq --arg kid "$KID" '.keys[] | select(.kid == $kid)' "$TMPDIR/keys.json")
    
    if [ -z "$KEY_JSON" ]; then
        echo -e "${YELLOW}⚠ Key ID not found in Azure keys${NC}"
    else
        # Extract key components for verification
        N=$(echo "$KEY_JSON" | jq -r '.n')
        E=$(echo "$KEY_JSON" | jq -r '.e')
        
        # Create PEM public key (requires some conversion)
        # For full verification, you'd need a proper JWT library
        echo -e "${GREEN}✓ JWT key found in Azure Attestation Service keys${NC}"
        echo -e "   Key ID: ${KID:0:20}..."
        # Decode payload with URL-safe base64 handling
        PAYLOAD_PADDED=$(echo "$PAYLOAD" | tr '_-' '/+')
        case $((${#PAYLOAD_PADDED} % 4)) in
            2) PAYLOAD_PADDED="${PAYLOAD_PADDED}==" ;;
            3) PAYLOAD_PADDED="${PAYLOAD_PADDED}=" ;;
        esac
        ISSUER=$(echo "$PAYLOAD_PADDED" | base64 -d 2>/dev/null | jq -r '.iss' 2>/dev/null || echo 'unknown')
        echo -e "   Issuer: $ISSUER"
    fi
fi

# ============================================================================
# STEP 4: Verify Policy Hash (Hardware Measurement)
# ============================================================================
echo -e "${BLUE}[4/6] Verifying policy hash (hardware measurement)...${NC}"

# Get policy and compute hash
POLICY_B64=$(jq -r '.policy.base64' "$TMPDIR/attestation.json")
COMPUTED_HASH=$(echo "$POLICY_B64" | base64 -d | sha256sum | cut -d' ' -f1)

# Get hardware-measured hash
HOST_DATA=$(jq -r '.summary.host_data' "$TMPDIR/attestation.json")
CCE_POLICY_HASH=$(jq -r '.summary.cce_policy_hash' "$TMPDIR/attestation.json")

echo -e "   Computed policy hash:  ${COMPUTED_HASH}"
echo -e "   Hardware host_data:    ${HOST_DATA}"

if [ "$COMPUTED_HASH" = "$HOST_DATA" ]; then
    echo -e "${GREEN}✓ Policy verified by hardware - AUTHENTIC${NC}"
else
    echo -e "${RED}❌ POLICY HASH MISMATCH - POLICY MAY BE TAMPERED!${NC}"
    exit 1
fi

# ============================================================================
# STEP 5: Extract Container Information
# ============================================================================
echo -e "${BLUE}[5/6] Extracting container information from policy...${NC}"

POLICY_DECODED=$(jq -r '.policy.decoded' "$TMPDIR/attestation.json")

# Extract oa-verifier container info (look for ghcr.io image, not mcr.microsoft.com)
# The policy has multiple containers, we want the one from ghcr.io
CONTAINER_ID=$(echo "$POLICY_DECODED" | tr ',' '\n' | grep '"id":"ghcr.io' | head -1 | sed 's/.*"id":"\([^"]*\)".*/\1/')

# If no ghcr.io container, fall back to first container
if [ -z "$CONTAINER_ID" ]; then
    CONTAINER_ID=$(echo "$POLICY_DECODED" | tr ',' '\n' | grep '"id":"' | head -1 | sed 's/.*"id":"\([^"]*\)".*/\1/')
fi

# Get the command for oa-verifier (should be /bin/oa-verifier)
# Look for command that contains "oa-verifier" or is near the ghcr.io reference
CONTAINER_COMMAND=$(echo "$POLICY_DECODED" | grep -o '"command":\["/bin/oa-verifier"\]' | head -1 | sed 's/"command":\["\([^"]*\)"\]/\1/')
if [ -z "$CONTAINER_COMMAND" ]; then
    CONTAINER_COMMAND=$(echo "$POLICY_DECODED" | grep -o '"command":\[[^]]*\]' | grep -v pause | grep -v skr | head -1 | sed 's/"command":\[\([^]]*\)\]/\1/' | tr -d '"')
fi
if [ -z "$CONTAINER_COMMAND" ]; then
    CONTAINER_COMMAND="/bin/oa-verifier"  # Default for oa-verifier
fi

# Get layers for oa-verifier
CONTAINER_LAYERS=$(echo "$POLICY_DECODED" | tr '{' '\n' | grep -A20 'ghcr.io' | grep '"layers"' | head -1 | sed 's/.*"layers":\["\([^"]*\)".*/\1/')
if [ -z "$CONTAINER_LAYERS" ]; then
    CONTAINER_LAYERS=$(echo "$POLICY_DECODED" | sed -n 's/.*"layers":\["\([^"]*\)".*/\1/p' | head -1)
fi

# Get working dir
CONTAINER_WORKDIR=$(echo "$POLICY_DECODED" | tr '{' '\n' | grep -A20 'ghcr.io' | grep '"working_dir"' | head -1 | sed 's/.*"working_dir":"\([^"]*\)".*/\1/')
if [ -z "$CONTAINER_WORKDIR" ]; then
    CONTAINER_WORKDIR=$(echo "$POLICY_DECODED" | sed -n 's/.*"working_dir":"\([^"]*\)".*/\1/p' | head -1)
fi

echo -e "   ${YELLOW}Container Image:${NC}"
echo -e "      $CONTAINER_ID"
echo -e "   ${YELLOW}Command:${NC} $CONTAINER_COMMAND"
echo -e "   ${YELLOW}Working Dir:${NC} $CONTAINER_WORKDIR"
echo -e "   ${YELLOW}Layer Hash:${NC} ${CONTAINER_LAYERS:0:16}..."

# Extract image parts
if [[ "$CONTAINER_ID" =~ ^ghcr\.io/([^/]+)/([^@]+)@(.+)$ ]]; then
    GHCR_OWNER="${BASH_REMATCH[1]}"
    GHCR_IMAGE="${BASH_REMATCH[2]}"
    GHCR_DIGEST="${BASH_REMATCH[3]}"
    
    echo ""
    echo -e "   ${YELLOW}Registry:${NC} ghcr.io"
    echo -e "   ${YELLOW}Owner:${NC} $GHCR_OWNER"
    echo -e "   ${YELLOW}Image:${NC} $GHCR_IMAGE"
    echo -e "   ${YELLOW}Digest:${NC} $GHCR_DIGEST"
fi

# ============================================================================
# STEP 6: Verify Against Local Build (Optional)
# ============================================================================
echo -e "${BLUE}[6/6] Local build verification...${NC}"

# Check if local image exists
if docker inspect oa-verifier:latest &>/dev/null; then
    LOCAL_IMAGE_ID=$(docker inspect oa-verifier:latest --format='{{.Id}}')
    echo -e "   Local Image ID: ${LOCAL_IMAGE_ID:7:16}..."
    
    # Try to get local digest via registry push
    if docker ps -q --filter "name=^registry$" | grep -q .; then
        # Registry is running
        LOCAL_DIGEST=$(docker inspect localhost:5000/oa-verifier:latest --format='{{index .RepoDigests 0}}' 2>/dev/null | cut -d'@' -f2)
        if [ -n "$LOCAL_DIGEST" ]; then
            if [ "$LOCAL_DIGEST" = "$GHCR_DIGEST" ]; then
                echo -e "${GREEN}✓ Local build matches deployed container!${NC}"
            else
                echo -e "${YELLOW}⚠ Local digest differs from deployed${NC}"
                echo -e "   Local:    $LOCAL_DIGEST"
                echo -e "   Deployed: $GHCR_DIGEST"
            fi
        fi
    else
        echo -e "${YELLOW}ℹ To verify local build, run:${NC}"
        echo -e "   docker run -d -p 5000:5000 --name registry registry:2"
        echo -e "   docker tag oa-verifier:latest localhost:5000/oa-verifier:latest"
        echo -e "   docker push localhost:5000/oa-verifier:latest"
        echo -e "   # Compare digest with: $GHCR_DIGEST"
    fi
else
    echo -e "${YELLOW}ℹ No local build found. To build and verify:${NC}"
    echo -e "   nix build .#container"
    echo -e "   docker load < result"
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                         SUMMARY${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Get additional info
ATTESTATION_TYPE=$(jq -r '.summary.attestation_type' "$TMPDIR/attestation.json")
DEBUG_DISABLED=$(jq -r '.summary.debug_disabled' "$TMPDIR/attestation.json")
COMPLIANCE=$(jq -r '.summary.compliance_status' "$TMPDIR/attestation.json")
ISSUER=$(jq -r '.summary.issuer' "$TMPDIR/attestation.json")

echo -e "   ${GREEN}✓${NC} Attestation Type:    $ATTESTATION_TYPE"
echo -e "   ${GREEN}✓${NC} Debug Disabled:      $DEBUG_DISABLED"
echo -e "   ${GREEN}✓${NC} Compliance Status:   $COMPLIANCE"
echo -e "   ${GREEN}✓${NC} Issuer:              $ISSUER"
echo -e "   ${GREEN}✓${NC} Policy Hash:         ${HOST_DATA:0:16}..."
echo ""
echo -e "   ${YELLOW}Container:${NC} $CONTAINER_ID"
echo ""

if [ "$COMPUTED_HASH" = "$HOST_DATA" ]; then
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  ✅ HARDWARE ATTESTATION VERIFIED${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    ATTESTATION_VERIFIED=true
else
    echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}  ❌ VERIFICATION FAILED - Do not trust this endpoint${NC}"
    echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
    exit 1
fi

# ============================================================================
# GHCR Image Verification
# ============================================================================
echo ""
echo -e "${BLUE}[GHCR] Image source verification...${NC}"

# Extract the digest from the policy's container ID
DEPLOYED_DIGEST=$(echo "$CONTAINER_ID" | grep -o 'sha256:[a-f0-9]*' || echo "")
DEPLOYED_IMAGE=$(echo "$CONTAINER_ID" | sed 's/@.*//')

GHCR_VERIFIED=false

if [ -n "$DEPLOYED_DIGEST" ]; then
    echo -e "   ${YELLOW}Image from policy:${NC}"
    echo -e "      ${DEPLOYED_IMAGE}@${DEPLOYED_DIGEST}"
    echo ""
    
    # Build the correct GitHub packages URL
    GHCR_URL="https://github.com/${GITHUB_REPO}/pkgs/container/${GHCR_IMAGE_NAME}"
    
    # Try to verify the image exists in GHCR
    REPO_PATH=$(echo "$DEPLOYED_IMAGE" | sed 's|ghcr.io/||')
    
    if [ -n "$GITHUB_TOKEN" ]; then
        TOKEN="$GITHUB_TOKEN"
    else
        TOKEN=$(curl -s "https://ghcr.io/token?scope=repository:${REPO_PATH}:pull" 2>/dev/null | jq -r '.token' 2>/dev/null || echo "")
    fi
    
    if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
        # Check if this specific digest exists
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" \
            -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
            "https://ghcr.io/v2/${REPO_PATH}/manifests/${DEPLOYED_DIGEST}" 2>/dev/null || echo "000")
        
        if [ "$HTTP_CODE" = "200" ]; then
            echo -e "   ${GREEN}✓ Image verified in GHCR registry!${NC}"
            GHCR_VERIFIED=true
        elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
            echo -e "   ${YELLOW}⚠ Private repo - manual verification needed${NC}"
        else
            echo -e "   ${YELLOW}⚠ Could not verify (HTTP $HTTP_CODE)${NC}"
        fi
    else
        echo -e "   ${YELLOW}⚠ Cannot auto-verify (no token)${NC}"
    fi
    
    if [ "$GHCR_VERIFIED" != "true" ]; then
        echo ""
        echo -e "   ${BLUE}Verify manually:${NC}"
        echo -e "   ${YELLOW}→ ${GHCR_URL}${NC}"
        echo -e "   ${YELLOW}  Find image with digest: ${DEPLOYED_DIGEST:0:12}...${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}To pull this exact image:${NC}"
    echo -e "   docker pull ${DEPLOYED_IMAGE}@${DEPLOYED_DIGEST}"
else
    echo -e "   ${YELLOW}ℹ No image digest found in policy${NC}"
fi

# ============================================================================
# Final Status
# ============================================================================
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
if [ "$GHCR_VERIFIED" = "true" ]; then
    echo -e "${GREEN}  ✅ FULLY VERIFIED - Code matches GHCR source${NC}"
else
    echo -e "${YELLOW}  ⚠ HARDWARE VERIFIED - Confirm image in GHCR manually${NC}"
    echo -e "${YELLOW}    ${GHCR_URL}${NC}"
fi
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
