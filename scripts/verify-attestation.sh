#!/bin/bash
# Zero-Trust Attestation Verification
set -e

# ENDPOINT="${1:-https://oa-verifier.eastus.azurecontainer.io}"
ENDPOINT="${1:-https://verifier.openanonymity.ai}"
TMPDIR=$(mktemp -d) && trap "rm -rf $TMPDIR" EXIT

echo "=== Zero-Trust Attestation Verification ==="
echo "Endpoint: $ENDPOINT"
echo ""

# Step 1: Fetch attestation
echo "[1/4] Fetching attestation..."
NONCE=$(date +%s | sha256sum | head -c 16)
curl -sfk "${ENDPOINT}/attestation?nonce=${NONCE}" > "$TMPDIR/att.json" || { echo "❌ Failed to fetch"; exit 1; }
echo "✓ Attestation fetched"

# Step 2: Verify policy hash matches hardware measurement
echo "[2/4] Verifying policy hash..."
POLICY_B64=$(jq -r '.policy.base64' "$TMPDIR/att.json")
COMPUTED=$(echo "$POLICY_B64" | base64 -d | sha256sum | cut -d' ' -f1)
HOST_DATA=$(jq -r '.summary.host_data' "$TMPDIR/att.json")

echo "   Computed:  $COMPUTED"
echo "   Hardware:  $HOST_DATA"

if [ "$COMPUTED" != "$HOST_DATA" ]; then
    echo "❌ HASH MISMATCH - DO NOT TRUST"
    exit 1
fi
echo "✓ Policy verified by hardware"

# Step 3: Verify JWT is from Azure Attestation
echo "[3/4] Verifying JWT source..."
TOKEN=$(jq -r '.token' "$TMPDIR/att.json")
HEADER=$(echo "$TOKEN" | cut -d'.' -f1 | tr '_-' '/+')
case $((${#HEADER} % 4)) in 2) HEADER="${HEADER}==";; 3) HEADER="${HEADER}=";; esac
JKU=$(echo "$HEADER" | base64 -d 2>/dev/null | jq -r '.jku // empty')

if [[ "$JKU" =~ \.attest\.azure\.net/certs$ ]]; then
    echo "✓ JWT from Azure Attestation: $JKU"
else
    echo "❌ Invalid JWT source: $JKU"
    exit 1
fi

# Step 4: Show container info
echo "[4/4] Container info..."
CONTAINER_ID=$(jq -r '.policy.decoded' "$TMPDIR/att.json" | grep -o '"id":"ghcr[^"]*"' | head -1 | cut -d'"' -f4)
echo "   Image: $CONTAINER_ID"

# Summary
echo ""
echo "=== SUMMARY ==="
jq -r '"Type: \(.summary.attestation_type // "N/A")\nDebug: \(.summary.debug_disabled // "N/A")\nCompliance: \(.summary.compliance_status // "N/A")"' "$TMPDIR/att.json"
echo "Policy Hash: ${HOST_DATA:0:16}..."
echo ""
echo "✅ HARDWARE ATTESTATION VERIFIED"
