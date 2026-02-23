#!/bin/bash
# =============================================================================
# LOCAL ZERO-TRUST VERIFICATION SCRIPT
# =============================================================================
# This script builds the container locally with Nix and compares the result
# against the live attestation from the deployed service.
#
# REQUIREMENTS:
#   - Linux x86_64 (Nix can't cross-compile from macOS to Linux)
#   - Nix installed with flakes enabled
#   - curl, jq
#
# USAGE:
#   ./scripts/verify-local.sh [SERVICE_URL]
#
# =============================================================================

set -e

STRICT_TLS_BINDING=true
SERVICE_URL=""

usage() {
    cat <<EOF
Usage: $0 [--strict-tls-binding] [SERVICE_URL]

Options:
  --strict-tls-binding  Fail if tls_pubkey_hash does not match live endpoint cert/public key.
  -h, --help            Show this help.

Examples:
  $0
  $0 https://oa-verifier.eastus.azurecontainer.io
  $0 --strict-tls-binding https://verifier.openanonymity.ai
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --strict-tls-binding)
            STRICT_TLS_BINDING=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            if [[ -n "$SERVICE_URL" ]]; then
                echo "❌ ERROR: Unexpected argument: $1"
                usage
                exit 1
            fi
            SERVICE_URL="$1"
            shift
            ;;
    esac
done

SERVICE_URL="${SERVICE_URL:-https://oa-verifier.eastus.azurecontainer.io}"
SERVICE_URL="${SERVICE_URL%/}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=============================================="
echo "  ZERO-TRUST LOCAL VERIFICATION"
echo "=============================================="
echo "  Strict TLS binding: $STRICT_TLS_BINDING"
echo ""

# Check we're on Linux x86_64
if [[ "$(uname -s)" != "Linux" ]] || [[ "$(uname -m)" != "x86_64" ]]; then
    echo "❌ ERROR: This script requires Linux x86_64"
    echo "   Current: $(uname -s) $(uname -m)"
    echo ""
    echo "   On macOS, you can use Docker to run this:"
    echo "   docker run --rm -v \$(pwd):/workspace -w /workspace nixos/nix bash scripts/verify-local.sh"
    exit 1
fi

# Check Nix is installed
if ! command -v nix &> /dev/null; then
    echo "❌ ERROR: Nix is not installed"
    echo "   Install: curl -L https://nixos.org/nix/install | sh"
    exit 1
fi

# Check required tools
for cmd in curl jq sha256sum openssl; do
    if ! command -v $cmd &> /dev/null; then
        echo "❌ ERROR: $cmd is not installed"
        exit 1
    fi
done

echo "Step 1: Fetching attestation from service..."
echo "   URL: $SERVICE_URL/attestation"
echo ""

ATTESTATION=$(curl -sk "$SERVICE_URL/attestation?nonce=verify-$(date +%s)")
if [[ -z "$ATTESTATION" ]]; then
    echo "❌ ERROR: Could not fetch attestation"
    exit 1
fi

REMOTE_POLICY_HASH=$(echo "$ATTESTATION" | jq -r '.summary.cce_policy_hash // .summary.host_data')
ATTESTED_TLS_HASH=$(echo "$ATTESTATION" | jq -r '.summary.tls_pubkey_hash // empty')
echo "   Remote policy hash: $REMOTE_POLICY_HASH"
echo ""

echo "Step 2: Verifying TLS channel binding..."
if [[ -z "$ATTESTED_TLS_HASH" ]]; then
    echo "   ⚠️  No tls_pubkey_hash in attestation summary"
    if [[ "$STRICT_TLS_BINDING" == "true" ]]; then
        echo "❌ ERROR: Strict mode enabled and tls_pubkey_hash is missing"
        exit 1
    fi
    TLS_BINDING_RESULT="MISSING"
else
    scheme="${SERVICE_URL%%://*}"
    endpoint_no_scheme="${SERVICE_URL#*://}"
    hostport="${endpoint_no_scheme%%/*}"
    host="${hostport%%:*}"
    port=""
    if [[ "$hostport" == *:* ]]; then
        port="${hostport##*:}"
    elif [[ "$scheme" == "https" ]]; then
        port="443"
    else
        port="80"
    fi

    if [[ "$scheme" != "https" ]]; then
        echo "   ⚠️  Endpoint is not HTTPS; cannot perform TLS channel-binding check"
        TLS_BINDING_RESULT="SKIPPED-NON-HTTPS"
        if [[ "$STRICT_TLS_BINDING" == "true" ]]; then
            echo "❌ ERROR: Strict mode enabled and endpoint is not HTTPS"
            exit 1
        fi
    else
        CERT_DER_FILE=$(mktemp)
        if ! echo | openssl s_client -connect "${host}:${port}" -servername "$host" 2>/dev/null \
            | openssl x509 -outform DER > "$CERT_DER_FILE" 2>/dev/null; then
            rm -f "$CERT_DER_FILE"
            echo "   ⚠️  Could not fetch endpoint TLS certificate from ${host}:${port}"
            TLS_BINDING_RESULT="CERT-FETCH-FAILED"
            if [[ "$STRICT_TLS_BINDING" == "true" ]]; then
                echo "❌ ERROR: Strict mode enabled and TLS certificate fetch failed"
                exit 1
            fi
        else
            LIVE_CERT_DER_HASH=$(sha256sum "$CERT_DER_FILE" | cut -d' ' -f1)
            LIVE_SPKI_HASH=$(openssl x509 -inform DER -in "$CERT_DER_FILE" -pubkey -noout \
                | openssl pkey -pubin -outform DER 2>/dev/null \
                | sha256sum | cut -d' ' -f1)
            rm -f "$CERT_DER_FILE"

            echo "   Attested hash:      $ATTESTED_TLS_HASH"
            echo "   Live SPKI hash:     $LIVE_SPKI_HASH"
            echo "   Live cert DER hash: $LIVE_CERT_DER_HASH"

            if [[ "$ATTESTED_TLS_HASH" == "$LIVE_SPKI_HASH" ]]; then
                echo "   ✓ Channel binding match (SPKI/public-key hash)"
                TLS_BINDING_RESULT="MATCH-SPKI"
            elif [[ "$ATTESTED_TLS_HASH" == "$LIVE_CERT_DER_HASH" ]]; then
                echo "   ✓ Channel binding match (leaf cert DER hash)"
                TLS_BINDING_RESULT="MATCH-CERT-DER"
            else
                CF_RAY=$(curl -skI "$SERVICE_URL/health" 2>/dev/null | tr -d '\r' | awk -F': ' 'tolower($1)=="cf-ray"{print $2}')
                if [[ -n "$CF_RAY" ]]; then
                    echo "   ⚠️  TLS hash mismatch with Cloudflare header detected (cf-ray: $CF_RAY)"
                    echo "      Expected if this hostname is Cloudflare proxied (orange cloud)."
                    TLS_BINDING_RESULT="MISMATCH-CLOUDFLARE"
                else
                    echo "   ⚠️  TLS hash mismatch (no Cloudflare header detected)"
                    TLS_BINDING_RESULT="MISMATCH"
                fi
                if [[ "$STRICT_TLS_BINDING" == "true" ]]; then
                    echo "❌ ERROR: Strict mode enabled and TLS channel binding failed"
                    exit 1
                fi
            fi
        fi
    fi
fi
echo ""

echo "Step 3: Building container with Nix (reproducible)..."
echo "   This may take a few minutes on first run..."
echo ""

cd "$PROJECT_DIR"
nix build .#container --extra-experimental-features "nix-command flakes"

if [[ ! -L result ]]; then
    echo "❌ ERROR: Nix build failed"
    exit 1
fi

echo "   Build complete!"
echo ""

echo "Step 4: Calculating local image hash..."
LOCAL_TARBALL_HASH=$(sha256sum result | cut -d' ' -f1)
echo "   Local tarball hash: $LOCAL_TARBALL_HASH"
echo ""

echo "Step 5: Loading image and getting ID..."
docker load < result > /dev/null 2>&1
LOCAL_IMAGE_ID=$(docker inspect oa-verifier:latest --format='{{.Id}}' | cut -d: -f2)
echo "   Local image ID: $LOCAL_IMAGE_ID"
echo ""

echo "Step 6: Generating CCE policy locally..."
echo "   (Requires az CLI with confcom extension)"

# Create temp deployment template
TEMP_DIR=$(mktemp -d)
cat > "$TEMP_DIR/template.json" << EOF
{
  "\$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
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
          "image": "oa-verifier:latest",
          "ports": [{"port": 443, "protocol": "TCP"}],
          "resources": {"requests": {"cpu": 1.0, "memoryInGB": 2.0}}
        }
      },{
        "name": "skr-sidecar",
        "properties": {
          "image": "mcr.microsoft.com/aci/skr@sha256:baa6acf093c011cb26799187b6a535e32bd8248f52dd2cd9c606732b8a23c112",
          "command": ["/skr.sh"],
          "ports": [{"port": 8080, "protocol": "TCP"}],
          "resources": {"requests": {"cpu": 0.5, "memoryInGB": 1.0}}
        }
      }],
      "osType": "Linux",
      "confidentialComputeProperties": {"ccePolicy": ""}
    }
  }]
}
EOF

if command -v az &> /dev/null && az extension show --name confcom &> /dev/null; then
    az confcom acipolicygen -a "$TEMP_DIR/template.json" --disable-stdio > /dev/null 2>&1
    LOCAL_POLICY=$(jq -r '.resources[0].properties.confidentialComputeProperties.ccePolicy' "$TEMP_DIR/template.json")
    LOCAL_POLICY_HASH=$(echo "$LOCAL_POLICY" | base64 -d | sha256sum | cut -d' ' -f1)
    echo "   Local policy hash: $LOCAL_POLICY_HASH"
else
    echo "   ⚠️  az confcom not available - cannot generate policy hash locally"
    LOCAL_POLICY_HASH="SKIPPED"
fi

rm -rf "$TEMP_DIR"
echo ""

echo "=============================================="
echo "  VERIFICATION RESULTS"
echo "=============================================="
echo ""
echo "Remote (from attestation):"
echo "  Policy Hash: $REMOTE_POLICY_HASH"
echo "  TLS Binding: $TLS_BINDING_RESULT"
echo ""
echo "Local (from Nix build):"
echo "  Tarball Hash: $LOCAL_TARBALL_HASH"
echo "  Image ID:     $LOCAL_IMAGE_ID"
echo "  Policy Hash:  $LOCAL_POLICY_HASH"
echo ""

if [[ "$LOCAL_POLICY_HASH" == "$REMOTE_POLICY_HASH" ]]; then
    echo "✅ VERIFICATION PASSED"
    echo "   The locally built image matches the deployed attestation!"
    echo "   You can trust the code running in the enclave."
    exit 0
elif [[ "$LOCAL_POLICY_HASH" == "SKIPPED" ]]; then
    echo "⚠️  PARTIAL VERIFICATION"
    echo "   Nix build succeeded but policy hash could not be compared."
    echo "   Install az CLI with confcom extension for full verification."
    exit 0
else
    echo "❌ VERIFICATION FAILED"
    echo "   Local build does NOT match the deployed attestation!"
    echo "   The deployed code may be different from this source."
    exit 1
fi
