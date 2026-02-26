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
INSECURE_SKIP_TLS_VERIFY=false
SERVICE_URL=""

usage() {
    cat <<EOF
Usage: $0 [--strict-tls-binding] [SERVICE_URL]

Options:
  --strict-tls-binding  Fail if tls_pubkey_hash does not match live endpoint cert/public key.
  --no-strict-tls-binding  Continue even if TLS channel binding cannot be strictly validated.
  --insecure-skip-tls-verify  Allow curl -k when fetching attestation (not zero-trust safe).
  -h, --help            Show this help.

Examples:
  $0
  $0 https://verifier.openanonymity.ai
  $0 --strict-tls-binding https://verifier.openanonymity.ai
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --strict-tls-binding)
            STRICT_TLS_BINDING=true
            shift
            ;;
        --no-strict-tls-binding)
            STRICT_TLS_BINDING=false
            shift
            ;;
        --insecure-skip-tls-verify)
            INSECURE_SKIP_TLS_VERIFY=true
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

SERVICE_URL="${SERVICE_URL:-https://verifier.openanonymity.ai}"
SERVICE_URL="${SERVICE_URL%/}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=============================================="
echo "  ZERO-TRUST LOCAL VERIFICATION"
echo "=============================================="
echo "  Strict TLS binding: $STRICT_TLS_BINDING"
echo "  Insecure TLS fetch: $INSECURE_SKIP_TLS_VERIFY"
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
for cmd in curl jq sha256sum openssl docker; do
    if ! command -v $cmd &> /dev/null; then
        echo "❌ ERROR: $cmd is not installed"
        exit 1
    fi
done

echo "Step 1: Fetching attestation from service..."
echo "   URL: $SERVICE_URL/attestation"
echo ""

if [[ "$INSECURE_SKIP_TLS_VERIFY" == "true" ]]; then
    CURL_FLAGS="-sfk"
else
    CURL_FLAGS="-sf"
fi
ATTESTATION=$(curl $CURL_FLAGS "$SERVICE_URL/attestation?nonce=verify-$(date +%s)")
if [[ -z "$ATTESTATION" ]]; then
    echo "❌ ERROR: Could not fetch attestation"
    exit 1
fi

REMOTE_POLICY_HASH=$(echo "$ATTESTATION" | jq -r '.summary.cce_policy_hash // .summary.host_data')
ATTESTED_TLS_HASH=$(echo "$ATTESTATION" | jq -r '.summary.tls_pubkey_hash // empty')
COMPUTED_REMOTE_POLICY_HASH=$(echo "$ATTESTATION" | jq -r '.policy.base64' | base64 -d | sha256sum | cut -d' ' -f1)
if [[ "$COMPUTED_REMOTE_POLICY_HASH" != "$REMOTE_POLICY_HASH" ]]; then
    echo "❌ ERROR: Attestation policy hash mismatch (decoded policy != host_data)"
    exit 1
fi
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
                echo "   ⚠️  TLS hash mismatch: endpoint certificate/public key does not match attested hash"
                TLS_BINDING_RESULT="MISMATCH"
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

echo "Step 6: Extracting deployed image digest from attestation policy..."
REMOTE_IMAGE=$(echo "$ATTESTATION" | jq -r '.policy.decoded | capture("\"id\":\"(?<img>[^\"]+)\"") | .img' 2>/dev/null || true)
if [[ -z "$REMOTE_IMAGE" || "$REMOTE_IMAGE" == "null" ]]; then
    echo "❌ ERROR: Could not extract image reference from attestation policy"
    exit 1
fi
REMOTE_DIGEST="${REMOTE_IMAGE##*@}"
if [[ -z "$REMOTE_DIGEST" || "$REMOTE_DIGEST" == "$REMOTE_IMAGE" ]]; then
    echo "❌ ERROR: Could not extract digest from image reference: $REMOTE_IMAGE"
    exit 1
fi
echo "   Remote image:  $REMOTE_IMAGE"
echo "   Remote digest: $REMOTE_DIGEST"
echo ""

echo "Step 7: Calculating local manifest digest..."
LOCAL_REGISTRY_NAME="oa-verifier-local-registry"
if docker ps -a --format '{{.Names}}' | grep -qx "$LOCAL_REGISTRY_NAME"; then
    docker rm -f "$LOCAL_REGISTRY_NAME" >/dev/null 2>&1 || true
fi
docker run -d -p 5000:5000 --name "$LOCAL_REGISTRY_NAME" registry:2 >/dev/null
trap 'docker rm -f "$LOCAL_REGISTRY_NAME" >/dev/null 2>&1 || true' EXIT

docker tag oa-verifier:latest localhost:5000/oa-verifier:latest
docker push localhost:5000/oa-verifier:latest >/dev/null
LOCAL_DIGEST=$(docker inspect localhost:5000/oa-verifier:latest --format='{{index .RepoDigests 0}}' | cut -d'@' -f2)
docker rm -f "$LOCAL_REGISTRY_NAME" >/dev/null 2>&1 || true
trap - EXIT

if [[ -z "$LOCAL_DIGEST" ]]; then
    echo "❌ ERROR: Could not determine local image digest"
    exit 1
fi
echo "   Local digest:  $LOCAL_DIGEST"
echo ""

echo "=============================================="
echo "  VERIFICATION RESULTS"
echo "=============================================="
echo ""
echo "Remote (from attestation):"
echo "  Policy Hash: $REMOTE_POLICY_HASH"
echo "  TLS Binding: $TLS_BINDING_RESULT"
echo "  Image Digest: $REMOTE_DIGEST"
echo ""
echo "Local (from Nix build):"
echo "  Tarball Hash: $LOCAL_TARBALL_HASH"
echo "  Image ID:     $LOCAL_IMAGE_ID"
echo "  Image Digest: $LOCAL_DIGEST"
echo ""

if [[ "$LOCAL_DIGEST" == "$REMOTE_DIGEST" ]]; then
    echo "✅ VERIFICATION PASSED"
    echo "   The locally built image digest matches the deployed attestation policy."
    echo "   You can trust this deployment is running this source build."
    exit 0
else
    echo "❌ VERIFICATION FAILED"
    echo "   Local build digest does NOT match the deployed attestation policy digest!"
    echo "   The deployed code may be different from this source."
    exit 1
fi
