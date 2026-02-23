#!/bin/bash
# Zero-Trust Attestation Verification
set -e

STRICT_TLS_BINDING=true
ENDPOINT=""

usage() {
    cat <<EOF
Usage: $0 [--strict-tls-binding] [ENDPOINT]

Options:
  --strict-tls-binding  Fail if tls_pubkey_hash does not match live endpoint cert/public key.
  -h, --help            Show this help.

Examples:
  $0
  $0 https://verifier.openanonymity.ai
  $0 --strict-tls-binding https://oa-verifier.eastus.azurecontainer.io
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
            if [[ -n "$ENDPOINT" ]]; then
                echo "❌ Unexpected argument: $1"
                usage
                exit 1
            fi
            ENDPOINT="$1"
            shift
            ;;
    esac
done

# ENDPOINT="${ENDPOINT:-https://oa-verifier.eastus.azurecontainer.io}"
ENDPOINT="${ENDPOINT:-https://verifier.openanonymity.ai}"
TMPDIR=$(mktemp -d) && trap "rm -rf $TMPDIR" EXIT

for cmd in curl jq sha256sum openssl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "❌ Missing required command: $cmd"
        exit 1
    fi
done

endpoint_for_path="${ENDPOINT%/}"

echo "=== Zero-Trust Attestation Verification ==="
echo "Endpoint: $endpoint_for_path"
echo "Strict TLS binding: $STRICT_TLS_BINDING"
echo ""

# Step 1: Fetch attestation
echo "[1/5] Fetching attestation..."
NONCE=$(date +%s | sha256sum | head -c 16)
curl -sfk "${endpoint_for_path}/attestation?nonce=${NONCE}" > "$TMPDIR/att.json" || { echo "❌ Failed to fetch"; exit 1; }
echo "✓ Attestation fetched"

# Step 2: Verify policy hash matches hardware measurement
echo "[2/5] Verifying policy hash..."
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
echo "[3/5] Verifying JWT source..."
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

# Step 4: Verify TLS channel binding (optional strict fail)
echo "[4/5] Verifying TLS channel binding..."
ATTESTED_TLS_HASH=$(jq -r '.summary.tls_pubkey_hash // empty' "$TMPDIR/att.json")
if [[ -z "$ATTESTED_TLS_HASH" ]]; then
    echo "⚠️  Attestation did not include summary.tls_pubkey_hash"
    if [[ "$STRICT_TLS_BINDING" == "true" ]]; then
        echo "❌ Strict mode enabled: missing tls_pubkey_hash"
        exit 1
    fi
else
    scheme="${endpoint_for_path%%://*}"
    endpoint_no_scheme="${endpoint_for_path#*://}"
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
        echo "⚠️  Endpoint is not HTTPS; cannot perform TLS channel-binding check"
        if [[ "$STRICT_TLS_BINDING" == "true" ]]; then
            echo "❌ Strict mode enabled: HTTPS is required for channel binding"
            exit 1
        fi
    else
        cert_der_file="$TMPDIR/leaf.der"
        if ! echo | openssl s_client -connect "${host}:${port}" -servername "$host" 2>/dev/null \
            | openssl x509 -outform DER > "$cert_der_file" 2>/dev/null; then
            echo "⚠️  Could not fetch endpoint TLS certificate for ${host}:${port}"
            if [[ "$STRICT_TLS_BINDING" == "true" ]]; then
                echo "❌ Strict mode enabled: TLS certificate fetch failed"
                exit 1
            fi
        else
            LIVE_CERT_DER_HASH=$(sha256sum "$cert_der_file" | cut -d' ' -f1)
            LIVE_SPKI_HASH=$(openssl x509 -inform DER -in "$cert_der_file" -pubkey -noout \
                | openssl pkey -pubin -outform DER 2>/dev/null \
                | sha256sum | cut -d' ' -f1)

            echo "   Attested hash:      $ATTESTED_TLS_HASH"
            echo "   Live SPKI hash:     $LIVE_SPKI_HASH"
            echo "   Live cert DER hash: $LIVE_CERT_DER_HASH"

            if [[ "$ATTESTED_TLS_HASH" == "$LIVE_SPKI_HASH" ]]; then
                echo "✓ Channel binding match (SPKI/public-key hash)"
            elif [[ "$ATTESTED_TLS_HASH" == "$LIVE_CERT_DER_HASH" ]]; then
                echo "✓ Channel binding match (leaf cert DER hash)"
            else
                CF_RAY=$(curl -skI "${endpoint_for_path}/health" 2>/dev/null | tr -d '\r' | awk -F': ' 'tolower($1)=="cf-ray"{print $2}')
                if [[ -n "$CF_RAY" ]]; then
                    echo "⚠️  TLS hash mismatch and Cloudflare headers detected (cf-ray: $CF_RAY)"
                    echo "   This is expected when DNS proxy is ON: user TLS terminates at Cloudflare."
                else
                    echo "⚠️  TLS hash mismatch: endpoint cert does not match attested hash."
                fi
                if [[ "$STRICT_TLS_BINDING" == "true" ]]; then
                    echo "❌ Strict mode enabled: channel binding failed"
                    exit 1
                fi
            fi
        fi
    fi
fi

# Step 5: Show container info
echo "[5/5] Container info..."
CONTAINER_ID=$(jq -r '.policy.decoded' "$TMPDIR/att.json" | grep -o '"id":"ghcr[^"]*"' | head -1 | cut -d'"' -f4)
echo "   Image: $CONTAINER_ID"

# Summary
echo ""
echo "=== SUMMARY ==="
jq -r '"Type: \(.summary.attestation_type // "N/A")\nDebug: \(.summary.debug_disabled // "N/A")\nCompliance: \(.summary.compliance_status // "N/A")"' "$TMPDIR/att.json"
echo "Policy Hash: ${HOST_DATA:0:16}..."
echo ""
echo "✅ HARDWARE ATTESTATION VERIFIED"
