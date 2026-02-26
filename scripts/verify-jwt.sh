#!/usr/bin/env bash
# Verify an Azure Attestation JWT: signature (RSA via openssl) + nonce.
# Usage: verify-jwt.sh <token> <verify_at> <expected_nonce>
# Requires: bash, openssl, jq, xxd, curl, base64
set -euo pipefail

TOKEN="$1"
VERIFY_AT="${2:-}"
EXPECTED_NONCE="${3:-}"

# --- helpers ---

b64url_decode() {
  local s="${1//-/+}"
  s="${s//_//}"
  case $(( ${#s} % 4 )) in
    2) s="${s}==" ;; 3) s="${s}=" ;;
  esac
  echo "$s" | base64 -d
}

asn1_len() {
  local len=$1
  if [ "$len" -lt 128 ]; then printf '%02x' "$len"
  elif [ "$len" -lt 256 ]; then printf '81%02x' "$len"
  else printf '82%04x' "$len"; fi
}

# --- split JWT ---

IFS='.' read -r HEADER_B64 PAYLOAD_B64 SIG_B64 <<< "$TOKEN"

HEADER_JSON=$(b64url_decode "$HEADER_B64")
ALG=$(echo "$HEADER_JSON" | jq -r '.alg')
KID=$(echo "$HEADER_JSON" | jq -r '.kid')
JKU=$(echo "$HEADER_JSON" | jq -r '.jku // empty')

# --- validate key URL ---

KEY_URL="${JKU:-$VERIFY_AT}"
if [ -n "$JKU" ] && [ -n "$VERIFY_AT" ] && [ "$JKU" != "$VERIFY_AT" ]; then
  echo "❌ jku mismatch: header=$JKU verify_at=$VERIFY_AT" >&2; exit 1
fi
if [[ ! "$KEY_URL" =~ ^https://[^/]*\.attest\.azure\.net/certs$ ]]; then
  echo "❌ untrusted key URL: $KEY_URL" >&2; exit 1
fi

# --- fetch JWKS and find key ---

JWKS=$(curl -sf "$KEY_URL") || { echo "❌ Failed to fetch JWKS from $KEY_URL" >&2; exit 1; }
JWK=$(echo "$JWKS" | jq -e --arg kid "$KID" '.keys[] | select(.kid == $kid)') \
  || { echo "❌ kid $KID not found in JWKS" >&2; exit 1; }

N_B64=$(echo "$JWK" | jq -r '.n')
E_B64=$(echo "$JWK" | jq -r '.e')

# --- convert JWK RSA to PEM ---

N_HEX=$(b64url_decode "$N_B64" | xxd -p | tr -d '\n')
E_HEX=$(b64url_decode "$E_B64" | xxd -p | tr -d '\n')

# Ensure positive ASN.1 integers (prepend 00 if high bit is set)
[[ "${N_HEX:0:1}" =~ [89a-f] ]] && N_HEX="00${N_HEX}"
[[ "${E_HEX:0:1}" =~ [89a-f] ]] && E_HEX="00${E_HEX}"

# RSAPublicKey ::= SEQUENCE { INTEGER n, INTEGER e }
N_DER="02$(asn1_len $(( ${#N_HEX} / 2 )))${N_HEX}"
E_DER="02$(asn1_len $(( ${#E_HEX} / 2 )))${E_HEX}"
RSA_BODY="${N_DER}${E_DER}"
RSA_SEQ="30$(asn1_len $(( ${#RSA_BODY} / 2 )))${RSA_BODY}"

# SubjectPublicKeyInfo wrapping
OID_RSA="06092a864886f70d0101010500"  # rsaEncryption OID + NULL
BITSTRING_BODY="00${RSA_SEQ}"
BITSTRING="03$(asn1_len $(( ${#BITSTRING_BODY} / 2 )))${BITSTRING_BODY}"
ALGO_SEQ="30$(asn1_len $(( ${#OID_RSA} / 2 )))${OID_RSA}"
SPKI_BODY="${ALGO_SEQ}${BITSTRING}"
SPKI="30$(asn1_len $(( ${#SPKI_BODY} / 2 )))${SPKI_BODY}"

TMPDIR=$(mktemp -d)
trap "rm -rf '$TMPDIR'" EXIT

{
  echo "-----BEGIN PUBLIC KEY-----"
  echo "$SPKI" | xxd -r -p | base64 | fold -w 64
  echo "-----END PUBLIC KEY-----"
} > "$TMPDIR/pubkey.pem"

# --- verify signature ---

b64url_decode "$SIG_B64" > "$TMPDIR/sig.bin"

case "$ALG" in
  RS256) DGST="-sha256" ;; RS384) DGST="-sha384" ;; RS512) DGST="-sha512" ;;
  *) echo "❌ Unsupported algorithm: $ALG" >&2; exit 1 ;;
esac

if ! echo -n "${HEADER_B64}.${PAYLOAD_B64}" | \
     openssl dgst "$DGST" -verify "$TMPDIR/pubkey.pem" -signature "$TMPDIR/sig.bin" > /dev/null 2>&1; then
  echo "❌ JWT signature verification failed" >&2; exit 1
fi

# --- verify nonce ---

PAYLOAD_JSON=$(b64url_decode "$PAYLOAD_B64")
NONCE=$(echo "$PAYLOAD_JSON" | jq -r '(."x-ms-runtime".nonce // ."x-ms-runtime"."client-payload".nonce) // empty')

if [ -n "$EXPECTED_NONCE" ]; then
  if [ -z "$NONCE" ]; then
    echo "❌ nonce missing from JWT runtime payload" >&2; exit 1
  fi
  if [ "$NONCE" != "$EXPECTED_NONCE" ]; then
    echo "❌ nonce mismatch: expected $EXPECTED_NONCE, got $NONCE" >&2; exit 1
  fi
fi

echo "JWT signature and nonce verified"
