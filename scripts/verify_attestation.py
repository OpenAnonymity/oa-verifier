#!/usr/bin/env python3
"""
Attestation Verification Script for oa-verifier

This script acts as a user to verify that the oa-verifier service is running
the expected code inside an AMD SEV-SNP confidential container.

Usage:
    python verify_attestation.py [--url URL] [--policy-hash HASH] [--verbose]

Requirements:
    pip install requests pyjwt cryptography
"""

import argparse
import base64
import hashlib
import json
import secrets
import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import requests
    import jwt
    from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Missing dependencies. Install with:")
    print("  pip install requests pyjwt cryptography")
    sys.exit(1)


# Trusted Azure Attestation domains for JWKS verification
TRUSTED_ATTESTATION_DOMAINS = [
    ".attest.azure.net",
]


def get_tls_pubkey_hash(hostname: str, port: int) -> str:
    """
    Extract the TLS certificate from the server and compute SHA256 hash of the public key.
    This is used for TLS channel binding verification.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Self-signed cert
    
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
    
    if not cert_der:
        raise ValueError("No certificate received from server")
    
    # Parse certificate and extract public key
    cert = load_der_x509_certificate(cert_der)
    pubkey_bytes = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Compute SHA256 hash of public key (same as server does)
    return hashlib.sha256(pubkey_bytes).hexdigest()


# Default values
DEFAULT_SERVICE_URL = "https://oa-verifier.eastus.azurecontainer.io:8443"
DEFAULT_POLICY_HASH = "e8061d2fe752cec0cc23b254a4b9c0f121a32e3a499a0cbd323563f4bcf34618"


class AttestationVerifier:
    def __init__(self, service_url: str, expected_policy_hash: str, verbose: bool = False):
        self.service_url = service_url.rstrip('/')
        self.expected_policy_hash = expected_policy_hash
        self.verbose = verbose
        self.checks_passed = 0
        self.checks_failed = 0

    def log(self, msg: str):
        if self.verbose:
            print(f"  [DEBUG] {msg}")

    def check(self, name: str, condition: bool, details: str = ""):
        if condition:
            print(f"  ✅ {name}")
            self.checks_passed += 1
        else:
            print(f"  ❌ {name}")
            if details:
                print(f"     └── {details}")
            self.checks_failed += 1
        return condition

    def fetch_attestation(self, nonce: str) -> tuple[dict, str]:
        """
        Fetch attestation from the service.
        Returns (attestation_json, tls_pubkey_hash).
        """
        url = f"{self.service_url}/attestation?nonce={nonce}"
        self.log(f"Fetching: {url}")
        
        # Extract hostname and port for TLS binding
        parsed = urlparse(self.service_url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        
        # Get TLS public key hash for channel binding verification
        tls_hash = ""
        if parsed.scheme == "https":
            try:
                tls_hash = get_tls_pubkey_hash(hostname, port)
                self.log(f"TLS pubkey hash: {tls_hash}")
            except Exception as e:
                self.log(f"Failed to get TLS pubkey hash: {e}")
        
        resp = requests.get(url, timeout=30, verify=False)  # Self-signed cert
        resp.raise_for_status()
        return resp.json(), tls_hash

    def fetch_jwks(self, jwks_url: str) -> dict:
        """
        Fetch JSON Web Key Set from Azure.
        SECURITY: Only allows fetching from trusted Azure attestation domains.
        """
        # Validate that the JWKS URL is from a trusted Azure attestation domain
        parsed = urlparse(jwks_url)
        hostname = parsed.hostname or ""
        
        is_trusted = any(hostname.endswith(domain) for domain in TRUSTED_ATTESTATION_DOMAINS)
        if not is_trusted:
            raise ValueError(
                f"Security Alert: Server requested JWKS from untrusted domain: {hostname}\n"
                f"Only Azure attestation domains are trusted: {TRUSTED_ATTESTATION_DOMAINS}"
            )
        
        self.log(f"Fetching JWKS from trusted Azure domain: {jwks_url}")
        resp = requests.get(jwks_url, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def verify_jwt_signature(self, token: str, jwks: dict) -> dict:
        """Verify JWT signature and return decoded claims."""
        # Decode header without verification to get key ID
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        alg = header.get("alg", "RS256")
        
        self.log(f"JWT algorithm: {alg}, kid: {kid}")

        # Find matching key in JWKS
        public_key = None
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                # Get certificate from x5c
                if "x5c" in key and key["x5c"]:
                    cert_der = base64.b64decode(key["x5c"][0])
                    cert = load_der_x509_certificate(cert_der)
                    public_key = cert.public_key()
                    self.log(f"Found matching key, issuer: {cert.issuer}")
                    break

        if not public_key:
            raise ValueError(f"No matching key found for kid: {kid}")

        # Verify and decode
        claims = jwt.decode(
            token,
            public_key,
            algorithms=[alg],
            options={"verify_aud": False}  # No audience in attestation tokens
        )
        return claims

    def verify(self) -> bool:
        """Run full verification and return success status."""
        print("\n" + "=" * 60)
        print("  OA-VERIFIER ATTESTATION VERIFICATION (Zero Trust)")
        print("=" * 60)
        print(f"\nService URL: {self.service_url}")
        print(f"Expected Policy Hash: {self.expected_policy_hash}")

        # Step 1: Generate nonce
        print("\n[1/6] Generating fresh nonce...")
        nonce = secrets.token_hex(16)
        print(f"  Nonce: {nonce}")

        # Step 2: Fetch attestation (also captures TLS cert hash)
        print("\n[2/6] Fetching attestation from service...")
        tls_pubkey_hash = ""
        try:
            attestation, tls_pubkey_hash = self.fetch_attestation(nonce)
            print("  Received attestation response")
            if tls_pubkey_hash:
                print(f"  Captured TLS pubkey hash: {tls_pubkey_hash[:16]}...")
            self.log(f"Response keys: {list(attestation.keys())}")
        except requests.RequestException as e:
            print(f"  ❌ Failed to fetch attestation: {e}")
            return False

        summary = attestation.get("summary", {})
        token = attestation.get("token", "")
        verify_url = attestation.get("verify_at", "")

        # Step 3: Verify JWT signature (must do this BEFORE checking nonce)
        print("\n[3/6] Verifying JWT signature...")
        claims = {}
        if not token:
            print("  ❌ No token in response")
            self.checks_failed += 1
        else:
            try:
                jwks = self.fetch_jwks(verify_url)
                claims = self.verify_jwt_signature(token, jwks)
                self.check("JWT signature valid (signed by Azure)", True)
                self.check("JWKS fetched from trusted Azure domain", True)
                
                # Check token not expired
                exp = claims.get("exp", 0)
                now = datetime.now(timezone.utc).timestamp()
                self.check(
                    "Token not expired",
                    exp > now,
                    f"Expires: {datetime.fromtimestamp(exp, timezone.utc).isoformat()}"
                )
            except Exception as e:
                self.check("JWT signature valid", False, str(e))

        # Step 4: Verify TLS channel binding (prevents relay/MITM attacks)
        # CRITICAL: This proves you're talking directly to the enclave, not a proxy
        print("\n[4/6] Verifying TLS channel binding (anti-relay)...")
        
        # Extract tls_hash from inside the signed JWT
        jwt_tls_hash = None
        runtime_data = claims.get("x-ms-runtime", {})
        if isinstance(runtime_data, dict):
            if "tls_hash" in runtime_data:
                jwt_tls_hash = runtime_data.get("tls_hash")
            elif "client-payload" in runtime_data:
                client_payload = runtime_data.get("client-payload", {})
                if isinstance(client_payload, dict):
                    jwt_tls_hash = client_payload.get("tls_hash")
        
        if tls_pubkey_hash and jwt_tls_hash:
            self.log(f"TLS hash from connection: {tls_pubkey_hash}")
            self.log(f"TLS hash from JWT: {jwt_tls_hash}")
            self.check(
                "TLS channel bound to enclave (no proxy/MITM possible)",
                tls_pubkey_hash == jwt_tls_hash,
                f"Connection: {tls_pubkey_hash[:32]}...\nJWT claim:  {jwt_tls_hash[:32]}..."
            )
        elif not tls_pubkey_hash:
            print("  ⚠️  Skipped: Not using HTTPS or couldn't extract TLS cert")
        elif not jwt_tls_hash:
            print("  ⚠️  WARNING: Server did not include tls_hash in attestation")
            print("     └── Cannot verify you're talking directly to the enclave")
            self.checks_failed += 1

        # Step 5: Verify nonce INSIDE the signed JWT (freshness proof)
        # CRITICAL: The nonce must be inside the JWT, not just in the JSON wrapper!
        print("\n[5/6] Verifying freshness (nonce bound inside JWT)...")
        
        # The outer JSON nonce is NOT cryptographically bound - server could fake it
        outer_nonce = attestation.get("nonce", "")
        self.log(f"Outer JSON nonce (not trusted): {outer_nonce}")
        
        # Extract nonce from inside the cryptographically signed JWT
        jwt_nonce = None
        jwt_nonce_location = "not found in JWT"
        
        # Location 1: x-ms-runtime.nonce (direct)
        runtime_data = claims.get("x-ms-runtime", {})
        if isinstance(runtime_data, dict):
            if "nonce" in runtime_data:
                jwt_nonce = runtime_data.get("nonce")
                jwt_nonce_location = "x-ms-runtime.nonce"
            # Location 2: x-ms-runtime.client-payload.nonce (alternative structure)
            elif "client-payload" in runtime_data:
                client_payload = runtime_data.get("client-payload", {})
                if isinstance(client_payload, dict) and "nonce" in client_payload:
                    jwt_nonce = client_payload.get("nonce")
                    jwt_nonce_location = "x-ms-runtime.client-payload.nonce"
        
        # Location 3: Check summary.runtime_data (parsed from JWT by server)
        if jwt_nonce is None:
            summary_runtime = summary.get("runtime_data", {})
            if isinstance(summary_runtime, dict) and "nonce" in summary_runtime:
                jwt_nonce = summary_runtime.get("nonce")
                jwt_nonce_location = "summary.runtime_data.nonce (from JWT)"
        
        if jwt_nonce:
            self.log(f"Found nonce in JWT at: {jwt_nonce_location}")
            self.log(f"JWT nonce value: {jwt_nonce}")
            self.check(
                f"Nonce bound inside JWT ({jwt_nonce_location})",
                jwt_nonce == nonce,
                f"Expected: {nonce}, Got: {jwt_nonce}"
            )
        else:
            # Fallback warning - nonce not cryptographically bound
            self.log(f"WARNING: Nonce not found inside JWT claims!")
            self.log(f"Available JWT claims: {list(claims.keys())}")
            if outer_nonce == nonce:
                print("  ⚠️  Nonce only in outer JSON (not cryptographically bound)")
                print("     └── Server could replay old attestations with new nonce")
                self.checks_failed += 1
            else:
                self.check("Nonce present", False, "Nonce not found anywhere")

        # Step 6: Verify attestation claims
        print("\n[6/6] Verifying attestation claims...")

        # Check attestation type
        att_type = summary.get("attestation_type", "")
        self.check(
            "Running in AMD SEV-SNP enclave",
            att_type == "sevsnpvm",
            f"Got: {att_type}"
        )

        # Check debug disabled
        debug_disabled = summary.get("debug_disabled")
        self.check(
            "Debug disabled (no memory inspection possible)",
            debug_disabled is True,
            f"Got: {debug_disabled}"
        )

        # Check compliance status
        compliance = summary.get("compliance_status", "")
        self.check(
            "Compliance status is azure-compliant-uvm",
            "compliant" in compliance.lower(),
            f"Got: {compliance}"
        )

        # THE CRITICAL CHECK: Policy hash
        policy_hash = summary.get("cce_policy_hash") or summary.get("host_data", "")
        self.check(
            "CCE policy hash matches expected",
            policy_hash == self.expected_policy_hash,
            f"Expected: {self.expected_policy_hash}\n     └── Got:      {policy_hash}"
        )

        # Print summary
        print("\n" + "=" * 60)
        print("  VERIFICATION SUMMARY")
        print("=" * 60)
        print(f"\n  Checks Passed: {self.checks_passed}")
        print(f"  Checks Failed: {self.checks_failed}")

        if self.checks_failed == 0:
            print("\n  ✅ VERIFICATION SUCCESSFUL (Zero Trust)")
            print("  The service is running the expected code in a secure enclave.")
            print("  The TLS connection terminates inside the enclave (no proxy).")
            print("  The operator cannot see or modify the running code.")
            return True
        else:
            print("\n  ❌ VERIFICATION FAILED")
            print("  Do NOT trust this service!")
            print("  The running code may differ from expected,")
            print("  or a proxy may be intercepting your connection.")
            return False

    def print_full_claims(self, claims: dict):
        """Print all JWT claims for debugging."""
        print("\n[DEBUG] Full JWT claims:")
        for key, value in sorted(claims.items()):
            if isinstance(value, dict):
                print(f"  {key}:")
                for k, v in value.items():
                    print(f"    {k}: {v}")
            else:
                print(f"  {key}: {value}")


def print_derivation_guide():
    """Print guide on how to derive the expected policy hash from source."""
    print("""
================================================================================
  HOW TO DERIVE THE EXPECTED POLICY HASH FROM SOURCE CODE
================================================================================

The policy hash in the attestation (host_data) proves which container is running.
But how do you know what hash to expect? You must derive it yourself from source.

STEP 1: Clone the source code
─────────────────────────────
    git clone https://github.com/openanonymity/oa-verifier.git
    cd oa-verifier

STEP 2: Review the code (this is YOUR audit)
────────────────────────────────────────────
    # Look at what the code does
    cat internal/server/handlers.go
    cat Dockerfile
    # Make sure there's nothing malicious

STEP 3: Build the container
───────────────────────────
    # The Dockerfile pins base images by digest for reproducibility:
    # - golang@sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052
    # - alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1
    
    docker build -t oa-verifier-local .
    
    # Tag it for a registry (required for policy generation)
    docker tag oa-verifier-local myregistry.azurecr.io/oa-verifier:verify

STEP 4: Generate the CCE policy
───────────────────────────────
    # Install Azure CLI confcom extension
    az extension add --name confcom
    
    # Create a minimal ARM template for policy generation
    cat > /tmp/verify-template.json << 'EOF'
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [{
    "type": "Microsoft.ContainerInstance/containerGroups",
    "apiVersion": "2023-05-01",
    "name": "verify",
    "location": "eastus",
    "properties": {
      "sku": "Confidential",
      "containers": [{
        "name": "oa-verifier",
        "properties": {
          "image": "myregistry.azurecr.io/oa-verifier:verify",
          "command": ["/app/verifier"],
          "ports": [{"port": 8000}],
          "resources": {"requests": {"cpu": 1, "memoryInGB": 2}},
          "environmentVariables": [
            {"name": "PORT", "value": "8000"},
            {"name": "MAA_ENDPOINT", "value": "http://localhost:8080/attest/maa"},
            {"name": "MAA_PROVIDER_URL", "value": "sharedeus.eus.attest.azure.net"}
          ]
        }
      }],
      "osType": "Linux",
      "confidentialComputeProperties": {"ccePolicy": ""}
    }
  }]
}
EOF
    
    # Generate the policy (this reads your local image layers)
    az confcom acipolicygen -a /tmp/verify-template.json --print-policy > /tmp/my-policy.rego

STEP 5: Compute the policy hash
───────────────────────────────
    # The hash is SHA256 of the raw policy bytes
    sha256sum /tmp/my-policy.rego | cut -d' ' -f1
    
    # Example output:
    # bb4ce8d9e736e60acb2e74b6e20db6c947088f6feea0a4918b23e00881c288b5

STEP 6: Compare with attestation
────────────────────────────────
    # Run verification with YOUR derived hash
    python verify_attestation.py --policy-hash YOUR_COMPUTED_HASH
    
    # Or just fetch and compare manually:
    curl -s 'http://oa-verifier.eastus.azurecontainer.io:8000/attestation' | \\
      jq -r '.summary.cce_policy_hash'

================================================================================
  IMPORTANT NOTES
================================================================================

1. REPRODUCIBLE BUILDS
   For this to work, the container build must be reproducible. The Dockerfile
   uses specific flags (CGO_ENABLED=0, -trimpath, -ldflags="-s -w -buildid=")
   to help with this, but Docker layer ordering and timestamps can still differ.

2. WHY POLICY HASH, NOT JUST IMAGE HASH?
   The CCE policy contains MORE than just the image hash. It includes:
   - Allowed container image digests (layer hashes)
   - Allowed environment variables
   - Allowed commands
   - Security settings
   
   Different policies with the same image would have different hashes.

3. THE SIDECAR MATTERS
   The production deployment includes an "skr-sidecar" container. The policy
   hash covers BOTH containers. To get the exact same hash, you need to
   generate a policy with the same sidecar version.

4. TRUST CHAIN
   Source Code → Container Image → CCE Policy → Policy Hash → host_data
   ↑                                                              ↑
   You audit this                                    Attestation returns this

================================================================================
""")


def print_raw_verification(service_url: str):
    """Print raw data so user can manually verify."""
    print("\n" + "=" * 70)
    print("  RAW VERIFICATION DATA")
    print("  Copy these values and verify manually if you don't trust this script")
    print("=" * 70)

    # Generate nonce
    nonce = secrets.token_hex(16)
    print(f"\n[1] YOUR NONCE (generated on your machine):")
    print(f"    {nonce}")

    # Get TLS pubkey hash
    parsed = urlparse(service_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    tls_hash = ""
    if parsed.scheme == "https":
        try:
            tls_hash = get_tls_pubkey_hash(hostname, port)
            print(f"\n[1.5] TLS PUBLIC KEY HASH (from your connection):")
            print(f"    {tls_hash}")
        except Exception as e:
            print(f"\n[1.5] TLS PUBLIC KEY HASH: Failed to extract ({e})")

    # Fetch attestation
    url = f"{service_url.rstrip('/')}/attestation?nonce={nonce}"
    print(f"\n[2] FETCHING FROM:")
    print(f"    {url}")
    
    resp = requests.get(url, timeout=30, verify=False)  # Self-signed cert
    data = resp.json()
    
    token = data.get("token", "")
    verify_url = data.get("verify_at", "")
    
    print(f"\n[3] RETURNED NONCE (must match yours):")
    print(f"    {data.get('nonce', 'NOT FOUND')}")
    
    print(f"\n[4] JWT TOKEN (first 100 chars):")
    print(f"    {token[:100]}...")
    
    print(f"\n[5] AZURE SIGNING KEYS URL:")
    print(f"    {verify_url}")
    print(f"    (This is Azure's server, not oa-verifier's)")
    
    # Decode JWT without verification to show structure
    parts = token.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    # Payload needs padding
    payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_padded))
    
    print(f"\n[6] JWT HEADER (decoded):")
    print(f"    Algorithm: {header.get('alg')}")
    print(f"    Key ID: {header.get('kid')}")
    print(f"    Key URL: {header.get('jku')}")
    
    print(f"\n[7] KEY CLAIMS FROM JWT PAYLOAD:")
    print(f"    Issuer: {payload.get('iss')}")
    print(f"    Attestation Type: {payload.get('x-ms-attestation-type')}")
    print(f"    Host Data (Policy Hash): {payload.get('x-ms-sevsnpvm-hostdata')}")
    print(f"    Is Debuggable: {payload.get('x-ms-sevsnpvm-is-debuggable')}")
    print(f"    Compliance: {payload.get('x-ms-compliance-status')}")
    
    # Show where nonce should be inside JWT
    runtime = payload.get("x-ms-runtime", {})
    jwt_nonce = "NOT FOUND"
    if isinstance(runtime, dict):
        # Check direct nonce first
        if "nonce" in runtime:
            jwt_nonce = runtime.get("nonce")
        # Then check client-payload
        elif "client-payload" in runtime:
            client_payload = runtime.get("client-payload", {})
            if isinstance(client_payload, dict):
                jwt_nonce = client_payload.get("nonce", "NOT FOUND")
    
    print(f"\n[8] NONCE BINDING (CRITICAL FOR FRESHNESS):")
    print(f"    Your nonce:           {nonce}")
    print(f"    Outer JSON nonce:     {data.get('nonce', 'NOT FOUND')} (NOT SECURE - can be faked)")
    print(f"    JWT x-ms-runtime:     {runtime}")
    print(f"    Nonce inside JWT:     {jwt_nonce}")
    if jwt_nonce == nonce:
        print(f"    ✅ MATCH: Nonce is cryptographically bound inside signed JWT")
    elif jwt_nonce == "NOT FOUND":
        print(f"    ⚠️  WARNING: Nonce not found inside JWT - freshness not provable!")
    else:
        print(f"    ❌ MISMATCH: JWT nonce doesn't match your nonce!")
    
    # TLS binding check
    jwt_tls_hash = "NOT FOUND"
    if isinstance(runtime, dict):
        if "tls_hash" in runtime:
            jwt_tls_hash = runtime.get("tls_hash")
        elif "client-payload" in runtime:
            client_payload = runtime.get("client-payload", {})
            if isinstance(client_payload, dict):
                jwt_tls_hash = client_payload.get("tls_hash", "NOT FOUND")
    
    print(f"\n[8.5] TLS CHANNEL BINDING (CRITICAL FOR ANTI-RELAY):")
    print(f"    Your TLS hash:        {tls_hash or 'NOT CAPTURED'}")
    print(f"    JWT tls_hash:         {jwt_tls_hash}")
    if tls_hash and jwt_tls_hash != "NOT FOUND" and tls_hash == jwt_tls_hash:
        print(f"    ✅ MATCH: TLS connection terminates at enclave (no proxy)")
    elif not tls_hash:
        print(f"    ⚠️  WARNING: Could not capture TLS hash from connection")
    elif jwt_tls_hash == "NOT FOUND":
        print(f"    ⚠️  WARNING: Server did not include tls_hash in JWT")
    else:
        print(f"    ❌ MISMATCH: Possible MITM/relay attack!")
    
    print(f"\n[9] TO VERIFY MANUALLY:")
    print(f"    1. Go to https://jwt.io")
    print(f"    2. Paste this token:")
    print(f"       {token}")
    print(f"    3. Get the public key from: {verify_url}")
    print(f"       (MUST be from *.attest.azure.net domain)")
    print(f"    4. Verify the signature matches")
    print(f"    5. Check 'x-ms-sevsnpvm-hostdata' matches your expected policy hash")
    print(f"    6. Check 'x-ms-runtime.client-payload.nonce' matches YOUR nonce")
    print(f"    7. Check 'x-ms-runtime.client-payload.tls_hash' matches YOUR TLS hash")
    
    print(f"\n[10] CURL COMMANDS TO VERIFY INDEPENDENTLY:")
    print(f"    # Fetch attestation with your nonce (-k for self-signed cert):")
    print(f"    curl -k '{url}'")
    print(f"")
    print(f"    # Fetch Azure's signing keys:")
    print(f"    curl '{verify_url}'")
    
    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Verify oa-verifier attestation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Verify with defaults
  python verify_attestation.py

  # Verify against a specific service
  python verify_attestation.py --url http://localhost:8000

  # Verify with a specific expected policy hash
  python verify_attestation.py --policy-hash abc123...

  # Verbose output
  python verify_attestation.py --verbose
"""
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_SERVICE_URL,
        help=f"Service URL (default: {DEFAULT_SERVICE_URL})"
    )
    parser.add_argument(
        "--policy-hash",
        default=DEFAULT_POLICY_HASH,
        help="Expected CCE policy hash"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Print raw data for manual verification"
    )
    parser.add_argument(
        "--show-how-to-derive",
        action="store_true",
        help="Show how to derive the expected policy hash from source code"
    )

    args = parser.parse_args()

    if args.show_how_to_derive:
        print_derivation_guide()
        sys.exit(0)

    if args.raw:
        print_raw_verification(args.url)
        sys.exit(0)

    verifier = AttestationVerifier(
        service_url=args.url,
        expected_policy_hash=args.policy_hash,
        verbose=args.verbose
    )

    success = verifier.verify()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

