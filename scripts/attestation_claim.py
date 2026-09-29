#!/usr/bin/env python3
"""Read host data only AFTER verify-jwt.sh has validated this exact token."""
import base64
import json
import re
import sys
import time


def policy_hash(token, now=None):
    payload = token.strip().split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    now = time.time() if now is None else now
    if claims.get("iss") != "https://sharedeus.eus.attest.azure.net":
        raise ValueError("Unexpected attestation issuer")
    if not claims.get("nbf", float("inf")) <= now < claims.get("exp", 0):
        raise ValueError("Attestation is expired or not yet valid")
    value = claims.get("x-ms-sevsnpvm-hostdata", "")
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Attestation lacks a valid signed CCE policy hash")
    return value


if __name__ == "__main__":
    try:
        print(policy_hash(sys.stdin.read()))
    except (ValueError, TypeError, IndexError) as error:
        sys.exit(f"Invalid attestation claims: {error}")
