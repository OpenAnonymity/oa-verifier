#!/usr/bin/env python3
"""Maintain the Key Vault release policy of the sealing key (SKR).

The verifier seals its persisted state (TLS bundle, station registry) under a
key that Azure Key Vault releases only to an enclave whose attestation claims
satisfy the key's *release policy*. The decisive claim is
``x-ms-sevsnpvm-hostdata``: the SHA-256 of the CCE policy of the running
container group, i.e. the same hash users verify through ``/attestation``.

Every image change changes that hash, so before a new build is deployed its
hash must be added to the release policy or the new verifier cannot open the
state it saved (it would start empty, exactly like before persistence). This
module builds that updated policy. It keeps a bounded window of recent hashes
so a rollback to the previous build can still unseal, and drops everything
older.

Only pure policy manipulation lives here so it can be unit-tested offline; the
workflow step reads the current policy with ``az``, calls :func:`merge`, and
writes the result back with ``az keyvault key set-attributes --policy``.

Reference: https://learn.microsoft.com/azure/confidential-computing/skr-policy-examples
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from typing import Any

HOSTDATA_CLAIM = "x-ms-sevsnpvm-hostdata"
DEFAULT_AUTHORITY = "https://sharedeus.eus.attest.azure.net"
# Claims every release must satisfy besides the policy hash. They pin the
# environment to a non-debuggable, Azure-compliant SEV-SNP utility VM.
FIXED_CLAIMS = (
    ("x-ms-attestation-type", "sevsnpvm"),
    ("x-ms-compliance-status", "azure-compliant-uvm"),
    ("x-ms-sevsnpvm-is-debuggable", "false"),
)
POLICY_VERSION = "1.0.0"
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def normalize_authority(authority: str) -> str:
    """Return the MAA authority as the https URL the policy expects."""
    authority = authority.strip().rstrip("/")
    if not authority:
        raise ValueError("empty attestation authority")
    if not authority.startswith("https://"):
        if "://" in authority:
            raise ValueError(f"attestation authority must be https: {authority}")
        authority = "https://" + authority
    return authority


def decode_policy(raw: str | bytes | None) -> dict[str, Any] | None:
    """Decode what ``az keyvault key show`` reports as ``releasePolicy.encodedPolicy``.

    Depending on the CLI version this is the JSON text itself, or that text
    base64/base64url-encoded. Returns None for an absent policy.
    """
    if raw is None:
        return None
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    text = raw.strip()
    if not text or text.lower() in {"null", "none"}:
        return None
    # Use az -o json for lossless transport. Depending on CLI version,
    # encodedPolicy is itself JSON text or base64 inside that JSON string.
    # Unwrap only bounded JSON string layers; never evaluate Python literals.
    for _ in range(3):
        try:
            obj = json.loads(text)
        except ValueError:
            break
        if isinstance(obj, str):
            text = obj.strip()
            continue
        return _as_policy(obj)
    padded = text + "=" * (-len(text) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return _as_policy(json.loads(decoder(padded).decode("utf-8")))
        except (ValueError, UnicodeDecodeError):
            continue
    raise ValueError("release policy is neither JSON nor base64-encoded JSON")


def _as_policy(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict) or not isinstance(obj.get("anyOf"), list):
        raise ValueError("release policy must be an object with an anyOf list")
    return obj


def existing_hashes(policy: dict[str, Any] | None, authority: str) -> list[str]:
    """Hashes currently authorised for ``authority``, most recent first.

    Order within the policy is the order we wrote (newest first), so it is
    preserved. Entries for other authorities or without a hostdata claim are
    ignored: they are not ours to keep.
    """
    if not policy:
        return []
    found: list[str] = []
    for entry in policy.get("anyOf", []):
        if not isinstance(entry, dict):
            continue
        entry_authority = entry.get("authority")
        if entry_authority and normalize_authority(str(entry_authority)) != authority:
            continue
        for claim in entry.get("allOf", []):
            if isinstance(claim, dict) and claim.get("claim") == HOSTDATA_CLAIM:
                value = str(claim.get("equals", "")).lower()
                if HASH_RE.match(value) and value not in found:
                    found.append(value)
    return found


def build_policy(hashes: list[str], authority: str) -> dict[str, Any]:
    """A release policy allowing exactly ``hashes`` (one anyOf entry each)."""
    if not hashes:
        raise ValueError("a release policy needs at least one policy hash")
    entries = []
    for h in hashes:
        entries.append({
            "authority": authority,
            "allOf": [{"claim": HOSTDATA_CLAIM, "equals": h}]
            + [{"claim": c, "equals": v} for c, v in FIXED_CLAIMS],
        })
    return {"version": POLICY_VERSION, "anyOf": entries}


def merge(current: dict[str, Any] | None, new_hash: str, keep: int, authority: str = DEFAULT_AUTHORITY) -> dict[str, Any]:
    """Return the policy to install: ``new_hash`` first, then up to ``keep-1``
    of the hashes already authorised, oldest dropped.

    ``keep`` is the total number of hashes allowed to unseal at once. 1 means
    "only the build being deployed" (no rollback without a human login); 2–4 is
    the practical range. Placeholder hashes used at key creation (all zeros)
    are always dropped.
    """
    new_hash = new_hash.strip().lower()
    if not HASH_RE.match(new_hash):
        raise ValueError(f"policy hash must be 64 hex characters, got {new_hash!r}")
    if keep < 1:
        raise ValueError("keep must be at least 1")
    authority = normalize_authority(authority)
    hashes = [new_hash]
    for h in existing_hashes(current, authority):
        if h == new_hash or set(h) == {"0"}:
            continue
        hashes.append(h)
    return build_policy(hashes[:keep], authority)


def same_policy(a: dict[str, Any] | None, b: dict[str, Any] | None, authority: str = DEFAULT_AUTHORITY) -> bool:
    """True when both policies authorise the same hashes in the same order, each
    with the fixed claims. Used to skip a Key Vault write that would change
    nothing."""
    if a is None or b is None:
        return False
    authority = normalize_authority(authority)
    ha, hb = existing_hashes(a, authority), existing_hashes(b, authority)
    if ha != hb or not ha:
        return False
    return all(allows(a, h, authority) and allows(b, h, authority) for h in ha)


def allows(policy: dict[str, Any] | None, policy_hash: str, authority: str = DEFAULT_AUTHORITY) -> bool:
    """True when ``policy`` has an entry for ``policy_hash`` with the fixed claims."""
    if not policy:
        return False
    authority = normalize_authority(authority)
    for entry in policy.get("anyOf", []):
        if not isinstance(entry, dict) or normalize_authority(str(entry.get("authority", ""))) != authority:
            continue
        claims = {c.get("claim"): str(c.get("equals", "")).lower() for c in entry.get("allOf", []) if isinstance(c, dict)}
        if claims.get(HOSTDATA_CLAIM) != policy_hash.lower():
            continue
        if all(claims.get(c) == v for c, v in FIXED_CLAIMS):
            return True
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("merge", help="print the policy to install for a new build (exit 3 if the current one is already identical)")
    m.add_argument("--current", help="file holding the current encodedPolicy (any encoding); '-' for stdin; omit if none")
    m.add_argument("--new-hash", required=True)
    m.add_argument("--keep", type=int, default=4)
    m.add_argument("--authority", default=DEFAULT_AUTHORITY)
    c = sub.add_parser("check", help="exit 0 when the policy allows the hash")
    c.add_argument("--current", required=True)
    c.add_argument("--hash", required=True)
    c.add_argument("--authority", default=DEFAULT_AUTHORITY)
    args = parser.parse_args(argv)

    def read(path: str | None) -> str | None:
        if path is None:
            return None
        if path == "-":
            return sys.stdin.read()
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    try:
        if args.cmd == "merge":
            current = decode_policy(read(args.current))
            policy = merge(current, args.new_hash, args.keep, args.authority)
            json.dump(policy, sys.stdout, indent=2)
            sys.stdout.write("\n")
            return 3 if same_policy(current, policy, args.authority) else 0
        ok = allows(decode_policy(read(args.current)), args.hash, args.authority)
        print("allowed" if ok else "not allowed")
        return 0 if ok else 1
    except (ValueError, OSError) as error:
        print(f"release_policy: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
