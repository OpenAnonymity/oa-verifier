#!/usr/bin/env python3
"""Validate narrowly queried Azure metadata; never infer a deployment from tags."""
import json
import os
from pathlib import Path
import re
import sys


def deployment_values(metadata, expected_identity=""):
    containers = metadata.get("containers") or []
    matches = [c for c in containers if c.get("name") == "oa-verifier"]
    if len(matches) != 1:
        raise ValueError("Expected exactly one oa-verifier container")
    match = re.fullmatch(
        r"(oaverifieracr\.azurecr\.io|ghcr\.io/openanonymity)"
        r"/oa-verifier@(sha256:[0-9a-f]{64})", matches[0].get("image", "")
    )
    if not match:
        raise ValueError("Deployed image must use an approved registry and immutable digest")
    registry, digest = match.groups()
    credentials = [c for c in metadata.get("registries") or []
                   if c.get("server") == registry.split("/")[0]]
    if len(credentials) > 1:
        raise ValueError("Ambiguous registry identity configuration")
    identity = credentials[0].get("identity") if credentials else None
    if identity and (registry != "oaverifieracr.azurecr.io" or identity != expected_identity):
        raise ValueError("Deployed pull identity does not match configured verification identity")
    return {
        "registry": registry,
        "digest": digest,
        "use_ghcr": str(registry.startswith("ghcr.io/")).lower(),
        "use_identity": str(bool(identity)).lower(),
    }


if __name__ == "__main__":
    try:
        values = deployment_values(json.loads(Path(sys.argv[1]).read_text()),
                                   os.environ.get("PULL_IDENTITY_ID", ""))
        for key, value in values.items():
            print(f"{key}={value}")
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        sys.exit(f"Cannot determine exact deployment: {error}")
