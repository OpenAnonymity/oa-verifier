#!/usr/bin/env python3
"""Inspect only the shared verifier; transient or unknown states never trigger a heal."""
import json
import os
import re
import subprocess
from pathlib import Path

TARGET = "oa-verifier-2"
RESOURCE_GROUP = "oa-verifier"


def inspect(run=subprocess.run):
    result = run(
        ["az", "container", "show", "--name", TARGET,
         "--resource-group", RESOURCE_GROUP, "--query", "provisioningState",
         "--output", "json", "--only-show-errors"],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode:
        # Do not mistake denied access, a missing subscription/resource group,
        # networking trouble or an arbitrary "NotFound" string for a missing group.
        if re.search(r"\(ResourceNotFound\)", result.stderr):
            return True, "Missing", "container group is missing"
        raise RuntimeError("Azure inspection failed; no recovery decision made")
    try:
        state = json.loads(result.stdout)
    except (ValueError, TypeError) as error:
        raise RuntimeError("Invalid Azure response; no recovery decision made") from error
    if not isinstance(state, str) or not state:
        raise RuntimeError("Missing provisioning state; no recovery decision made")
    if state == "Failed":
        return True, state, "provisioningState is Failed"
    known = {"Succeeded", "Creating", "Updating", "Deleting", "Repairing", "Pending"}
    state = state if state in known else "Unknown"
    return False, state, "group is present and not explicitly Failed; leave it unchanged"


def main():
    heal, state, reason = inspect()
    output = (
        f"needs_heal={str(heal).lower()}\n"
        f"provisioning_state={state}\n"
        f"reason={reason}\n"
        f"sample_log=provisioningState={state}; {reason}\n"
    )
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        stream.write(output)
    print(output, end="")


if __name__ == "__main__":
    main()
