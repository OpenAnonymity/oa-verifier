"""Independent verification must reconstruct the exact policy used for deployment."""
from pathlib import Path
import re
import subprocess
import sys
import textwrap
import unittest


WORKFLOWS = Path(__file__).resolve().parents[2] / ".github/workflows"


def reconstructed_policy(workflow_name):
    workflow = (WORKFLOWS / workflow_name).read_text()
    scripts = re.findall(
        r'MODIFIED_POLICY=\$\(echo "\$BASE_POLICY" \| python3 -c \'\n(.*?)\n +\'\)',
        workflow,
        re.DOTALL,
    )
    if len(scripts) != 1:
        raise AssertionError("Expected one policy transformation in " + workflow_name)
    base_policy = (
        'package policy\n'
        'containers := [{"env_rules": [], "id": "verifier"}, '
        '{"env_rules": [], "id": "sidecar"}]\n\n'
        'allow_properties := true\n'
    )
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(scripts[0])],
        input=base_policy, text=True, capture_output=True, check=True,
    )
    return result.stdout


class PolicyParityTests(unittest.TestCase):
    def test_verification_reconstructs_deployed_dynamic_environment_policy(self):
        self.assertEqual(
            reconstructed_policy("build-and-sign.yml"),
            reconstructed_policy("verify-attestation.yml"),
            "Verification policy differs from deployment; signed policy hash will not match.",
        )
