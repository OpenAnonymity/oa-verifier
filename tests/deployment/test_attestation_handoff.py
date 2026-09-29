"""Regressions for the ACR/GHCR policy-hash mismatch and read-only reruns."""
import base64
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"scripts/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


deployment = load("deployed_image")
attestation = load("attestation_claim")
DIGEST = "sha256:" + "a" * 64
IDENTITY = "/subscriptions/example/resourceGroups/oa-verifier/providers/Microsoft.ManagedIdentity/userAssignedIdentities/pull"


def metadata(registry="oaverifieracr.azurecr.io", identity=None):
    return {"containers": [{"name": "oa-verifier", "image": f"{registry}/oa-verifier@{DIGEST}"}],
            "registries": [{"server": registry.split("/")[0], "identity": identity}]}


class DeploymentTests(unittest.TestCase):
    def test_live_acr_wins_even_when_same_digest_exists_in_ghcr(self):
        acr = deployment.deployment_values(metadata(identity=IDENTITY), IDENTITY)
        ghcr = deployment.deployment_values(metadata("ghcr.io/openanonymity"))
        self.assertEqual(acr["digest"], ghcr["digest"])
        self.assertNotEqual(acr["registry"], ghcr["registry"])
        self.assertEqual(acr["registry"], "oaverifieracr.azurecr.io")
        self.assertEqual(acr["use_identity"], "true")
        self.assertEqual(acr["use_ghcr"], "false")

    def test_public_ghcr_and_acr_password_modes(self):
        self.assertEqual(deployment.deployment_values(metadata())["use_identity"], "false")
        self.assertEqual(deployment.deployment_values(metadata("ghcr.io/openanonymity"))["use_ghcr"], "true")

    def test_missing_metadata_never_guesses_latest(self):
        for value in [{}, {"containers": []}, {"containers": None}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                deployment.deployment_values(value)

    def test_rejects_tags_unknown_registries_and_output_injection(self):
        for image in ["oaverifieracr.azurecr.io/oa-verifier:latest",
                      f"evil.example/oa-verifier@{DIGEST}",
                      f"ghcr.io/another-owner/oa-verifier@{DIGEST}",
                      f"oaverifieracr.azurecr.io/oa-verifier@{DIGEST}\nuse_identity=false"]:
            value = metadata()
            value["containers"][0]["image"] = image
            with self.subTest(image=image), self.assertRaises(ValueError):
                deployment.deployment_values(value)

    def test_missing_or_changed_identity_fails(self):
        for expected in ["", IDENTITY + "-different"]:
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                deployment.deployment_values(metadata(identity=IDENTITY), expected)

    def test_duplicate_target_is_ambiguous(self):
        value = metadata()
        value["containers"] *= 2
        with self.assertRaises(ValueError):
            deployment.deployment_values(value)


class SignedClaimTests(unittest.TestCase):
    def claims(self, **updates):
        claims = {"iss": "https://sharedeus.eus.attest.azure.net", "nbf": 100,
                  "exp": 200, "x-ms-sevsnpvm-hostdata": "b" * 64}
        claims.update(updates)
        encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        return f"header.{encoded}.signature"

    def test_signed_host_data_is_used(self):
        self.assertEqual(attestation.policy_hash(self.claims(), now=150), "b" * 64)

    def test_wrong_issuer_expiry_and_missing_hash_fail(self):
        for update in [{"iss": "https://untrusted.example"}, {"exp": 149},
                       {"nbf": 151}, {"x-ms-sevsnpvm-hostdata": ""},
                       {"x-ms-sevsnpvm-hostdata": None}]:
            with self.subTest(update=update), self.assertRaises(ValueError):
                attestation.policy_hash(self.claims(**update), now=150)


class WorkflowTests(unittest.TestCase):
    def test_manual_verification_cannot_redeploy(self):
        workflow = (ROOT / ".github/workflows/verify-attestation.yml").read_text()
        for mutation in ["az container delete", "az container create", "az container restart",
                         "az deployment", "docker push", "workflow_dispatch.yml"]:
            self.assertNotIn(mutation, workflow)
        self.assertIn("az container show", workflow)
        self.assertIn("ref: ${{ inputs.source_revision || github.sha }}", workflow)
        self.assertIn("working-directory: source", workflow)
        self.assertNotIn("needs.build-and-deploy.outputs", workflow)
        self.assertNotIn(".summary.cce_policy_hash", workflow)
        self.assertLess(workflow.index("bash scripts/verify-jwt.sh"),
                        workflow.index("python3 scripts/attestation_claim.py"))
        self.assertNotIn("docker pull \"$ACR_IMAGE\"", workflow)
        self.assertNotIn("docker pull \"$GHCR_IMAGE\"", workflow)
        self.assertIn("Independent attestation verification: $RESULT", workflow)

    def test_post_deploy_reuses_manual_verification(self):
        workflow = (ROOT / ".github/workflows/build-and-sign.yml").read_text()
        self.assertIn("uses: ./.github/workflows/verify-attestation.yml", workflow)
        self.assertNotIn("deploy_digest:", workflow)
        self.assertNotIn("deploy_registry:", workflow)


if __name__ == "__main__":
    unittest.main()
