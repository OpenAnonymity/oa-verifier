import base64
import importlib.util
import io
import json
import re
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("release_policy", ROOT / "scripts/release_policy.py")
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)

H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
H5 = "5" * 64
ZERO = "0" * 64


class DecodeTests(unittest.TestCase):
    def test_absent_policy(self):
        for raw in (None, "", "null", "None", b""):
            self.assertIsNone(subject.decode_policy(raw))

    def test_json_base64_and_base64url(self):
        policy = subject.build_policy([H1], subject.DEFAULT_AUTHORITY)
        text = json.dumps(policy)
        self.assertEqual(subject.decode_policy(text), policy)
        self.assertEqual(subject.decode_policy(base64.b64encode(text.encode()).decode()), policy)
        self.assertEqual(subject.decode_policy(base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")), policy)

    def test_azure_json_output_preserves_nested_policy_text(self):
        policy = subject.build_policy([H1], subject.DEFAULT_AUTHORITY)
        text = json.dumps(policy)
        # -o json encodes the CLI string instead of applying TSV escaping.
        self.assertEqual(subject.decode_policy(json.dumps(text)), policy)
        self.assertEqual(subject.decode_policy(json.dumps(base64.b64encode(text.encode()).decode())), policy)
        with self.assertRaises(ValueError):
            subject.decode_policy(json.dumps(json.dumps("not a policy")))

    def test_garbage_fails_closed(self):
        with self.assertRaises(ValueError):
            subject.decode_policy("not a policy")
        with self.assertRaises(ValueError):
            subject.decode_policy(json.dumps({"version": "1.0.0"}))


class MergeTests(unittest.TestCase):
    def test_first_deploy_replaces_placeholder(self):
        current = subject.build_policy([ZERO], subject.DEFAULT_AUTHORITY)
        merged = subject.merge(current, H1, keep=4)
        self.assertEqual(subject.existing_hashes(merged, subject.DEFAULT_AUTHORITY), [H1])
        self.assertTrue(subject.allows(merged, H1))
        self.assertFalse(subject.allows(merged, ZERO))

    def test_new_hash_first_and_window_bounded(self):
        current = subject.build_policy([H3, H2, H1], subject.DEFAULT_AUTHORITY)
        merged = subject.merge(current, H4, keep=3)
        self.assertEqual(subject.existing_hashes(merged, subject.DEFAULT_AUTHORITY), [H4, H3, H2])
        self.assertFalse(subject.allows(merged, H1))
        # Redeploying a hash already present moves it to the front without duplicating it.
        again = subject.merge(merged, H2, keep=3)
        self.assertEqual(subject.existing_hashes(again, subject.DEFAULT_AUTHORITY), [H2, H4, H3])

    def test_keep_one_means_only_current_build(self):
        current = subject.build_policy([H1], subject.DEFAULT_AUTHORITY)
        merged = subject.merge(current, H2, keep=1)
        self.assertEqual(subject.existing_hashes(merged, subject.DEFAULT_AUTHORITY), [H2])

    def test_every_entry_carries_the_fixed_claims(self):
        merged = subject.merge(None, H1, keep=2)
        for entry in merged["anyOf"]:
            claims = {c["claim"]: c["equals"] for c in entry["allOf"]}
            self.assertEqual(claims["x-ms-sevsnpvm-hostdata"], H1)
            self.assertEqual(claims["x-ms-attestation-type"], "sevsnpvm")
            self.assertEqual(claims["x-ms-compliance-status"], "azure-compliant-uvm")
            self.assertEqual(claims["x-ms-sevsnpvm-is-debuggable"], "false")
            self.assertEqual(entry["authority"], subject.DEFAULT_AUTHORITY)
        self.assertEqual(merged["version"], "1.0.0")

    def test_entries_of_other_authorities_are_not_carried_over(self):
        current = subject.build_policy([H1], "https://other.attest.azure.net")
        merged = subject.merge(current, H2, keep=4, authority="sharedeus.eus.attest.azure.net")
        self.assertEqual(subject.existing_hashes(merged, subject.DEFAULT_AUTHORITY), [H2])

    def test_hash_and_keep_validation(self):
        with self.assertRaises(ValueError):
            subject.merge(None, "abc", keep=2)
        with self.assertRaises(ValueError):
            subject.merge(None, H1.upper() + "0", keep=2)
        with self.assertRaises(ValueError):
            subject.merge(None, H1, keep=0)
        self.assertTrue(subject.allows(subject.merge(None, H1.upper(), keep=1), H1))

    def test_allows_requires_fixed_claims(self):
        weak = {"version": "1.0.0", "anyOf": [{"authority": subject.DEFAULT_AUTHORITY,
                                                "allOf": [{"claim": "x-ms-sevsnpvm-hostdata", "equals": H1}]}]}
        self.assertFalse(subject.allows(weak, H1))
        self.assertTrue(subject.allows(subject.build_policy([H1], subject.DEFAULT_AUTHORITY), H1))
        self.assertFalse(subject.allows(None, H1))


class SamePolicyTests(unittest.TestCase):
    def test_identical_order_and_claims(self):
        a = subject.build_policy([H2, H1], subject.DEFAULT_AUTHORITY)
        self.assertTrue(subject.same_policy(a, subject.build_policy([H2, H1], subject.DEFAULT_AUTHORITY)))
        self.assertFalse(subject.same_policy(a, subject.build_policy([H1, H2], subject.DEFAULT_AUTHORITY)))
        self.assertFalse(subject.same_policy(a, subject.build_policy([H2], subject.DEFAULT_AUTHORITY)))
        self.assertFalse(subject.same_policy(None, a))
        weak = {"version": "1.0.0", "anyOf": [{"authority": subject.DEFAULT_AUTHORITY,
                                                "allOf": [{"claim": "x-ms-sevsnpvm-hostdata", "equals": H2}]},
                                               {"authority": subject.DEFAULT_AUTHORITY,
                                                "allOf": [{"claim": "x-ms-sevsnpvm-hostdata", "equals": H1}]}]}
        self.assertFalse(subject.same_policy(weak, a), "missing fixed claims must force a rewrite")

    def test_redeploy_of_current_build_is_a_no_op_but_rollback_reorders(self):
        current = subject.build_policy([H2, H1], subject.DEFAULT_AUTHORITY)
        self.assertTrue(subject.same_policy(current, subject.merge(current, H2, keep=4)))
        self.assertFalse(subject.same_policy(current, subject.merge(current, H1, keep=4)))


class CLITests(unittest.TestCase):
    def test_merge_and_check_round_trip(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = subject.main(["merge", "--new-hash", H1, "--keep", "2"])
        self.assertEqual(rc, 0)
        policy = json.loads(out.getvalue())
        self.assertTrue(subject.allows(policy, H1))

        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(policy, fh)
            path = fh.name
        with redirect_stdout(io.StringIO()):
            self.assertEqual(subject.main(["check", "--current", path, "--hash", H1]), 0)
            self.assertEqual(subject.main(["check", "--current", path, "--hash", H2]), 1)
            self.assertEqual(subject.main(["merge", "--current", path, "--new-hash", "bad"]), 2)
            # Same build again: nothing to write.
            self.assertEqual(subject.main(["merge", "--current", path, "--new-hash", H1, "--keep", "2"]), 3)
            # New build: write needed.
            self.assertEqual(subject.main(["merge", "--current", path, "--new-hash", H2, "--keep", "2"]), 0)


class WorkflowTests(unittest.TestCase):
    def test_release_policy_is_authorised_before_the_group_is_deleted(self):
        workflow = (ROOT / ".github/workflows/build-and-sign.yml").read_text()
        authorise = workflow.index("name: Authorize this build")
        delete = workflow.index("name: Delete existing container group")
        self.assertLess(authorise, delete)
        self.assertIn("python3 scripts/release_policy.py merge", workflow)
        self.assertIn("python3 scripts/release_policy.py check", workflow)
        self.assertEqual(workflow.count('--query "releasePolicy.encodedPolicy" -o json'), 2)
        self.assertNotIn('--query "releasePolicy.encodedPolicy" -o tsv', workflow)
        self.assertIn('3) echo "✅ release policy already current', workflow)
        # Only Key Vault-backed modes can be deployed to the group (no volume).
        self.assertIn("file|file-sealed) echo", workflow)
        # The step is gated on a sealed mode being configured and must not run on PRs.
        condition = re.search(r"- name: Authorize this build[^\n]*\n\s+if: ([^\n]+)", workflow).group(1)
        self.assertIn("steps.policy.outputs.sealed_modes != '0'", condition)
        self.assertIn("github.event_name != 'pull_request'", condition)

    def test_sealed_variables_are_in_the_policy_allow_list_and_the_template(self):
        workflow = (ROOT / ".github/workflows/build-and-sign.yml").read_text()
        allow = workflow.split("optional_env_vars = [", 1)[1].split("]", 1)[0]
        for name in ["TLS_CERT_STORE", "TLS_CERT_KEK_VAULT", "TLS_CERT_KEK_NAME", "TLS_CERT_SECRET_VAULT",
                     "TLS_CERT_MSI_CLIENT_ID", "STATION_STATE_STORE", "STATION_STATE_SECRET_NAME",
                     "STATION_FAILURE_GRACE_SECONDS"]:
            self.assertIn(f'"{name}"', allow, name)
        # Values come from repository variables (names, not secrets) and only
        # appear in the deployment template, never in the measured policy template.
        policy_template = workflow.split("/tmp/aci-policy-template.json << EOF", 1)[1].split("EOF", 1)[0]
        deploy_template = workflow.split("/tmp/aci-deploy.json << DEPLOY_EOF", 1)[1].split("DEPLOY_EOF", 1)[0]
        for name in ["TLS_CERT_STORE", "STATION_STATE_STORE", "TLS_CERT_KEK_VAULT", "TLS_CERT_MSI_CLIENT_ID"]:
            self.assertNotIn(name, policy_template, name)
            self.assertIn(f'"name": "{name}"', deploy_template, name)
        self.assertIn('${{ env.DASHBOARD_STATION_STATE_STORE || vars.STATION_STATE_STORE }}', workflow)
        for var in ["vars.TLS_CERT_STORE", "vars.SEALED_KEK_VAULT", "vars.SEALED_KEK_NAME"]:
            self.assertIn("${{ " + var + " }}", workflow)
        self.assertNotIn("secrets.SEALED_", workflow)


if __name__ == "__main__":
    unittest.main()
