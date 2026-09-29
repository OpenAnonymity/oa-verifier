"""Offline regressions for rollout decisions that can destroy the live group."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("self_heal", ROOT / "scripts/self_heal.py")
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class SelfHealTests(unittest.TestCase):
    def inspect(self, state=None, error="", status=0):
        def run(command, **kwargs):
            self.assertIn("oa-verifier-2", command)
            self.assertEqual(command[1:3], ["container", "show"])
            self.assertEqual(kwargs["timeout"], 60)
            return subprocess.CompletedProcess(command, status, json.dumps(state), error)
        return subject.inspect(run)

    def test_failed_group_is_eligible(self):
        self.assertTrue(self.inspect("Failed")[0])

    def test_explicitly_missing_group_is_eligible(self):
        self.assertTrue(self.inspect(error="ERROR: (ResourceNotFound) resource missing", status=3)[0])

    def test_in_progress_and_successful_groups_are_not_recreated(self):
        for state in ["Repairing", "Creating", "Updating", "Deleting", "Pending", "Succeeded"]:
            with self.subTest(state=state):
                self.assertFalse(self.inspect(state)[0])

    def test_waiting_or_unknown_values_do_not_trigger_recreation(self):
        for state in ["Waiting", "Stopped", "NewPlatformState", "x\nneeds_heal=true"]:
            with self.subTest(state=state):
                heal, safe_state, _ = self.inspect(state)
                self.assertFalse(heal)
                self.assertEqual(safe_state, "Unknown")

    def test_api_failures_are_not_missing_groups(self):
        for message in ["AuthorizationFailed", "timeout", "(ResourceGroupNotFound)",
                        "SubscriptionNotFound", "could not be found", "NotFound"]:
            with self.subTest(message=message), self.assertRaises(RuntimeError):
                self.inspect(error=message, status=1)

    def test_empty_or_malformed_state_fails_closed(self):
        for state in [None, "", {}, [], True]:
            with self.subTest(state=state), self.assertRaises(RuntimeError):
                self.inspect(state)

    def test_non_json_response_fails_closed(self):
        with self.assertRaises(RuntimeError):
            subject.inspect(lambda *a, **k: subprocess.CompletedProcess([], 0, "not-json", ""))

    def test_inspection_timeout_propagates(self):
        def run(*args, **kwargs):
            raise subprocess.TimeoutExpired("az", 60)
        with self.assertRaises(subprocess.TimeoutExpired):
            subject.inspect(run)


class WorkflowTests(unittest.TestCase):
    def test_lock_matches_declared_input(self):
        flake = (ROOT / "flake.nix").read_text()
        ref = re.search(r'nixpkgs.url = "github:NixOS/nixpkgs/([^\"]+)"', flake).group(1)
        self.assertEqual(json.loads((ROOT / "flake.lock").read_text())["nodes"]["nixpkgs"]["original"]["ref"], ref)

    def test_all_ci_nix_builds_and_shells_reject_lock_updates(self):
        found = 0
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            for line in path.read_text().splitlines():
                if re.search(r"\bnix (build|develop)\b", line):
                    found += 1
                    self.assertIn("--no-update-lock-file", line, f"{path}: {line}")
        self.assertGreater(found, 0)

    def test_recovery_requires_one_explicit_manual_main_dispatch(self):
        workflow = (ROOT / ".github/workflows/build-and-sign.yml").read_text()
        if (ROOT / "deploy/production/isolated.py").exists():
            self.assertNotIn("az container restart", workflow)
            self.assertIn("environment: oa-production-20260917", workflow)
            return
        condition = re.search(r"- name: Recovery test[^\n]+\n\s+if: ([^\n]+)", workflow).group(1)
        # Evaluate the actual simple boolean condition over the event/input matrix.
        for event in ["push", "pull_request", "workflow_dispatch"]:
            for ref in ["refs/heads/main", "refs/heads/feature"]:
                for requested in [False, True]:
                    for skip in ["", "false", "true"]:
                        expr = condition.replace("github.event_name", repr(event)).replace("github.ref", repr(ref))
                        expr = expr.replace("inputs.run_recovery_test", repr(requested)).replace("vars.ACI_SKIP_RECOVERY_TEST", repr(skip))
                        expr = expr.replace("== true", "== True").replace("&&", "and")
                        actual = eval(expr, {"__builtins__": {}})
                        expected = event == "workflow_dispatch" and ref == "refs/heads/main" and requested and skip != "true"
                        self.assertEqual(actual, expected, (event, ref, requested, skip))
        self.assertRegex(workflow, r"run_recovery_test:\n(?:[^\n]*\n){1,5}\s+default: false")

    def test_self_heal_never_requests_the_optional_restart(self):
        if (ROOT / "deploy/production/isolated.py").exists():
            self.assertFalse((ROOT / ".github/workflows/self-heal.yml").exists())
            return
        workflow = (ROOT / ".github/workflows/self-heal.yml").read_text()
        self.assertIn("run: python3 scripts/self_heal.py", workflow)
        self.assertNotIn("run_recovery_test=true", workflow)
        self.assertNotIn("NOT_RUNNING_COUNT", workflow)
        self.assertIn("FAILED_DEPLOY_BACKOFF_SECONDS: '10800'", workflow)
        self.assertIn("--branch main", workflow)
        self.assertIn(".updatedAt", workflow)


if __name__ == "__main__":
    unittest.main()
