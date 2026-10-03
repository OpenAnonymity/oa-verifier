"""The manual restart action must remain pinned to the existing staging group."""
import copy
import io
import json
import os
from pathlib import Path
import textwrap
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/restart-staging-verifier.yml'
TEXT = WORKFLOW.read_text()
CODE = textwrap.dedent(TEXT.split("python3 - <<'PY'\n", 1)[1].split('\n          PY', 1)[0])
MODULE = {'__name__': 'restart_guard_test'}
exec(compile(CODE, str(WORKFLOW), 'exec'), MODULE)
IMAGE = 'oaverifieracr.azurecr.io/oa-verifier@sha256:' + 'a' * 64


def fixture():
    return {'name': 'oa-verifier-2', 'id': '/subscriptions/fixture/resourceGroups/oa-verifier/providers/Microsoft.ContainerInstance/containerGroups/oa-verifier-2',
            'location': 'eastus', 'provisioningState': 'Succeeded',
            'ipAddress': {'dnsNameLabel': 'oa-verifier-2'},
            'containers': [{'name': 'oa-verifier', 'image': IMAGE,
                            'instanceView': {'currentState': {'state': 'Running'}},
                            'environmentVariables': [
                                {'name': 'STATION_REGISTRY_URL', 'value': 'https://org-staging.openanonymity.ai'},
                                {'name': 'TLS_DOMAIN', 'value': 'verifier2.openanonymity.ai'},
                                {'name': 'STATION_REGISTRY_SECRET', 'secureValue': 'MUST-NOT-PRINT'}]}]}


class RestartGuardTests(unittest.TestCase):
    def test_accepts_only_current_pinned_staging_image(self):
        self.assertEqual(MODULE['validate'](fixture(), IMAGE, True), IMAGE)
        for image in ['', IMAGE[:-1] + 'b']:
            with self.assertRaises(ValueError):
                MODULE['validate'](fixture(), image, True)

    def test_wrong_target_unstable_state_and_mutable_image_rejected(self):
        mutations = [lambda g: g.update(name='oa-verifier-production'),
                     lambda g: g.update(id=g['id'].replace('/oa-verifier/', '/production/')),
                     lambda g: g.update(location='westus'),
                     lambda g: g.update(provisioningState='Updating'),
                     lambda g: g['ipAddress'].update(dnsNameLabel='production'),
                     lambda g: g['containers'][0]['instanceView']['currentState'].update(state='Waiting'),
                     lambda g: g['containers'][0].update(image='oaverifieracr.azurecr.io/oa-verifier:latest'),
                     lambda g: g['containers'].append(copy.deepcopy(g['containers'][0]))]
        for mutate in mutations:
            g = fixture(); mutate(g)
            with self.subTest(group=g['name']), self.assertRaises(ValueError):
                MODULE['validate'](g, IMAGE, True)

    def test_wrong_registry_domain_or_enabled_persistence_rejected(self):
        for name, value in [('STATION_REGISTRY_URL', 'https://org.openanonymity.ai'),
                            ('TLS_DOMAIN', 'verifier-production-20260917.openanonymity.ai'),
                            ('STATION_STATE_STORE', 'keyvault-sealed')]:
            g = fixture()
            g['containers'][0]['environmentVariables'].append({'name': name, 'value': value})
            with self.subTest(name=name), self.assertRaises(ValueError):
                MODULE['validate'](g, IMAGE, True)

    def run_main(self, requested=False, skip=False, failure=None):
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            self.assertIn('oa-verifier-2', command)
            if command[2] == 'show':
                return SimpleNamespace(stdout=json.dumps(fixture()))
            self.assertEqual(command[1:3], ['container', 'restart'])
            if failure:
                raise failure
            return SimpleNamespace(stdout='')
        out = io.StringIO()
        with patch.dict(os.environ, {'CONFIRM_RESTART': str(requested).lower(), 'EXPECTED_IMAGE': IMAGE,
                                     'SKIP_RECOVERY_TEST': str(skip).lower()}), \
             patch.object(MODULE['subprocess'], 'run', side_effect=run), redirect_stdout(out):
            MODULE['main']()
        self.assertNotIn('MUST-NOT-PRINT', out.getvalue())
        return calls

    def test_default_preflight_does_not_restart(self):
        self.assertEqual(len(self.run_main()), 1)

    def test_confirmed_test_restarts_exactly_once(self):
        calls = self.run_main(True)
        self.assertEqual([c[2] for c in calls], ['show', 'restart'])

    def test_existing_skip_guard_blocks(self):
        with self.assertRaisesRegex(SystemExit, 'prohibits restart'):
            self.run_main(True, True)

    def test_ambiguous_restart_failure_is_not_retried(self):
        with self.assertRaisesRegex(RuntimeError, 'timeout'):
            self.run_main(True, failure=RuntimeError('timeout'))

    def test_workflow_manual_only_and_excluded_from_deployment(self):
        self.assertIn("if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'", TEXT)
        self.assertNotIn('  push:', TEXT)
        self.assertNotIn('  schedule:', TEXT)
        self.assertIn('default: false', TEXT)
        self.assertIn("'.github/workflows/restart-staging-verifier.yml'", (ROOT / '.github/workflows/build-and-sign.yml').read_text())
        for forbidden in ['az container delete', 'az container create', 'gh workflow run', 'curl -k', 'nix build']:
            self.assertNotIn(forbidden, TEXT)


if __name__ == '__main__':
    unittest.main()
