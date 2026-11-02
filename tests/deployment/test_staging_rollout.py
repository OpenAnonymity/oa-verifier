"""Offline guards for the fixed staging replacement and rollback path."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('staging_rollout', ROOT / 'scripts/staging_rollout.py')
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


def fixture():
    values = {'TLS_DOMAIN': subject.DOMAIN, 'STATION_REGISTRY_URL': subject.REGISTRY,
              'STATION_STATE_STORE': 'keyvault-sealed', 'TLS_CERT_STORE': 'keyvault-sealed',
              'TLS_CERT_KEK_VAULT': 'https://oa-verifier2-sealed.vault.azure.net',
              'TLS_CERT_SECRET_VAULT': 'https://oa-verifier2-sealed.vault.azure.net',
              'CCE_POLICY_B64': base64.b64encode(b'fixed measured policy').decode()}
    return {'name': subject.TARGET, 'location': 'eastus', 'type': 'Microsoft.ContainerInstance/containerGroups',
            'identity': {'type': 'UserAssigned', 'tenantId': 'readonly',
                         'userAssignedIdentities': {'/staging-identity': {'clientId': 'readonly'}}},
            'properties': {'sku': 'Confidential', 'provisioningState': 'Succeeded',
                           'provisioningTimeoutInSeconds': 1800,
                           'containers': [{'name': 'oa-verifier', 'properties': {
                               'image': 'registry/app@sha256:old', 'instanceView': {'state': 'Running'},
                               'environmentVariables': [{'name': k, 'value': v} for k, v in values.items()]
                                                       + [{'name': 'STATION_REGISTRY_SECRET'}]}}],
                           'ipAddress': {'ip': '192.0.2.1', 'fqdn': 'example.invalid', 'dnsNameLabel': subject.TARGET},
                           'imageRegistryCredentials': [{'server': 'registry', 'identity': '/staging-identity'}]}}


class RolloutTests(unittest.TestCase):
    def candidate(self):
        data = fixture()
        subject.environment(data)['STATION_REGISTRY_SECRET']['secureValue'] = 'test-only-secret'
        return data

    def test_rollback_preserves_image_policy_and_stores_and_removes_readonly_properties(self):
        live = fixture()
        candidate = self.candidate()
        candidate['properties']['containers'][0]['properties']['image'] = 'registry/app@sha256:new'
        template = subject.rollback_template(live, candidate)
        restored = template['resources'][0]
        self.assertEqual(restored['properties']['containers'][0]['properties']['image'], 'registry/app@sha256:old')
        self.assertEqual(subject.environment(restored)['CCE_POLICY_B64'], subject.environment(live)['CCE_POLICY_B64'])
        self.assertEqual(subject.environment(restored)['STATION_REGISTRY_SECRET']['secureValue'], 'test-only-secret')
        self.assertNotIn('tenantId', restored['identity'])
        self.assertEqual(restored['identity']['userAssignedIdentities'], {'/staging-identity': {}})
        self.assertNotIn('provisioningTimeoutInSeconds', restored['properties'])
        self.assertNotIn('instanceView', restored['properties']['containers'][0]['properties'])
        self.assertNotIn('ip', restored['properties']['ipAddress'])
        self.assertNotIn('fqdn', restored['properties']['ipAddress'])
        self.assertEqual(subject.environment(live)['STATION_REGISTRY_SECRET'], {'name': 'STATION_REGISTRY_SECRET'})

    def test_production_wrong_domain_or_unsealed_state_is_rejected(self):
        for change in ('name', 'domain', 'registry', 'store', 'vault'):
            live = fixture()
            if change == 'name': live['name'] = subject.PRODUCTION
            if change == 'domain': subject.environment(live)['TLS_DOMAIN']['value'] = 'production.invalid'
            if change == 'registry': subject.environment(live)['STATION_REGISTRY_URL']['value'] = 'https://org-live.openanonymity.ai'
            if change == 'store': subject.environment(live)['TLS_CERT_STORE']['value'] = 'none'
            if change == 'vault': subject.environment(live)['TLS_CERT_KEK_VAULT']['value'] = 'https://prod.vault.azure.net'
            with self.subTest(change=change), self.assertRaises(ValueError):
                subject.assert_staging(live)

    def test_unknown_secure_input_aborts_before_mutation(self):
        with self.assertRaises(ValueError):
            subject.rollback_template(fixture(), fixture())

    def test_changed_baseline_does_not_delete_any_container(self):
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / 'record.json'
            record.write_text(json.dumps({'prepared': True, 'baseline_fingerprint': 'different'}))
            with patch.object(subject, 'RECORD', record), patch.object(subject, 'resource', return_value=fixture()), patch.object(subject, 'az') as az:
                with self.assertRaises(ValueError): subject.deploy()
                az.assert_not_called()

    def test_failed_deployment_invokes_rollback_and_only_deletes_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / 'record.json'
            record.write_text(json.dumps({'prepared': True, 'baseline_fingerprint': subject.fingerprint(fixture()),
                                           'production_fingerprint': subject.fingerprint(fixture())}))
            with patch.object(subject, 'RECORD', record), patch.object(subject, 'resource', return_value=fixture()), patch.object(subject, 'az') as az, patch.object(subject, 'apply', side_effect=RuntimeError), patch.object(subject, 'rollback') as rollback:
                with self.assertRaises(RuntimeError): subject.deploy()
                rollback.assert_called_once()
                az.assert_called_once_with('container', 'delete', '-g', subject.GROUP, '-n', subject.TARGET, '--yes')
                self.assertTrue(json.loads(record.read_text())['mutation_started'])

    def test_only_explicit_pending_identity_deletion_is_retried(self):
        args = ['az', 'deployment', 'group', 'create']
        fail = subprocess.CompletedProcess(args, 1, '', 'FailedIdentityOperation pending delete operation')
        good = subprocess.CompletedProcess(args, 0, '{}', '')
        with patch.object(subject.subprocess, 'run', side_effect=[fail, good]) as run, patch.object(subject.time, 'sleep'):
            self.assertEqual(subject.run(args), {})
            self.assertEqual(run.call_count, 2)
        fail = subprocess.CompletedProcess(args, 1, '', 'AuthorizationFailed SECRET_SHOULD_NOT_ESCAPE')
        with patch.object(subject.subprocess, 'run', return_value=fail) as run, patch.object(subject.time, 'sleep') as sleep:
            with self.assertRaises(RuntimeError) as caught: subject.run(args)
            self.assertNotIn('SECRET_SHOULD_NOT_ESCAPE', str(caught.exception))
            self.assertEqual(run.call_count, 1)
            sleep.assert_not_called()

    def test_existing_rollback_and_accepted_rollout_are_not_repeated(self):
        for state in ({'rollback_complete': True}, {'accepted': True}, {'mutation_started': False}):
            with tempfile.TemporaryDirectory() as directory:
                record = Path(directory) / 'record.json'
                record.write_text(json.dumps({'mutation_started': True, **state}))
                with patch.object(subject, 'RECORD', record), patch.object(subject, 'az') as az:
                    subject.rollback()
                    az.assert_not_called()

    def test_workflow_checks_and_rollback_are_in_the_same_guarded_job(self):
        text = (ROOT / '.github/workflows/build-and-sign.yml').read_text()
        self.assertIn('nix develop --no-update-lock-file --command go test -race ./...', text)
        self.assertIn('"name": "STATION_FAILURE_GRACE_SECONDS", "value": "604800"', text)
        self.assertLess(text.index('staging_rollout.py prepare'), text.index('Authorize this build'))
        self.assertLess(text.index('Refuse a stale dashboard'), text.index('staging_rollout.py deploy'))
        self.assertLess(text.index('Verify Deployed'), text.index('staging_rollout.py accept')) if 'Verify Deployed' in text else None
        self.assertIn("if: failure() && github.event_name != 'pull_request' && github.ref == 'refs/heads/main'", text)
        self.assertNotIn('az container delete', text)
        self.assertIn("baseline = record['baseline_policy_sha256']", text)
        self.assertIn('assert allows(policy, baseline', text)


if __name__ == '__main__':
    unittest.main()
