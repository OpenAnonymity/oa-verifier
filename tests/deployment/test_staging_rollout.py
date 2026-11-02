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

    def test_rollback_restores_logging_credential_and_strips_empty_readback_fields(self):
        live, candidate = fixture(), self.candidate()
        live['properties']['isCustomProvisioningTimeout'] = False
        live['properties']['containers'][0]['properties']['configMap'] = {'keyValuePairs': None}
        live['properties']['diagnostics'] = {'logAnalytics': {'workspaceId': 'staging'}}
        candidate['properties']['diagnostics'] = {'logAnalytics': {'workspaceId': 'staging', 'workspaceKey': 'test-only'}}
        props = subject.rollback_template(live, candidate)['resources'][0]['properties']
        self.assertEqual(props['diagnostics']['logAnalytics']['workspaceKey'], 'test-only')
        self.assertNotIn('isCustomProvisioningTimeout', props)
        self.assertNotIn('configMap', props['containers'][0]['properties'])
        candidate['properties']['diagnostics']['logAnalytics']['workspaceId'] = 'different'
        with self.assertRaises(ValueError):
            subject.rollback_template(live, candidate)

    def test_repeated_rollback_observes_restored_group_without_deleting_it(self):
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / 'record.json'
            record.write_text(json.dumps({'mutation_started': True, 'rollback_resource_restored': True}))
            with patch.object(subject, 'RECORD', record), patch.object(subject, 'az') as az, patch.object(subject, 'apply') as apply, patch.object(subject, 'wait_ready'):
                subject.rollback()
                az.assert_not_called()
                apply.assert_not_called()
                self.assertTrue(json.loads(record.read_text())['rollback_complete'])

    def test_readiness_uses_current_ip_with_existing_certificate_validation(self):
        health = {'status': 'healthy', 'persistence': {'loaded': True, 'store': 'keyvault-sealed'}}
        record = {'approved_station_fingerprint': 'approval', 'certificate_sha256': 'cert', 'origin': 'old.invalid'}
        with patch.object(subject, 'fetch', return_value=health) as fetch, patch.object(subject, 'resource', return_value=fixture()), patch.object(subject, 'approved_fingerprint', return_value='approval') as approval, patch.object(subject, 'certificate', return_value='cert') as certificate, patch.object(subject, 'write_record'):
            subject.wait_ready(record, timeout=1)
            fetch.assert_called_once_with('/health', '192.0.2.1')
            approval.assert_called_once_with('192.0.2.1')
            certificate.assert_called_once_with('192.0.2.1')
            self.assertTrue(all(record['readiness_checks'].values()))

    def test_direct_origin_transport_retains_tls_hostname_validation(self):
        with patch.object(subject.http.client, 'HTTPSConnection') as connection, patch.object(subject.socket, 'create_connection') as socket, patch.object(subject.ssl, 'create_default_context') as context, patch.object(subject.json, 'load', return_value={'ok': True}):
            connection.return_value.getresponse.return_value.status = 200
            self.assertEqual(subject.fetch('/health', '192.0.2.1'), {'ok': True})
            connection.assert_called_once_with(subject.DOMAIN, timeout=15)
            context.return_value.wrap_socket.assert_called_once_with(socket.return_value, server_hostname=subject.DOMAIN)
            connection.return_value.close.assert_called_once()

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

    def test_build_tracks_all_nix_source_inputs_and_origin_probe_is_bounded(self):
        text = (ROOT / '.github/workflows/build-and-sign.yml').read_text()
        filters = text.split('filters: |', 1)[1].split('- name: Decide whether to build', 1)[0]
        self.assertIn("- '**'", filters)
        self.assertIn('src = ./.;', (ROOT / 'flake.nix').read_text())
        self.assertIn('timeout 20s openssl s_client -connect "${ORIGIN_IP}:443"', text)
        self.assertIn('-verify_hostname "$SNI" -verify_return_error', text)


if __name__ == '__main__':
    unittest.main()
