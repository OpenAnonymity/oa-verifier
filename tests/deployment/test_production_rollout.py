import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deploy/production'))
import controls
import rollout as r
import dispatch


def baseline():
    record = {'rekor_log_index': '123', 'signing_payload_hash': 'sha256:' + 'a' * 64,
              'station_store': 'keyvault-sealed'}
    resource = r.base_template(r.BASE_IMAGE, r.public_environment(record))['resources'][0]
    resource['id'] = r.RESOURCE_ID
    resource['properties']['confidentialComputeProperties']['ccePolicy'] = 'b2xk'
    return resource


def desired(phase='pending', revision=1, enabled=True):
    return {'environment': 'production', 'verifier_url': controls.VERIFIER,
            'desired': {'revision': revision, 'grace_enabled': True,
                        'encrypted_storage_enabled': enabled,
                        'deployment': {'phase': phase, 'run_id': '123'}}}


class ProductionControlsTests(unittest.TestCase):
    def test_dispatch_does_not_claim_and_blocks_duplicate_run(self):
        with patch.object(controls, 'read', return_value=desired()['desired']), patch.object(controls, 'claim') as claim, patch.object(dispatch.subprocess, 'check_output', return_value='[{"status":"in_progress"}]'), patch.object(dispatch.subprocess, 'run') as run:
            dispatch.main()
            claim.assert_not_called()
            run.assert_not_called()

    def test_dispatch_uses_only_production_workflow_and_exact_revision(self):
        with patch.object(controls, 'read', return_value=desired()['desired']), patch.object(controls, 'claim') as claim, patch.object(dispatch.subprocess, 'check_output', return_value='[]'), patch.object(dispatch.subprocess, 'run') as run:
            dispatch.main()
            claim.assert_not_called()
            self.assertIn('controls_revision=1', run.call_args.args[0])
            self.assertIn('station_store=keyvault-sealed', run.call_args.args[0])
            self.assertIn('deploy-production-verifier.yml', run.call_args.args[0])

    def test_wrong_environment_and_verifier_rejected(self):
        for change in ({'environment': 'staging'}, {'verifier_url': 'https://verifier2.openanonymity.ai'}):
            value = desired(); value.update(change)
            with self.assertRaises(ValueError): controls.validate(value)

    def test_only_matching_pending_request_can_be_claimed(self):
        for state in (desired('running'), desired(revision=2), desired(enabled=False)):
            with patch.object(controls, 'request', return_value=state) as req, patch.dict(os.environ, GITHUB_RUN_ID='123'):
                with self.assertRaises(ValueError): controls.claim(1, 'keyvault-sealed')
                self.assertEqual(req.call_count, 1)

    def test_claim_owned_by_actual_run(self):
        with patch.object(controls, 'request', side_effect=[desired(), {'claimed': True}]) as req, patch.dict(os.environ, GITHUB_RUN_ID='123'):
            controls.claim(1, 'keyvault-sealed')
            self.assertEqual(req.call_args.args, ('/claim', {'revision': 1, 'run_id': '123'}))

    def test_expired_or_other_run_fence_rejected(self):
        for phase, run in [('pending', '123'), ('running', '456')]:
            value = desired(phase); value['desired']['deployment']['run_id'] = run
            with patch.object(controls, 'request', return_value=value), patch.dict(os.environ, GITHUB_RUN_ID='123'):
                with self.assertRaises(ValueError): controls.check(1, 'keyvault-sealed')


class ProductionRolloutTests(unittest.TestCase):
    def test_baseline_rejects_wrong_target_image_and_sidecar(self):
        r.validate_baseline(baseline())
        for field in ('target', 'image', 'sidecar', 'tls'):
            b = baseline()
            if field == 'target': b['id'] = b['id'].replace(r.TARGET, r.STAGING)
            if field == 'image':
                b['properties']['containers'][0]['properties']['image'] = 'other'
                b['tags'] = {}
            if field == 'sidecar': b['properties']['containers'][1]['properties']['image'] = 'other'
            if field == 'tls':
                next(e for e in b['properties']['containers'][0]['properties']['environmentVariables'] if e['name'] == 'TLS_DOMAIN')['value'] = 'verifier2.openanonymity.ai'
            with self.assertRaises(ValueError): r.validate_baseline(b)

    def test_fixed_public_security_configuration(self):
        env = r.public_environment({'station_store': 'none', 'rekor_log_index': '123', 'signing_payload_hash': 'test'})
        self.assertEqual(env['TLS_CERT_STORE'], 'keyvault-sealed')
        self.assertEqual(env['STATION_STATE_STORE'], 'none')
        self.assertEqual(env['REGISTRY_WARMUP_SECONDS'], '604800')
        self.assertEqual(env['STATION_REGISTRY_URL'], 'https://org-live.openanonymity.ai')
        self.assertEqual(env['TLS_CERT_SECRET_VAULT'], r.VAULT_URL)

    def test_policy_binds_public_values_and_only_secrets_are_dynamic(self):
        text = 'containers := ' + json.dumps([{'name':'oa-verifier', 'id':r.BASE_IMAGE, 'env_rules': [{'pattern': 'TLS_DOMAIN=' + r.DOMAIN, 'strategy': 'string'}]}, {'name':'skr-sidecar', 'id':r.SIDECAR, 'env_rules': []}, {'name':'pause-container','command':['/pause']}]) + '\n\nallow_properties := true'
        result = r.protect_policy(text, r.BASE_IMAGE, {'TLS_DOMAIN':r.DOMAIN})
        self.assertIn('TLS_DOMAIN=' + r.DOMAIN, result)
        self.assertNotIn('TLS_DOMAIN=.+', result)
        self.assertIn('STATION_REGISTRY_SECRET=.+', result)
        self.assertNotIn('STATION_REGISTRY_URL=.+', result)
        self.assertIn('"allow_stdio_access":false', result)
        with self.assertRaises(ValueError):
            r.protect_policy(text.replace('pause-container','unknown-container'), r.BASE_IMAGE, {'TLS_DOMAIN':r.DOMAIN})
        with self.assertRaises(ValueError):
            r.protect_policy(text, 'wrong-image', {'TLS_DOMAIN':r.DOMAIN})

    def test_fingerprint_ignores_status_but_detects_configuration_change(self):
        b = baseline(); other = copy.deepcopy(b)
        other['properties']['instanceView'] = {'state': 'Running'}
        other['properties']['ipAddress']['ip'] = '192.0.2.1'
        self.assertEqual(r.resource_fingerprint(b), r.resource_fingerprint(other))
        other['properties']['containers'][0]['properties']['image'] = 'changed'
        self.assertNotEqual(r.resource_fingerprint(b), r.resource_fingerprint(other))

    def test_rollback_preserves_old_policy_without_embedding_credentials(self):
        b = baseline(); b.pop('identity')
        b['properties']['imageRegistryCredentials'] = [{'server': 'oaverifieracr.azurecr.io', 'username': 'hidden', 'password': None}]
        with patch.dict(os.environ, PRODUCTION_REGISTRY_SECRET='registry-private', CF_DNS_API_TOKEN='cf-private', ACME_EMAIL='email-private', ACR_USERNAME='acr-user', ACR_PASSWORD='acr-private'):
            result, values = r.rollback_template(b)
        self.assertEqual(result['resources'][0]['properties']['confidentialComputeProperties']['ccePolicy'], 'b2xk')
        self.assertEqual(result['resources'][0]['properties']['containers'][0]['properties']['image'], r.BASE_IMAGE)
        for private in ('registry-private', 'cf-private', 'email-private', 'acr-private'):
            self.assertNotIn(private, json.dumps(result))
        self.assertEqual(values['acrPassword'], 'acr-private')

    def test_stale_control_stops_before_any_container_mutation(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(r, 'RECORD', Path(directory) / 'record.json'):
            b = baseline()
            r.save_record({'templates_validated': True, 'source_revision': r.REVISION, 'baseline_fingerprint': r.resource_fingerprint(b), 'station_store': 'keyvault-sealed'})
            with patch.dict(os.environ, CONTROLS_REVISION='1'), patch.object(r, 'current_resource', return_value=b), patch.object(r, 'check_registry'), patch.object(controls, 'claim'), patch.object(controls, 'check', side_effect=ValueError('stale')), patch.object(r, 'authorize_policy'), patch.object(r, 'az') as az:
                with self.assertRaises(ValueError): r.deploy()
                az.assert_not_called()

    def test_deploy_failure_restores_exact_prior_template(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(r, 'RECORD', Path(directory) / 'record.json'):
            b = baseline()
            r.save_record({'templates_validated': True, 'source_revision': r.REVISION, 'baseline_fingerprint': r.resource_fingerprint(b), 'baseline_image': r.BASE_IMAGE, 'station_store': 'keyvault-sealed'})
            with patch.dict(os.environ, CONTROLS_REVISION='1'), patch.object(r, 'current_resource', return_value=b), patch.object(r, 'check_registry'), patch.object(controls, 'claim'), patch.object(controls, 'check'), patch.object(r, 'authorize_policy'), patch.object(r, 'az'), patch.object(r, 'apply', side_effect=[ValueError('failed'), None]) as apply:
                with self.assertRaises(RuntimeError): r.deploy()
                self.assertEqual(apply.call_args_list[-1].args, ('rollback.json', 'rollback-parameters.json'))
                self.assertTrue(r.read_record()['rollback_resource_restored'])

    def test_workflow_never_deploys_on_push(self):
        text = (ROOT / '.github/workflows/deploy-production-verifier.yml').read_text()
        self.assertIn("if: github.event_name == 'workflow_dispatch' && inputs.operation == 'deploy'", text)
        self.assertIn('environment: oa-production-20260917', text)
        self.assertNotIn('secrets.STATION_REGISTRY_SECRET', text)
        self.assertNotIn('cancel-in-progress: true', text)


if __name__ == '__main__': unittest.main()
