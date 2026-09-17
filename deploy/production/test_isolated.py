"""Offline checks for fixed-target isolation and secret-safe deployment files."""
import base64, json, os, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import isolated as subject

class IsolatedDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.previous = os.getcwd(); self.temp = tempfile.TemporaryDirectory(); os.chdir(self.temp.name)
        self.env = {'ACR_USERNAME': 'oaverifieracr', 'ACR_PASSWORD': 'credential-password-test-12345',
                    'PRODUCTION_REGISTRY_SECRET': 'fresh-production-secret-test-1234567890',
                    'CF_DNS_API_TOKEN': 'dns-token-test-1234567890', 'ACME_EMAIL': 'test-acme-contact@example.invalid',
                    'IMAGE_REF': 'oaverifieracr.azurecr.io/oa-verifier-production-20260917@sha256:' + 'a'*64,
                    'GITHUB_RUN_ID': '123'}
        self.envpatch = patch.dict(os.environ, self.env); self.envpatch.start()
        subject.save_record({'image_ref': self.env['IMAGE_REF'], 'rekor_log_index': '1', 'signing_payload_hash': 'sha256:'+'b'*64})
    def tearDown(self):
        self.envpatch.stop(); os.chdir(self.previous); self.temp.cleanup()
    def fake_confcom(self, command, **kwargs):
        document = Path(command[4]); data = json.loads(document.read_text())
        policy = 'package policy\ncontainers := [{"env_rules":[]}]\n\nallow_properties := true\n'
        data['resources'][0]['properties']['confidentialComputeProperties']['ccePolicy'] = base64.b64encode(policy.encode()).decode()
        document.write_text(json.dumps(data))
        return type('Result', (), {'returncode': 0})()
    def test_secure_parameters_and_private_cleanup(self):
        with patch.object(subject.subprocess, 'run', self.fake_confcom): subject.prepare()
        template_path = subject.PRIVATE/'deployment.json'; params_path = subject.PRIVATE/'parameters.json'
        template = json.loads(template_path.read_text()); params = json.loads(params_path.read_text())
        self.assertEqual(template['resources'][0]['name'], subject.TARGET)
        self.assertTrue(all(v['type']=='secureString' for v in template['parameters'].values()))
        self.assertEqual(template['resources'][0]['properties']['imageRegistryCredentials'][0]['username'], "[parameters('acrUsername')]")
        for key in ['ACR_PASSWORD','PRODUCTION_REGISTRY_SECRET','CF_DNS_API_TOKEN','ACME_EMAIL']:
            self.assertNotIn(self.env[key], template_path.read_text())
            self.assertNotIn(self.env[key], Path('policy.rego').read_text())
            self.assertIn(self.env[key], params_path.read_text())
        self.assertEqual(template_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(params_path.stat().st_mode & 0o777, 0o600)
        subject.cleanup(); self.assertFalse(subject.PRIVATE.exists())
    def test_existing_container_cannot_be_overwritten(self):
        with patch.object(subject, 'az', return_value=[subject.TARGET]) as call:
            with self.assertRaisesRegex(RuntimeError, 'refusing overwrite'): subject.deploy()
            self.assertEqual(call.call_count, 1)
    def test_existing_dns_cannot_be_overwritten(self):
        with patch.object(subject, 'zone', return_value='zone'), patch.object(subject, 'cf', return_value=[{'id':'existing'}]) as call:
            with self.assertRaisesRegex(RuntimeError, 'refusing overwrite'): subject.dns()
            self.assertEqual(call.call_count, 1); self.assertEqual(call.call_args.args[0], 'GET')
    def test_unexpected_image_rejected_before_policy_generation(self):
        os.environ['IMAGE_REF'] = 'oaverifieracr.azurecr.io/oa-verifier@sha256:'+'a'*64
        with self.assertRaises(AssertionError): subject.prepare()
    def test_missing_credential_rejected(self):
        os.environ['ACME_EMAIL'] = ''
        with self.assertRaisesRegex(RuntimeError, 'Missing required'): subject.prepare()

if __name__ == '__main__': unittest.main()
