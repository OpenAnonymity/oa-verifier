import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('controls', ROOT / 'scripts/staging_controls.py')
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)


class StagingControlsTests(unittest.TestCase):
    def test_only_ready_staging_and_strict_settings_accepted(self):
        data = {'environment':'staging','storage_control_ready':True,
                'desired':{'revision':3,'encrypted_storage_enabled':True}}
        self.assertEqual(controls.validate(data), (3, 'keyvault-sealed'))
        for field, value in [('environment','production'), ('storage_control_ready',False)]:
            with self.assertRaises(ValueError):
                controls.validate({**data,field:value})
        for field, value in [('revision','3'), ('revision',-1), ('encrypted_storage_enabled','true')]:
            with self.assertRaises(ValueError):
                controls.validate({**data,'desired':{**data['desired'],field:value}})

    def test_workflow_maintenance_does_not_deploy_and_worker_is_opt_in(self):
        build = (ROOT / '.github/workflows/build-and-sign.yml').read_text()
        ignored = build.split('paths-ignore:',1)[1].split('pull_request:',1)[0]
        for path in ['.github/workflows/apply-staging-controls.yml','scripts/staging_controls.py']:
            self.assertIn(path, ignored)
        worker = (ROOT / '.github/workflows/apply-staging-controls.yml').read_text()
        self.assertIn("if: vars.STAGING_DASHBOARD_CONTROLS == 'true'", worker)
        self.assertIn('if not claim(revision):', worker)
        self.assertIn('group: verifier2-runtime-mutation', build)
        self.assertIn('Refuse a stale dashboard deployment request', build)
        self.assertNotIn('AZURE_CREDENTIALS', worker)


if __name__ == '__main__':
    unittest.main()
