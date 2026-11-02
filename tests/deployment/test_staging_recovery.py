import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import subprocess

spec = importlib.util.spec_from_file_location('recovery', Path(__file__).parents[2] / 'scripts/staging_recovery.py')
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class RecoveryTests(unittest.TestCase):
    def fixture(self):
        return {'resources': [{'properties': {
            'isCustomProvisioningTimeout': False,
            'containers': [{'properties': {'configMap': {'keyValuePairs': None}}}],
            'diagnostics': {'logAnalytics': {'workspaceId': 'expected'}}}}]}

    def test_reconstructs_write_only_logging_input_without_mutating_baseline(self):
        baseline = self.fixture()
        before = copy.deepcopy(baseline)
        result = recovery.restore_write_inputs(baseline, {
            'LOG_ANALYTICS_WORKSPACE_ID': 'expected', 'LOG_ANALYTICS_WORKSPACE_KEY': 'test-only'})
        props = result['resources'][0]['properties']
        self.assertEqual(baseline, before)
        self.assertNotIn('isCustomProvisioningTimeout', props)
        self.assertNotIn('configMap', props['containers'][0]['properties'])
        self.assertEqual(props['diagnostics']['logAnalytics']['workspaceKey'], 'test-only')

    def test_requires_matching_logging_workspace_and_credential(self):
        for env in ({}, {'LOG_ANALYTICS_WORKSPACE_ID': 'wrong', 'LOG_ANALYTICS_WORKSPACE_KEY': 'test-only'}):
            with self.assertRaises(ValueError):
                recovery.restore_write_inputs(self.fixture(), env)

    def test_preserves_nonempty_config_map(self):
        baseline = self.fixture()
        baseline['resources'][0]['properties']['containers'][0]['properties']['configMap']['keyValuePairs'] = {'x': 'y'}
        baseline['resources'][0]['properties'].pop('diagnostics')
        result = recovery.restore_write_inputs(baseline, {})
        self.assertEqual(result['resources'][0]['properties']['containers'][0]['properties']['configMap'], {'keyValuePairs': {'x': 'y'}})

    def test_authorization_failure_never_counts_as_missing_resource(self):
        with patch.object(recovery.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'AuthorizationFailed')):
            with self.assertRaises(RuntimeError):
                recovery.az('container', 'show', optional=True)

    def test_only_resource_not_found_is_optional(self):
        with patch.object(recovery.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'ResourceNotFound')):
            self.assertIsNone(recovery.az('container', 'show', optional=True))
