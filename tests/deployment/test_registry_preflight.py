"""A bad registry pair must fail before replacing verifier2, without exporting data."""
import contextlib
import io
import json
import os
from pathlib import Path
import textwrap
import unittest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError


WORKFLOW = Path(__file__).resolve().parents[2] / '.github/workflows/build-and-sign.yml'


class RegistryPreflightTests(unittest.TestCase):
    def run_preflight(self, *, url='https://org-staging.openanonymity.ai', credential='fixture-secret',
                      stations=None, error=None):
        text = WORKFLOW.read_text()
        block = text.split('      - name: Verify staging registry authorization before deployment', 1)[1]
        code = textwrap.dedent(block.split("python3 - <<'PY'\n", 1)[1].split('\n          PY', 1)[0])
        opener = MagicMock()
        response = io.StringIO(json.dumps({'stations': [{'station_id': 'fixture'}] if stations is None else stations}))
        opener.open.return_value.__enter__.return_value = response
        if error:
            opener.open.side_effect = error
        output = io.StringIO()
        with patch.dict(os.environ, {'REGISTRY_BASE_URL': url, 'REGISTRY_AUTH': credential}), \
             patch('urllib.request.build_opener', return_value=opener), \
             contextlib.redirect_stdout(output):
            exec(compile(code, '<registry-preflight>', 'exec'), {})
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, 'https://org-staging.openanonymity.ai/verifier/registered_stations')
        self.assertEqual(request.get_header('Authorization'), 'Bearer fixture-secret')
        self.assertEqual(request.get_header('User-agent'), 'Go-http-client/1.1')
        self.assertNotIn('fixture-secret', output.getvalue())
        self.assertNotIn('station_id', output.getvalue())
        return output.getvalue()

    def test_valid_pair_reports_only_count(self):
        self.assertIn('station count=1', self.run_preflight())

    def test_wrong_environment_is_rejected_before_network(self):
        for url in ['https://org.openanonymity.ai', 'http://org-staging.openanonymity.ai',
                    'https://org-staging.openanonymity.ai@evil.example',
                    'https://org-staging.openanonymity.ai?redirect=elsewhere']:
            with self.subTest(url=url), patch('urllib.request.Request') as request:
                with self.assertRaisesRegex(SystemExit, 'must use the staging registry'):
                    self.run_preflight(url=url)
                request.assert_not_called()

    def test_missing_credential_fails(self):
        with self.assertRaisesRegex(SystemExit, 'credential missing'):
            self.run_preflight(credential='')

    def test_rejection_or_redirect_fails(self):
        for status in (302, 401, 403, 503):
            with self.subTest(status=status), self.assertRaisesRegex(SystemExit, 'HTTP ' + str(status)):
                self.run_preflight(error=HTTPError('https://org-staging.openanonymity.ai', status,
                                                  'fixture error', {}, None))

    def test_empty_registry_fails(self):
        with self.assertRaisesRegex(SystemExit, 'no authorized stations'):
            self.run_preflight(stations=[])

    def test_preflight_precedes_container_replacement(self):
        text = WORKFLOW.read_text()
        self.assertLess(text.index('name: Verify staging registry authorization'),
                        text.index('az container delete'))
