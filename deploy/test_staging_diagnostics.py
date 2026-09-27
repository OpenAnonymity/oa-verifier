import json
import unittest
from staging_diagnostics import summarize_logs


class DiagnosticPrivacyTests(unittest.TestCase):
    def test_outputs_categories_without_log_values(self):
        raw = 'time=2026-09-27T20:00:00Z msg="failed to create provisioning key" error="OpenRouter session rejected with status 403" email=private@example.invalid Cookie=secret-cookie key=secret-key'
        result = summarize_logs(raw)
        encoded = json.dumps(result)
        self.assertNotIn("private@example.invalid", encoded)
        self.assertNotIn("secret-cookie", encoded)
        self.assertNotIn("secret-key", encoded)
        self.assertEqual(result["error_status_counts"], {"403": 1})
        self.assertEqual(result["categories"]["failed to create provisioning key"]["count"], 1)

    def test_unknown_log_content_is_not_forwarded(self):
        result = summarize_logs('arbitrary secret prompt and account information')
        self.assertEqual(result, {"line_count": 1, "categories": {}, "error_status_counts": {}})


if __name__ == "__main__":
    unittest.main()
