import json
import unittest
from staging_diagnostics import summarize_logs, summarize_metrics


class DiagnosticPrivacyTests(unittest.TestCase):
    def test_metrics_exclude_resource_and_dimension_identifiers(self):
        result = summarize_metrics({"resourceId": "private-resource", "value": [{
            "name": {"value": "CpuUsage"}, "timeseries": [{
                "metadatavalues": [{"value": "private-dimension"}],
                "data": [{"timeStamp": "2026-09-27T00:00:00Z", "average": 12,
                          "maximum": 20, "extra": "private-extra"}]}]}]})
        encoded = json.dumps(result)
        self.assertNotIn("private", encoded)
        self.assertEqual(result[0]["points"][0]["maximum"], 20)

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
