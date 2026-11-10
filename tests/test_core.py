import json
import tempfile
import unittest
from pathlib import Path

from exposurescope.core import ScopeError, build_report, host, import_ct, import_dns, ownership


class CoreTests(unittest.TestCase):
    def test_scope_normalization(self):
        self.assertEqual(host("API.Example.Invalid.", "example.invalid"), "api.example.invalid")
        with self.assertRaises(ScopeError):
            host("example.invalid.evil.test", "example.invalid")

    def test_dns_and_ct_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dns = root / "dns.jsonl"
            dns.write_text(json.dumps({"name": "api.example.invalid", "type": "A", "value": "198.51.100.1",
                                       "observed_at": "2026-01-01T00:00:00Z", "source": "test-only"}) + "\n")
            ct = root / "ct.jsonl"
            ct.write_text(json.dumps({"dns_names": ["api.example.invalid", "outside.test"],
                                      "certificate_sha256": "a" * 64, "observed_at": "2026-01-02T00:00:00Z",
                                      "source": "test-only-ct"}) + "\n")
            report = build_report("example.invalid", [dns], [ct])
        self.assertEqual(len(report["assets"]), 1)
        self.assertEqual(report["network_requests"], 0)
        self.assertIn("out-of-scope", " ".join(report["issues"]))

    def test_txt_value_not_exported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dns.jsonl"
            path.write_text(json.dumps({"name": "example.invalid", "type": "TXT", "value": "private-test-token",
                                        "observed_at": "2026-01-01T00:00:00Z", "source": "fixture"}) + "\n")
            rows, issues = import_dns(path, "example.invalid")
        self.assertEqual(issues, [])
        self.assertNotIn("private-test-token", json.dumps(rows))

    def test_history_and_operator_ownership(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "dns.jsonl"
            path.write_text(json.dumps({"name": "a.example.invalid", "type": "A", "value": "192.0.2.1",
                                        "observed_at": "2026-01-01T00:00:00Z", "source": "fixture"}) + "\n")
            owner_file = root / "owners.json"
            owner_file.write_text(json.dumps({"a.example.invalid": "test owner"}))
            first = build_report("example.invalid", [path], [], ownership(owner_file, "example.invalid"))
            path.write_text(json.dumps({"name": "b.example.invalid", "type": "A", "value": "192.0.2.2",
                                        "observed_at": "2026-01-02T00:00:00Z", "source": "fixture"}) + "\n")
            second = build_report("example.invalid", [path], [], previous=first)
        self.assertEqual(first["assets"][0]["ownership_status"], "operator_asserted")
        self.assertEqual(second["changes"]["newly_observed"], ["b.example.invalid"])
        self.assertEqual(second["changes"]["not_observed_in_current_import"], ["a.example.invalid"])


if __name__ == "__main__":
    unittest.main()
