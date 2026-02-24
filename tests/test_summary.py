"""Tests for opendast.summary."""

import io
import sys
import unittest

from opendast.summary import print_summary


class TestPrintSummary(unittest.TestCase):
    def _capture_summary(self, findings, target, token_count, iterations=0, duration=0.0):
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            print_summary(findings, target, token_count, iterations=iterations, duration=duration)
        finally:
            sys.stdout = old_stdout
        return captured.getvalue()

    def test_no_findings(self):
        output = self._capture_summary(
            [], "http://example.com", "1,000/100,000", iterations=5, duration=120.0
        )
        self.assertIn("SCAN SUMMARY", output)
        self.assertIn("http://example.com", output)
        self.assertIn("1,000/100,000", output)
        self.assertIn("Iterations: 5", output)
        self.assertIn("Duration: 2m 0s", output)
        self.assertIn("Total Findings: 0", output)
        self.assertIn("No vulnerabilities found", output)

    def test_duration_seconds_only(self):
        output = self._capture_summary([], "http://example.com", "0", iterations=1, duration=45.0)
        self.assertIn("Duration: 45s", output)

    def test_duration_minutes_and_seconds(self):
        output = self._capture_summary([], "http://example.com", "0", iterations=1, duration=185.0)
        self.assertIn("Duration: 3m 5s", output)

    def test_with_findings(self):
        findings = [
            {"severity": "HIGH", "vulnerability_type": "XSS", "url": "http://example.com/xss"},
            {"severity": "CRITICAL", "vulnerability_type": "SQLi", "url": "http://example.com/sql"},
        ]
        output = self._capture_summary(findings, "http://example.com", "5,000/100,000")
        self.assertIn("Total Findings: 2", output)
        self.assertIn("XSS", output)
        self.assertIn("SQLi", output)
        # CRITICAL should appear before HIGH (sorted by severity)
        sqli_pos = output.index("SQLi")
        xss_pos = output.index("XSS")
        self.assertLess(sqli_pos, xss_pos)

    def test_severity_sorting_order(self):
        findings = [
            {"severity": "LOW", "vulnerability_type": "Info Leak", "url": "http://x.com"},
            {"severity": "CRITICAL", "vulnerability_type": "RCE", "url": "http://x.com"},
            {"severity": "MEDIUM", "vulnerability_type": "XSS", "url": "http://x.com"},
        ]
        output = self._capture_summary(findings, "http://x.com", "0")
        rce_pos = output.index("RCE")
        xss_pos = output.index("XSS")
        leak_pos = output.index("Info Leak")
        self.assertLess(rce_pos, xss_pos)
        self.assertLess(xss_pos, leak_pos)

    def test_missing_fields_use_question_mark(self):
        findings = [{}]  # Missing all fields
        output = self._capture_summary(findings, "http://example.com", "0")
        self.assertIn("[?]", output)

    def test_medium_severity_uses_yellow(self):
        findings = [
            {"severity": "MEDIUM", "vulnerability_type": "test", "url": "http://x.com"},
        ]
        output = self._capture_summary(findings, "http://x.com", "0")
        self.assertIn("\033[93m", output)  # YELLOW

    def test_info_severity_uses_reset_color(self):
        findings = [
            {"severity": "INFO", "vulnerability_type": "test", "url": "http://x.com"},
        ]
        output = self._capture_summary(findings, "http://x.com", "0")
        self.assertIn("INFO", output)


if __name__ == "__main__":
    unittest.main()
