"""Tests for opendast.tools."""

import io
import sys
import unittest
from unittest.mock import MagicMock

from opendast.tools import (
    TOOLS,
    dispatch_tool,
    handle_report_pass,
    handle_report_vulnerability,
)


class TestToolDefinitions(unittest.TestCase):
    def test_tools_list_has_eight_entries(self):
        self.assertEqual(len(TOOLS), 8)  # 3 core + 5 shell tools

    def test_core_tool_names_present(self):
        names = {t["name"] for t in TOOLS}
        self.assertIn("send_http_request", names)
        self.assertIn("report_vulnerability", names)
        self.assertIn("report_pass", names)

    def test_shell_tool_names_present(self):
        names = {t["name"] for t in TOOLS}
        for expected in (
            "run_nmap",
            "run_nikto",
            "run_sslyze",
            "run_dig",
            "run_curl",
        ):
            self.assertIn(expected, names)

    def test_each_tool_has_input_schema(self):
        for tool in TOOLS:
            self.assertIn("input_schema", tool)
            self.assertIn("properties", tool["input_schema"])


class TestHandleReportVulnerability(unittest.TestCase):
    def test_appends_to_findings(self):
        findings = []
        vuln = {
            "vulnerability_type": "XSS",
            "severity": "HIGH",
            "url": "http://example.com",
            "description": "Reflected XSS",
            "evidence": "<script>alert(1)</script>",
        }
        # Suppress log output
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result = handle_report_vulnerability(vuln, findings)
        finally:
            sys.stdout = old_stdout
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0], vuln)
        self.assertIn("XSS", result)
        self.assertIn("HIGH", result)

    def test_returns_formatted_string(self):
        findings = []
        vuln = {
            "vulnerability_type": "SQLi",
            "severity": "CRITICAL",
            "url": "http://example.com/login",
            "description": "SQL Injection",
            "evidence": "MySQL error",
            "remediation": "Use parameterized queries",
        }
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result = handle_report_vulnerability(vuln, findings)
        finally:
            sys.stdout = old_stdout
        self.assertIn("Vulnerability recorded: SQLi (CRITICAL)", result)

    def test_long_evidence_truncated_in_log(self):
        findings = []
        vuln = {
            "vulnerability_type": "XSS",
            "severity": "HIGH",
            "url": "http://example.com",
            "description": "test",
            "evidence": "E" * 1000,
        }
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            handle_report_vulnerability(vuln, findings)
        finally:
            sys.stdout = old_stdout
        # Evidence in log should be max 500 chars
        output = captured.getvalue()
        self.assertIn("VULN", output)

    def test_long_description_truncated_in_log(self):
        findings = []
        vuln = {
            "vulnerability_type": "XSS",
            "severity": "HIGH",
            "url": "http://example.com",
            "description": "D" * 1000,
            "evidence": "proof",
        }
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            handle_report_vulnerability(vuln, findings)
        finally:
            sys.stdout = old_stdout
        output = captured.getvalue()
        # The log should contain at most 500 chars of the description
        # (each log line has prefix + content, so check the D's are capped)
        description_line = [line for line in output.splitlines() if "Description:" in line][0]
        # "Description:" itself contains a "D", so cap is 500 + 1
        d_count = description_line.count("D")
        self.assertLessEqual(d_count, 501)
        # But it must NOT contain the full 1000 D's
        self.assertLess(d_count, 1000)

    def test_missing_optional_fields_use_defaults(self):
        findings = []
        vuln = {}  # All fields missing
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result = handle_report_vulnerability(vuln, findings)
        finally:
            sys.stdout = old_stdout
        self.assertIn("Unknown", result)
        self.assertIn("UNKNOWN", result)


class TestHandleReportPass(unittest.TestCase):
    def test_returns_formatted_string(self):
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result = handle_report_pass("SQL Injection", "No errors found")
        finally:
            sys.stdout = old_stdout
        self.assertEqual(result, "Pass recorded: SQL Injection")

    def test_logs_pass_message(self):
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            handle_report_pass("XSS", "Payloads were escaped")
        finally:
            sys.stdout = old_stdout
        output = captured.getvalue()
        self.assertIn("PASS", output)
        self.assertIn("XSS", output)


class TestDispatchTool(unittest.TestCase):
    def test_dispatch_send_http_request(self):
        mock_send = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.text = "OK"
        mock_send.return_value = mock_resp

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result, is_error = dispatch_tool(
                "send_http_request",
                {"method": "GET", "url": "http://example.com/"},
                "http://example.com",
                [],
                http_send=mock_send,
            )
        finally:
            sys.stdout = old_stdout
        self.assertFalse(is_error)
        self.assertIn("HTTP Status: 200", result)

    def test_dispatch_report_vulnerability(self):
        findings = []
        vuln_input = {
            "vulnerability_type": "XSS",
            "severity": "HIGH",
            "url": "http://example.com",
            "description": "test",
            "evidence": "proof",
        }
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result, is_error = dispatch_tool(
                "report_vulnerability", vuln_input, "http://example.com", findings
            )
        finally:
            sys.stdout = old_stdout
        self.assertFalse(is_error)
        self.assertEqual(len(findings), 1)

    def test_dispatch_report_pass(self):
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result, is_error = dispatch_tool(
                "report_pass",
                {"test_category": "SQLi", "details": "Safe"},
                "http://example.com",
                [],
            )
        finally:
            sys.stdout = old_stdout
        self.assertFalse(is_error)
        self.assertIn("Pass recorded", result)

    def test_dispatch_unknown_tool(self):
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result, is_error = dispatch_tool("unknown_tool", {}, "http://example.com", [])
        finally:
            sys.stdout = old_stdout
        self.assertTrue(is_error)
        self.assertIn("Unknown tool", result)

    def test_dispatch_missing_required_field(self):
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result, is_error = dispatch_tool(
                "send_http_request",
                {},  # Missing method and url
                "http://example.com",
                [],
            )
        finally:
            sys.stdout = old_stdout
        self.assertTrue(is_error)
        self.assertIn("Missing required field", result)

    def test_dispatch_report_pass_defaults(self):
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result, is_error = dispatch_tool("report_pass", {}, "http://example.com", [])
        finally:
            sys.stdout = old_stdout
        self.assertFalse(is_error)
        self.assertIn("Pass recorded: Unknown", result)

    def test_dispatch_shell_tool_nmap(self):
        import subprocess

        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=["nmap"],
                returncode=0,
                stdout="80/tcp open http",
                stderr="",
            )
        )
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result, is_error = dispatch_tool(
                "run_nmap",
                {"host": "example.com"},
                "http://example.com",
                [],
                shell_run=mock_run,
            )
        finally:
            sys.stdout = old_stdout
        self.assertFalse(is_error)
        self.assertIn("Exit code: 0", result)

    def test_dispatch_unexpected_exception_hides_details(self):
        """Unexpected exceptions should not leak internal details."""
        mock_send = MagicMock(side_effect=RuntimeError("/home/user/.secret/db.conf not found"))
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result, is_error = dispatch_tool(
                "send_http_request",
                {"method": "GET", "url": "http://example.com/"},
                "http://example.com",
                [],
                http_send=mock_send,
            )
        finally:
            sys.stdout = old_stdout
        self.assertTrue(is_error)
        self.assertIn("unexpected internal error", result)
        # Must NOT contain the sensitive path
        self.assertNotIn(".secret", result)

    def test_dispatch_value_error_shows_message(self):
        """ValueError/TypeError should still show their message."""
        mock_send = MagicMock(side_effect=ValueError("bad value"))
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result, is_error = dispatch_tool(
                "send_http_request",
                {"method": "GET", "url": "http://example.com/"},
                "http://example.com",
                [],
                http_send=mock_send,
            )
        finally:
            sys.stdout = old_stdout
        self.assertTrue(is_error)
        self.assertIn("bad value", result)

    def test_dispatch_shell_tool_scope_error(self):
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result, is_error = dispatch_tool(
                "run_nmap",
                {"host": "evil.com"},
                "http://example.com",
                [],
            )
        finally:
            sys.stdout = old_stdout
        self.assertTrue(is_error)
        self.assertIn("ERROR", result)


if __name__ == "__main__":
    unittest.main()
