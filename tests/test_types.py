"""Tests for opendast.types."""

import unittest

from opendast.types import Finding, ScanResult, ShellToolConfig, ToolResult


class TestFinding(unittest.TestCase):
    def test_finding_is_dict(self):
        finding: Finding = {
            "vulnerability_type": "XSS",
            "severity": "HIGH",
            "url": "http://example.com",
            "description": "Reflected XSS",
            "evidence": "<script>alert(1)</script>",
        }
        self.assertIsInstance(finding, dict)

    def test_finding_supports_get(self):
        finding: Finding = {"vulnerability_type": "SQLi", "severity": "CRITICAL"}
        self.assertEqual(finding.get("severity"), "CRITICAL")
        self.assertIsNone(finding.get("remediation"))

    def test_finding_supports_bracket_access(self):
        finding: Finding = {"vulnerability_type": "XSS"}
        self.assertEqual(finding["vulnerability_type"], "XSS")

    def test_empty_finding(self):
        finding: Finding = {}
        self.assertEqual(len(finding), 0)


class TestScanResult(unittest.TestCase):
    def test_tuple_unpacking(self):
        result = ScanResult(findings=[], token_count=500, iterations=3, duration=10.5)
        findings, tokens, iters, dur = result
        self.assertEqual(findings, [])
        self.assertEqual(tokens, 500)
        self.assertEqual(iters, 3)
        self.assertAlmostEqual(dur, 10.5)

    def test_named_access(self):
        result = ScanResult(findings=[], token_count=100, iterations=1, duration=1.0)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.token_count, 100)
        self.assertEqual(result.iterations, 1)
        self.assertAlmostEqual(result.duration, 1.0)

    def test_is_tuple(self):
        result = ScanResult([], 0, 0, 0.0)
        self.assertIsInstance(result, tuple)

    def test_star_unpacking(self):
        result = ScanResult([], 100, 2, 5.0)
        findings, *rest = result
        self.assertEqual(findings, [])
        self.assertEqual(rest, [100, 2, 5.0])


class TestToolResult(unittest.TestCase):
    def test_tuple_unpacking(self):
        result = ToolResult(text="ok", is_error=False)
        text, is_error = result
        self.assertEqual(text, "ok")
        self.assertFalse(is_error)

    def test_named_access(self):
        result = ToolResult("error msg", True)
        self.assertEqual(result.text, "error msg")
        self.assertTrue(result.is_error)

    def test_is_tuple(self):
        result = ToolResult("x", False)
        self.assertIsInstance(result, tuple)


class TestShellToolConfig(unittest.TestCase):
    def test_is_dict(self):
        config: ShellToolConfig = {
            "binary": "nmap",
            "scope_mode": "host_only",
            "build_args": lambda inp, tgt: [inp["host"]],
        }
        self.assertIsInstance(config, dict)
        self.assertEqual(config["binary"], "nmap")
        self.assertEqual(config["scope_mode"], "host_only")


if __name__ == "__main__":
    unittest.main()
