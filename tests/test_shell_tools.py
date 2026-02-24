"""Tests for open_dast.shell_tools."""

import io
import subprocess
import sys
import unittest
from unittest.mock import MagicMock

from open_dast.shell_tools import (
    SHELL_TOOL_DEFINITIONS,
    SHELL_TOOL_REGISTRY,
    build_curl_args,
    build_dig_args,
    build_dirb_args,
    build_nikto_args,
    build_nmap_args,
    build_sslyze_args,
    build_whatweb_args,
    execute_shell_tool,
    sanitize_args,
    validate_scope_host_only,
    validate_scope_url,
)

# ─── Scope Validation ────────────────────────────────────────────────────────


class TestValidateScopeHostOnly(unittest.TestCase):
    def test_allows_target_host(self):
        result = validate_scope_host_only("http://example.com", "example.com")
        self.assertIsNone(result)

    def test_allows_target_host_with_port(self):
        result = validate_scope_host_only("http://example.com:8080", "example.com")
        self.assertIsNone(result)

    def test_blocks_different_host(self):
        result = validate_scope_host_only("http://example.com", "evil.com")
        self.assertIsNotNone(result)
        self.assertIn("ERROR", result)
        self.assertIn("outside target scope", result)

    def test_blocks_subdomain(self):
        result = validate_scope_host_only("http://example.com", "sub.example.com")
        self.assertIsNotNone(result)
        self.assertIn("ERROR", result)


class TestValidateScopeUrl(unittest.TestCase):
    def test_allows_in_scope_url(self):
        result = validate_scope_url("http://example.com", "http://example.com/path")
        self.assertIsNone(result)

    def test_allows_exact_url(self):
        result = validate_scope_url("http://example.com", "http://example.com")
        self.assertIsNone(result)

    def test_blocks_out_of_scope(self):
        result = validate_scope_url("http://example.com", "http://evil.com/path")
        self.assertIsNotNone(result)
        self.assertIn("ERROR", result)

    def test_trailing_slash_normalization(self):
        result = validate_scope_url("http://example.com/", "http://example.com/path")
        self.assertIsNone(result)


# ─── Argument Sanitization ───────────────────────────────────────────────────


class TestSanitizeArgs(unittest.TestCase):
    def test_clean_args_pass(self):
        self.assertIsNone(sanitize_args(["-sV", "--ports", "80,443", "example.com"]))

    def test_hyphens_and_colons_pass(self):
        self.assertIsNone(sanitize_args(["-p", "80:443", "--script", "default,safe"]))

    def test_semicolon_blocked(self):
        result = sanitize_args(["example.com;rm -rf /"])
        self.assertIn("ERROR", result)

    def test_pipe_blocked(self):
        result = sanitize_args(["host | cat /etc/passwd"])
        self.assertIn("ERROR", result)

    def test_backtick_blocked(self):
        result = sanitize_args(["`whoami`"])
        self.assertIn("ERROR", result)

    def test_dollar_sign_blocked(self):
        result = sanitize_args(["$HOME"])
        self.assertIn("ERROR", result)

    def test_ampersand_blocked(self):
        result = sanitize_args(["host & sleep 10"])
        self.assertIn("ERROR", result)

    def test_parentheses_blocked(self):
        result = sanitize_args(["$(id)"])
        self.assertIn("ERROR", result)


# ─── Argument Builders ───────────────────────────────────────────────────────


class TestBuildNmapArgs(unittest.TestCase):
    def test_default_service_detection(self):
        args = build_nmap_args({"host": "example.com"}, "http://example.com")
        self.assertIn("-sV", args)
        self.assertIn("--version-intensity", args)
        self.assertIn("example.com", args)

    def test_quick_scan(self):
        args = build_nmap_args({"host": "example.com", "scan_type": "quick"}, "http://example.com")
        self.assertIn("-T4", args)
        self.assertIn("-F", args)

    def test_scripts_scan(self):
        args = build_nmap_args(
            {"host": "example.com", "scan_type": "scripts"}, "http://example.com"
        )
        self.assertIn("--script", args)
        self.assertIn("default,safe", args)

    def test_unknown_scan_type_defaults_to_sv(self):
        args = build_nmap_args(
            {"host": "example.com", "scan_type": "unknown"}, "http://example.com"
        )
        self.assertIn("-sV", args)

    def test_ports_specified(self):
        args = build_nmap_args({"host": "example.com", "ports": "80,443"}, "http://example.com")
        idx = args.index("-p")
        self.assertEqual(args[idx + 1], "80,443")

    def test_no_ports_omits_flag(self):
        args = build_nmap_args({"host": "example.com"}, "http://example.com")
        self.assertNotIn("-p", args)

    def test_safety_flags_always_present(self):
        args = build_nmap_args({"host": "example.com"}, "http://example.com")
        self.assertIn("--max-retries", args)
        self.assertIn("--host-timeout", args)


class TestBuildNiktoArgs(unittest.TestCase):
    def test_default_args(self):
        args = build_nikto_args({"host": "example.com"}, "http://example.com")
        self.assertEqual(args[0:2], ["-h", "example.com"])
        self.assertIn("-p", args)
        self.assertIn("80", args)

    def test_custom_port(self):
        args = build_nikto_args({"host": "example.com", "port": "8443"}, "http://example.com")
        idx = args.index("-p")
        self.assertEqual(args[idx + 1], "8443")

    def test_ssl_flag(self):
        args = build_nikto_args({"host": "example.com", "ssl": True}, "http://example.com")
        self.assertIn("-ssl", args)

    def test_no_ssl_by_default(self):
        args = build_nikto_args({"host": "example.com"}, "http://example.com")
        self.assertNotIn("-ssl", args)


class TestBuildSslyzeArgs(unittest.TestCase):
    def test_default_port(self):
        args = build_sslyze_args({"host": "example.com"}, "http://example.com")
        self.assertEqual(args, ["example.com:443"])

    def test_custom_port(self):
        args = build_sslyze_args({"host": "example.com", "port": "8443"}, "http://example.com")
        self.assertEqual(args, ["example.com:8443"])


class TestBuildDigArgs(unittest.TestCase):
    def test_default_a_record(self):
        args = build_dig_args({"host": "example.com"}, "http://example.com")
        self.assertEqual(args, ["example.com", "A", "+short"])

    def test_mx_record(self):
        args = build_dig_args({"host": "example.com", "record_type": "MX"}, "http://example.com")
        self.assertIn("MX", args)

    def test_case_insensitive(self):
        args = build_dig_args({"host": "example.com", "record_type": "txt"}, "http://example.com")
        self.assertIn("TXT", args)

    def test_invalid_record_type_raises(self):
        with self.assertRaises(ValueError) as ctx:
            build_dig_args({"host": "example.com", "record_type": "INVALID"}, "http://example.com")
        self.assertIn("not allowed", str(ctx.exception))


class TestBuildWhatwebArgs(unittest.TestCase):
    def test_default_args(self):
        args = build_whatweb_args({"url": "http://example.com"}, "http://example.com")
        self.assertIn("-a", args)
        self.assertIn("1", args)
        self.assertIn("--color=never", args)
        self.assertIn("http://example.com", args)

    def test_custom_aggression(self):
        args = build_whatweb_args(
            {"url": "http://example.com", "aggression": "3"}, "http://example.com"
        )
        idx = args.index("-a")
        self.assertEqual(args[idx + 1], "3")

    def test_invalid_aggression_defaults_to_1(self):
        args = build_whatweb_args(
            {"url": "http://example.com", "aggression": "99"}, "http://example.com"
        )
        idx = args.index("-a")
        self.assertEqual(args[idx + 1], "1")


class TestBuildDirbArgs(unittest.TestCase):
    def test_default_wordlist(self):
        args = build_dirb_args({"url": "http://example.com"}, "http://example.com")
        self.assertEqual(args[0], "http://example.com")
        self.assertEqual(args[1], "/usr/share/dirb/wordlists/common.txt")
        self.assertIn("-S", args)
        self.assertIn("-r", args)

    def test_custom_valid_wordlist(self):
        args = build_dirb_args(
            {"url": "http://example.com", "wordlist": "/usr/share/dirb/wordlists/big.txt"},
            "http://example.com",
        )
        self.assertEqual(args[1], "/usr/share/dirb/wordlists/big.txt")

    def test_disallowed_wordlist_raises(self):
        with self.assertRaises(ValueError) as ctx:
            build_dirb_args(
                {"url": "http://example.com", "wordlist": "/etc/passwd"},
                "http://example.com",
            )
        self.assertIn("Wordlist must be in", str(ctx.exception))


class TestBuildCurlArgs(unittest.TestCase):
    def test_default_get(self):
        args = build_curl_args({"url": "http://example.com"}, "http://example.com")
        self.assertIn("-s", args)
        self.assertIn("-i", args)
        self.assertIn("-L", args)
        self.assertIn("-X", args)
        idx = args.index("-X")
        self.assertEqual(args[idx + 1], "GET")
        self.assertEqual(args[-1], "http://example.com")

    def test_post_method(self):
        args = build_curl_args(
            {"url": "http://example.com", "method": "POST"}, "http://example.com"
        )
        idx = args.index("-X")
        self.assertEqual(args[idx + 1], "POST")

    def test_headers_added(self):
        args = build_curl_args(
            {"url": "http://example.com", "headers": {"Authorization": "Bearer tok"}},
            "http://example.com",
        )
        self.assertIn("-H", args)
        idx = args.index("-H")
        self.assertEqual(args[idx + 1], "Authorization: Bearer tok")

    def test_no_include_headers(self):
        args = build_curl_args(
            {"url": "http://example.com", "include_headers": False}, "http://example.com"
        )
        self.assertNotIn("-i", args)

    def test_no_follow_redirects(self):
        args = build_curl_args(
            {"url": "http://example.com", "follow_redirects": False}, "http://example.com"
        )
        self.assertNotIn("-L", args)


# ─── Tool Definitions ────────────────────────────────────────────────────────


class TestShellToolDefinitions(unittest.TestCase):
    def test_definitions_count(self):
        self.assertEqual(len(SHELL_TOOL_DEFINITIONS), 7)

    def test_names_match_registry(self):
        def_names = {d["name"] for d in SHELL_TOOL_DEFINITIONS}
        reg_names = set(SHELL_TOOL_REGISTRY.keys())
        self.assertEqual(def_names, reg_names)

    def test_each_has_required_fields(self):
        for defn in SHELL_TOOL_DEFINITIONS:
            self.assertIn("name", defn)
            self.assertIn("description", defn)
            self.assertIn("input_schema", defn)
            self.assertIn("properties", defn["input_schema"])
            self.assertIn("required", defn["input_schema"])


# ─── Generic Executor ────────────────────────────────────────────────────────


class TestExecuteShellTool(unittest.TestCase):
    def _suppress_stdout(self):
        self._old_stdout = sys.stdout
        sys.stdout = io.StringIO()

    def _restore_stdout(self):
        sys.stdout = self._old_stdout

    def test_happy_path_nmap(self):
        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=["nmap", "-sV", "example.com"],
                returncode=0,
                stdout="PORT  STATE SERVICE\n80/tcp open  http",
                stderr="",
            )
        )
        self._suppress_stdout()
        try:
            result = execute_shell_tool(
                "run_nmap",
                {"host": "example.com"},
                "http://example.com",
                shell_run=mock_run,
            )
        finally:
            self._restore_stdout()
        self.assertIn("Exit code: 0", result)
        self.assertIn("80/tcp open", result)
        mock_run.assert_called_once()

    def test_stderr_included(self):
        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=["nmap"],
                returncode=0,
                stdout="output",
                stderr="warning: something",
            )
        )
        self._suppress_stdout()
        try:
            result = execute_shell_tool(
                "run_nmap",
                {"host": "example.com"},
                "http://example.com",
                shell_run=mock_run,
            )
        finally:
            self._restore_stdout()
        self.assertIn("--- stderr ---", result)
        self.assertIn("warning: something", result)

    def test_output_truncation(self):
        long_output = "A" * 6000
        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=["nmap"],
                returncode=0,
                stdout=long_output,
                stderr="",
            )
        )
        self._suppress_stdout()
        try:
            result = execute_shell_tool(
                "run_nmap",
                {"host": "example.com"},
                "http://example.com",
                shell_run=mock_run,
            )
        finally:
            self._restore_stdout()
        self.assertIn("truncated", result)
        self.assertIn("6000 total chars", result)

    def test_timeout_expired(self):
        mock_run = MagicMock(side_effect=subprocess.TimeoutExpired("nmap", 120))
        self._suppress_stdout()
        try:
            result = execute_shell_tool(
                "run_nmap",
                {"host": "example.com"},
                "http://example.com",
                shell_run=mock_run,
            )
        finally:
            self._restore_stdout()
        self.assertIn("ERROR", result)
        self.assertIn("timed out", result)

    def test_binary_not_found(self):
        mock_run = MagicMock(side_effect=FileNotFoundError())
        self._suppress_stdout()
        try:
            result = execute_shell_tool(
                "run_nmap",
                {"host": "example.com"},
                "http://example.com",
                shell_run=mock_run,
            )
        finally:
            self._restore_stdout()
        self.assertIn("ERROR", result)
        self.assertIn("not found", result)

    def test_os_error(self):
        mock_run = MagicMock(side_effect=OSError("Permission denied"))
        self._suppress_stdout()
        try:
            result = execute_shell_tool(
                "run_nmap",
                {"host": "example.com"},
                "http://example.com",
                shell_run=mock_run,
            )
        finally:
            self._restore_stdout()
        self.assertIn("ERROR", result)
        self.assertIn("Failed to execute", result)

    def test_unknown_tool_name(self):
        result = execute_shell_tool(
            "run_unknown",
            {"host": "example.com"},
            "http://example.com",
        )
        self.assertIn("ERROR", result)
        self.assertIn("Unknown shell tool", result)

    def test_scope_violation_blocked(self):
        result = execute_shell_tool(
            "run_nmap",
            {"host": "evil.com"},
            "http://example.com",
        )
        self.assertIn("ERROR", result)
        self.assertIn("outside target scope", result)

    def test_url_scope_violation_blocked(self):
        result = execute_shell_tool(
            "run_curl",
            {"url": "http://evil.com/"},
            "http://example.com",
        )
        self.assertIn("ERROR", result)
        self.assertIn("outside target scope", result)

    def test_dangerous_args_blocked(self):
        self._suppress_stdout()
        try:
            # The host passes scope check but nmap args get sanitized
            result = execute_shell_tool(
                "run_nmap",
                {"host": "example.com", "ports": "80;rm -rf /"},
                "http://example.com",
            )
        finally:
            self._restore_stdout()
        self.assertIn("ERROR", result)
        self.assertIn("disallowed characters", result)

    def test_invalid_args_returns_error(self):
        # Missing required 'host' key for nmap
        result = execute_shell_tool(
            "run_nmap",
            {},
            "http://example.com",
        )
        self.assertIn("ERROR", result)

    def test_dig_invalid_record_type_returns_error(self):
        result = execute_shell_tool(
            "run_dig",
            {"host": "example.com", "record_type": "BOGUS"},
            "http://example.com",
        )
        self.assertIn("ERROR", result)
        self.assertIn("Invalid arguments", result)

    def test_dirb_invalid_wordlist_returns_error(self):
        result = execute_shell_tool(
            "run_dirb",
            {"url": "http://example.com", "wordlist": "/etc/passwd"},
            "http://example.com",
        )
        self.assertIn("ERROR", result)
        self.assertIn("Invalid arguments", result)

    def test_curl_url_scope_passes(self):
        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=["curl"],
                returncode=0,
                stdout="HTTP/1.1 200 OK\n\n<html>",
                stderr="",
            )
        )
        self._suppress_stdout()
        try:
            result = execute_shell_tool(
                "run_curl",
                {"url": "http://example.com/path"},
                "http://example.com",
                shell_run=mock_run,
            )
        finally:
            self._restore_stdout()
        self.assertIn("Exit code: 0", result)

    def test_whatweb_passes(self):
        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=["whatweb"],
                returncode=0,
                stdout="http://example.com [200 OK]",
                stderr="",
            )
        )
        self._suppress_stdout()
        try:
            result = execute_shell_tool(
                "run_whatweb",
                {"url": "http://example.com"},
                "http://example.com",
                shell_run=mock_run,
            )
        finally:
            self._restore_stdout()
        self.assertIn("Exit code: 0", result)

    def test_nonzero_exit_code_reported(self):
        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(
                args=["nmap"],
                returncode=1,
                stdout="",
                stderr="error occurred",
            )
        )
        self._suppress_stdout()
        try:
            result = execute_shell_tool(
                "run_nmap",
                {"host": "example.com"},
                "http://example.com",
                shell_run=mock_run,
            )
        finally:
            self._restore_stdout()
        self.assertIn("Exit code: 1", result)


if __name__ == "__main__":
    unittest.main()
