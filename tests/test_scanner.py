"""Tests for opendast.scanner."""

import io
import os
import sys
import tempfile
import unittest
from typing import Any
from unittest.mock import MagicMock, patch

from anthropic.types import TextBlock, ToolUseBlock

from opendast.constants import MAX_ITERATIONS
from opendast.scanner import AnthropicClientWrapper, call_api_with_retries, run_scan


class FakeUsage:
    def __init__(self, input_tokens=100, output_tokens=50):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


def make_text_block(text: str = "Done") -> TextBlock:
    return TextBlock(type="text", text=text)


def make_tool_use_block(
    name: str = "report_pass",
    input_data: dict[str, Any] | None = None,
    tool_id: str = "tool_1",
) -> ToolUseBlock:
    return ToolUseBlock(
        type="tool_use",
        id=tool_id,
        name=name,
        input=input_data or {"test_category": "Test", "details": "Passed"},
    )


class FakeResponse:
    def __init__(self, stop_reason="end_turn", content=None, usage=None):
        self.stop_reason = stop_reason
        self.content = content or [make_text_block()]
        self.usage = usage or FakeUsage()


class FakeApiClient:
    """Fake API client for testing."""

    def __init__(self, responses=None):
        self._responses = list(responses) if responses else [FakeResponse()]
        self._call_count = 0

    def create(self, **kwargs: Any) -> Any:  # test fake — no real Message needed
        if self._call_count < len(self._responses):
            resp = self._responses[self._call_count]
            self._call_count += 1
            return resp
        return FakeResponse()


class TestCallApiWithRetries(unittest.TestCase):
    def test_success_first_attempt(self):
        client = FakeApiClient()
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result = call_api_with_retries(client, [], "system prompt")
        finally:
            sys.stdout = old_stdout
        self.assertIsNotNone(result)

    @patch("opendast.scanner.time.sleep")
    def test_connection_error_retries_then_fails(self, mock_sleep):
        import anthropic

        client = MagicMock()
        client.create.side_effect = anthropic.APIConnectionError(request=MagicMock())

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result = call_api_with_retries(client, [], "prompt")
        finally:
            sys.stdout = old_stdout
        self.assertIsNone(result)

    @patch("opendast.scanner.time.sleep")
    def test_rate_limit_retries(self, mock_sleep):
        import anthropic

        client = MagicMock()
        # Fail twice, then succeed
        resp = FakeResponse()
        client.create.side_effect = [
            anthropic.RateLimitError(
                message="rate limited",
                response=MagicMock(status_code=429, headers={}),
                body=None,
            ),
            resp,
        ]

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result = call_api_with_retries(client, [], "prompt")
        finally:
            sys.stdout = old_stdout
        self.assertIsNotNone(result)
        mock_sleep.assert_called_once_with(30)

    def test_auth_error_exits(self):
        import anthropic

        client = MagicMock()
        client.create.side_effect = anthropic.AuthenticationError(
            message="invalid key",
            response=MagicMock(status_code=401, headers={}),
            body=None,
        )

        old_stdout, old_stderr = sys.stdout, sys.stderr
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()
        try:
            with self.assertRaises(SystemExit) as ctx:
                call_api_with_retries(client, [], "prompt")
            self.assertEqual(ctx.exception.code, 2)
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    @patch("opendast.scanner.time.sleep")
    def test_api_status_error_retries_then_fails(self, mock_sleep):
        import anthropic

        client = MagicMock()
        client.create.side_effect = anthropic.APIStatusError(
            message="server error",
            response=MagicMock(status_code=500, headers={}),
            body=None,
        )

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result = call_api_with_retries(client, [], "prompt")
        finally:
            sys.stdout = old_stdout
        self.assertIsNone(result)

    @patch("opendast.scanner.time.sleep")
    def test_overloaded_529_uses_long_backoff(self, mock_sleep):
        import anthropic

        client = MagicMock()
        resp = FakeResponse()
        client.create.side_effect = [
            anthropic.APIStatusError(
                message="Overloaded",
                response=MagicMock(status_code=529, headers={}),
                body=None,
            ),
            resp,
        ]

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result = call_api_with_retries(client, [], "prompt")
        finally:
            sys.stdout = old_stdout
        self.assertIsNotNone(result)
        mock_sleep.assert_called_once_with(30)

    @patch("opendast.scanner.time.sleep")
    def test_overloaded_529_retries_all_attempts(self, mock_sleep):
        import anthropic

        client = MagicMock()
        client.create.side_effect = anthropic.APIStatusError(
            message="Overloaded",
            response=MagicMock(status_code=529, headers={}),
            body=None,
        )

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result = call_api_with_retries(client, [], "prompt")
        finally:
            sys.stdout = old_stdout
        # 529 retries all attempts (doesn't abort early like other status errors)
        self.assertIsNone(result)
        self.assertEqual(mock_sleep.call_count, 3)
        mock_sleep.assert_any_call(30)
        mock_sleep.assert_any_call(60)
        mock_sleep.assert_any_call(90)


class TestRunScan(unittest.TestCase):
    def _create_playbook(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write("# Test playbook\n\nTest SQL Injection")
        return f.name

    def test_end_turn_stops_loop(self):
        playbook = self._create_playbook()
        try:
            client = FakeApiClient([FakeResponse(stop_reason="end_turn")])
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                findings, tokens, iterations, duration = run_scan(
                    target="http://example.com",
                    playbook_path=playbook,
                    token_limit=100_000,
                    client=client,
                )
            finally:
                sys.stdout = old_stdout
            self.assertEqual(findings, [])
            self.assertGreater(tokens, 0)
            self.assertEqual(iterations, 1)
            self.assertGreaterEqual(duration, 0.0)
        finally:
            os.unlink(playbook)

    def test_tool_use_then_end_turn(self):
        playbook = self._create_playbook()
        try:
            tool_response = FakeResponse(
                stop_reason="tool_use",
                content=[
                    make_text_block("Testing..."),
                    make_tool_use_block(
                        "report_pass", {"test_category": "SQLi", "details": "Safe"}
                    ),
                ],
            )
            end_response = FakeResponse(stop_reason="end_turn")
            client = FakeApiClient([tool_response, end_response])

            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                findings, tokens, iterations, duration = run_scan(
                    target="http://example.com",
                    playbook_path=playbook,
                    token_limit=100_000,
                    client=client,
                )
            finally:
                sys.stdout = old_stdout
            self.assertEqual(findings, [])
            self.assertEqual(iterations, 2)
        finally:
            os.unlink(playbook)

    def test_vulnerability_reported(self):
        playbook = self._create_playbook()
        try:
            vuln_data = {
                "vulnerability_type": "XSS",
                "severity": "HIGH",
                "url": "http://example.com/xss",
                "description": "Reflected XSS",
                "evidence": "<script>alert(1)</script>",
            }
            tool_response = FakeResponse(
                stop_reason="tool_use",
                content=[make_tool_use_block("report_vulnerability", vuln_data)],
            )
            end_response = FakeResponse(stop_reason="end_turn")
            client = FakeApiClient([tool_response, end_response])

            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                findings, *_ = run_scan(
                    target="http://example.com",
                    playbook_path=playbook,
                    token_limit=100_000,
                    client=client,
                )
            finally:
                sys.stdout = old_stdout
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].get("severity"), "HIGH")
        finally:
            os.unlink(playbook)

    def test_token_limit_stops_scan(self):
        playbook = self._create_playbook()
        try:
            # Create responses that keep going with tool calls
            tool_resp = FakeResponse(
                stop_reason="tool_use",
                content=[
                    make_tool_use_block("report_pass", {"test_category": "T", "details": "ok"})
                ],
                usage=FakeUsage(input_tokens=60000, output_tokens=50000),
            )
            client = FakeApiClient([tool_resp] * 5)

            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                findings, tokens, iterations, duration = run_scan(
                    target="http://example.com",
                    playbook_path=playbook,
                    token_limit=100_000,
                    client=client,
                )
            finally:
                sys.stdout = old_stdout
            # Should have stopped due to token limit
            self.assertGreaterEqual(tokens, 100_000)
        finally:
            os.unlink(playbook)

    def test_api_returns_none_aborts(self):
        playbook = self._create_playbook()
        try:
            client = MagicMock()
            client.create.return_value = None

            # Patch call_api_with_retries to return None
            with patch("opendast.scanner.call_api_with_retries", return_value=None):
                old_stdout = sys.stdout
                sys.stdout = io.StringIO()
                try:
                    findings, tokens, iterations, duration = run_scan(
                        target="http://example.com",
                        playbook_path=playbook,
                        token_limit=100_000,
                        client=client,
                    )
                finally:
                    sys.stdout = old_stdout
            self.assertEqual(findings, [])
            self.assertEqual(tokens, 0)
            self.assertEqual(iterations, 1)
        finally:
            os.unlink(playbook)

    def test_unexpected_stop_reason_ends_scan(self):
        playbook = self._create_playbook()
        try:
            weird_response = FakeResponse(stop_reason="max_tokens")
            client = FakeApiClient([weird_response])

            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                findings, *_ = run_scan(
                    target="http://example.com",
                    playbook_path=playbook,
                    token_limit=100_000,
                    client=client,
                )
            finally:
                sys.stdout = old_stdout
            self.assertEqual(findings, [])
        finally:
            os.unlink(playbook)

    def test_http_request_tool_uses_injected_http_send(self):
        playbook = self._create_playbook()
        try:
            mock_http = MagicMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {"Content-Type": "text/html"}
            mock_resp.text = "<html>OK</html>"
            mock_http.return_value = mock_resp

            tool_response = FakeResponse(
                stop_reason="tool_use",
                content=[
                    make_tool_use_block(
                        "send_http_request",
                        {"method": "GET", "url": "http://example.com/"},
                    )
                ],
            )
            end_response = FakeResponse(stop_reason="end_turn")
            client = FakeApiClient([tool_response, end_response])

            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                run_scan(
                    target="http://example.com",
                    playbook_path=playbook,
                    token_limit=100_000,
                    client=client,
                    http_send=mock_http,
                )
            finally:
                sys.stdout = old_stdout
            mock_http.assert_called_once()
        finally:
            os.unlink(playbook)

    def test_tool_error_marked_as_error(self):
        playbook = self._create_playbook()
        try:
            tool_response = FakeResponse(
                stop_reason="tool_use",
                content=[
                    make_tool_use_block(
                        "send_http_request",
                        {},  # Missing required fields -> KeyError
                    )
                ],
            )
            end_response = FakeResponse(stop_reason="end_turn")
            client = FakeApiClient([tool_response, end_response])

            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                findings, *_ = run_scan(
                    target="http://example.com",
                    playbook_path=playbook,
                    token_limit=100_000,
                    client=client,
                )
            finally:
                sys.stdout = old_stdout
            self.assertEqual(findings, [])
        finally:
            os.unlink(playbook)

    def test_shell_run_threaded_to_dispatch(self):
        playbook = self._create_playbook()
        try:
            import subprocess

            mock_shell = MagicMock(
                return_value=subprocess.CompletedProcess(
                    args=["nmap"],
                    returncode=0,
                    stdout="80/tcp open http",
                    stderr="",
                )
            )
            tool_response = FakeResponse(
                stop_reason="tool_use",
                content=[
                    make_tool_use_block(
                        "run_nmap",
                        {"host": "example.com"},
                    )
                ],
            )
            end_response = FakeResponse(stop_reason="end_turn")
            client = FakeApiClient([tool_response, end_response])

            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                run_scan(
                    target="http://example.com",
                    playbook_path=playbook,
                    token_limit=100_000,
                    client=client,
                    shell_run=mock_shell,
                )
            finally:
                sys.stdout = old_stdout
            mock_shell.assert_called_once()
        finally:
            os.unlink(playbook)

    def test_iteration_limit_reached(self):
        playbook = self._create_playbook()
        try:
            # Create enough tool responses to hit the iteration limit
            tool_resp = FakeResponse(
                stop_reason="tool_use",
                content=[
                    make_tool_use_block("report_pass", {"test_category": "T", "details": "ok"})
                ],
                usage=FakeUsage(input_tokens=10, output_tokens=10),
            )
            client = FakeApiClient([tool_resp] * (MAX_ITERATIONS + 1))

            old_stdout = sys.stdout
            captured = io.StringIO()
            sys.stdout = captured
            try:
                findings, *_ = run_scan(
                    target="http://example.com",
                    playbook_path=playbook,
                    token_limit=1_000_000,
                    client=client,
                )
            finally:
                sys.stdout = old_stdout
            self.assertIn("Iteration limit", captured.getvalue())
        finally:
            os.unlink(playbook)

    def test_inline_playbook_content_bypasses_file(self):
        """When playbook_content is provided, no file is read."""
        client = FakeApiClient([FakeResponse(stop_reason="end_turn")])
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            with patch("opendast.scanner.load_playbook") as mock_load:
                findings, tokens, *_ = run_scan(
                    target="http://example.com",
                    playbook_path="nonexistent.md",
                    token_limit=100_000,
                    client=client,
                    playbook_content="# Inline\nTest SQLi",
                )
                mock_load.assert_not_called()
        finally:
            sys.stdout = old_stdout
        self.assertEqual(findings, [])
        self.assertGreater(tokens, 0)

    def test_empty_playbook_content_falls_back_to_file(self):
        """When playbook_content is empty, load_playbook is called."""
        playbook = self._create_playbook()
        try:
            client = FakeApiClient([FakeResponse(stop_reason="end_turn")])
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            try:
                with patch("opendast.scanner.load_playbook", return_value="# File") as mock_load:
                    run_scan(
                        target="http://example.com",
                        playbook_path=playbook,
                        token_limit=100_000,
                        client=client,
                        playbook_content="",
                    )
                    mock_load.assert_called_once_with(playbook)
            finally:
                sys.stdout = old_stdout
        finally:
            os.unlink(playbook)


class TestAnthropicClientWrapper(unittest.TestCase):
    @patch("opendast.scanner.anthropic.Anthropic")
    def test_create_delegates_to_client(self, MockAnthropic):
        mock_client = MagicMock()
        MockAnthropic.return_value = mock_client
        wrapper = AnthropicClientWrapper("sk-test")
        wrapper.create(model="test", max_tokens=10, system="sys", tools=[], messages=[])
        mock_client.messages.create.assert_called_once()


if __name__ == "__main__":
    unittest.main()
