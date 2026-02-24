"""Tests for opendast.http_client."""

import unittest
from unittest.mock import MagicMock

import requests

from opendast.http_client import ALLOWED_HTTP_METHODS, _is_url_in_scope, execute_http_request


class TestExecuteHttpRequest(unittest.TestCase):
    def _make_mock_response(self, status=200, headers=None, text="OK"):
        resp = MagicMock()
        resp.status_code = status
        resp.headers = headers or {"Content-Type": "text/html"}
        resp.text = text
        return resp

    def test_scope_validation_blocks_out_of_scope(self):
        result = execute_http_request(
            method="GET",
            url="http://evil.com/steal",
            target_base="http://example.com",
        )
        self.assertIn("outside the target scope", result)
        self.assertIn("ERROR", result)

    def test_scope_validation_allows_in_scope(self):
        mock_send = MagicMock(return_value=self._make_mock_response())
        result = execute_http_request(
            method="GET",
            url="http://example.com/api/v1",
            target_base="http://example.com",
            http_send=mock_send,
        )
        self.assertIn("HTTP Status: 200", result)
        mock_send.assert_called_once()

    def test_scope_validation_trailing_slash_normalization(self):
        mock_send = MagicMock(return_value=self._make_mock_response())
        result = execute_http_request(
            method="GET",
            url="http://example.com/test",
            target_base="http://example.com/",
            http_send=mock_send,
        )
        self.assertIn("HTTP Status: 200", result)

    def test_headers_forwarded(self):
        mock_send = MagicMock(return_value=self._make_mock_response())
        execute_http_request(
            method="GET",
            url="http://example.com/",
            target_base="http://example.com",
            headers={"Authorization": "Bearer token"},
            http_send=mock_send,
        )
        call_kwargs = mock_send.call_args[1]
        self.assertEqual(call_kwargs["headers"]["Authorization"], "Bearer token")

    def test_content_type_set(self):
        mock_send = MagicMock(return_value=self._make_mock_response())
        execute_http_request(
            method="POST",
            url="http://example.com/",
            target_base="http://example.com",
            content_type="application/json",
            http_send=mock_send,
        )
        call_kwargs = mock_send.call_args[1]
        self.assertEqual(call_kwargs["headers"]["Content-Type"], "application/json")

    def test_body_encoded(self):
        mock_send = MagicMock(return_value=self._make_mock_response())
        execute_http_request(
            method="POST",
            url="http://example.com/",
            target_base="http://example.com",
            body='{"key": "value"}',
            http_send=mock_send,
        )
        call_kwargs = mock_send.call_args[1]
        self.assertEqual(call_kwargs["data"], b'{"key": "value"}')

    def test_body_none_sends_none(self):
        mock_send = MagicMock(return_value=self._make_mock_response())
        execute_http_request(
            method="GET",
            url="http://example.com/",
            target_base="http://example.com",
            http_send=mock_send,
        )
        call_kwargs = mock_send.call_args[1]
        self.assertIsNone(call_kwargs["data"])

    def test_connection_error(self):
        mock_send = MagicMock(side_effect=requests.exceptions.ConnectionError())
        result = execute_http_request(
            method="GET",
            url="http://example.com/",
            target_base="http://example.com",
            http_send=mock_send,
        )
        self.assertIn("Connection failed", result)

    def test_timeout_error(self):
        mock_send = MagicMock(side_effect=requests.exceptions.Timeout())
        result = execute_http_request(
            method="GET",
            url="http://example.com/",
            target_base="http://example.com",
            http_send=mock_send,
        )
        self.assertIn("timed out", result)

    def test_allow_redirects_false(self):
        """Redirects are no longer followed automatically; TooManyRedirects cannot occur."""
        mock_send = MagicMock(return_value=self._make_mock_response())
        execute_http_request(
            method="GET",
            url="http://example.com/",
            target_base="http://example.com",
            http_send=mock_send,
        )
        call_kwargs = mock_send.call_args[1]
        self.assertFalse(call_kwargs["allow_redirects"])

    def test_generic_request_exception(self):
        mock_send = MagicMock(side_effect=requests.exceptions.RequestException("fail"))
        result = execute_http_request(
            method="GET",
            url="http://example.com/",
            target_base="http://example.com",
            http_send=mock_send,
        )
        self.assertIn("Request failed", result)

    def test_response_body_truncation(self):
        long_body = "A" * 3000
        resp = self._make_mock_response(text=long_body)
        mock_send = MagicMock(return_value=resp)
        result = execute_http_request(
            method="GET",
            url="http://example.com/",
            target_base="http://example.com",
            http_send=mock_send,
        )
        self.assertIn("truncated", result)
        self.assertIn("3000 total chars", result)

    def test_response_body_no_truncation(self):
        short_body = "A" * 100
        resp = self._make_mock_response(text=short_body)
        mock_send = MagicMock(return_value=resp)
        result = execute_http_request(
            method="GET",
            url="http://example.com/",
            target_base="http://example.com",
            http_send=mock_send,
        )
        self.assertNotIn("truncated", result)

    def test_response_headers_formatted(self):
        resp = self._make_mock_response(
            headers={"X-Custom": "value", "Server": "nginx"},
        )
        mock_send = MagicMock(return_value=resp)
        result = execute_http_request(
            method="GET",
            url="http://example.com/",
            target_base="http://example.com",
            http_send=mock_send,
        )
        self.assertIn("X-Custom: value", result)
        self.assertIn("Server: nginx", result)

    def test_custom_timeout_passed(self):
        mock_send = MagicMock(return_value=self._make_mock_response())
        execute_http_request(
            method="GET",
            url="http://example.com/",
            target_base="http://example.com",
            http_send=mock_send,
            timeout=30,
        )
        call_kwargs = mock_send.call_args[1]
        self.assertEqual(call_kwargs["timeout"], 30)

    def test_scope_blocks_credential_injection(self):
        """SSRF: http://example.com@evil.com passes startswith but not urlparse."""
        result = execute_http_request(
            method="GET",
            url="http://example.com@evil.com/path",
            target_base="http://example.com",
        )
        self.assertIn("ERROR", result)
        self.assertIn("outside the target scope", result)

    def test_scope_blocks_suffix_attack(self):
        """SSRF: http://example.com.evil.com should not match http://example.com."""
        result = execute_http_request(
            method="GET",
            url="http://example.com.evil.com/path",
            target_base="http://example.com",
        )
        self.assertIn("ERROR", result)
        self.assertIn("outside the target scope", result)

    def test_scope_blocks_scheme_mismatch(self):
        result = execute_http_request(
            method="GET",
            url="https://example.com/path",
            target_base="http://example.com",
        )
        self.assertIn("ERROR", result)
        self.assertIn("outside the target scope", result)

    def test_redirect_in_scope_flagged(self):
        """3xx redirect to an in-scope URL includes 'in scope' label."""
        resp = self._make_mock_response(
            status=302,
            headers={"Location": "http://example.com/new-path", "Content-Type": "text/html"},
            text="",
        )
        mock_send = MagicMock(return_value=resp)
        result = execute_http_request(
            method="GET",
            url="http://example.com/old",
            target_base="http://example.com",
            http_send=mock_send,
        )
        self.assertIn("HTTP Status: 302", result)
        self.assertIn("Redirect target (in scope)", result)
        # Verify allow_redirects=False was passed
        call_kwargs = mock_send.call_args[1]
        self.assertFalse(call_kwargs["allow_redirects"])

    def test_redirect_out_of_scope_not_followed(self):
        """3xx redirect to out-of-scope URL (e.g. cloud metadata) is flagged."""
        resp = self._make_mock_response(
            status=302,
            headers={
                "Location": "http://169.254.169.254/latest/meta-data/",
                "Content-Type": "text/html",
            },
            text="",
        )
        mock_send = MagicMock(return_value=resp)
        result = execute_http_request(
            method="GET",
            url="http://example.com/redir",
            target_base="http://example.com",
            http_send=mock_send,
        )
        self.assertIn("OUT OF SCOPE", result)
        self.assertIn("169.254.169.254", result)

    def test_redirect_no_location_header(self):
        resp = self._make_mock_response(
            status=301,
            headers={"Content-Type": "text/html"},
            text="",
        )
        mock_send = MagicMock(return_value=resp)
        result = execute_http_request(
            method="GET",
            url="http://example.com/redir",
            target_base="http://example.com",
            http_send=mock_send,
        )
        self.assertIn("no Location header", result)

    def test_invalid_method_blocked(self):
        result = execute_http_request(
            method="TRACE",
            url="http://example.com/",
            target_base="http://example.com",
        )
        self.assertIn("ERROR", result)
        self.assertIn("not allowed", result)

    def test_method_injection_blocked(self):
        result = execute_http_request(
            method="GET\r\nX-Injected: true",
            url="http://example.com/",
            target_base="http://example.com",
        )
        self.assertIn("ERROR", result)
        self.assertIn("not allowed", result)

    def test_all_allowed_methods_accepted(self):
        for method in ALLOWED_HTTP_METHODS:
            mock_send = MagicMock(return_value=self._make_mock_response())
            result = execute_http_request(
                method=method,
                url="http://example.com/",
                target_base="http://example.com",
                http_send=mock_send,
            )
            self.assertIn("HTTP Status: 200", result, f"Method {method} should be allowed")


class TestIsUrlInScope(unittest.TestCase):
    def test_same_host_in_scope(self):
        self.assertTrue(_is_url_in_scope("http://example.com/foo", "http://example.com"))

    def test_credential_injection_blocked(self):
        self.assertFalse(_is_url_in_scope("http://example.com@evil.com", "http://example.com"))

    def test_suffix_attack_blocked(self):
        self.assertFalse(_is_url_in_scope("http://example.com.evil.com/path", "http://example.com"))

    def test_scheme_mismatch_blocked(self):
        self.assertFalse(_is_url_in_scope("https://example.com/foo", "http://example.com"))

    def test_path_prefix_enforced(self):
        self.assertTrue(_is_url_in_scope("http://example.com/app/page", "http://example.com/app"))
        self.assertFalse(_is_url_in_scope("http://example.com/other", "http://example.com/app"))

    def test_empty_target_path(self):
        self.assertTrue(_is_url_in_scope("http://example.com/anything", "http://example.com"))


if __name__ == "__main__":
    unittest.main()
