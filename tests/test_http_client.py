"""Tests for open_dast.http_client."""

import unittest
from unittest.mock import MagicMock

import requests

from open_dast.http_client import execute_http_request


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

    def test_too_many_redirects(self):
        mock_send = MagicMock(side_effect=requests.exceptions.TooManyRedirects())
        result = execute_http_request(
            method="GET",
            url="http://example.com/",
            target_base="http://example.com",
            http_send=mock_send,
        )
        self.assertIn("Too many redirects", result)

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


if __name__ == "__main__":
    unittest.main()
