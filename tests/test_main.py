"""Tests for main.py entry point."""

import io
import sys
import unittest
from unittest.mock import MagicMock, patch


class TestMain(unittest.TestCase):
    @patch("main.run_scan")
    @patch("main.parse_arguments")
    def test_exit_code_0_no_findings(self, mock_parse, mock_scan):
        mock_parse.return_value = MagicMock(
            target="http://example.com",
            playbook="playbook.md",
            token_limit=100_000,
            api_key="sk-test",
        )
        mock_scan.return_value = ([], 500, 3, 10.0)

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            from main import main

            code = main()
        finally:
            sys.stdout = old_stdout
        self.assertEqual(code, 0)

    @patch("main.run_scan")
    @patch("main.parse_arguments")
    def test_exit_code_1_critical_findings(self, mock_parse, mock_scan):
        mock_parse.return_value = MagicMock(
            target="http://example.com",
            playbook="playbook.md",
            token_limit=100_000,
            api_key="sk-test",
        )
        mock_scan.return_value = (
            [{"severity": "CRITICAL", "vulnerability_type": "SQLi", "url": "http://example.com"}],
            1000,
            5,
            30.0,
        )

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            from main import main

            code = main()
        finally:
            sys.stdout = old_stdout
        self.assertEqual(code, 1)

    @patch("main.run_scan")
    @patch("main.parse_arguments")
    def test_exit_code_1_medium_findings(self, mock_parse, mock_scan):
        mock_parse.return_value = MagicMock(
            target="http://example.com",
            playbook="playbook.md",
            token_limit=100_000,
            api_key="sk-test",
        )
        mock_scan.return_value = (
            [{"severity": "MEDIUM", "vulnerability_type": "XSS", "url": "http://example.com"}],
            1000,
            4,
            20.0,
        )

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            from main import main

            code = main()
        finally:
            sys.stdout = old_stdout
        self.assertEqual(code, 1)

    @patch("main.run_scan")
    @patch("main.parse_arguments")
    def test_exit_code_0_low_findings_only(self, mock_parse, mock_scan):
        mock_parse.return_value = MagicMock(
            target="http://example.com",
            playbook="playbook.md",
            token_limit=100_000,
            api_key="sk-test",
        )
        mock_scan.return_value = (
            [{"severity": "LOW", "vulnerability_type": "Info", "url": "http://example.com"}],
            500,
            2,
            8.0,
        )

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            from main import main

            code = main()
        finally:
            sys.stdout = old_stdout
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
