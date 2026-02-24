"""Tests for opendast.logger."""

import io
import sys
import unittest

from opendast.logger import log_info, log_pass, log_vuln


class TestLogVuln(unittest.TestCase):
    def test_output_contains_vuln_prefix(self):
        captured = io.StringIO()
        sys.stdout = captured
        try:
            log_vuln("SQL Injection found")
        finally:
            sys.stdout = sys.__stdout__
        output = captured.getvalue()
        self.assertIn("VULN", output)
        self.assertIn("SQL Injection found", output)

    def test_output_contains_ansi_red(self):
        captured = io.StringIO()
        sys.stdout = captured
        try:
            log_vuln("test")
        finally:
            sys.stdout = sys.__stdout__
        self.assertIn("\033[91m", captured.getvalue())


class TestLogInfo(unittest.TestCase):
    def test_output_contains_info_prefix(self):
        captured = io.StringIO()
        sys.stdout = captured
        try:
            log_info("Starting scan")
        finally:
            sys.stdout = sys.__stdout__
        output = captured.getvalue()
        self.assertIn("INFO", output)
        self.assertIn("Starting scan", output)

    def test_output_contains_ansi_cyan(self):
        captured = io.StringIO()
        sys.stdout = captured
        try:
            log_info("test")
        finally:
            sys.stdout = sys.__stdout__
        self.assertIn("\033[96m", captured.getvalue())


class TestLogPass(unittest.TestCase):
    def test_output_contains_pass_prefix(self):
        captured = io.StringIO()
        sys.stdout = captured
        try:
            log_pass("XSS tests passed")
        finally:
            sys.stdout = sys.__stdout__
        output = captured.getvalue()
        self.assertIn("PASS", output)
        self.assertIn("XSS tests passed", output)

    def test_output_contains_ansi_green(self):
        captured = io.StringIO()
        sys.stdout = captured
        try:
            log_pass("test")
        finally:
            sys.stdout = sys.__stdout__
        self.assertIn("\033[92m", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
