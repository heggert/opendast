"""Tests for open_dast.config."""

import os
import unittest

from open_dast.config import parse_arguments


class TestParseArguments(unittest.TestCase):
    def test_valid_args(self):
        args = parse_arguments(
            [
                "--target",
                "http://example.com",
                "--api-key",
                "sk-test-key",
            ]
        )
        self.assertEqual(args.target, "http://example.com")
        self.assertEqual(args.api_key, "sk-test-key")
        self.assertEqual(args.token_limit, 100_000)
        self.assertEqual(args.playbook, "playbooks/web_scan.md")

    def test_https_target(self):
        args = parse_arguments(
            [
                "--target",
                "https://secure.example.com",
                "--api-key",
                "sk-test",
            ]
        )
        self.assertEqual(args.target, "https://secure.example.com")

    def test_custom_token_limit(self):
        args = parse_arguments(
            [
                "--target",
                "http://example.com",
                "--api-key",
                "sk-test",
                "--token-limit",
                "50000",
            ]
        )
        self.assertEqual(args.token_limit, 50000)

    def test_custom_playbook(self):
        args = parse_arguments(
            [
                "--target",
                "http://example.com",
                "--api-key",
                "sk-test",
                "--playbook",
                "custom.md",
            ]
        )
        self.assertEqual(args.playbook, "custom.md")

    def test_invalid_target_no_scheme(self):
        with self.assertRaises(SystemExit) as ctx:
            parse_arguments(["--target", "example.com", "--api-key", "sk-test"])
        self.assertEqual(ctx.exception.code, 2)

    def test_missing_target(self):
        with self.assertRaises(SystemExit) as ctx:
            parse_arguments(["--api-key", "sk-test"])
        self.assertEqual(ctx.exception.code, 2)

    def test_missing_api_key_no_env(self):
        env_backup = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            with self.assertRaises(SystemExit) as ctx:
                parse_arguments(["--target", "http://example.com"])
            self.assertEqual(ctx.exception.code, 2)
        finally:
            if env_backup is not None:
                os.environ["ANTHROPIC_API_KEY"] = env_backup

    def test_api_key_from_env(self):
        os.environ["ANTHROPIC_API_KEY"] = "sk-from-env"
        try:
            args = parse_arguments(["--target", "http://example.com"])
            self.assertEqual(args.api_key, "sk-from-env")
        finally:
            del os.environ["ANTHROPIC_API_KEY"]


if __name__ == "__main__":
    unittest.main()
