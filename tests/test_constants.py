"""Tests for open_dast.constants."""

import unittest

from open_dast import constants


class TestConstants(unittest.TestCase):
    """Verify all expected constants are defined and have sane values."""

    def test_ansi_codes_are_strings(self):
        for code in (
            constants.RED,
            constants.GREEN,
            constants.YELLOW,
            constants.CYAN,
            constants.BOLD,
            constants.RESET,
        ):
            self.assertIsInstance(code, str)
            self.assertTrue(code.startswith("\033["))

    def test_max_iterations_positive(self):
        self.assertGreater(constants.MAX_ITERATIONS, 0)

    def test_default_token_limit_positive(self):
        self.assertGreater(constants.DEFAULT_TOKEN_LIMIT, 0)

    def test_request_timeout_positive(self):
        self.assertGreater(constants.REQUEST_TIMEOUT, 0)

    def test_max_body_snippet_positive(self):
        self.assertGreater(constants.MAX_BODY_SNIPPET, 0)

    def test_max_api_retries_positive(self):
        self.assertGreater(constants.MAX_API_RETRIES, 0)

    def test_default_model_is_set(self):
        self.assertIsInstance(constants.DEFAULT_MODEL, str)
        self.assertTrue(len(constants.DEFAULT_MODEL) > 0)

    def test_shell_timeout_positive(self):
        self.assertGreater(constants.SHELL_TIMEOUT, 0)

    def test_max_shell_output_positive(self):
        self.assertGreater(constants.MAX_SHELL_OUTPUT, 0)


if __name__ == "__main__":
    unittest.main()
