"""Tests for opendast __version__."""

import unittest

import opendast


class TestVersion(unittest.TestCase):
    def test_version_is_string(self):
        self.assertIsInstance(opendast.__version__, str)

    def test_version_is_semver(self):
        self.assertRegex(opendast.__version__, r"^\d+\.\d+\.\d+")

    @unittest.skipIf(
        opendast.__version__ == "0.0.0-dev",
        "package not installed (pip install . required)",
    )
    def test_version_not_fallback_when_installed(self):
        self.assertNotEqual(opendast.__version__, "0.0.0-dev")


if __name__ == "__main__":
    unittest.main()
