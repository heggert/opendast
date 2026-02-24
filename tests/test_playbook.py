"""Tests for open_dast.playbook."""

import os
import tempfile
import unittest

from open_dast.playbook import load_playbook


class TestLoadPlaybook(unittest.TestCase):
    def test_load_existing_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write("# Test Playbook\n\nSome content")
            path = f.name
        try:
            content = load_playbook(path)
            self.assertEqual(content, "# Test Playbook\n\nSome content")
        finally:
            os.unlink(path)

    def test_file_not_found_exits(self):
        with self.assertRaises(SystemExit) as ctx:
            load_playbook("/nonexistent/path/playbook.md")
        self.assertEqual(ctx.exception.code, 2)

    def test_permission_error_exits(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            f.write("content")
            path = f.name
        try:
            os.chmod(path, 0o000)
            with self.assertRaises(SystemExit) as ctx:
                load_playbook(path)
            self.assertEqual(ctx.exception.code, 2)
        finally:
            os.chmod(path, 0o644)
            os.unlink(path)

    def test_load_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            path = f.name
        try:
            content = load_playbook(path)
            self.assertEqual(content, "")
        finally:
            os.unlink(path)

    def test_load_unicode_content(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False, encoding="utf-8"
        ) as f:
            f.write("# Playbook 🔒\n\nSécurité")
            path = f.name
        try:
            content = load_playbook(path)
            self.assertIn("🔒", content)
            self.assertIn("Sécurité", content)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
