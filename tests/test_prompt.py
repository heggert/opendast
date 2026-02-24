"""Tests for opendast.prompt."""

import unittest

from opendast.prompt import build_system_prompt


class TestBuildSystemPrompt(unittest.TestCase):
    def test_contains_target(self):
        prompt = build_system_prompt("http://example.com", "# Playbook")
        self.assertIn("http://example.com", prompt)

    def test_contains_playbook_content(self):
        prompt = build_system_prompt("http://example.com", "## SQL Injection\nTest params")
        self.assertIn("## SQL Injection", prompt)
        self.assertIn("Test params", prompt)

    def test_contains_critical_rules(self):
        prompt = build_system_prompt("http://test.local", "content")
        self.assertIn("CRITICAL RULES", prompt)
        self.assertIn("Do NOT perform destructive actions", prompt)

    def test_target_appears_in_scope_rule(self):
        prompt = build_system_prompt("http://staging.app.com", "playbook")
        # Target should appear in the scope restriction rule
        count = prompt.count("http://staging.app.com")
        self.assertGreaterEqual(count, 2)  # In TARGET: and in rule 1

    def test_contains_playbook_section(self):
        prompt = build_system_prompt("http://example.com", "my playbook")
        self.assertIn("PLAYBOOK:", prompt)
        self.assertIn("my playbook", prompt)

    def test_contains_shell_tools_section(self):
        prompt = build_system_prompt("http://example.com", "playbook")
        self.assertIn("SHELL SECURITY TOOLS:", prompt)
        for tool in (
            "run_nmap",
            "run_nikto",
            "run_sslyze",
            "run_dig",
            "run_curl",
        ):
            self.assertIn(tool, prompt)


if __name__ == "__main__":
    unittest.main()
