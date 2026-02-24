"""Logging utilities with ANSI color codes for CI/CD readability."""

from open_dast.constants import BOLD, CYAN, GREEN, RED, RESET


def log_vuln(msg: str) -> None:
    """Log a vulnerability finding."""
    print(f"{RED}{BOLD}[🚨 VULN]{RESET} {RED}{msg}{RESET}")


def log_info(msg: str) -> None:
    """Log an informational message."""
    print(f"{CYAN}[ℹ️  INFO]{RESET} {msg}")


def log_pass(msg: str) -> None:
    """Log a passing test result."""
    print(f"{GREEN}[✅ PASS]{RESET} {GREEN}{msg}{RESET}")
