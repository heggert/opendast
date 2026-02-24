"""Scan summary reporting."""

from opendast.constants import BOLD, GREEN, RED, RESET, YELLOW
from opendast.types import Finding


def _format_duration(seconds: float) -> str:
    """Format a duration in seconds into a human-readable string."""
    m, s = divmod(int(seconds), 60)
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def print_summary(
    findings: list[Finding],
    target: str,
    token_count: str,
    iterations: int = 0,
    duration: float = 0.0,
) -> None:
    """Print a formatted scan summary to stdout."""
    border = f"{BOLD}{'=' * 60}{RESET}"
    print(f"\n{border}")
    print(f"{BOLD}  SCAN SUMMARY{RESET}")
    print(border)
    print(f"  Target: {target}")
    print(f"  Tokens Used: {token_count}")
    print(f"  Iterations: {iterations}")
    print(f"  Duration: {_format_duration(duration)}")
    print(f"  Total Findings: {len(findings)}")

    if findings:
        print()
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            findings, key=lambda f: severity_order.get(f.get("severity", "INFO"), 5)
        )
        for f in sorted_findings:
            sev = f.get("severity", "?")
            vtype = f.get("vulnerability_type", "?")
            url = f.get("url", "?")
            color = RED if sev in ("CRITICAL", "HIGH") else YELLOW if sev == "MEDIUM" else RESET
            print(f"  {color}[{sev}]{RESET} {vtype} at {url}")
    else:
        print(f"\n  {GREEN}No vulnerabilities found.{RESET}")

    print(f"{border}\n")
