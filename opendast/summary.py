"""Scan summary reporting."""

from open_dast.constants import BOLD, GREEN, RED, RESET, YELLOW


def print_summary(findings: list[dict], target: str, token_count: str) -> None:
    """Print a formatted scan summary to stdout."""
    border = f"{BOLD}{'=' * 60}{RESET}"
    print(f"\n{border}")
    print(f"{BOLD}  SCAN SUMMARY{RESET}")
    print(border)
    print(f"  Target: {target}")
    print(f"  Tokens Used: {token_count}")
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
