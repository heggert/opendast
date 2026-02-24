#!/usr/bin/env python3
"""Open-DAST: AI-Driven Dynamic Application Security Testing Tool — Entry Point."""

import sys

from open_dast.config import parse_arguments
from open_dast.logger import log_info, log_pass, log_vuln
from open_dast.scanner import AnthropicClientWrapper, run_scan
from open_dast.summary import print_summary


def main() -> int:
    args = parse_arguments()

    log_info("Open-DAST Security Scanner Starting")
    log_info(f"Target: {args.target}")
    log_info(f"Model: {args.model}")
    log_info(f"Playbook: {args.playbook}")
    log_info(f"Token Limit: {args.token_limit:,}")
    print()

    client = AnthropicClientWrapper(args.api_key)
    findings, token_count = run_scan(
        target=args.target,
        playbook_path=args.playbook,
        token_limit=args.token_limit,
        client=client,
        model=args.model,
    )

    print_summary(findings, args.target, f"{token_count:,}/{args.token_limit:,}")

    # Exit code: 1 if any CRITICAL/HIGH/MEDIUM findings, 0 otherwise
    has_significant = any(f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM") for f in findings)

    if has_significant:
        log_vuln(f"Scan complete. {len(findings)} finding(s). Exiting with code 1.")
        return 1
    else:
        log_pass("Scan complete. No significant vulnerabilities. Exiting with code 0.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
