#!/usr/bin/env python3
"""OpenDAST: AI-Driven Dynamic Application Security Testing Tool — Entry Point."""

import sys

from opendast import __version__
from opendast.config import parse_arguments
from opendast.logger import log_info, log_pass, log_vuln
from opendast.scanner import AnthropicClientWrapper, run_scan
from opendast.summary import print_summary


def main() -> int:
    args = parse_arguments()

    log_info(f"OpenDAST Security Scanner v{__version__}")
    log_info(f"Target: {args.target}")
    log_info(f"Model: {args.model}")
    if args.playbook_content:
        log_info("Playbook: inline content")
    else:
        log_info(f"Playbook: {args.playbook}")
    log_info(f"Token Limit: {args.token_limit:,}")
    print()

    client = AnthropicClientWrapper(args.api_key)
    findings, token_count, iterations, duration = run_scan(
        target=args.target,
        playbook_path=args.playbook,
        token_limit=args.token_limit,
        client=client,
        model=args.model,
        playbook_content=args.playbook_content,
    )

    print_summary(
        findings,
        args.target,
        f"{token_count:,}/{args.token_limit:,}",
        iterations=iterations,
        duration=duration,
    )

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
