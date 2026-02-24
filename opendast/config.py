"""Argument parsing and configuration."""

import argparse
import os

from open_dast.constants import DEFAULT_MODEL, DEFAULT_TOKEN_LIMIT


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments. Pass argv for testing; None reads sys.argv."""
    parser = argparse.ArgumentParser(
        description="Open-DAST: AI-Driven Dynamic Application Security Testing Tool",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target URL of the staging application (e.g., http://staging.app.com)",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("ANTHROPIC_API_KEY", ""),
        help="Anthropic API key (default: $ANTHROPIC_API_KEY env var)",
    )
    parser.add_argument(
        "--token-limit",
        type=int,
        default=DEFAULT_TOKEN_LIMIT,
        help=f"Maximum token usage for cost control (default: {DEFAULT_TOKEN_LIMIT})",
    )
    parser.add_argument(
        "--playbook",
        default="playbooks/web_scan.md",
        help="Path to the markdown playbook file (default: playbooks/web_scan.md)",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("ANTHROPIC_MODEL", DEFAULT_MODEL),
        help=f"Claude model ID to use (default: {DEFAULT_MODEL})",
    )
    args = parser.parse_args(argv)

    if not args.target.startswith(("http://", "https://")):
        parser.error("--target must start with http:// or https://")

    if not args.api_key:
        parser.error("--api-key is required (or set ANTHROPIC_API_KEY env var)")

    return args
