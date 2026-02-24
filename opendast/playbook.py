"""Playbook loading."""

import sys

from open_dast.constants import RED, RESET


def load_playbook(path: str) -> str:
    """Load a markdown playbook file and return its contents."""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        print(f"{RED}Error: Playbook file not found: {path}{RESET}", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print(f"{RED}Error: Cannot read playbook file: {path}{RESET}", file=sys.stderr)
        sys.exit(2)
