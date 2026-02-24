# OpenDAST — Contributor Guide

## Project Structure

```
open_dast/
  config.py        # CLI argument parsing (argparse)
  constants.py     # ANSI codes, scan limits, default model
  http_client.py   # HTTP request execution with timeout handling
  logger.py        # Coloured stdout logging ([VULN], [INFO], [PASS])
  playbook.py      # Markdown playbook loader
  prompt.py        # System-prompt builder for the LLM
  scanner.py       # Core agentic scan loop (ApiClient protocol + DI)
  shell_tools.py   # Shell command tool execution (nmap, nikto, etc.)
  summary.py       # Scan-results summary printer
  tools.py         # Tool definitions & dispatch for the LLM tool-use API
main.py            # Entry point
playbooks/         # Example playbook files
tests/             # unittest-based test suite (mirrors open_dast/ modules)
```

## Dev Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install ruff pytest coverage detect-secrets pre-commit
pre-commit install
```

## Running Tests

```bash
# Full suite with coverage
python3 -m pytest tests/ -v --cov=open_dast --cov-report=term-missing

# Single module
python3 -m pytest tests/test_scanner.py -v
```

Target: **80-90 % line coverage** (enforced in CI at 80 %).

## Linting & Formatting

```bash
ruff check . --fix
ruff format .
```

Config lives in `pyproject.toml` (Python 3.11+, line-length 100).

## Code Standards

- **Python 3.11+**, type hints encouraged
- **unittest** only — no pytest fixtures or external test frameworks
- **Dependency Injection** — every module accepts collaborators as arguments so tests can substitute fakes/mocks
- Imports follow `isort`-style grouping (stdlib, third-party, local) — enforced by ruff `I` rules
- Logging goes to **stdout** via `open_dast.logger` (ANSI-coloured prefixes)

## Pre-commit

Hooks are defined in `.pre-commit-config.yaml`:
- trailing-whitespace, end-of-file-fixer, check-yaml, check-added-large-files
- `detect-secrets` (baseline in `.secrets.baseline`)
- `ruff check --fix` + `ruff format`

Run manually: `pre-commit run --all-files`
