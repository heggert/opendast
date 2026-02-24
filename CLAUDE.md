# OpenDAST — Contributor Guide

## Project Structure

- `main.py` — entry point
- `opendast/` — core library (one module per concern)
- `tests/` — unittest-based test suite (mirrors `opendast/` modules)
- `playbooks/` — default playbooks (custom playbooks via `--playbook`)

## Dev Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install .
pip install ruff pytest coverage detect-secrets pre-commit
pre-commit install
```

## Running Tests

```bash
# Full suite with coverage
python3 -m pytest tests/ -v --cov=opendast --cov-report=term-missing

# Single module
python3 -m pytest tests/test_scanner.py -v
```

Target: **80-90 % line coverage** (enforced in CI at 80 %).

## Linting & Formatting

```bash
ruff check . --fix
ruff format .
```

Config lives in `pyproject.toml` (Python 3.13+, line-length 100).

## Code Standards

- **Python 3.13+**, type hints encouraged
- **unittest** only — no pytest fixtures or external test frameworks
- **Dependency Injection** — every module accepts collaborators as arguments so tests can substitute fakes/mocks
- Imports follow `isort`-style grouping (stdlib, third-party, local) — enforced by ruff `I` rules
- Logging goes to **stdout** via `opendast.logger` (ANSI-coloured prefixes)

## Typing & Linting

Shared types live in `opendast/types.py`. This module imports nothing from
`opendast/` to avoid circular imports. All other modules import from it.

**TypedDict for structured dicts:**
- `Finding` — vulnerability findings (`total=False`, all keys optional because the LLM may omit fields; code uses `.get()` with defaults).
- `ShellToolConfig` — shell tool registry entries (`binary`, `scope_mode`, `build_args`).

**NamedTuple for return types:**
- `ScanResult` — 4-tuple from `run_scan` (findings, token_count, iterations, duration). Backward-compatible with tuple unpacking.
- `ToolResult` — 2-tuple from `dispatch_tool` (text, is_error).

**Callable aliases:**
- `HttpSender = Callable[..., Any]` and `ShellRunner = Callable[..., CompletedProcess[str]]`. Tests use `MagicMock`, so these stay as Callable aliases (not Protocols).

**Anthropic SDK types (`anthropic.types`):**
- `Message`, `MessageParam`, `ToolParam`, `ToolResultBlockParam`, `TextBlock`, `ToolUseBlock` are used in `scanner.py`, `tools.py`, and `shell_tools.py` for API-facing data.
- Content block dispatch uses `isinstance(block, ToolUseBlock)` / `isinstance(block, TextBlock)` for proper type narrowing. Tests construct real SDK `TextBlock`/`ToolUseBlock` objects (via `make_text_block`/`make_tool_use_block` helpers) to satisfy `isinstance`.
- Inline tool definitions use `cast(list[ToolParam], [...])` because pyright can't infer nested dict literals as `ToolParam`.
- LLM-supplied `dict[str, Any]` is cast to `Finding` at the boundary (`cast(Finding, vuln_data)`) since runtime validation happens upstream.

**`tool_input` stays `dict[str, Any]`** — these are LLM-supplied and validated at runtime. Per-tool-input TypedDicts would add no safety.

**Linting rules:**
- `ruff check .` must pass with zero errors before merging.
- `ruff format --check .` must report no files to reformat.
- Unused imports are errors (ruff `F401`). When moving a type alias to `types.py`, remove the old import from the source module.

## Security

OpenDAST executes HTTP requests and shell commands driven by LLM output.
Every change must be reviewed for security impact.

**Scope enforcement:**
- URL scope checks must compare parsed hostnames (`urlparse`), never string prefixes (`startswith`). String prefixes are bypassed by `http://target@evil.com` and `http://target.evil.com`.
- File-path allowlists must canonicalize with `os.path.realpath()` before checking prefixes, to block `../` traversal.

**LLM-supplied input is untrusted:**
- Validate all values from tool_input against explicit allowlists (HTTP methods, record types, aggression levels, etc.).
- Reject `\r` and `\n` in any value that ends up in HTTP headers or shell arguments.
- Truncate all LLM-supplied strings before logging (see `evidence[:500]` pattern in `tools.py`).

**Error handling:**
- Never expose internal paths, stack traces, or config details in error messages returned to the LLM. Use generic messages for unexpected exceptions.

**Network:**
- HTTP requests must use `allow_redirects=False`. Surface redirect targets to the LLM with in-scope/out-of-scope labels instead of following them blindly.
- `verify=False` is intentional (DAST scanners test staging with self-signed certs).

**Shell execution:**
- Always use list-based `subprocess.run` (never `shell=True`).
- All arguments pass through `sanitize_args` to reject shell metacharacters.

## Pre-commit

Hooks are defined in `.pre-commit-config.yaml`:
- trailing-whitespace, end-of-file-fixer, check-yaml, check-added-large-files
- `detect-secrets` (baseline in `.secrets.baseline`)
- `ruff check --fix` + `ruff format`

Run manually: `pre-commit run --all-files`
