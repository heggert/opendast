# OpenDAST Examples & Reference

This directory contains ready-to-use CI/CD pipeline examples organized by
integration pattern, plus a complete reference for running OpenDAST in
containers.

| Folder | Pattern | Trigger | Blocks? |
|--------|---------|---------|---------|
| [post-deploy-gate/](post-deploy-gate/) | Post-Deploy Gate | After staging deploy | Yes |
| [merge-request-scan/](merge-request-scan/) | Merge Request Scan | PR/MR opened or updated | Yes |
| [scheduled-scan/](scheduled-scan/) | Scheduled Scan | Cron (weekly/nightly) | No (advisory) |
| [on-demand-scan/](on-demand-scan/) | On-Demand Scan | Manual trigger | No |
| [release-gate/](release-gate/) | Release Gate | Version tag pushed | Yes |

Each folder contains a `github-actions.yml` and a `gitlab-ci.yml` that are
self-contained and copy-paste ready.

---

## Integration Patterns

### Post-Deploy Gate

The most common pattern: run a full DAST scan **after** your staging
deployment succeeds, and block production promotion if vulnerabilities are
found. This is the last automated check before code reaches production.

The trigger is tied to your deploy workflow completing successfully. On GitHub
Actions this uses `workflow_run`; on GitLab CI it uses pipeline stage
ordering with `needs:`. The target URL is your static staging environment
(e.g., `https://staging.example.com`).

Use the full default playbook for comprehensive coverage and a token limit
of 300,000. Set `allow_failure: false` (GitLab) or let the exit code fail
the job (GitHub) to enforce the gate.

See [`post-deploy-gate/`](post-deploy-gate/) for complete examples.

### Merge Request Scan

Shift security left by scanning every pull request or merge request against
its review/preview environment. Developers get immediate feedback on
security issues introduced by their changes, before the code reaches the
main branch.

The target URL is typically a dynamic review environment
(e.g., `https://pr-42.preview.example.com`). Since these scans run
frequently, use a lightweight inline playbook focused on fast checks
(security headers, information disclosure) and a token limit of 300,000 to
keep costs reasonable per PR. The scan blocks the merge on findings.

See [`merge-request-scan/`](merge-request-scan/) for complete examples.

### Scheduled Scan

Run a full DAST scan on a recurring schedule (e.g., weekly Monday at 02:00
UTC). Results are **advisory** — they don't block anything — and surface
regressions or newly disclosed vulnerability classes over time.

This pattern is useful for continuous monitoring of staging or production
environments. Use a generous token limit (500,000) and the full default
playbook to maximize coverage. Consider volume-mounting your playbooks
directory from the repo so customizations are picked up without rebuilding
the image.

See [`scheduled-scan/`](scheduled-scan/) for complete examples.

### On-Demand Scan

Manually trigger a DAST scan with customizable target URL, token limit, and
playbook content. Useful for ad-hoc security assessments, testing new
playbooks before committing them, or scanning specific environments on
request.

On GitHub Actions, `workflow_dispatch` inputs let the user fill in target,
token limit, and inline playbook content from the Actions UI. On GitLab,
overrideable CI/CD variables serve the same purpose via the "Run pipeline"
form.

See [`on-demand-scan/`](on-demand-scan/) for complete examples.

### Release Gate

A formal release approval checkpoint: run a full DAST scan when a version
tag (`v*`) is pushed, and block the release pipeline if vulnerabilities are
found. This is the last line of defense before a tagged release is published.

The workflow typically has two jobs: deploy the release candidate to staging,
then run the DAST scan against it. Use the full default playbook and a
300,000 token limit. On GitLab, set `allow_failure: false` to enforce the
gate.

See [`release-gate/`](release-gate/) for complete examples.

---

## Playbook Delivery Methods

There are three ways to provide a playbook to OpenDAST. Choose the method
that fits your integration pattern:

**1. Default (baked into the image)**
The container ships with `playbooks/web_scan.md`. If you don't specify a
playbook, this is used automatically. Best for post-deploy gates and release
gates where comprehensive coverage is the goal.
See: [`post-deploy-gate/`](post-deploy-gate/),
[`release-gate/`](release-gate/).

**2. Inline via `OPENDAST_PLAYBOOK` environment variable**
Pass playbook markdown directly as an environment variable. Best for
merge-request scans and on-demand scans where you want a lightweight,
pipeline-specific playbook without managing files.
See: [`merge-request-scan/`](merge-request-scan/),
[`on-demand-scan/`](on-demand-scan/).

**3. File via volume mount**
Check out your repo, then volume-mount the playbooks directory into the
container with `-v`. Best for scheduled scans where you want to customize
the playbook in your repo without rebuilding the image.
See: [`scheduled-scan/`](scheduled-scan/).

**Precedence:** `--playbook-content` CLI arg > `OPENDAST_PLAYBOOK` env var
> `--playbook` file path.

---

## Token Limits & Model Selection

### Recommended token limits

The `--token-limit` flag sets a soft cap on how many tokens the agent can
consume during a scan. Actual usage may slightly exceed the limit because
the check happens between iterations. A standard scan with the default
playbook typically uses between 300k and 500k tokens. More detailed or
broader-scoped scans (e.g., large attack surfaces, extended playbooks with
many test categories) can consume around 1M tokens.

| Scope | Token Limit | Use Case |
|-------|-------------|----------|
| 300,000 | Narrow | Focused scans: security headers, info disclosure, single feature |
| 500,000 | Standard | Full default playbook against a typical web application |
| 1,000,000 | Deep | Extended playbooks, large attack surfaces, thorough coverage |

Start with `--token-limit 300000` and increase if the agent runs out of
budget before completing all test categories. The agent will stop
gracefully when the limit is reached, reporting whatever findings it has
gathered so far.

### Model selection

OpenDAST defaults to **Claude Sonnet 4.6** (`claude-sonnet-4-6`) for a good
balance of capability and cost. For the best attack reasoning and
exploit-chaining capabilities, set `ANTHROPIC_MODEL=claude-opus-4-6` or
pass `--model claude-opus-4-6`.

| Model | ID | Trade-off |
|-------|-----|-----------|
| **Opus 4.6** | `claude-opus-4-6` | Best reasoning and exploit chaining. Higher cost per token. Recommended for release gates and deep scans. |
| **Sonnet 4.6** (default) | `claude-sonnet-4-6` | Good balance of capability and cost. Suitable for routine scans. |
| **Haiku 4.5** | `claude-haiku-4-5-20251001` | Cheapest and fastest. Good for focused playbooks and high-frequency scans. |

Opus delivers the most thorough results — it chains exploits better and
reasons more deeply about application behavior. For high-frequency patterns
like merge-request scans, Haiku or Sonnet keeps per-PR costs low. Use Opus
for release gates, post-deploy gates, and deep scheduled scans where
thoroughness matters most.

---

## Container Image

```
ghcr.io/heggert/opendast:latest
```

Based on `python:3.13-slim`. Pre-installed security tools:

| Tool | Purpose |
|------|---------|
| nmap | Port scanning & service detection |
| nikto | Web server vulnerability scanning |
| sslyze | TLS/SSL configuration analysis |
| dig | DNS reconnaissance |
| curl | Advanced HTTP testing |

The container runs as a non-root `opendast` user. The entrypoint is
`python main.py`, so CLI arguments are passed directly after the image name.

---

## CLI Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--target` | Yes | &mdash; | Target URL (must start with `http://` or `https://`) |
| `--api-key` | No | `$ANTHROPIC_API_KEY` | Anthropic API key |
| `--token-limit` | No | `100000` | Soft token budget for cost control (actual usage may slightly exceed) |
| `--playbook` | No | `playbooks/web_scan.md` | Path to a markdown playbook file |
| `--playbook-content` | No | `$OPENDAST_PLAYBOOK` | Inline playbook markdown (takes precedence over `--playbook`) |
| `--model` | No | `$ANTHROPIC_MODEL` or `claude-sonnet-4-6` | Claude model ID |

---

## Environment Variables

| Variable | Maps to | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | `--api-key` | Anthropic API key. Required unless `--api-key` is passed. |
| `ANTHROPIC_MODEL` | `--model` | Override the default Claude model. |
| `OPENDAST_PLAYBOOK` | `--playbook-content` | Inline playbook markdown. Lets CI/CD pipelines pass scan instructions without mounting files. |

**Precedence for playbooks:**
`--playbook-content` CLI arg > `OPENDAST_PLAYBOOK` env var > `--playbook` file path

**Precedence for API key:**
`--api-key` CLI arg > `ANTHROPIC_API_KEY` env var

**Precedence for model:**
`--model` CLI arg > `ANTHROPIC_MODEL` env var > built-in default

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete &mdash; no CRITICAL, HIGH, or MEDIUM findings |
| `1` | Scan complete &mdash; at least one CRITICAL, HIGH, or MEDIUM finding |
| `2` | Configuration error (invalid target, missing API key, playbook not found) |

Use exit code 1 to fail CI/CD pipelines and block deployments when
significant vulnerabilities are detected. LOW and INFO findings do not
fail the pipeline.

---

## Scan Limits & Defaults

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_ITERATIONS` | 20 | Maximum agentic loop iterations per scan |
| `DEFAULT_TOKEN_LIMIT` | 100,000 | Default token budget (override with `--token-limit`) |
| `REQUEST_TIMEOUT` | 10 s | HTTP request timeout |
| `SHELL_TIMEOUT` | 120 s | Shell tool execution timeout |
| `MAX_API_RETRIES` | 3 | Anthropic API retry attempts on transient errors |
| `MAX_BODY_SNIPPET` | 2,000 chars | HTTP response body shown to the LLM per request |
| `MAX_SHELL_OUTPUT` | 4,000 chars | Shell tool output shown to the LLM per execution |

---

## Available Agent Tools

During a scan the LLM agent can invoke the following tools. All tools are
scope-locked to the target host/URL.

### HTTP & Reporting

| Tool | Description |
|------|-------------|
| `send_http_request` | Send an HTTP request (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS) to the target. Returns status, headers, and truncated body. Redirects are surfaced with in-scope/out-of-scope labels, not followed. |
| `report_vulnerability` | Report a confirmed vulnerability with type, severity, URL, description, evidence, and optional remediation. |
| `report_pass` | Report that a test category passed (application is not vulnerable). |

### Shell Security Tools

| Tool | Description | Scope mode |
|------|-------------|------------|
| `run_nmap` | Port scanning & service detection. Scan types: `quick`, `service_detection`, `scripts`. | host |
| `run_nikto` | Web server vulnerability scanning with optional SSL and port. | host |
| `run_sslyze` | TLS/SSL analysis (ciphers, protocols, certificate checks). | host |
| `run_dig` | DNS lookup. Record types: A, AAAA, MX, NS, TXT, CNAME, SOA, ANY. | host |
| `run_curl` | Advanced HTTP testing via curl (raw TLS, HTTP/2, custom protocols). | url |

**Scope modes:**
- **host** &mdash; tool argument must match the target hostname exactly.
- **url** &mdash; tool argument must be a URL within the target's scheme, host, and path prefix.

---

## Security Controls

OpenDAST executes HTTP requests and shell commands driven by the LLM. These
safety mechanisms are enforced at runtime:

- **URL scope** &mdash; Hostnames are compared via `urlparse()`, blocking
  suffix attacks (`target.evil.com`) and credential injection (`target@evil.com`).
- **Shell argument sanitization** &mdash; All arguments are checked against a
  metacharacter blocklist (`` ; & | ` $ ( ) { } [ ] < > ! \ ``). Commands use
  list-based `subprocess.run()`, never `shell=True`.
- **Path canonicalization** &mdash; Wordlist paths are resolved with
  `os.path.realpath()` before allowlist checking, blocking `../` traversal.
- **Header injection prevention** &mdash; `\r` and `\n` are rejected in HTTP
  header keys and values.
- **Redirects** &mdash; HTTP redirects are not followed. Redirect targets are
  surfaced to the LLM with in-scope/out-of-scope labels.
- **Output truncation** &mdash; HTTP bodies (2,000 chars) and shell output
  (4,000 chars) are truncated before reaching the LLM.
- **Error isolation** &mdash; Internal paths and stack traces are never exposed
  to the LLM. Generic error messages are returned for unexpected failures.

---

## Usage Examples

### Minimal Docker Run

```bash
docker run --rm \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  ghcr.io/heggert/opendast:latest \
  --target "https://staging.example.com" \
  --token-limit 300000
```

### Inline Playbook via Environment Variable

```bash
docker run --rm \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  -e OPENDAST_PLAYBOOK="$(cat <<'EOF'
# Quick Scan
## Scope & Rules
- Only test the provided target URL and its subpaths.
- Do NOT attempt destructive operations.

## Test Categories
### 1. Security Headers
Send GET / and check for CSP, X-Frame-Options, HSTS.

### 2. Information Disclosure
Probe /.env, /.git/config, /server-status.
EOF
)" \
  ghcr.io/heggert/opendast:latest \
  --target "https://staging.example.com" \
  --token-limit 300000
```

### Inline Playbook via CLI Argument

```bash
docker run --rm \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  ghcr.io/heggert/opendast:latest \
  --target "https://staging.example.com" \
  --token-limit 300000 \
  --playbook-content "# Scan headers only
Check CSP, X-Frame-Options, and HSTS on GET /."
```

### Custom Playbook File (Volume Mount)

```bash
docker run --rm \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  -v "$(pwd)/my-playbooks:/custom:ro" \
  ghcr.io/heggert/opendast:latest \
  --target "https://staging.example.com" \
  --token-limit 300000 \
  --playbook /custom/api_scan.md
```

### Override the Model

```bash
docker run --rm \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  -e ANTHROPIC_MODEL="claude-sonnet-4-6" \
  ghcr.io/heggert/opendast:latest \
  --target "https://staging.example.com" \
  --token-limit 300000
```

---

## Writing Custom Playbooks

Playbooks are plain markdown files. The LLM reads the playbook content and
follows the instructions to test the target. A playbook typically contains:

1. **Scope & Rules** &mdash; boundaries for the scan (e.g., no destructive
   actions, PoC requirements).
2. **Test Categories** &mdash; each category describes what to test, which
   payloads to send, and what response patterns confirm a vulnerability.
3. **Severity Ratings** &mdash; mapping of vulnerability types to severity
   levels (CRITICAL, HIGH, MEDIUM, LOW, INFO).

The default playbook (`playbooks/web_scan.md`) covers SQL Injection, XSS,
Security Headers, Authentication, Information Disclosure, and Data Leakage.
Use it as a starting point for custom playbooks.

Keep playbooks focused: a shorter, targeted playbook (e.g., "only test
headers and info disclosure") runs faster and uses fewer tokens than the
full default scan.
