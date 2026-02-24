# Beginner's Guide: Your First OpenDAST Scan

This guide walks you through adding OpenDAST to a GitHub Actions pipeline
from scratch. By the end you will have a working DAST scan that runs after
every staging deploy **and** a manual trigger so you can run it on demand.

We use a small inline playbook and a low token limit (100k) so the first
scan is fast, cheap, and easy to understand. Everything lives in a single
YAML file — no extra files to create.

---

## Prerequisites

1. A deployed web application you own and are authorized to test
   (e.g., `https://staging.yourapp.com`).
2. An [Anthropic API key](https://console.anthropic.com/) with access to
   Claude.
3. A GitHub repository with Actions enabled.

---

## Step 1 — Store your API key

Go to your repository on GitHub:

**Settings > Secrets and variables > Actions > New repository secret**

| Name | Value |
|------|-------|
| `ANTHROPIC_API_KEY` | Your Anthropic API key (`sk-ant-...`) |

This keeps the key out of your code. The workflow reads it at runtime.

---

## Step 2 — Create the GitHub Actions workflow

Create `.github/workflows/dast-scan.yml` in your repository. This single
file contains the workflow **and** the playbook — nothing else to set up:

```yaml
name: DAST Scan

# --- Triggers ---
# 1. Automatically after your staging deploy workflow succeeds.
# 2. Manually from the Actions tab (click "Run workflow").
on:
  workflow_run:
    workflows: ["Deploy to Staging"]
    types: [completed]
  workflow_dispatch:

jobs:
  dast:
    # Only run after a successful deploy (always run for manual triggers).
    if: >
      github.event_name == 'workflow_dispatch' ||
      github.event.workflow_run.conclusion == 'success'
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/heggert/opendast:latest
      env:
        ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}

        # --- Playbook (inline) ---
        # The playbook tells the agent what to test and how to rate findings.
        # This beginner playbook covers three quick categories. Edit it
        # directly here — no extra files needed.
        OPENDAST_PLAYBOOK: |
          # Beginner Scan

          ## Scope & Rules
          - Only test the provided target URL and its subpaths.
          - Do NOT attempt destructive operations (no DELETE, no DROP TABLE).
          - Every finding MUST include proof: quote the exact request you sent
            and the response snippet that confirms the issue.

          ## Test Categories

          ### 1. Security Headers
          Send a GET request to / and check the response headers.

          Report as MEDIUM if any of these are missing:
          - Content-Security-Policy
          - X-Frame-Options
          - Strict-Transport-Security (only if the target uses HTTPS)

          Report as LOW if missing:
          - X-Content-Type-Options

          Report as LOW if present and leaking version info:
          - Server (e.g., "Apache/2.4.51" is bad, "Apache" alone is fine)
          - X-Powered-By (should not be present at all)

          ### 2. Information Disclosure
          Send a GET request to each of these paths:
          - /.env
          - /.git/config
          - /server-status

          If any returns HTTP 200 with recognizable content (credentials,
          git config, server metrics), report as CRITICAL.
          If all return 404 or 403, report this category as PASS.

          ### 3. Error Handling
          Send a GET request to a non-existent path like /opendast-test-404.

          Check the error page for:
          - Stack traces or file paths (report as MEDIUM)
          - Framework or database version strings (report as LOW)
          - A generic error page with no technical details (PASS)

    steps:
      - name: Run OpenDAST
        run: >
          python main.py
          --target "https://staging.yourapp.com"
          --token-limit 100000
```

Replace `https://staging.yourapp.com` with your actual staging URL, and
rename `"Deploy to Staging"` to match your deploy workflow's `name:` field.

### Understanding the playbook

The playbook is passed inline via the `OPENDAST_PLAYBOOK` environment
variable. It is plain markdown that tells the AI agent what to test:

- **Scope & Rules** — boundaries so the agent stays safe (no destructive
  operations, proof required for every finding).
- **Security Headers** — a single GET request checks whether standard
  protection headers are present.
- **Information Disclosure** — probes three common paths where credentials
  or config files are accidentally exposed.
- **Error Handling** — hits a non-existent path to see if the error page
  leaks internal details.

Three focused categories keep the scan fast and well within the 100k token
budget. The default playbook (`playbooks/web_scan.md`) covers six categories
including SQL injection and XSS, but uses more tokens. Start here, scale up
later.

### What each part of the workflow does

| Line | Purpose |
|------|---------|
| `workflow_run` | Fires after the named deploy workflow finishes. |
| `workflow_dispatch` | Adds a "Run workflow" button in the Actions tab. |
| `if: ... conclusion == 'success'` | Skips the scan if the deploy failed. Manual runs always pass this check. |
| `image: ghcr.io/heggert/opendast:latest` | Runs the job inside the OpenDAST container (all tools pre-installed). |
| `OPENDAST_PLAYBOOK: \|` | Passes the playbook as an inline environment variable — no files to mount. |
| `--token-limit 100000` | Soft-caps the scan at ~100k tokens (actual usage may slightly exceed). Enough for the beginner playbook. |

---

## Step 3 — Run it

**Automatic:** Push to your main branch and let your deploy workflow run.
After the deploy succeeds, the DAST scan starts automatically.

**Manual:** Go to **Actions > DAST Scan > Run workflow** and click the
green button.

---

## Step 4 — Read the results

The scan output appears in the GitHub Actions job log. You will see:

- Which test categories the agent ran
- The exact HTTP requests it sent
- Findings with severity, evidence, and proof-of-concept
- A final summary of all results

### Exit codes

| Code | Meaning | Pipeline effect |
|------|---------|-----------------|
| `0` | No CRITICAL, HIGH, or MEDIUM findings | Job passes (green check) |
| `1` | At least one CRITICAL, HIGH, or MEDIUM finding | Job fails (red X) |
| `2` | Configuration error (bad URL, missing API key) | Job fails (red X) |

LOW and INFO findings are reported but do not fail the pipeline.

---

## What to try next

**Increase coverage:** Switch to the full default playbook by removing the
`OPENDAST_PLAYBOOK` environment variable from your workflow. The container
ships with `playbooks/web_scan.md` which covers SQL injection, XSS,
authentication testing, and more.

**Increase the token budget:** Bump `--token-limit` to `300000` or `500000`
for deeper scans. The default playbook typically uses 300k--500k tokens for
a standard web application, and up to 1M for large attack surfaces. See
[examples/README.md](examples/README.md#token-limits--model-selection) for
detailed guidance.

**Try a different model:** OpenDAST defaults to Claude Haiku 4.5, which is
the cheapest and fastest option. For the best attack reasoning and
exploit-chaining, set `ANTHROPIC_MODEL=claude-opus-4-6` (higher cost per
token but significantly more thorough). `claude-sonnet-4-6` offers a good
middle ground between capability and cost.

**Explore more patterns:** The [`examples/`](examples/) directory has
ready-to-use workflows for five integration patterns:
- [Post-deploy gate](examples/post-deploy-gate/) — block production promotion
- [Merge-request scan](examples/merge-request-scan/) — scan every PR
- [Scheduled scan](examples/scheduled-scan/) — weekly regression detection
- [On-demand scan](examples/on-demand-scan/) — manual ad-hoc assessments
- [Release gate](examples/release-gate/) — block tagged releases

**Write your own playbook:** Playbooks are plain markdown. Add test
categories for your application's specific attack surface (API endpoints,
authentication flows, file uploads). See
[examples/README.md](examples/README.md#writing-custom-playbooks) for tips.
