# 🛡️ OpenDAST: Autonomous AI Security Agent for CI/CD

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker: Ready](https://img.shields.io/badge/Docker-Lightweight-blue.svg)](#)
[![Engine: Claude Code CLI](https://img.shields.io/badge/Engine-Claude%20Code-purple.svg)](#)
[![AI: Claude](https://img.shields.io/badge/Powered%20by-Claude-black.svg)](#)

*This is NOT a static code scanner. We weaponized a developer tool to actively hack your staging environment before you deploy.*

OpenDAST is a true Black-Box Application Security Testing tool running natively inside your CI/CD pipeline. It does not scan source code. It treats your deployed application exactly like a real-world attacker would—from the outside, chaining dynamic attacks together.

### ⚡ The Differentiator: Claude Code as an Attack Engine

Most pipeline security tools are old-school static analyzers (SAST) that throw thousands of false positives.
No widely-adopted project matches our specific architecture: *We encapsulated Anthropic's official claude-code CLI tool inside a Linux Docker container and turned it into an autonomous offensive agent.*

1. **The Machine is the Attacker:** The LLM runs natively in the container environment, leveraging the Model Context Protocol (MCP) to act with system-level agency.
2. **Dynamic Planning:** Claude reads a plain-text Markdown playbook, reads the target parameters, and plans a structured attack. Defaults to Sonnet 4.6 — upgrade to Opus 4.6 (`--model claude-opus-4-6`) for the deepest attack reasoning.
3. **Execution & Chaining Exploits:** It generates specific HTTP payloads, executes them directly from the container, and feeds the live HTTP responses back into its own agentic loop. If it finds a small information leak, it uses that new knowledge to build a secondary, highly targeted payload—chaining attacks to achieve a full breach.
4. **Pipeline Integration:** All of this is packaged in a single, lightweight Docker container that fails your build (Exit Code 1) only if a real vulnerability is proven.

---

### 🧠 The Agentic Loop in Action

1. *Context:* Ingests your playbook.md (e.g., "Attempt to bypass the login using SQL Injection").
2. *Reconnaissance:* The agent probes the live application endpoints from within the Linux container.
3. *Attack Generation & Execution:* The LLM generates and fires a weaponized HTTP request.
4. *Evaluation:* The HTTP response (headers, body, status) is analyzed by Claude.
5. *Iteration:* If the attack fails or hits a WAF, the AI adapts its payload and strikes again.
6. *Verdict:* If a vulnerability is confirmed via a successful exploit (PoC), the pipeline breaks before vulnerable code reaches production.

---

### 🚀 Quick Start (Docker)

You don't need to install heavy security suites. Drop the container into your pipeline:

```bash
docker run --rm \
  -e ANTHROPIC_API_KEY="your-api-key" \
  ghcr.io/heggert/opendast:latest \
  --target "https://staging.your-app.com" \
  --token-limit 300000
```

New to OpenDAST? Follow the [**Beginner's Guide**](BEGINNERS_GUIDE.md) to set up your first scan in minutes with a simple playbook and a manual trigger.

See [`examples/`](examples/) for five CI/CD integration patterns (post-deploy gate, merge-request scan, scheduled scan, on-demand scan, release gate) with ready-to-use GitHub Actions and GitLab CI examples, plus a detailed reference of all CLI arguments, environment variables, and available tools.

### 📖 Configuration as Code (playbook.md)

Control the autonomous agent using plain English. No complex YAML syntax required.

```markdown
# OpenDAST Playbook
- Target the authentication endpoints on the provided URL.
- Attempt to bypass the login using SQL Injection techniques.
- Check if rate limiting is enforced by sending rapid requests.
- Verify if the server leaks stack traces on error 500.
```

### ⚠️ Legal Disclaimer

For authorized testing only. OpenDAST is a powerful offensive security tool. It is designed exclusively for testing environments and applications you explicitly own or have written permission to test. By weaponizing the claude-code CLI, this tool demonstrates real-world agentic attack capabilities. The authors are not responsible for any misuse or damage caused by this tool.

---

### 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
