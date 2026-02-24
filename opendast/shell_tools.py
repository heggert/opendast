"""Shell-based security tool execution for the agentic loop."""

import re
import subprocess
from collections.abc import Callable
from urllib.parse import urlparse

from open_dast.constants import MAX_SHELL_OUTPUT, SHELL_TIMEOUT
from open_dast.logger import log_info

# Type alias for the injectable subprocess runner
ShellRunner = Callable[..., subprocess.CompletedProcess]

# Characters that could enable injection even without shell=True
DANGEROUS_PATTERN = re.compile(r"[;&|`$(){}\[\]<>!\\]")


# ─── Scope Validation ────────────────────────────────────────────────────────


def validate_scope_host_only(target_base: str, host: str) -> str | None:
    """Return error string if host is not the target host, else None."""
    target_host = urlparse(target_base).hostname
    if host != target_host:
        return f"ERROR: Host '{host}' is outside target scope '{target_host}'. Blocked."
    return None


def validate_scope_url(target_base: str, url: str) -> str | None:
    """Return error string if url does not start with target_base."""
    normalized = target_base.rstrip("/")
    if not url.startswith(normalized):
        return f"ERROR: URL '{url}' is outside target scope '{normalized}'. Blocked."
    return None


# ─── Argument Sanitization ───────────────────────────────────────────────────


def sanitize_args(args: list[str]) -> str | None:
    """Return error string if any arg contains dangerous characters, else None."""
    for arg in args:
        if DANGEROUS_PATTERN.search(arg):
            return f"ERROR: Argument contains disallowed characters: '{arg}'. Blocked for safety."
    return None


# ─── Per-Tool Argument Builders ──────────────────────────────────────────────


def build_nmap_args(tool_input: dict, target_base: str) -> list[str]:
    """Build nmap command args. Only allows safe scan types."""
    host = tool_input["host"]
    ports = tool_input.get("ports", "")
    scan_type = tool_input.get("scan_type", "service_detection")

    args = []
    if scan_type == "service_detection":
        args.extend(["-sV", "--version-intensity", "2"])
    elif scan_type == "quick":
        args.extend(["-T4", "-F"])
    elif scan_type == "scripts":
        args.extend(["-sV", "--script", "default,safe"])
    else:
        args.extend(["-sV"])

    if ports:
        args.extend(["-p", ports])

    args.extend(["--max-retries", "2", "--host-timeout", "60s"])
    args.append(host)
    return args


def build_nikto_args(tool_input: dict, target_base: str) -> list[str]:
    """Build nikto command args."""
    host = tool_input["host"]
    port = tool_input.get("port", "80")
    ssl = tool_input.get("ssl", False)
    args = ["-h", host, "-p", str(port), "-maxtime", "120s"]
    if ssl:
        args.append("-ssl")
    return args


def build_sslyze_args(tool_input: dict, target_base: str) -> list[str]:
    """Build sslyze command args."""
    host = tool_input["host"]
    port = tool_input.get("port", "443")
    return [f"{host}:{port}"]


def build_dig_args(tool_input: dict, target_base: str) -> list[str]:
    """Build dig command args."""
    host = tool_input["host"]
    record_type = tool_input.get("record_type", "A")
    allowed_types = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "ANY"}
    if record_type.upper() not in allowed_types:
        raise ValueError(f"Record type '{record_type}' not allowed. Use: {allowed_types}")
    return [host, record_type.upper(), "+short"]


def build_whatweb_args(tool_input: dict, target_base: str) -> list[str]:
    """Build whatweb command args."""
    url = tool_input["url"]
    aggression = tool_input.get("aggression", "1")
    if aggression not in ("1", "2", "3"):
        aggression = "1"
    return ["-a", aggression, "--color=never", url]


def build_dirb_args(tool_input: dict, target_base: str) -> list[str]:
    """Build dirb command args."""
    url = tool_input["url"]
    wordlist = tool_input.get("wordlist", "/usr/share/dirb/wordlists/common.txt")
    if not wordlist.startswith("/usr/share/dirb/wordlists/"):
        raise ValueError("Wordlist must be in /usr/share/dirb/wordlists/")
    return [url, wordlist, "-S", "-r"]


def build_curl_args(tool_input: dict, target_base: str) -> list[str]:
    """Build curl command args."""
    url = tool_input["url"]
    method = tool_input.get("method", "GET")
    headers = tool_input.get("headers", {})
    include_headers = tool_input.get("include_headers", True)
    follow_redirects = tool_input.get("follow_redirects", True)

    args = ["-s", "--max-time", "15"]
    if include_headers:
        args.append("-i")
    if follow_redirects:
        args.append("-L")
    args.extend(["-X", method])
    for k, v in headers.items():
        args.extend(["-H", f"{k}: {v}"])
    args.append(url)
    return args


# ─── Tool Registry ───────────────────────────────────────────────────────────

SHELL_TOOL_REGISTRY: dict[str, dict] = {
    "run_nmap": {
        "binary": "nmap",
        "scope_mode": "host_only",
        "build_args": build_nmap_args,
    },
    "run_nikto": {
        "binary": "nikto",
        "scope_mode": "host_only",
        "build_args": build_nikto_args,
    },
    "run_sslyze": {
        "binary": "sslyze",
        "scope_mode": "host_only",
        "build_args": build_sslyze_args,
    },
    "run_dig": {
        "binary": "dig",
        "scope_mode": "host_only",
        "build_args": build_dig_args,
    },
    "run_whatweb": {
        "binary": "whatweb",
        "scope_mode": "url_scope",
        "build_args": build_whatweb_args,
    },
    "run_dirb": {
        "binary": "dirb",
        "scope_mode": "url_scope",
        "build_args": build_dirb_args,
    },
    "run_curl": {
        "binary": "curl",
        "scope_mode": "url_scope",
        "build_args": build_curl_args,
    },
}


# ─── Tool Definitions (Anthropic tool_use format) ────────────────────────────

SHELL_TOOL_DEFINITIONS = [
    {
        "name": "run_nmap",
        "description": (
            "Run an nmap scan against the target host for port scanning and service detection. "
            "Only the target host is allowed. Returns scan output text."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "The hostname or IP to scan. Must match the target.",
                },
                "ports": {
                    "type": "string",
                    "description": "Comma-separated port list (e.g., '80,443,8080'). Empty = default ports.",
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["quick", "service_detection", "scripts"],
                    "description": "Scan type: 'quick' (fast), 'service_detection' (version info), 'scripts' (default+safe NSE scripts).",
                },
            },
            "required": ["host"],
        },
    },
    {
        "name": "run_nikto",
        "description": (
            "Run Nikto web server scanner against the target to detect misconfigurations, "
            "default files, and known vulnerabilities. Only the target host is allowed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Target hostname. Must match the target scope.",
                },
                "port": {
                    "type": "string",
                    "description": "Target port (default: '80').",
                },
                "ssl": {
                    "type": "boolean",
                    "description": "Use SSL/TLS (default: false).",
                },
            },
            "required": ["host"],
        },
    },
    {
        "name": "run_sslyze",
        "description": (
            "Analyze TLS/SSL configuration of the target. Checks certificate validity, "
            "cipher suites, protocol versions, and common TLS misconfigurations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Target hostname. Must match the target scope.",
                },
                "port": {
                    "type": "string",
                    "description": "Target port (default: '443').",
                },
            },
            "required": ["host"],
        },
    },
    {
        "name": "run_dig",
        "description": (
            "Perform DNS lookup on the target host. Useful for discovering DNS records, "
            "subdomains, mail servers, and nameservers."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {
                    "type": "string",
                    "description": "Target hostname. Must match the target scope.",
                },
                "record_type": {
                    "type": "string",
                    "enum": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "ANY"],
                    "description": "DNS record type (default: 'A').",
                },
            },
            "required": ["host"],
        },
    },
    {
        "name": "run_whatweb",
        "description": (
            "Fingerprint web technologies on the target URL. Identifies CMS, frameworks, "
            "server software, JavaScript libraries, and other technologies."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL. Must be within the target scope.",
                },
                "aggression": {
                    "type": "string",
                    "enum": ["1", "2", "3"],
                    "description": "Aggression level: '1'=stealthy (default), '3'=aggressive.",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "run_dirb",
        "description": (
            "Brute-force directories and files on the target URL. Discovers hidden paths, "
            "admin panels, backup files, and other content not linked from the main site."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target base URL. Must be within the target scope.",
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to wordlist file (default: /usr/share/dirb/wordlists/common.txt). Must be in /usr/share/dirb/wordlists/.",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "run_curl",
        "description": (
            "Execute a curl command for advanced HTTP testing. Useful for testing specific "
            "TLS behaviors, HTTP/2, custom protocols, or when you need raw curl features "
            "not available via send_http_request."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL. Must be within the target scope.",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
                    "description": "HTTP method (default: 'GET').",
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "HTTP headers as key-value pairs.",
                },
                "include_headers": {
                    "type": "boolean",
                    "description": "Include response headers in output (default: true).",
                },
                "follow_redirects": {
                    "type": "boolean",
                    "description": "Follow HTTP redirects (default: true).",
                },
            },
            "required": ["url"],
        },
    },
]


# ─── Generic Executor ────────────────────────────────────────────────────────


def _validate_scope(config: dict, tool_input: dict, target_base: str) -> str | None:
    """Validate scope based on the tool's scope_mode."""
    scope_mode = config["scope_mode"]
    if scope_mode == "host_only":
        return validate_scope_host_only(target_base, tool_input.get("host", ""))
    elif scope_mode == "url_scope":
        return validate_scope_url(target_base, tool_input.get("url", ""))
    return None


def execute_shell_tool(
    tool_name: str,
    tool_input: dict,
    target_base: str,
    shell_run: ShellRunner | None = None,
) -> str:
    """Execute a registered shell tool with scope validation, timeout, and output truncation.

    Args:
        tool_name: Must be a key in SHELL_TOOL_REGISTRY.
        tool_input: The arguments from Claude's tool_use block.
        target_base: The --target URL for scope enforcement.
        shell_run: Injectable subprocess runner. Defaults to subprocess.run.
    """
    config = SHELL_TOOL_REGISTRY.get(tool_name)
    if config is None:
        return f"ERROR: Unknown shell tool '{tool_name}'"

    # Scope validation
    scope_error = _validate_scope(config, tool_input, target_base)
    if scope_error:
        return scope_error

    # Build the command args using the tool-specific builder
    try:
        cmd_args = config["build_args"](tool_input, target_base)
    except (ValueError, KeyError) as e:
        return f"ERROR: Invalid arguments: {e}"

    # Argument sanitization
    sanitization_error = sanitize_args(cmd_args)
    if sanitization_error:
        return sanitization_error

    runner = shell_run or subprocess.run
    full_cmd = [config["binary"]] + cmd_args

    log_info(f"Shell: {' '.join(full_cmd)}")

    try:
        result = runner(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=SHELL_TIMEOUT,
        )
    except FileNotFoundError:
        return f"ERROR: Binary '{config['binary']}' not found. Is it installed in the Docker image?"
    except subprocess.TimeoutExpired:
        return f"ERROR: Command timed out after {SHELL_TIMEOUT}s."
    except OSError as e:
        return f"ERROR: Failed to execute command: {e}"

    # Combine and truncate output
    output = result.stdout
    if result.stderr:
        output += f"\n--- stderr ---\n{result.stderr}"

    if len(output) > MAX_SHELL_OUTPUT:
        output = output[:MAX_SHELL_OUTPUT] + f"\n... [truncated, {len(output)} total chars]"

    return f"Exit code: {result.returncode}\nOutput:\n{output}"
