"""Tool definitions and dispatch for the agentic loop."""

from typing import Any, cast

from anthropic.types import ToolParam

from opendast.http_client import execute_http_request
from opendast.logger import log_info, log_pass, log_vuln
from opendast.shell_tools import SHELL_TOOL_DEFINITIONS, SHELL_TOOL_REGISTRY, execute_shell_tool
from opendast.types import Finding, HttpSender, ShellRunner, ToolResult

TOOLS: list[ToolParam] = (
    cast(
        list[ToolParam],
        [
            {
                "name": "send_http_request",
                "description": (
                    "Send an HTTP request to the target application for security testing. "
                    "Use this to deliver attack payloads and observe the application's response. "
                    "Returns the HTTP status code, response headers, and a truncated body snippet "
                    "(max 2000 chars). Only target URLs within the scope provided in the system prompt."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "method": {
                            "type": "string",
                            "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
                            "description": "The HTTP method to use.",
                        },
                        "url": {
                            "type": "string",
                            "description": "The full URL to send the request to. Must be within the target scope.",
                        },
                        "headers": {
                            "type": "object",
                            "description": "Optional HTTP headers as key-value pairs.",
                            "additionalProperties": {"type": "string"},
                        },
                        "body": {
                            "type": "string",
                            "description": "Optional request body for POST/PUT/PATCH requests.",
                        },
                        "content_type": {
                            "type": "string",
                            "description": "Content-Type header for the body (e.g., 'application/json', 'application/x-www-form-urlencoded').",
                        },
                    },
                    "required": ["method", "url"],
                },
            },
            {
                "name": "report_vulnerability",
                "description": (
                    "Report a confirmed security vulnerability. You MUST only call this when you "
                    "have concrete evidence in the HTTP response (e.g., SQL error messages, reflected "
                    "XSS payload in body, unauthorized data access). The 'evidence' field must contain "
                    "the specific part of the HTTP response that proves the vulnerability."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "vulnerability_type": {
                            "type": "string",
                            "description": "Category (e.g., 'SQL Injection', 'XSS', 'Missing Security Headers').",
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                            "description": "Severity level.",
                        },
                        "url": {
                            "type": "string",
                            "description": "The URL where the vulnerability was found.",
                        },
                        "description": {
                            "type": "string",
                            "description": "Detailed description of the vulnerability and its impact.",
                        },
                        "evidence": {
                            "type": "string",
                            "description": "Concrete proof from the HTTP response that confirms this vulnerability.",
                        },
                        "request_details": {
                            "type": "string",
                            "description": "The HTTP request that triggered the vulnerability.",
                        },
                        "remediation": {
                            "type": "string",
                            "description": "Recommended fix.",
                        },
                    },
                    "required": [
                        "vulnerability_type",
                        "severity",
                        "url",
                        "description",
                        "evidence",
                    ],
                },
            },
            {
                "name": "report_pass",
                "description": (
                    "Report that a security test category passed -- the application is NOT vulnerable "
                    "to the tested attack vector. Call this when you have confirmed the application "
                    "properly defends against a specific category."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "test_category": {
                            "type": "string",
                            "description": "The test category that passed (e.g., 'SQL Injection', 'XSS').",
                        },
                        "details": {
                            "type": "string",
                            "description": "Brief explanation of what was tested and why it passed.",
                        },
                    },
                    "required": ["test_category", "details"],
                },
            },
        ],
    )
    + SHELL_TOOL_DEFINITIONS
)


def handle_report_vulnerability(vuln_data: dict[str, Any], findings: list[Finding]) -> str:
    """Record and log a vulnerability finding."""
    findings.append(cast(Finding, vuln_data))
    severity = vuln_data.get("severity", "UNKNOWN")
    vuln_type = vuln_data.get("vulnerability_type", "Unknown")
    url = vuln_data.get("url", "N/A")
    description = vuln_data.get("description", "")
    evidence = vuln_data.get("evidence", "")
    remediation = vuln_data.get("remediation", "N/A")

    log_vuln(f"{severity} - {vuln_type} at {url}")
    log_vuln(f"Description: {description[:500]}")
    log_vuln(f"Evidence: {evidence[:500]}")
    if remediation:
        log_vuln(f"Remediation: {remediation}")

    return f"Vulnerability recorded: {vuln_type} ({severity}) at {url}"


def handle_report_pass(test_category: str, details: str) -> str:
    """Record and log a passing test result."""
    log_pass(f"{test_category} - {details}")
    return f"Pass recorded: {test_category}"


def dispatch_tool(
    tool_name: str,
    tool_input: dict[str, Any],
    target_base: str,
    findings: list[Finding],
    http_send: HttpSender | None = None,
    shell_run: ShellRunner | None = None,
) -> ToolResult:
    """Dispatch a tool call. Returns ToolResult(text, is_error).

    Args:
        http_send: Injectable HTTP callable for testing. Passed through to execute_http_request.
        shell_run: Injectable subprocess runner for testing. Passed through to execute_shell_tool.
    """
    try:
        if tool_name == "send_http_request":
            log_info(f"Sending {tool_input.get('method', '?')} {tool_input.get('url', '?')}")
            text = execute_http_request(
                method=tool_input["method"],
                url=tool_input["url"],
                target_base=target_base,
                headers=tool_input.get("headers"),
                body=tool_input.get("body"),
                content_type=tool_input.get("content_type"),
                http_send=http_send,
            )
            return ToolResult(text, False)

        elif tool_name == "report_vulnerability":
            text = handle_report_vulnerability(tool_input, findings)
            return ToolResult(text, False)

        elif tool_name == "report_pass":
            text = handle_report_pass(
                tool_input.get("test_category", "Unknown"),
                tool_input.get("details", ""),
            )
            return ToolResult(text, False)

        elif tool_name in SHELL_TOOL_REGISTRY:
            text = execute_shell_tool(
                tool_name,
                tool_input,
                target_base,
                shell_run=shell_run,
            )
            return ToolResult(text, text.startswith("ERROR:"))

        else:
            return ToolResult(f"Unknown tool: {tool_name}", True)

    except KeyError as e:
        return ToolResult(f"Missing required field: {e}", True)
    except (ValueError, TypeError) as e:
        return ToolResult(f"Tool execution error: {e}", True)
    except Exception:
        return ToolResult("Tool execution error: unexpected internal error.", True)
