"""Shared type definitions for OpenDAST."""

import subprocess
from collections.abc import Callable
from typing import Any, Literal, NamedTuple, NotRequired, TypedDict

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class Finding(TypedDict, total=False):
    vulnerability_type: str
    severity: Severity
    url: str
    description: str
    evidence: str
    remediation: NotRequired[str]
    request_details: NotRequired[str]


class ScanResult(NamedTuple):
    findings: list[Finding]
    token_count: int
    iterations: int
    duration: float


class ToolResult(NamedTuple):
    text: str
    is_error: bool


ArgBuilder = Callable[[dict[str, Any], str], list[str]]


class ShellToolConfig(TypedDict):
    binary: str
    scope_mode: Literal["host_only", "url_scope"]
    build_args: ArgBuilder


HttpSender = Callable[..., Any]
ShellRunner = Callable[..., subprocess.CompletedProcess[str]]
