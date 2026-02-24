"""HTTP request execution for security testing."""

from urllib.parse import urlparse

import requests as default_http
import urllib3

from opendast.constants import MAX_BODY_SNIPPET, REQUEST_TIMEOUT
from opendast.types import HttpSender

# DAST scanners intentionally use verify=False (self-signed certs on staging).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ALLOWED_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


def _is_url_in_scope(url: str, target_base: str) -> bool:
    """Check if *url* is within the scope defined by *target_base*.

    Compares scheme, hostname, and path prefix using ``urlparse`` so that
    credential-injection attacks like ``http://target@evil.com`` are caught.
    """
    target = urlparse(target_base)
    parsed = urlparse(url)

    if parsed.scheme != target.scheme:
        return False
    if parsed.hostname != target.hostname:
        return False

    target_path = target.path.rstrip("/")
    return not target_path or parsed.path.startswith(target_path)


def execute_http_request(
    method: str,
    url: str,
    target_base: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    content_type: str | None = None,
    http_send: HttpSender | None = None,
    timeout: int = REQUEST_TIMEOUT,
) -> str:
    """Send an HTTP request and return a formatted response string.

    Args:
        http_send: Injectable callable matching requests.request signature.
                   Defaults to requests.request.
    """
    # Method validation
    if method not in ALLOWED_HTTP_METHODS:
        return f"ERROR: HTTP method '{method}' is not allowed. Use one of: {sorted(ALLOWED_HTTP_METHODS)}"

    # Scope validation
    if not _is_url_in_scope(url, target_base):
        return f"ERROR: URL '{url}' is outside the target scope '{target_base}'. Request blocked."

    send = http_send or default_http.request

    req_headers = dict(headers) if headers else {}
    if content_type:
        req_headers["Content-Type"] = content_type

    try:
        response = send(
            method=method,
            url=url,
            headers=req_headers,
            data=body.encode("utf-8") if body else None,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
        )
    except default_http.exceptions.ConnectionError:
        return f"ERROR: Connection failed to {url}. Target may be unreachable."
    except default_http.exceptions.Timeout:
        return f"ERROR: Request to {url} timed out after {timeout}s."
    except default_http.exceptions.RequestException as e:
        return f"ERROR: Request failed: {e}"

    # Format response for Claude
    resp_headers = "\n".join(f"  {k}: {v}" for k, v in response.headers.items())
    body_snippet = response.text[:MAX_BODY_SNIPPET]
    if len(response.text) > MAX_BODY_SNIPPET:
        body_snippet += f"\n... [truncated, {len(response.text)} total chars]"

    parts = [
        f"HTTP Status: {response.status_code}",
        f"Response Headers:\n{resp_headers}",
        f"Response Body (first {MAX_BODY_SNIPPET} chars):\n{body_snippet}",
    ]

    # Surface redirect information without blindly following it
    if 300 <= response.status_code < 400:
        location = response.headers.get("Location", "")
        if location:
            if _is_url_in_scope(location, target_base):
                parts.append(f"\nRedirect target (in scope): {location}")
            else:
                parts.append(f"\nRedirect target (OUT OF SCOPE — not followed): {location}")
        else:
            parts.append("\nRedirect response with no Location header.")

    return "\n".join(parts)
