"""HTTP request execution for security testing."""

from collections.abc import Callable

import requests as default_http

from open_dast.constants import MAX_BODY_SNIPPET, REQUEST_TIMEOUT


def execute_http_request(
    method: str,
    url: str,
    target_base: str,
    headers: dict | None = None,
    body: str | None = None,
    content_type: str | None = None,
    http_send: Callable | None = None,
    timeout: int = REQUEST_TIMEOUT,
) -> str:
    """Send an HTTP request and return a formatted response string.

    Args:
        http_send: Injectable callable matching requests.request signature.
                   Defaults to requests.request.
    """
    # Scope validation
    normalized_target = target_base.rstrip("/")
    if not url.startswith(normalized_target):
        return f"ERROR: URL '{url}' is outside the target scope '{normalized_target}'. Request blocked."

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
            allow_redirects=True,
            verify=False,
        )
    except default_http.exceptions.ConnectionError:
        return f"ERROR: Connection failed to {url}. Target may be unreachable."
    except default_http.exceptions.Timeout:
        return f"ERROR: Request to {url} timed out after {timeout}s."
    except default_http.exceptions.TooManyRedirects:
        return f"ERROR: Too many redirects for {url}."
    except default_http.exceptions.RequestException as e:
        return f"ERROR: Request failed: {e}"

    # Format response for Claude
    resp_headers = "\n".join(f"  {k}: {v}" for k, v in response.headers.items())
    body_snippet = response.text[:MAX_BODY_SNIPPET]
    if len(response.text) > MAX_BODY_SNIPPET:
        body_snippet += f"\n... [truncated, {len(response.text)} total chars]"

    return (
        f"HTTP Status: {response.status_code}\n"
        f"Response Headers:\n{resp_headers}\n"
        f"Response Body (first {MAX_BODY_SNIPPET} chars):\n{body_snippet}"
    )
