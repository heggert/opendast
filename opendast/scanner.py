"""Core agentic scan loop."""

import sys
import time
from typing import Any, Protocol

import anthropic

from open_dast.constants import DEFAULT_MODEL, MAX_API_RETRIES, MAX_ITERATIONS, RED, RESET
from open_dast.logger import log_info
from open_dast.playbook import load_playbook
from open_dast.prompt import build_system_prompt
from open_dast.tools import TOOLS, dispatch_tool


class ApiClient(Protocol):
    """Protocol for the Anthropic-compatible API client."""

    def create(self, **kwargs: Any) -> Any: ...


class AnthropicClientWrapper:
    """Wraps the real Anthropic client to match our ApiClient protocol."""

    def __init__(self, api_key: str) -> None:
        self._client = anthropic.Anthropic(api_key=api_key)

    def create(self, **kwargs: Any) -> Any:
        return self._client.messages.create(**kwargs)


def call_api_with_retries(
    client: ApiClient,
    messages: list[dict],
    system_prompt: str,
    model: str = DEFAULT_MODEL,
) -> Any | None:
    """Call the Anthropic API with retry logic. Returns response or None."""
    for attempt in range(1, MAX_API_RETRIES + 1):
        try:
            response = client.create(
                model=model,
                max_tokens=4096,
                system=system_prompt,
                tools=TOOLS,
                messages=messages,
            )
            return response
        except anthropic.APIConnectionError:
            log_info(f"API connection failed (attempt {attempt}/{MAX_API_RETRIES})")
            if attempt < MAX_API_RETRIES:
                time.sleep(2**attempt)
            else:
                log_info("Could not connect to Anthropic API. Aborting scan.")
                return None
        except anthropic.RateLimitError:
            wait = 30 * attempt
            log_info(f"Rate limited. Waiting {wait}s (attempt {attempt}/{MAX_API_RETRIES})")
            time.sleep(wait)
        except anthropic.AuthenticationError:
            print(
                f"{RED}Error: Invalid Anthropic API key.{RESET}",
                file=sys.stderr,
            )
            sys.exit(2)
        except anthropic.APIStatusError as e:
            log_info(f"API error: {e.status_code} - {e.message}")
            if attempt < MAX_API_RETRIES:
                time.sleep(2**attempt)
            else:
                log_info("API errors persisted. Aborting scan.")
                return None
    return None


def run_scan(
    target: str,
    playbook_path: str,
    token_limit: int,
    client: ApiClient,
    model: str = DEFAULT_MODEL,
    http_send=None,
    shell_run=None,
) -> tuple[list[dict], int]:
    """Execute the agentic DAST scan loop.

    Args:
        target: Target URL.
        playbook_path: Path to the playbook markdown file.
        token_limit: Maximum token budget.
        client: API client implementing the ApiClient protocol.
        model: Claude model ID to use.
        http_send: Optional injectable HTTP callable for testing.
        shell_run: Optional injectable subprocess runner for testing.

    Returns:
        Tuple of (findings list, total token count).
    """
    playbook_content = load_playbook(playbook_path)
    system_prompt = build_system_prompt(target, playbook_content)

    findings: list[dict] = []
    token_count = 0
    iteration = 0

    messages = [
        {
            "role": "user",
            "content": f"Begin the DAST scan against {target}. Follow the playbook systematically.",
        }
    ]

    while iteration < MAX_ITERATIONS:
        iteration += 1
        log_info(f"Iteration {iteration}/{MAX_ITERATIONS} - Sending to Claude...")

        response = call_api_with_retries(client, messages, system_prompt, model=model)

        if response is None:
            log_info("No response from API. Aborting scan.")
            return findings, token_count

        # Track tokens
        token_count += response.usage.input_tokens + response.usage.output_tokens
        log_info(f"Token usage: {token_count:,}/{token_limit:,}")

        # Check if Claude is done (no more tool calls)
        if response.stop_reason == "end_turn":
            for block in response.content:
                if hasattr(block, "text"):
                    log_info(f"Claude: {block.text[:500]}")
            break

        # Process tool calls
        if response.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": response.content})

            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result_text, is_error = dispatch_tool(
                        block.name,
                        block.input,
                        target,
                        findings,
                        http_send=http_send,
                        shell_run=shell_run,
                    )
                    tool_result = {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result_text,
                    }
                    if is_error:
                        tool_result["is_error"] = True
                    tool_results.append(tool_result)
                elif hasattr(block, "text") and block.text:
                    log_info(f"Claude: {block.text[:300]}")

            messages.append({"role": "user", "content": tool_results})
        else:
            log_info(f"Unexpected stop reason: {response.stop_reason}. Ending scan.")
            break

        # Token limit check
        if token_count >= token_limit:
            log_info("Token limit reached. Ending scan.")
            break

    if iteration >= MAX_ITERATIONS:
        log_info(f"Iteration limit ({MAX_ITERATIONS}) reached. Ending scan.")

    return findings, token_count
