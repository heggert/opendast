"""Constants and configuration values."""

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Scan limits
MAX_ITERATIONS = 20
DEFAULT_TOKEN_LIMIT = 100_000
REQUEST_TIMEOUT = 10
MAX_BODY_SNIPPET = 2000
MAX_API_RETRIES = 3

# Shell tool limits
SHELL_TIMEOUT = 120
MAX_SHELL_OUTPUT = 4000

# Model (default; can be overridden via --model CLI arg)
DEFAULT_MODEL = "claude-haiku-4-5-20251001"
