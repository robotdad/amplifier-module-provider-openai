"""OAuth constants and PKCE helper functions for OpenAI subscription authentication.

Implements RFC 7636 PKCE (Proof Key for Code Exchange) and defines all
OAuth/device flow endpoints for OpenAI authentication.
"""

import base64
import hashlib
import json
import logging
import os
import secrets

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OAuth issuer and endpoints
# ---------------------------------------------------------------------------

OAUTH_ISSUER = "https://auth.openai.com"
OAUTH_AUTHORIZE_URL = f"{OAUTH_ISSUER}/oauth/authorize"
OAUTH_TOKEN_URL = f"{OAUTH_ISSUER}/oauth/token"

# ---------------------------------------------------------------------------
# Client identity and scopes
# ---------------------------------------------------------------------------

OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
OAUTH_SCOPES = "openid profile email offline_access"

# ---------------------------------------------------------------------------
# Local callback (browser-based flow)
# ---------------------------------------------------------------------------

OAUTH_CALLBACK_PORT = 1455
OAUTH_CALLBACK_URL = f"http://localhost:{OAUTH_CALLBACK_PORT}/auth/callback"

# ---------------------------------------------------------------------------
# Device code flow endpoints
# ---------------------------------------------------------------------------

DEVICE_CODE_USERCODE_URL = f"{OAUTH_ISSUER}/api/accounts/deviceauth/usercode"
DEVICE_CODE_TOKEN_URL = f"{OAUTH_ISSUER}/api/accounts/deviceauth/token"
DEVICE_CODE_VERIFICATION_URL = f"{OAUTH_ISSUER}/codex/device"
DEVICE_CODE_POLL_INTERVAL = 5  # seconds between polling attempts

# ---------------------------------------------------------------------------
# ChatGPT Codex API
# ---------------------------------------------------------------------------

CHATGPT_CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"

# ---------------------------------------------------------------------------
# Token storage
# ---------------------------------------------------------------------------

TOKEN_FILE_PATH = "~/.amplifier/openai-oauth.json"

# ---------------------------------------------------------------------------
# Subscription-gated models
# ---------------------------------------------------------------------------

SUBSCRIPTION_MODELS = [
    "gpt-5.4",
    "gpt-5.4-pro",
    "gpt-5.4-mini",
    "gpt-5.4-nano",
    "gpt-5.3-codex",
]

# ---------------------------------------------------------------------------
# Token storage helpers
# ---------------------------------------------------------------------------


def save_tokens(tokens: dict, path: str | None = None) -> None:
    """Write tokens as JSON to disk with 0600 permissions.

    Creates parent directories if they do not exist.
    Defaults to TOKEN_FILE_PATH with ~ expansion when path is None.

    Args:
        tokens: Dictionary of token data to persist.
        path: Destination file path. Defaults to TOKEN_FILE_PATH.
    """
    if path is None:
        path = os.path.expanduser(TOKEN_FILE_PATH)

    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    with open(path, "w") as f:
        json.dump(tokens, f)

    os.chmod(path, 0o600)
    logger.debug("Tokens saved to %s", path)


def load_tokens(path: str | None = None) -> dict | None:
    """Read tokens from a JSON file on disk.

    Returns the parsed dict on success.
    Returns None if the file is missing, empty, or contains malformed JSON.

    Args:
        path: Source file path. Defaults to TOKEN_FILE_PATH.

    Returns:
        Token dict on success, None otherwise.
    """
    if path is None:
        path = os.path.expanduser(TOKEN_FILE_PATH)

    try:
        with open(path) as f:
            content = f.read()
        if not content.strip():
            return None
        return json.loads(content)
    except FileNotFoundError:
        logger.debug("Token file not found: %s", path)
        return None
    except json.JSONDecodeError:
        logger.warning("Malformed JSON in token file: %s", path)
        return None


# ---------------------------------------------------------------------------
# PKCE helpers (RFC 7636)
# ---------------------------------------------------------------------------


def generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE (code_verifier, code_challenge) pair per RFC 7636.

    The verifier is a URL-safe random string of 43–128 characters.
    The challenge is BASE64URL(SHA256(verifier)) with no padding.

    Returns:
        A (code_verifier, code_challenge) tuple, both as ASCII strings.
    """
    # secrets.token_urlsafe(32) produces 43 URL-safe characters (base64url of 32 bytes)
    code_verifier = secrets.token_urlsafe(32)

    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    return code_verifier, code_challenge
