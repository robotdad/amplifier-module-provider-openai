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
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from urllib.request import Request, urlopen

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
# Token validation
# ---------------------------------------------------------------------------


def is_token_valid(tokens: dict | None) -> bool:
    """Check whether a token dict contains a valid, unexpired access token.

    Returns True only if ``tokens`` contains a non-empty ``access_token`` and
    an ``expires_at`` timestamp that is strictly in the future.

    Args:
        tokens: Token dict (typically loaded via :func:`load_tokens`) or None.

    Returns:
        True if the token exists and has not expired, False otherwise.
    """
    if tokens is None:
        return False

    if not tokens.get("access_token"):
        return False

    expires_at = tokens.get("expires_at")
    if not expires_at:
        return False

    try:
        expiry = datetime.fromisoformat(expires_at)
    except (ValueError, TypeError):
        return False

    # Treat timezone-naive datetimes as UTC.
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)

    return expiry > datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# Token refresh
# ---------------------------------------------------------------------------


async def refresh_tokens(refresh_token: str, path: str | None = None) -> dict | None:
    """Exchange a refresh token for new credentials.

    POSTs to OAUTH_TOKEN_URL with the grant_type=refresh_token flow.
    On success, persists the new token dict to disk and returns it.
    On failure, logs a warning and returns None.

    Args:
        refresh_token: The refresh token to exchange.
        path: Destination file path for token storage. Defaults to TOKEN_FILE_PATH.

    Returns:
        Token dict on success, None on failure.
    """
    data = urlencode(
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": OAUTH_CLIENT_ID,
        }
    ).encode("utf-8")

    req = Request(OAUTH_TOKEN_URL, data=data, method="POST")

    try:
        with urlopen(req) as response:
            token_data = json.loads(response.read())
    except Exception as exc:
        logger.warning("Failed to refresh tokens: %s", exc)
        return None

    # Compute expires_at from the expires_in field in the response.
    expires_in = token_data.get("expires_in", 3600)
    expires_at = (
        datetime.now(tz=timezone.utc) + timedelta(seconds=expires_in)
    ).isoformat()

    # Preserve account_id from any existing tokens stored on disk.
    existing = load_tokens(path)
    account_id = existing.get("account_id") if existing else None

    result = {
        "auth_mode": "oauth",
        "access_token": token_data["access_token"],
        "refresh_token": token_data.get("refresh_token", refresh_token),
        "id_token": token_data.get("id_token"),
        "account_id": account_id,
        "expires_at": expires_at,
    }

    save_tokens(result, path)
    return result


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
