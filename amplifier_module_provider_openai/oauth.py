"""OAuth constants and PKCE helper functions for OpenAI subscription authentication.

Implements RFC 7636 PKCE (Proof Key for Code Exchange) and defines all
OAuth/device flow endpoints for OpenAI authentication.
"""

import base64
import hashlib
import secrets

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
