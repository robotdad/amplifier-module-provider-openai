"""OAuth constants and PKCE helper functions for OpenAI subscription authentication.

Implements RFC 7636 PKCE (Proof Key for Code Exchange) and defines all
OAuth/device flow endpoints for OpenAI authentication.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import threading  # noqa: F401 — required by spec; run_in_executor uses threads internally
import webbrowser
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse
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
    req.add_header("User-Agent", "amplifier-openai-provider/1.0")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

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
# Authorization code exchange
# ---------------------------------------------------------------------------


async def exchange_code_for_tokens(
    *,
    code: str,
    code_verifier: str,
    redirect_uri: str,
    token_file_path: str | None = None,
) -> dict:
    """Exchange an authorization code for OAuth tokens.

    POSTs to OAUTH_TOKEN_URL with the grant_type=authorization_code flow.
    On success, persists the token dict to disk and returns it.
    Raises on failure (does not catch exceptions).

    Args:
        code: The authorization code received from the OAuth redirect.
        code_verifier: The PKCE code verifier that matches the original challenge.
        redirect_uri: The redirect URI used in the original authorization request.
        token_file_path: Destination file path for token storage. Defaults to TOKEN_FILE_PATH.

    Returns:
        Token dict with auth_mode, access_token, refresh_token, id_token, account_id,
        and expires_at.

    Raises:
        Exception: Any error from the HTTP request or response parsing propagates up.
    """
    data = urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
            "client_id": OAUTH_CLIENT_ID,
            "redirect_uri": redirect_uri,
        }
    ).encode("utf-8")

    req = Request(OAUTH_TOKEN_URL, data=data, method="POST")
    req.add_header("User-Agent", "amplifier-openai-provider/1.0")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    with urlopen(req) as response:
        token_data = json.loads(response.read())

    id_token = token_data.get("id_token", "")
    account_id = extract_account_id(id_token)

    expires_in = token_data.get("expires_in", 3600)
    expires_at = (
        datetime.now(tz=timezone.utc) + timedelta(seconds=expires_in)
    ).isoformat()

    result = {
        "auth_mode": "oauth",
        "access_token": token_data["access_token"],
        "refresh_token": token_data.get("refresh_token"),
        "id_token": id_token,
        "account_id": account_id,
        "expires_at": expires_at,
    }

    save_tokens(result, token_file_path)
    return result


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


def extract_account_id(id_token: str) -> str:
    """Decode a JWT id_token and extract the account ID.

    Decodes the JWT payload segment without signature verification (the token
    was just received over HTTPS from the issuer).  Looks for ``account_id``
    inside the ``https://api.openai.com/profile`` custom claim first; falls
    back to the standard ``sub`` claim.

    Adds base64url padding if needed before decoding.

    Args:
        id_token: A JWT string in the form ``header.payload.signature``.

    Returns:
        The account ID string, or an empty string on any failure (empty input,
        malformed JWT, missing claims, decode errors).
    """
    if not id_token:
        return ""

    try:
        parts = id_token.split(".")
        if len(parts) != 3:
            return ""

        payload_b64 = parts[1]
        # Add base64url padding so that len is a multiple of 4.
        padding_needed = (4 - len(payload_b64) % 4) % 4
        payload_b64 += "=" * padding_needed

        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes)

        # Primary: OpenAI profile custom claim.
        profile = payload.get("https://api.openai.com/profile")
        if isinstance(profile, dict):
            account_id = profile.get("account_id")
            if account_id:
                return str(account_id)

        # Fallback: standard subject claim.
        return str(payload.get("sub", ""))
    except Exception:
        return ""


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


# ---------------------------------------------------------------------------
# Device code flow
# ---------------------------------------------------------------------------


async def start_device_code_flow() -> dict:
    """Perform device code authorization flow and return authorization credentials.

    Step 1: POSTs to DEVICE_CODE_USERCODE_URL with client_id and scope to
    obtain a user_code, device_code, and polling interval.

    Step 2: Prints the verification URL and user code to the terminal so the
    user can authorize the device in a browser.

    Step 3: Polls DEVICE_CODE_TOKEN_URL until the user authorizes or an error
    occurs.  Handles these poll responses:

    - ``authorization_pending``: continue polling after sleeping *interval* seconds.
    - ``slow_down``: increase *interval* by 5 and continue polling.
    - ``expired_token``: raise :exc:`RuntimeError`.
    - any other error: raise :exc:`RuntimeError`.
    - success (no ``error`` key): return immediately.

    Returns:
        A dict with keys:

        - ``authorization_code``: the code returned by the authorization server.
        - ``code_verifier``: a freshly generated PKCE code verifier string for
          use when exchanging the authorization code for tokens.

    Raises:
        RuntimeError: If the device code expires or the server returns an
            unhandled error.
    """
    # Generate a PKCE pair; code_verifier is returned to the caller for later
    # token exchange via exchange_code_for_tokens().
    code_verifier, _ = generate_pkce_pair()

    # Step 1: Request a device code and user code from the authorization server.
    data = json.dumps(
        {
            "client_id": OAUTH_CLIENT_ID,
            "scope": OAUTH_SCOPES,
        }
    ).encode("utf-8")

    req = Request(DEVICE_CODE_USERCODE_URL, data=data, method="POST")
    req.add_header("User-Agent", "amplifier-openai-provider/1.0")
    req.add_header("Content-Type", "application/json")
    with urlopen(req) as response:
        device_data = json.loads(response.read())

    user_code: str = device_data["user_code"]
    device_code: str = device_data.get("device_code") or device_data.get("device_auth_id", "")
    interval: int = int(device_data.get("interval", DEVICE_CODE_POLL_INTERVAL))

    # Step 2: Prompt the user to authorize via their browser.
    # Use stderr so the message is visible even when the CLI UI has captured stdout.
    import sys
    print(f"\n\nOpen this URL on any device: {DEVICE_CODE_VERIFICATION_URL}", file=sys.stderr, flush=True)
    print(f"Enter code: {user_code}\n", file=sys.stderr, flush=True)
    logger.warning("OpenAI OAuth: visit %s and enter code: %s", DEVICE_CODE_VERIFICATION_URL, user_code)

    # Step 3: Poll until authorized or an error occurs.
    from urllib.error import HTTPError

    device_auth_id = device_data.get("device_auth_id", device_code)

    while True:
        await asyncio.sleep(interval)

        poll_data = json.dumps(
            {
                "client_id": OAUTH_CLIENT_ID,
                "device_auth_id": device_auth_id,
                "user_code": user_code,
            }
        ).encode("utf-8")

        poll_req = Request(DEVICE_CODE_TOKEN_URL, data=poll_data, method="POST")
        poll_req.add_header("User-Agent", "amplifier-openai-provider/1.0")
        poll_req.add_header("Content-Type", "application/json")

        try:
            with urlopen(poll_req) as response:
                result = json.loads(response.read())
            logger.warning("Device code poll success response: %s", list(result.keys()))
            # Success — return the authorization code and PKCE verifier.
            # The response may contain authorization_code (for token exchange)
            # or tokens directly (access_token, refresh_token).
            if "authorization_code" in result:
                return {
                    "authorization_code": result["authorization_code"],
                    "code_verifier": code_verifier,
                }
            else:
                # Tokens returned directly — skip the exchange step.
                return {"tokens_direct": True, **result}
        except HTTPError as e:
            body = json.loads(e.read().decode("utf-8", errors="replace"))
            error_code = body.get("error", {}).get("code", "")

            if error_code in ("deviceauth_authorization_unknown", "authorization_pending"):
                continue  # User hasn't authorized yet; sleep then retry.
            elif error_code == "slow_down":
                interval += 5
                continue
            elif error_code in ("expired_token", "deviceauth_expired"):
                raise RuntimeError("Device code expired. Please try again.")
            else:
                raise RuntimeError(f"Device code flow error: {error_code} - {body}")


# ---------------------------------------------------------------------------
# Browser-based PKCE flow
# ---------------------------------------------------------------------------


async def start_browser_flow() -> dict:
    """Perform browser-based PKCE authorization and return authorization credentials.

    Step 1: Generates a PKCE (code_verifier, code_challenge) pair.

    Step 2: Starts a local HTTP server on localhost:OAUTH_CALLBACK_PORT with a
    CallbackHandler that captures the 'code' query parameter from the OAuth
    redirect.

    Step 3: Builds the authorization URL with client_id, redirect_uri,
    response_type=code, scope, code_challenge, and code_challenge_method=S256,
    then opens it in the user's browser via webbrowser.open().

    Step 4: Waits up to 300 seconds for the browser callback via
    loop.run_in_executor(), then returns the captured code.

    Returns:
        A dict with keys:

        - ``authorization_code``: the authorization code returned by the server.
        - ``code_verifier``: the PKCE code verifier string for use when
          exchanging the authorization code for tokens.

    Raises:
        OSError: If the callback port is already in use.
        RuntimeError: If the authorization server returns an error callback or
            the 300-second wait times out.
    """
    code_verifier, code_challenge = generate_pkce_pair()

    result: dict = {}

    class CallbackHandler(BaseHTTPRequestHandler):
        """Handles a single OAuth callback GET request."""

        def do_GET(self) -> None:
            """Parse the callback URL and capture the authorization code."""
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            if "code" in params:
                result["code"] = params["code"][0]
                self.send_response(200)
                self.end_headers()
                self.wfile.write(
                    b"<html><body>"
                    b"<h1>Authorization successful!</h1>"
                    b"<p>You may close this window.</p>"
                    b"</body></html>"
                )
            elif "error" in params:
                result["error"] = params["error"][0]
                self.send_response(400)
                self.end_headers()
                self.wfile.write(
                    b"<html><body>"
                    b"<h1>Authorization error.</h1>"
                    b"<p>Please try again.</p>"
                    b"</body></html>"
                )
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h1>Invalid callback.</h1></body></html>"
                )

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            """Suppress all server request log output."""

    server = HTTPServer(("localhost", OAUTH_CALLBACK_PORT), CallbackHandler)

    auth_params = urlencode(
        {
            "client_id": OAUTH_CLIENT_ID,
            "redirect_uri": OAUTH_CALLBACK_URL,
            "response_type": "code",
            "scope": OAUTH_SCOPES,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    auth_url = f"{OAUTH_AUTHORIZE_URL}?{auth_params}"
    webbrowser.open(auth_url)

    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(None, server.handle_request),
            timeout=300,
        )
    except asyncio.TimeoutError:
        raise RuntimeError("Browser authorization timed out after 300 seconds.")
    finally:
        server.server_close()

    if "error" in result:
        raise RuntimeError(f"Authorization error: {result['error']}")

    return {
        "authorization_code": result["code"],
        "code_verifier": code_verifier,
    }


# ---------------------------------------------------------------------------
# Dual-path login orchestration
# ---------------------------------------------------------------------------


def _is_ssh_session() -> bool:
    """Detect if we're running inside an SSH session."""
    return bool(os.environ.get("SSH_CLIENT") or os.environ.get("SSH_TTY"))


async def login(*, token_file_path: str | None = None) -> dict:
    """Authenticate using browser or device code flow, whichever succeeds first.

    If running over SSH, skips the browser flow entirely and uses device code
    only (browser flow would open on the remote machine's display, not the
    user's local machine).

    On local desktop: runs both flows concurrently; whichever succeeds first
    wins and the other is cancelled.

    Args:
        token_file_path: Destination file path for token storage.
            Defaults to TOKEN_FILE_PATH.

    Returns:
        Token dict from exchange_code_for_tokens().

    Raises:
        RuntimeError: If all authentication methods fail.
    """
    # During mount(), only use device code flow. Browser flow is inappropriate
    # here — it opens a browser during session startup which blocks the UI and
    # can launch on a physical display the user isn't looking at (e.g. SSH into
    # a Pi with HDMI). Device code works everywhere: the user opens the URL on
    # any device they have handy.
    tasks: list[asyncio.Task] = [asyncio.create_task(start_device_code_flow())]

    pending: set = set(tasks)
    errors: list[str] = []

    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if task.cancelled():
                continue
            exc = task.exception()
            if exc is None:
                # Winner found — cancel all remaining tasks
                for t in pending:
                    t.cancel()
                result = task.result()

                if result.get("tokens_direct"):
                    # Device code flow returned tokens directly — save and return.
                    tokens = {
                        "auth_mode": "oauth",
                        "access_token": result.get("access_token", ""),
                        "refresh_token": result.get("refresh_token", ""),
                        "id_token": result.get("id_token", ""),
                        "account_id": extract_account_id(result.get("id_token", "")),
                        "expires_at": result.get("expires_at", ""),
                    }
                    save_tokens(tokens, token_file_path)
                    return tokens

                return await exchange_code_for_tokens(
                    code=result["authorization_code"],
                    code_verifier=result["code_verifier"],
                    redirect_uri=OAUTH_CALLBACK_URL,
                    token_file_path=token_file_path,
                )
            else:
                errors.append(str(exc))

    raise RuntimeError(f"All authentication methods failed: {'; '.join(errors)}")
