# OpenAI OAuth/Subscription Auth — Implementation Plan

> **Execution:** Use the subagent-driven-development workflow to implement this plan.

**Goal:** Let ChatGPT Plus/Pro subscribers use Amplifier without an API key by adding OAuth-based subscription authentication alongside the existing API key path.

**Architecture:** A new `oauth.py` module encapsulates all OAuth concerns (constants, PKCE, device code flow, browser login, token storage/refresh). The existing `__init__.py` gets thin conditionals at five touch points (`get_info()`, `mount()`, `client` property, `list_models()`, 401 handler). Both auth paths share the same SDK call paths — only client construction differs.

**Tech Stack:** Python stdlib only for OAuth (hashlib, secrets, base64, urllib, json, http.server, webbrowser, asyncio). OpenAI Python SDK for API calls. pytest + unittest.mock for tests.

**Design doc:** `docs/plans/2026-04-21-openai-oauth-subscription-auth-design.md`

---

## Important: Existing Tests Must Keep Passing

The API key path is completely untouched. At the end of each phase, run the full test suite:

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/ -v
```

Every existing test must pass. If any fail, stop and fix before proceeding.

---

## Phase 1: `oauth.py` Core Infrastructure

This phase creates the `oauth.py` module with constants, PKCE helpers, token storage (save/load/validate), and token refresh. Everything is unit-testable in isolation with mocked HTTP. No login flows yet.

---

### Task 1: Constants and PKCE Helpers

**Files:**
- Create: `amplifier_module_provider_openai/oauth.py`
- Create: `tests/test_oauth.py`

**Step 1: Write the failing tests**

Create `tests/test_oauth.py` with tests for PKCE helper functions and constants:

```python
"""Unit tests for oauth.py — constants, PKCE helpers, token storage, refresh."""

import base64
import hashlib

from amplifier_module_provider_openai.oauth import (
    CHATGPT_CODEX_BASE_URL,
    DEVICE_CODE_POLL_INTERVAL,
    DEVICE_CODE_TOKEN_URL,
    DEVICE_CODE_USERCODE_URL,
    DEVICE_CODE_VERIFICATION_URL,
    OAUTH_AUTHORIZE_URL,
    OAUTH_CALLBACK_PORT,
    OAUTH_CALLBACK_URL,
    OAUTH_CLIENT_ID,
    OAUTH_ISSUER,
    OAUTH_SCOPES,
    OAUTH_TOKEN_URL,
    SUBSCRIPTION_MODELS,
    TOKEN_FILE_PATH,
    generate_pkce_pair,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConstants:
    """All OAuth constants must be defined with correct values."""

    def test_oauth_issuer(self):
        assert OAUTH_ISSUER == "https://auth.openai.com"

    def test_authorize_url_uses_issuer(self):
        assert OAUTH_AUTHORIZE_URL == "https://auth.openai.com/oauth/authorize"

    def test_token_url_uses_issuer(self):
        assert OAUTH_TOKEN_URL == "https://auth.openai.com/oauth/token"

    def test_client_id(self):
        assert OAUTH_CLIENT_ID == "app_EMoamEEZ73f0CkXaXp7hrann"

    def test_scopes(self):
        assert OAUTH_SCOPES == "openid profile email offline_access"

    def test_callback_url(self):
        assert OAUTH_CALLBACK_URL == "http://localhost:1455/auth/callback"

    def test_callback_port(self):
        assert OAUTH_CALLBACK_PORT == 1455

    def test_device_code_usercode_url(self):
        assert DEVICE_CODE_USERCODE_URL == "https://auth.openai.com/api/accounts/deviceauth/usercode"

    def test_device_code_token_url(self):
        assert DEVICE_CODE_TOKEN_URL == "https://auth.openai.com/api/accounts/deviceauth/token"

    def test_device_code_verification_url(self):
        assert DEVICE_CODE_VERIFICATION_URL == "https://auth.openai.com/codex/device"

    def test_device_code_poll_interval(self):
        assert DEVICE_CODE_POLL_INTERVAL == 5

    def test_chatgpt_codex_base_url(self):
        assert CHATGPT_CODEX_BASE_URL == "https://chatgpt.com/backend-api/codex"

    def test_token_file_path(self):
        assert TOKEN_FILE_PATH == "~/.amplifier/openai-oauth.json"

    def test_subscription_models(self):
        assert SUBSCRIPTION_MODELS == [
            "gpt-5.4",
            "gpt-5.4-pro",
            "gpt-5.4-mini",
            "gpt-5.4-nano",
            "gpt-5.3-codex",
        ]


# ---------------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------------


class TestPKCE:
    """generate_pkce_pair() must return a valid RFC 7636 pair."""

    def test_returns_verifier_and_challenge(self):
        verifier, challenge = generate_pkce_pair()
        assert isinstance(verifier, str)
        assert isinstance(challenge, str)

    def test_verifier_length_between_43_and_128(self):
        """RFC 7636 section 4.1: verifier is 43-128 characters."""
        verifier, _ = generate_pkce_pair()
        assert 43 <= len(verifier) <= 128

    def test_verifier_is_url_safe(self):
        """Verifier must use only unreserved URI characters (A-Z, a-z, 0-9, -, ., _, ~)."""
        import re
        verifier, _ = generate_pkce_pair()
        assert re.match(r'^[A-Za-z0-9\-._~]+$', verifier)

    def test_challenge_is_sha256_of_verifier(self):
        """Challenge must be base64url(SHA256(verifier)) with no padding."""
        verifier, challenge = generate_pkce_pair()
        expected_digest = hashlib.sha256(verifier.encode("ascii")).digest()
        expected_challenge = base64.urlsafe_b64encode(expected_digest).rstrip(b"=").decode("ascii")
        assert challenge == expected_challenge

    def test_each_call_returns_unique_pair(self):
        pair1 = generate_pkce_pair()
        pair2 = generate_pkce_pair()
        assert pair1[0] != pair2[0]
        assert pair1[1] != pair2[1]
```

**Step 2: Run tests to verify they fail**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py -v
```

Expected: FAIL — `ModuleNotFoundError` or `ImportError` because `oauth.py` does not exist yet.

**Step 3: Write the implementation**

Create `amplifier_module_provider_openai/oauth.py`:

```python
"""OAuth/subscription authentication for the OpenAI provider.

Encapsulates all OAuth concerns: constants, PKCE helpers, token storage,
token refresh, and dual-path login (browser PKCE + device code).

The provider imports from this module but never touches OAuth internals.
"""

import base64
import hashlib
import secrets

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OAUTH_ISSUER = "https://auth.openai.com"
OAUTH_AUTHORIZE_URL = f"{OAUTH_ISSUER}/oauth/authorize"
OAUTH_TOKEN_URL = f"{OAUTH_ISSUER}/oauth/token"
OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
OAUTH_SCOPES = "openid profile email offline_access"
OAUTH_CALLBACK_URL = "http://localhost:1455/auth/callback"
OAUTH_CALLBACK_PORT = 1455

DEVICE_CODE_USERCODE_URL = f"{OAUTH_ISSUER}/api/accounts/deviceauth/usercode"
DEVICE_CODE_TOKEN_URL = f"{OAUTH_ISSUER}/api/accounts/deviceauth/token"
DEVICE_CODE_VERIFICATION_URL = f"{OAUTH_ISSUER}/codex/device"
DEVICE_CODE_POLL_INTERVAL = 5  # seconds

CHATGPT_CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"
TOKEN_FILE_PATH = "~/.amplifier/openai-oauth.json"

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
    """Generate a PKCE code verifier and challenge pair.

    Returns:
        (code_verifier, code_challenge) where:
        - code_verifier is a 43-128 char URL-safe random string
        - code_challenge is base64url(SHA256(code_verifier)) with no padding
    """
    # 32 random bytes -> 43 base64url characters (no padding)
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge
```

**Step 4: Run tests to verify they pass**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py -v
```

Expected: All tests PASS.

**Step 5: Run full test suite to verify no regressions**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/ -v
```

Expected: All existing tests PASS.

**Step 6: Commit**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
git add amplifier_module_provider_openai/oauth.py tests/test_oauth.py
git commit -m "feat(oauth): add constants and PKCE helpers"
```

---

### Task 2: Token Storage — Save and Load

**Files:**
- Modify: `amplifier_module_provider_openai/oauth.py`
- Modify: `tests/test_oauth.py`

**Step 1: Write the failing tests**

Add to `tests/test_oauth.py`:

```python
import json
import os
import stat

from amplifier_module_provider_openai.oauth import (
    load_tokens,
    save_tokens,
)


# ---------------------------------------------------------------------------
# Token storage
# ---------------------------------------------------------------------------


class TestSaveTokens:
    """save_tokens() writes JSON to disk with 0600 permissions."""

    def test_creates_file_with_correct_content(self, tmp_path):
        token_file = tmp_path / "openai-oauth.json"
        tokens = {
            "auth_mode": "oauth",
            "access_token": "at_123",
            "refresh_token": "rt_456",
            "id_token": "id_789",
            "account_id": "acct_abc",
            "expires_at": "2026-04-21T14:00:00Z",
        }
        save_tokens(tokens, str(token_file))
        data = json.loads(token_file.read_text())
        assert data == tokens

    def test_file_has_0600_permissions(self, tmp_path):
        token_file = tmp_path / "openai-oauth.json"
        save_tokens({"access_token": "test"}, str(token_file))
        mode = stat.S_IMODE(os.stat(str(token_file)).st_mode)
        assert mode == 0o600

    def test_creates_parent_directory_if_missing(self, tmp_path):
        nested = tmp_path / "subdir" / "openai-oauth.json"
        save_tokens({"access_token": "test"}, str(nested))
        assert nested.exists()

    def test_overwrites_existing_file(self, tmp_path):
        token_file = tmp_path / "openai-oauth.json"
        save_tokens({"access_token": "old"}, str(token_file))
        save_tokens({"access_token": "new"}, str(token_file))
        data = json.loads(token_file.read_text())
        assert data["access_token"] == "new"


class TestLoadTokens:
    """load_tokens() reads JSON from disk or returns None."""

    def test_returns_dict_for_valid_file(self, tmp_path):
        token_file = tmp_path / "openai-oauth.json"
        expected = {"access_token": "at_123", "refresh_token": "rt_456"}
        token_file.write_text(json.dumps(expected))
        result = load_tokens(str(token_file))
        assert result == expected

    def test_returns_none_for_missing_file(self, tmp_path):
        token_file = tmp_path / "nonexistent.json"
        result = load_tokens(str(token_file))
        assert result is None

    def test_returns_none_for_malformed_json(self, tmp_path):
        token_file = tmp_path / "openai-oauth.json"
        token_file.write_text("not valid json {{{")
        result = load_tokens(str(token_file))
        assert result is None

    def test_returns_none_for_empty_file(self, tmp_path):
        token_file = tmp_path / "openai-oauth.json"
        token_file.write_text("")
        result = load_tokens(str(token_file))
        assert result is None
```

**Step 2: Run tests to verify they fail**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py::TestSaveTokens tests/test_oauth.py::TestLoadTokens -v
```

Expected: FAIL — `ImportError` for `load_tokens` and `save_tokens`.

**Step 3: Write the implementation**

Add to `amplifier_module_provider_openai/oauth.py` (after the existing code):

```python
import json
import logging
import os

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Token storage
# ---------------------------------------------------------------------------


def save_tokens(tokens: dict, path: str | None = None) -> None:
    """Save tokens to a JSON file with 0600 permissions.

    Args:
        tokens: Token data to persist.
        path: File path. Defaults to TOKEN_FILE_PATH (~ expanded).
    """
    file_path = os.path.expanduser(path or TOKEN_FILE_PATH)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w") as f:
        json.dump(tokens, f, indent=2)
    os.chmod(file_path, 0o600)


def load_tokens(path: str | None = None) -> dict | None:
    """Load tokens from the JSON file.

    Returns:
        Token dict if file exists and is valid JSON, None otherwise.
    """
    file_path = os.path.expanduser(path or TOKEN_FILE_PATH)
    try:
        with open(file_path) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
        return data
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return None
```

Note: Move the `import json`, `import logging`, `import os` to the top of the file alongside the existing imports.

**Step 4: Run tests to verify they pass**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py::TestSaveTokens tests/test_oauth.py::TestLoadTokens -v
```

Expected: All tests PASS.

**Step 5: Commit**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
git add amplifier_module_provider_openai/oauth.py tests/test_oauth.py
git commit -m "feat(oauth): add token save/load with file permissions"
```

---

### Task 3: Token Validation

**Files:**
- Modify: `amplifier_module_provider_openai/oauth.py`
- Modify: `tests/test_oauth.py`

**Step 1: Write the failing tests**

Add to `tests/test_oauth.py`:

```python
from datetime import datetime, timezone, timedelta

from amplifier_module_provider_openai.oauth import is_token_valid


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------


class TestIsTokenValid:
    """is_token_valid() checks if tokens exist and are not expired."""

    def test_valid_token_not_expired(self):
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        tokens = {
            "access_token": "at_123",
            "refresh_token": "rt_456",
            "expires_at": future,
        }
        assert is_token_valid(tokens) is True

    def test_expired_token(self):
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        tokens = {
            "access_token": "at_123",
            "refresh_token": "rt_456",
            "expires_at": past,
        }
        assert is_token_valid(tokens) is False

    def test_none_tokens(self):
        assert is_token_valid(None) is False

    def test_missing_access_token(self):
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        tokens = {"refresh_token": "rt_456", "expires_at": future}
        assert is_token_valid(tokens) is False

    def test_missing_expires_at(self):
        tokens = {"access_token": "at_123", "refresh_token": "rt_456"}
        assert is_token_valid(tokens) is False

    def test_malformed_expires_at(self):
        tokens = {
            "access_token": "at_123",
            "refresh_token": "rt_456",
            "expires_at": "not-a-date",
        }
        assert is_token_valid(tokens) is False
```

**Step 2: Run tests to verify they fail**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py::TestIsTokenValid -v
```

Expected: FAIL — `ImportError` for `is_token_valid`.

**Step 3: Write the implementation**

Add to `amplifier_module_provider_openai/oauth.py`:

```python
from datetime import datetime, timezone


def is_token_valid(tokens: dict | None) -> bool:
    """Check if stored tokens exist and have not expired.

    Args:
        tokens: Token dict from load_tokens(), or None.

    Returns:
        True if tokens exist, have an access_token, and expires_at is in the future.
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
        # Ensure timezone-aware comparison
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return expiry > datetime.now(timezone.utc)
    except (ValueError, TypeError):
        return False
```

**Step 4: Run tests to verify they pass**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py::TestIsTokenValid -v
```

Expected: All tests PASS.

**Step 5: Commit**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
git add amplifier_module_provider_openai/oauth.py tests/test_oauth.py
git commit -m "feat(oauth): add token expiry validation"
```

---

### Task 4: Token Refresh

**Files:**
- Modify: `amplifier_module_provider_openai/oauth.py`
- Modify: `tests/test_oauth.py`

**Step 1: Write the failing tests**

Add to `tests/test_oauth.py`:

```python
import asyncio
from unittest.mock import patch, MagicMock

from amplifier_module_provider_openai.oauth import refresh_tokens


# ---------------------------------------------------------------------------
# Token refresh
# ---------------------------------------------------------------------------


def _mock_urlopen_response(data: dict, status: int = 200):
    """Create a mock urllib response that returns JSON data."""
    mock_response = MagicMock()
    mock_response.status = status
    mock_response.read.return_value = json.dumps(data).encode("utf-8")
    mock_response.__enter__ = MagicMock(return_value=mock_response)
    mock_response.__exit__ = MagicMock(return_value=False)
    return mock_response


class TestRefreshTokens:
    """refresh_tokens() exchanges a refresh token for new credentials."""

    def test_successful_refresh_returns_new_tokens(self, tmp_path):
        token_file = str(tmp_path / "tokens.json")
        old_tokens = {
            "access_token": "old_at",
            "refresh_token": "old_rt",
            "id_token": "old_id",
            "account_id": "acct_abc",
            "expires_at": "2026-04-21T12:00:00+00:00",
        }
        save_tokens(old_tokens, token_file)

        server_response = {
            "access_token": "new_at",
            "refresh_token": "new_rt",
            "id_token": "old_id",
            "expires_in": 3600,
        }
        mock_resp = _mock_urlopen_response(server_response)

        with patch("amplifier_module_provider_openai.oauth.urlopen", return_value=mock_resp):
            result = asyncio.run(refresh_tokens("old_rt", token_file))

        assert result["access_token"] == "new_at"
        assert result["refresh_token"] == "new_rt"
        assert "expires_at" in result
        assert result["account_id"] == "acct_abc"

    def test_refresh_saves_to_disk(self, tmp_path):
        token_file = str(tmp_path / "tokens.json")
        old_tokens = {
            "access_token": "old_at",
            "refresh_token": "old_rt",
            "account_id": "acct_abc",
            "expires_at": "2026-04-21T12:00:00+00:00",
        }
        save_tokens(old_tokens, token_file)

        server_response = {
            "access_token": "new_at",
            "refresh_token": "new_rt",
            "id_token": "old_id",
            "expires_in": 3600,
        }
        mock_resp = _mock_urlopen_response(server_response)

        with patch("amplifier_module_provider_openai.oauth.urlopen", return_value=mock_resp):
            asyncio.run(refresh_tokens("old_rt", token_file))

        saved = json.loads((tmp_path / "tokens.json").read_text())
        assert saved["access_token"] == "new_at"

    def test_refresh_sends_correct_request(self, tmp_path):
        token_file = str(tmp_path / "tokens.json")
        save_tokens({"access_token": "x", "refresh_token": "rt", "account_id": "a", "expires_at": "x"}, token_file)

        server_response = {
            "access_token": "new",
            "refresh_token": "new_rt",
            "id_token": "id",
            "expires_in": 3600,
        }
        mock_resp = _mock_urlopen_response(server_response)

        with patch("amplifier_module_provider_openai.oauth.urlopen", return_value=mock_resp) as mock_urlopen:
            asyncio.run(refresh_tokens("rt", token_file))

        # Verify the request was made to the token endpoint
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        assert OAUTH_TOKEN_URL in request.full_url
        body = request.data.decode("utf-8")
        assert "grant_type=refresh_token" in body
        assert "refresh_token=rt" in body
        assert f"client_id={OAUTH_CLIENT_ID}" in body

    def test_refresh_failure_returns_none(self, tmp_path):
        token_file = str(tmp_path / "tokens.json")
        save_tokens({"access_token": "x", "refresh_token": "rt", "account_id": "a", "expires_at": "x"}, token_file)

        with patch("amplifier_module_provider_openai.oauth.urlopen", side_effect=Exception("network error")):
            result = asyncio.run(refresh_tokens("bad_rt", token_file))

        assert result is None
```

**Step 2: Run tests to verify they fail**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py::TestRefreshTokens -v
```

Expected: FAIL — `ImportError` for `refresh_tokens`.

**Step 3: Write the implementation**

Add to `amplifier_module_provider_openai/oauth.py`:

```python
from datetime import timedelta
from urllib.request import urlopen, Request
from urllib.parse import urlencode


async def refresh_tokens(
    refresh_token: str, path: str | None = None
) -> dict | None:
    """Exchange a refresh token for new credentials.

    Posts to the OAuth token endpoint with grant_type=refresh_token.
    On success, saves new tokens to disk and returns them.

    Args:
        refresh_token: The refresh token to exchange.
        path: Token file path. Defaults to TOKEN_FILE_PATH.

    Returns:
        Updated token dict on success, None on failure.
    """
    file_path = os.path.expanduser(path or TOKEN_FILE_PATH)
    try:
        # Load existing tokens to preserve account_id
        existing = load_tokens(file_path) or {}

        body = urlencode({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": OAUTH_CLIENT_ID,
        }).encode("utf-8")

        req = Request(
            OAUTH_TOKEN_URL,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        expires_at = (
            datetime.now(timezone.utc) + timedelta(seconds=data["expires_in"])
        ).isoformat()

        tokens = {
            "auth_mode": "oauth",
            "access_token": data["access_token"],
            "refresh_token": data.get("refresh_token", refresh_token),
            "id_token": data.get("id_token", existing.get("id_token", "")),
            "account_id": existing.get("account_id", ""),
            "expires_at": expires_at,
        }
        save_tokens(tokens, file_path)
        return tokens

    except Exception:
        logger.warning("OAuth token refresh failed", exc_info=True)
        return None
```

Note: Move the `from datetime import ...`, `from urllib.request import ...`, and `from urllib.parse import ...` imports to the top of the file.

**Step 4: Run tests to verify they pass**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py::TestRefreshTokens -v
```

Expected: All tests PASS.

**Step 5: Run full test suite**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/ -v
```

Expected: All existing tests PASS.

**Step 6: Commit**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
git add amplifier_module_provider_openai/oauth.py tests/test_oauth.py
git commit -m "feat(oauth): add token refresh with disk persistence"
```

---

### Task 5: Account ID Extraction from id_token

**Files:**
- Modify: `amplifier_module_provider_openai/oauth.py`
- Modify: `tests/test_oauth.py`

The `account_id` is extracted from the JWT `id_token` claims after a token exchange. We need a helper that decodes the JWT payload (without signature verification — the token was just received over HTTPS from the issuer).

**Step 1: Write the failing tests**

Add to `tests/test_oauth.py`:

```python
from amplifier_module_provider_openai.oauth import extract_account_id


class TestExtractAccountId:
    """extract_account_id() decodes the id_token JWT to get the account ID."""

    def _make_jwt(self, payload: dict) -> str:
        """Create a fake JWT (header.payload.signature) with the given payload."""
        header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        signature = "fakesig"
        return f"{header}.{body}.{signature}"

    def test_extracts_account_id_from_claims(self):
        jwt = self._make_jwt({
            "sub": "user_123",
            "https://api.openai.com/auth": {"user_id": "user_123"},
            "https://api.openai.com/profile": {"account_id": "acct_abc123"},
        })
        result = extract_account_id(jwt)
        assert result == "acct_abc123"

    def test_falls_back_to_sub_claim(self):
        jwt = self._make_jwt({"sub": "user_456"})
        result = extract_account_id(jwt)
        assert result == "user_456"

    def test_returns_empty_string_for_invalid_jwt(self):
        result = extract_account_id("not.a.valid.jwt")
        assert result == ""

    def test_returns_empty_string_for_empty_string(self):
        result = extract_account_id("")
        assert result == ""
```

**Step 2: Run tests to verify they fail**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py::TestExtractAccountId -v
```

Expected: FAIL — `ImportError` for `extract_account_id`.

**Step 3: Write the implementation**

Add to `amplifier_module_provider_openai/oauth.py`:

```python
def extract_account_id(id_token: str) -> str:
    """Extract the account ID from an OpenAI id_token JWT.

    Decodes the JWT payload without signature verification (the token
    was just received from the issuer over HTTPS).

    Looks for account_id in the OpenAI profile claim first, then falls
    back to the standard 'sub' claim.

    Args:
        id_token: The JWT id_token string.

    Returns:
        Account ID string, or empty string if extraction fails.
    """
    if not id_token:
        return ""
    try:
        # JWT is header.payload.signature — we only need the payload
        parts = id_token.split(".")
        if len(parts) < 2:
            return ""
        # Add padding if needed (base64url requires padding to 4-byte boundary)
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        claims = json.loads(payload_bytes)

        # Try OpenAI-specific profile claim first
        profile = claims.get("https://api.openai.com/profile", {})
        if isinstance(profile, dict) and profile.get("account_id"):
            return profile["account_id"]

        # Fall back to standard sub claim
        return claims.get("sub", "")
    except Exception:
        logger.debug("Failed to extract account_id from id_token", exc_info=True)
        return ""
```

**Step 4: Run tests to verify they pass**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py::TestExtractAccountId -v
```

Expected: All tests PASS.

**Step 5: Commit**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
git add amplifier_module_provider_openai/oauth.py tests/test_oauth.py
git commit -m "feat(oauth): add JWT account_id extraction"
```

---

## Phase 1 Checkpoint

Run the full test suite to make sure nothing is broken:

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/ -v
```

All existing tests plus all new `test_oauth.py` tests must pass.

At this point `oauth.py` exports: constants, `generate_pkce_pair()`, `save_tokens()`, `load_tokens()`, `is_token_valid()`, `refresh_tokens()`, `extract_account_id()`.

---

## Phase 2: `oauth.py` Login Flows

This phase adds the device code flow, browser PKCE flow, and dual-path login orchestration. These build on the Phase 1 infrastructure.

---

### Task 6: Token Exchange Helper

Both login paths (device code and browser PKCE) end with the same token exchange step. Extract that as a shared helper first.

**Files:**
- Modify: `amplifier_module_provider_openai/oauth.py`
- Modify: `tests/test_oauth.py`

**Step 1: Write the failing tests**

Add to `tests/test_oauth.py`:

```python
from amplifier_module_provider_openai.oauth import exchange_code_for_tokens


class TestExchangeCodeForTokens:
    """exchange_code_for_tokens() POSTs an auth code to the token endpoint."""

    def test_successful_exchange_returns_tokens(self, tmp_path):
        token_file = str(tmp_path / "tokens.json")
        server_response = {
            "access_token": "at_new",
            "refresh_token": "rt_new",
            "id_token": self._make_jwt({"sub": "user_1", "https://api.openai.com/profile": {"account_id": "acct_xyz"}}),
            "expires_in": 3600,
        }
        mock_resp = _mock_urlopen_response(server_response)

        with patch("amplifier_module_provider_openai.oauth.urlopen", return_value=mock_resp):
            result = asyncio.run(
                exchange_code_for_tokens(
                    code="auth_code_123",
                    code_verifier="verifier_abc",
                    redirect_uri=OAUTH_CALLBACK_URL,
                    token_file_path=token_file,
                )
            )

        assert result["access_token"] == "at_new"
        assert result["refresh_token"] == "rt_new"
        assert result["account_id"] == "acct_xyz"
        assert "expires_at" in result

    def test_exchange_saves_to_disk(self, tmp_path):
        token_file = str(tmp_path / "tokens.json")
        server_response = {
            "access_token": "at_saved",
            "refresh_token": "rt_saved",
            "id_token": self._make_jwt({"sub": "user_1"}),
            "expires_in": 3600,
        }
        mock_resp = _mock_urlopen_response(server_response)

        with patch("amplifier_module_provider_openai.oauth.urlopen", return_value=mock_resp):
            asyncio.run(
                exchange_code_for_tokens(
                    code="code",
                    code_verifier="verifier",
                    redirect_uri=OAUTH_CALLBACK_URL,
                    token_file_path=token_file,
                )
            )

        saved = json.loads((tmp_path / "tokens.json").read_text())
        assert saved["access_token"] == "at_saved"

    def test_exchange_sends_correct_params(self, tmp_path):
        token_file = str(tmp_path / "tokens.json")
        server_response = {
            "access_token": "at",
            "refresh_token": "rt",
            "id_token": self._make_jwt({"sub": "u"}),
            "expires_in": 3600,
        }
        mock_resp = _mock_urlopen_response(server_response)

        with patch("amplifier_module_provider_openai.oauth.urlopen", return_value=mock_resp) as mock_urlopen:
            asyncio.run(
                exchange_code_for_tokens(
                    code="my_code",
                    code_verifier="my_verifier",
                    redirect_uri="http://localhost:1455/auth/callback",
                    token_file_path=token_file,
                )
            )

        request = mock_urlopen.call_args[0][0]
        body = request.data.decode("utf-8")
        assert "grant_type=authorization_code" in body
        assert "code=my_code" in body
        assert "code_verifier=my_verifier" in body
        assert f"client_id={OAUTH_CLIENT_ID}" in body
        assert "redirect_uri=" in body

    def test_exchange_failure_raises(self, tmp_path):
        token_file = str(tmp_path / "tokens.json")
        with patch("amplifier_module_provider_openai.oauth.urlopen", side_effect=Exception("fail")):
            with pytest.raises(Exception):
                asyncio.run(
                    exchange_code_for_tokens(
                        code="code",
                        code_verifier="verifier",
                        redirect_uri=OAUTH_CALLBACK_URL,
                        token_file_path=token_file,
                    )
                )

    def _make_jwt(self, payload: dict) -> str:
        header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        return f"{header}.{body}.fakesig"
```

**Step 2: Run tests to verify they fail**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py::TestExchangeCodeForTokens -v
```

Expected: FAIL — `ImportError` for `exchange_code_for_tokens`.

**Step 3: Write the implementation**

Add to `amplifier_module_provider_openai/oauth.py`:

```python
async def exchange_code_for_tokens(
    *,
    code: str,
    code_verifier: str,
    redirect_uri: str,
    token_file_path: str | None = None,
) -> dict:
    """Exchange an authorization code for tokens.

    This is the shared final step for both browser PKCE and device code flows.

    Args:
        code: The authorization code from the OAuth flow.
        code_verifier: The PKCE code verifier.
        redirect_uri: The redirect URI used in the authorization request.
        token_file_path: Path to save tokens. Defaults to TOKEN_FILE_PATH.

    Returns:
        Token dict with access_token, refresh_token, id_token, account_id, expires_at.

    Raises:
        Exception: If the token exchange fails.
    """
    file_path = os.path.expanduser(token_file_path or TOKEN_FILE_PATH)

    body = urlencode({
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": code_verifier,
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": redirect_uri,
    }).encode("utf-8")

    req = Request(
        OAUTH_TOKEN_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urlopen(req) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    id_token_str = data.get("id_token", "")
    account_id = extract_account_id(id_token_str)

    expires_at = (
        datetime.now(timezone.utc) + timedelta(seconds=data["expires_in"])
    ).isoformat()

    tokens = {
        "auth_mode": "oauth",
        "access_token": data["access_token"],
        "refresh_token": data.get("refresh_token", ""),
        "id_token": id_token_str,
        "account_id": account_id,
        "expires_at": expires_at,
    }
    save_tokens(tokens, file_path)
    return tokens
```

**Step 4: Run tests to verify they pass**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py::TestExchangeCodeForTokens -v
```

Expected: All tests PASS.

**Step 5: Commit**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
git add amplifier_module_provider_openai/oauth.py tests/test_oauth.py
git commit -m "feat(oauth): add shared token exchange helper"
```

---

### Task 7: Device Code Flow

**Files:**
- Modify: `amplifier_module_provider_openai/oauth.py`
- Modify: `tests/test_oauth.py`

**Step 1: Write the failing tests**

Add to `tests/test_oauth.py`:

```python
from amplifier_module_provider_openai.oauth import start_device_code_flow


class TestDeviceCodeFlow:
    """Device code flow: request code, poll until authorized, exchange tokens."""

    def test_requests_device_code(self):
        """start_device_code_flow() posts to the device code endpoint."""
        device_response = {
            "user_code": "ABCD-1234",
            "device_code": "dev_code_xyz",
            "verification_uri": DEVICE_CODE_VERIFICATION_URL,
            "expires_in": 900,
            "interval": 5,
        }
        # First call: device code request
        # Second call: token polling returns authorization_pending
        # Third call: token polling returns success with auth code
        poll_pending = {"error": "authorization_pending"}
        poll_success = {
            "authorization_code": "auth_code_from_device",
            "code_verifier": "device_verifier_abc",
        }
        mock_responses = [
            _mock_urlopen_response(device_response),
            _mock_urlopen_response(poll_pending),
            _mock_urlopen_response(poll_success),
        ]

        with patch("amplifier_module_provider_openai.oauth.urlopen", side_effect=mock_responses):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = asyncio.run(start_device_code_flow())

        assert result["authorization_code"] == "auth_code_from_device"
        assert result["code_verifier"] == "device_verifier_abc"

    def test_polls_until_authorized(self):
        """Polling continues through authorization_pending responses."""
        device_response = {
            "user_code": "WXYZ-5678",
            "device_code": "dev_code_2",
            "verification_uri": DEVICE_CODE_VERIFICATION_URL,
            "expires_in": 900,
            "interval": 5,
        }
        pending = _mock_urlopen_response({"error": "authorization_pending"})
        success = _mock_urlopen_response({
            "authorization_code": "final_code",
            "code_verifier": "final_verifier",
        })

        with patch("amplifier_module_provider_openai.oauth.urlopen", side_effect=[
            _mock_urlopen_response(device_response),
            pending,
            pending,
            pending,
            success,
        ]):
            with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                result = asyncio.run(start_device_code_flow())

        assert result["authorization_code"] == "final_code"
        # Should have slept between polls
        assert mock_sleep.await_count >= 3

    def test_expired_device_code_raises(self):
        """Expired device code raises an error."""
        device_response = {
            "user_code": "EXPR-0000",
            "device_code": "dev_expired",
            "verification_uri": DEVICE_CODE_VERIFICATION_URL,
            "expires_in": 900,
            "interval": 5,
        }
        expired = _mock_urlopen_response({"error": "expired_token"})

        with patch("amplifier_module_provider_openai.oauth.urlopen", side_effect=[
            _mock_urlopen_response(device_response),
            expired,
        ]):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                with pytest.raises(Exception, match="expired"):
                    asyncio.run(start_device_code_flow())
```

**Step 2: Run tests to verify they fail**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py::TestDeviceCodeFlow -v
```

Expected: FAIL — `ImportError` for `start_device_code_flow`.

**Step 3: Write the implementation**

Add to `amplifier_module_provider_openai/oauth.py`:

```python
import asyncio


async def start_device_code_flow() -> dict:
    """Run the device code authorization flow.

    1. POST to device code endpoint to get a user code.
    2. Display verification URL and code to the terminal.
    3. Poll the token endpoint until authorized or expired.

    Returns:
        Dict with 'authorization_code' and 'code_verifier' keys.

    Raises:
        RuntimeError: If the device code expires or an unrecoverable error occurs.
    """
    # Step 1: Request a device code
    body = urlencode({
        "client_id": OAUTH_CLIENT_ID,
        "scope": OAUTH_SCOPES,
    }).encode("utf-8")

    req = Request(
        DEVICE_CODE_USERCODE_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urlopen(req) as resp:
        device_data = json.loads(resp.read().decode("utf-8"))

    user_code = device_data["user_code"]
    device_code = device_data["device_code"]
    interval = device_data.get("interval", DEVICE_CODE_POLL_INTERVAL)

    # Step 2: Display the code to the user
    print(f"\nOpen this URL on any device: {DEVICE_CODE_VERIFICATION_URL}")
    print(f"Enter code: {user_code}\n")

    # Step 3: Poll until authorized
    while True:
        await asyncio.sleep(interval)

        poll_body = urlencode({
            "client_id": OAUTH_CLIENT_ID,
            "device_code": device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }).encode("utf-8")

        poll_req = Request(
            DEVICE_CODE_TOKEN_URL,
            data=poll_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urlopen(poll_req) as poll_resp:
            poll_data = json.loads(poll_resp.read().decode("utf-8"))

        error = poll_data.get("error")
        if error == "authorization_pending":
            continue
        elif error == "slow_down":
            interval += 5  # Back off as requested
            continue
        elif error == "expired_token":
            raise RuntimeError(
                "Device code expired. Please try again."
            )
        elif error:
            raise RuntimeError(f"Device code flow error: {error}")
        else:
            # Success — return the authorization code and verifier
            return {
                "authorization_code": poll_data["authorization_code"],
                "code_verifier": poll_data["code_verifier"],
            }
```

**Step 4: Run tests to verify they pass**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py::TestDeviceCodeFlow -v
```

Expected: All tests PASS.

**Step 5: Commit**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
git add amplifier_module_provider_openai/oauth.py tests/test_oauth.py
git commit -m "feat(oauth): add device code authorization flow"
```

---

### Task 8: Browser PKCE Flow

**Files:**
- Modify: `amplifier_module_provider_openai/oauth.py`
- Modify: `tests/test_oauth.py`

**Step 1: Write the failing tests**

Add to `tests/test_oauth.py`:

```python
from amplifier_module_provider_openai.oauth import start_browser_flow


class TestBrowserFlow:
    """Browser PKCE flow: local server, browser open, callback capture."""

    def test_returns_code_and_verifier_on_callback(self):
        """Successful browser callback returns authorization code and verifier."""
        # We'll mock the server and browser parts
        # The browser flow generates a PKCE pair, starts a server, opens browser,
        # and waits for the callback.
        # For testing, we simulate the callback being received immediately.

        async def _simulate_browser_flow():
            from amplifier_module_provider_openai.oauth import start_browser_flow
            import threading
            import urllib.request

            # Start the browser flow in a task (don't actually open browser)
            with patch("webbrowser.open", return_value=True):
                # Create a task for the browser flow
                flow_task = asyncio.create_task(start_browser_flow())

                # Give the server a moment to start
                await asyncio.sleep(0.1)

                # Simulate the OAuth callback hitting localhost:1455
                try:
                    callback_url = f"http://localhost:{OAUTH_CALLBACK_PORT}/auth/callback?code=browser_code_123&state=test"
                    urllib.request.urlopen(callback_url, timeout=2)
                except Exception:
                    pass  # The server may close the connection after handling

                result = await asyncio.wait_for(flow_task, timeout=5)
                return result

        result = asyncio.run(_simulate_browser_flow())
        assert result["authorization_code"] == "browser_code_123"
        assert "code_verifier" in result

    def test_port_unavailable_raises(self):
        """If port 1455 is already in use, start_browser_flow raises."""
        import socket

        # Bind the port first to simulate it being unavailable
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("localhost", OAUTH_CALLBACK_PORT))
            sock.listen(1)

            with pytest.raises(OSError):
                asyncio.run(start_browser_flow())
        finally:
            sock.close()
```

**Step 2: Run tests to verify they fail**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py::TestBrowserFlow -v
```

Expected: FAIL — `ImportError` for `start_browser_flow`.

**Step 3: Write the implementation**

Add to `amplifier_module_provider_openai/oauth.py`:

```python
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading


async def start_browser_flow() -> dict:
    """Run the browser-based PKCE authorization flow.

    1. Generate PKCE verifier/challenge.
    2. Start a local HTTP server on port 1455 to receive the callback.
    3. Open the browser to the authorization URL.
    4. Wait for the callback with the authorization code.

    Returns:
        Dict with 'authorization_code' and 'code_verifier' keys.

    Raises:
        OSError: If port 1455 is unavailable.
        RuntimeError: If the callback is not received or contains an error.
    """
    code_verifier, code_challenge = generate_pkce_pair()

    # Result container shared between the handler and the caller
    result: dict = {}
    error: list[str] = []

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)

            if "code" in params:
                result["authorization_code"] = params["code"][0]
                result["code_verifier"] = code_verifier
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h1>Authorization successful!</h1>"
                    b"<p>You can close this tab and return to Amplifier.</p>"
                    b"</body></html>"
                )
            elif "error" in params:
                error.append(params["error"][0])
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Authorization failed.")
            else:
                self.send_response(400)
                self.end_headers()

        def log_message(self, format, *args):
            pass  # Suppress server logs

    # Start the local callback server
    server = HTTPServer(("localhost", OAUTH_CALLBACK_PORT), CallbackHandler)
    server.timeout = 300  # 5 minute timeout

    # Build the authorization URL
    auth_params = urlencode({
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": OAUTH_CALLBACK_URL,
        "response_type": "code",
        "scope": OAUTH_SCOPES,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    })
    auth_url = f"{OAUTH_AUTHORIZE_URL}?{auth_params}"

    # Run the server in a thread, open browser, wait for callback
    def _serve():
        server.handle_request()  # Handle exactly one request

    server_thread = threading.Thread(target=_serve, daemon=True)
    server_thread.start()

    try:
        webbrowser.open(auth_url)

        # Wait for the callback (in a non-blocking way)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, server_thread.join, 300)

        if error:
            raise RuntimeError(f"Browser auth failed: {error[0]}")
        if not result:
            raise RuntimeError("Browser auth timed out — no callback received.")

        return result
    finally:
        server.server_close()
```

**Step 4: Run tests to verify they pass**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py::TestBrowserFlow -v
```

Expected: All tests PASS. (The port-unavailable test may need adjustment if port 1455 is not available in CI — see note below.)

> **Note for implementer:** If the callback integration test is flaky in your environment due to port binding timing, add `@pytest.mark.skipif` or restructure to mock `HTTPServer` instead. The key assertion is that the function wires PKCE verifier through to the result dict.

**Step 5: Commit**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
git add amplifier_module_provider_openai/oauth.py tests/test_oauth.py
git commit -m "feat(oauth): add browser PKCE authorization flow"
```

---

### Task 9: Dual-Path Login Orchestration

**Files:**
- Modify: `amplifier_module_provider_openai/oauth.py`
- Modify: `tests/test_oauth.py`

The `login()` function runs both flows in parallel. First to complete wins.

**Step 1: Write the failing tests**

Add to `tests/test_oauth.py`:

```python
from amplifier_module_provider_openai.oauth import login


class TestLogin:
    """login() runs device code + browser flows in parallel, first wins."""

    def _make_jwt(self, payload: dict) -> str:
        header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        return f"{header}.{body}.fakesig"

    def test_device_code_wins_when_browser_fails(self, tmp_path):
        """If browser flow fails (port unavailable), device code flow still works."""
        token_file = str(tmp_path / "tokens.json")

        device_result = {
            "authorization_code": "device_auth_code",
            "code_verifier": "device_verifier",
        }
        exchange_result = {
            "access_token": "at_from_device",
            "refresh_token": "rt_from_device",
            "id_token": self._make_jwt({"sub": "user_1"}),
            "account_id": "user_1",
            "expires_at": "2026-04-21T15:00:00+00:00",
            "auth_mode": "oauth",
        }

        with patch("amplifier_module_provider_openai.oauth.start_browser_flow", side_effect=OSError("port in use")):
            with patch("amplifier_module_provider_openai.oauth.start_device_code_flow", new_callable=AsyncMock, return_value=device_result):
                with patch("amplifier_module_provider_openai.oauth.exchange_code_for_tokens", new_callable=AsyncMock, return_value=exchange_result):
                    result = asyncio.run(login(token_file_path=token_file))

        assert result["access_token"] == "at_from_device"

    def test_browser_wins_when_faster(self, tmp_path):
        """If browser flow completes first, device code is cancelled."""
        token_file = str(tmp_path / "tokens.json")

        browser_result = {
            "authorization_code": "browser_auth_code",
            "code_verifier": "browser_verifier",
        }
        exchange_result = {
            "access_token": "at_from_browser",
            "refresh_token": "rt_from_browser",
            "id_token": self._make_jwt({"sub": "user_2"}),
            "account_id": "user_2",
            "expires_at": "2026-04-21T15:00:00+00:00",
            "auth_mode": "oauth",
        }

        async def slow_device():
            await asyncio.sleep(100)  # Will be cancelled
            return {"authorization_code": "never", "code_verifier": "never"}

        with patch("amplifier_module_provider_openai.oauth.start_browser_flow", new_callable=AsyncMock, return_value=browser_result):
            with patch("amplifier_module_provider_openai.oauth.start_device_code_flow", side_effect=slow_device):
                with patch("amplifier_module_provider_openai.oauth.exchange_code_for_tokens", new_callable=AsyncMock, return_value=exchange_result):
                    result = asyncio.run(login(token_file_path=token_file))

        assert result["access_token"] == "at_from_browser"

    def test_both_fail_raises(self, tmp_path):
        """If both flows fail, login raises an error."""
        token_file = str(tmp_path / "tokens.json")

        with patch("amplifier_module_provider_openai.oauth.start_browser_flow", side_effect=OSError("port in use")):
            with patch("amplifier_module_provider_openai.oauth.start_device_code_flow", new_callable=AsyncMock, side_effect=RuntimeError("expired")):
                with pytest.raises(RuntimeError, match="All authentication methods failed"):
                    asyncio.run(login(token_file_path=token_file))
```

**Step 2: Run tests to verify they fail**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py::TestLogin -v
```

Expected: FAIL — `ImportError` for `login`.

**Step 3: Write the implementation**

Add to `amplifier_module_provider_openai/oauth.py`:

```python
async def login(*, token_file_path: str | None = None) -> dict:
    """Run dual-path OAuth login: browser PKCE + device code in parallel.

    Whichever path delivers an authorization code first wins. The other is
    cancelled. The code is then exchanged for tokens at /oauth/token.

    On desktop machines, the browser opens and the user barely notices the
    device code in the terminal. On headless/SSH environments, the browser
    attempt fails silently and the user grabs the device code on their phone.

    Args:
        token_file_path: Path to save tokens. Defaults to TOKEN_FILE_PATH.

    Returns:
        Token dict with access_token, refresh_token, account_id, etc.

    Raises:
        RuntimeError: If both flows fail.
    """
    file_path = token_file_path or TOKEN_FILE_PATH

    async def _try_browser():
        return await start_browser_flow()

    async def _try_device():
        return await start_device_code_flow()

    # Run both flows as concurrent tasks
    browser_task = asyncio.create_task(_try_browser())
    device_task = asyncio.create_task(_try_device())

    done, pending = await asyncio.wait(
        {browser_task, device_task},
        return_when=asyncio.FIRST_COMPLETED,
    )

    # Cancel the losing task
    for task in pending:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

    # Find the successful result
    winner_result = None
    errors = []
    for task in done:
        try:
            winner_result = task.result()
            break
        except Exception as e:
            errors.append(e)

    # If the first completed task failed, check if the other is still pending
    # (it shouldn't be since we used FIRST_COMPLETED, but handle edge cases)
    if winner_result is None:
        # Wait for any remaining tasks
        if pending:
            done2, _ = await asyncio.wait(pending, timeout=0.1)
            for task in done2:
                try:
                    winner_result = task.result()
                    break
                except Exception as e:
                    errors.append(e)

    if winner_result is None:
        error_details = "; ".join(str(e) for e in errors)
        raise RuntimeError(
            f"All authentication methods failed: {error_details}"
        )

    # Exchange the authorization code for tokens
    redirect_uri = OAUTH_CALLBACK_URL
    tokens = await exchange_code_for_tokens(
        code=winner_result["authorization_code"],
        code_verifier=winner_result["code_verifier"],
        redirect_uri=redirect_uri,
        token_file_path=file_path,
    )
    return tokens
```

**Step 4: Run tests to verify they pass**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_oauth.py::TestLogin -v
```

Expected: All tests PASS.

**Step 5: Run full test suite**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/ -v
```

Expected: All tests PASS.

**Step 6: Commit**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
git add amplifier_module_provider_openai/oauth.py tests/test_oauth.py
git commit -m "feat(oauth): add dual-path login orchestration"
```

---

## Phase 2 Checkpoint

Run the full test suite:

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/ -v
```

At this point `oauth.py` is complete with all public functions: `generate_pkce_pair()`, `save_tokens()`, `load_tokens()`, `is_token_valid()`, `refresh_tokens()`, `extract_account_id()`, `exchange_code_for_tokens()`, `start_device_code_flow()`, `start_browser_flow()`, `login()`, plus all constants.

---

## Phase 3: `__init__.py` Integration

This phase modifies the existing provider at five touch points and adds integration tests. The existing API key path must remain completely untouched.

---

### Task 10: Add `auth_mode` ConfigField to `get_info()`

**Files:**
- Modify: `amplifier_module_provider_openai/__init__.py` (around line 250)
- Create: `tests/test_subscription_auth.py`

**Step 1: Write the failing test**

Create `tests/test_subscription_auth.py`:

```python
"""Integration tests for subscription (OAuth) authentication path."""

import asyncio
import json
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from amplifier_core import ModelInfo, ModuleCoordinator
from amplifier_core import llm_errors as kernel_errors
from amplifier_core.message_models import ChatRequest, Message

from amplifier_module_provider_openai import OpenAIProvider


# ---------------------------------------------------------------------------
# Helpers (same pattern as test_openai_provider.py)
# ---------------------------------------------------------------------------


class DummyResponse:
    """Minimal response stub for provider tests."""

    def __init__(self, output=None):
        self.output = output or []
        self.usage = SimpleNamespace(
            input_tokens=10, output_tokens=5, total_tokens=15
        )
        self.status = "completed"
        self.id = "resp_test"


class FakeHooks:
    def __init__(self):
        self.events: list[tuple[str, dict]] = []

    async def emit(self, name: str, payload: dict) -> None:
        self.events.append((name, payload))


class FakeCoordinator:
    def __init__(self):
        self.hooks = FakeHooks()


def _make_provider(**config_overrides) -> OpenAIProvider:
    config = {"max_retries": 0, "use_streaming": False, **config_overrides}
    return OpenAIProvider(api_key="test-key", config=config)


def _simple_request() -> ChatRequest:
    return ChatRequest(messages=[Message(role="user", content="Hello")])


# ---------------------------------------------------------------------------
# get_info() — auth_mode ConfigField
# ---------------------------------------------------------------------------


class TestAuthModeConfigField:
    """get_info() must include an auth_mode ConfigField."""

    def test_auth_mode_field_present(self):
        provider = _make_provider()
        info = provider.get_info()
        field_ids = [f.id for f in info.config_fields]
        assert "auth_mode" in field_ids

    def test_auth_mode_field_is_select_type(self):
        provider = _make_provider()
        info = provider.get_info()
        field = next(f for f in info.config_fields if f.id == "auth_mode")
        assert field.field_type == "select"

    def test_auth_mode_options(self):
        provider = _make_provider()
        info = provider.get_info()
        field = next(f for f in info.config_fields if f.id == "auth_mode")
        assert field.options == ["api_key", "subscription"]

    def test_auth_mode_default_is_api_key(self):
        provider = _make_provider()
        info = provider.get_info()
        field = next(f for f in info.config_fields if f.id == "auth_mode")
        assert field.default == "api_key"
```

**Step 2: Run tests to verify they fail**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_subscription_auth.py::TestAuthModeConfigField -v
```

Expected: FAIL — `auth_mode` not found in config_fields.

**Step 3: Write the implementation**

In `amplifier_module_provider_openai/__init__.py`, find the `config_fields` list inside `get_info()` (around line 250). Add the `auth_mode` field as the **first** item in the list (before `api_key`), so the user picks auth mode before being prompted for an API key:

Insert this before the existing `ConfigField(id="api_key", ...)` at line 251:

```python
                ConfigField(
                    id="auth_mode",
                    display_name="Authentication Method",
                    field_type="select",
                    options=["api_key", "subscription"],
                    default="api_key",
                ),
```

**Step 4: Run tests to verify they pass**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_subscription_auth.py::TestAuthModeConfigField -v
```

Expected: All tests PASS.

**Step 5: Run full test suite to check for regressions**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/ -v
```

Expected: All existing tests PASS.

**Step 6: Commit**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
git add amplifier_module_provider_openai/__init__.py tests/test_subscription_auth.py
git commit -m "feat(subscription): add auth_mode ConfigField to get_info()"
```

---

### Task 11: Add `auth_mode` to `__init__()` and Modify `mount()`

**Files:**
- Modify: `amplifier_module_provider_openai/__init__.py` (lines ~97-88)
- Modify: `tests/test_subscription_auth.py`

**Step 1: Write the failing tests**

Add to `tests/test_subscription_auth.py`:

```python
from amplifier_module_provider_openai.oauth import CHATGPT_CODEX_BASE_URL


# ---------------------------------------------------------------------------
# mount() — subscription path
# ---------------------------------------------------------------------------


class TestMountSubscription:
    """mount() loads OAuth tokens when auth_mode is subscription."""

    def test_subscription_mount_calls_oauth_load(self, tmp_path):
        """mount() in subscription mode calls oauth.load_tokens."""
        token_file = str(tmp_path / "tokens.json")
        valid_tokens = {
            "auth_mode": "oauth",
            "access_token": "at_test",
            "refresh_token": "rt_test",
            "id_token": "id_test",
            "account_id": "acct_test",
            "expires_at": "2099-01-01T00:00:00+00:00",
        }

        with patch("amplifier_module_provider_openai.oauth.TOKEN_FILE_PATH", token_file):
            from amplifier_module_provider_openai import oauth
            oauth.save_tokens(valid_tokens, token_file)

            from amplifier_module_provider_openai import mount

            fake_coordinator = MagicMock()
            fake_coordinator.mount = AsyncMock()
            config = {"auth_mode": "subscription"}

            with patch("amplifier_module_provider_openai.oauth.load_tokens", return_value=valid_tokens) as mock_load:
                with patch("amplifier_module_provider_openai.oauth.is_token_valid", return_value=True):
                    asyncio.run(mount(cast(ModuleCoordinator, fake_coordinator), config))

            mock_load.assert_called_once()

    def test_api_key_mount_unchanged(self):
        """mount() with api_key auth_mode (or no auth_mode) uses existing API key path."""
        from amplifier_module_provider_openai import mount

        fake_coordinator = MagicMock()
        fake_coordinator.mount = AsyncMock()

        # With explicit api_key mode
        config = {"auth_mode": "api_key", "api_key": "sk-test"}
        cleanup = asyncio.run(mount(cast(ModuleCoordinator, fake_coordinator), config))
        assert cleanup is not None  # Should mount successfully with API key

    def test_subscription_mount_sets_auth_mode_on_provider(self, tmp_path):
        """Provider instance has _auth_mode = 'subscription' after subscription mount."""
        valid_tokens = {
            "access_token": "at_test",
            "refresh_token": "rt_test",
            "account_id": "acct_test",
            "expires_at": "2099-01-01T00:00:00+00:00",
        }

        provider = OpenAIProvider(
            config={"auth_mode": "subscription"}
        )
        assert provider._auth_mode == "subscription"
```

**Step 2: Run tests to verify they fail**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_subscription_auth.py::TestMountSubscription -v
```

Expected: FAIL — `_auth_mode` attribute not found.

**Step 3: Write the implementation**

**3a. Modify `__init__()` (around line 110):**

Add after `self.config = config or {}` (line 112):

```python
        # Authentication mode: "api_key" (default) or "subscription" (OAuth)
        self._auth_mode = self.config.get("auth_mode", "api_key")
        # OAuth credentials (set during mount for subscription mode)
        self._access_token: str | None = None
        self._account_id: str | None = None
```

**3b. Modify `mount()` function (lines 69-88):**

Add the import at the top of the file (after the existing imports around line 54):

```python
from . import oauth
```

Replace the existing `mount()` function with:

```python
async def mount(coordinator: ModuleCoordinator, config: dict[str, Any] | None = None):
    """Mount the OpenAI provider."""
    config = config or {}
    auth_mode = config.get("auth_mode", "api_key")

    if auth_mode == "subscription":
        # Subscription mode: load or obtain OAuth tokens
        tokens = oauth.load_tokens()

        if tokens and oauth.is_token_valid(tokens):
            # Tokens exist and are valid — use them
            pass
        elif tokens and tokens.get("refresh_token"):
            # Tokens expired — try refresh
            refreshed = await oauth.refresh_tokens(tokens["refresh_token"])
            if refreshed:
                tokens = refreshed
            else:
                # Refresh failed — need full login
                tokens = await oauth.login()
        else:
            # No tokens or no refresh token — need full login
            tokens = await oauth.login()

        provider = OpenAIProvider(config=config, coordinator=coordinator)
        provider._access_token = tokens["access_token"]
        provider._account_id = tokens.get("account_id", "")
    else:
        # API key mode: existing behavior, completely untouched
        api_key = config.get("api_key") or os.environ.get("OPENAI_API_KEY")
        if not api_key:
            logger.warning("No API key found for OpenAI provider")
            return None
        provider = OpenAIProvider(api_key=api_key, config=config, coordinator=coordinator)

    await coordinator.mount("providers", provider, name="openai")
    logger.info("Mounted OpenAIProvider (Responses API)")

    async def cleanup():
        await provider.close()

    return cleanup
```

**Step 4: Run tests to verify they pass**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_subscription_auth.py::TestMountSubscription -v
```

Expected: All tests PASS.

**Step 5: Run full test suite**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/ -v
```

Expected: All existing tests PASS.

**Step 6: Commit**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
git add amplifier_module_provider_openai/__init__.py tests/test_subscription_auth.py
git commit -m "feat(subscription): add auth_mode to init and subscription mount path"
```

---

### Task 12: Modify `client` Property for Subscription Mode

**Files:**
- Modify: `amplifier_module_provider_openai/__init__.py` (lines ~179-188)
- Modify: `tests/test_subscription_auth.py`

**Step 1: Write the failing tests**

Add to `tests/test_subscription_auth.py`:

```python
# ---------------------------------------------------------------------------
# Client construction — subscription mode
# ---------------------------------------------------------------------------


class TestClientConstruction:
    """Client property constructs different clients based on auth_mode."""

    def test_subscription_client_uses_chatgpt_base_url(self):
        provider = OpenAIProvider(config={"auth_mode": "subscription"})
        provider._access_token = "at_test"
        provider._account_id = "acct_test"

        client = provider.client
        assert str(client.base_url).rstrip("/") == CHATGPT_CODEX_BASE_URL

    def test_subscription_client_sends_account_id_header(self):
        provider = OpenAIProvider(config={"auth_mode": "subscription"})
        provider._access_token = "at_test"
        provider._account_id = "acct_test"

        client = provider.client
        # The default_headers should include ChatGPT-Account-Id
        assert client._custom_headers.get("ChatGPT-Account-Id") == "acct_test"

    def test_subscription_client_uses_access_token_as_api_key(self):
        provider = OpenAIProvider(config={"auth_mode": "subscription"})
        provider._access_token = "my_oauth_token"
        provider._account_id = "acct_test"

        client = provider.client
        assert client.api_key == "my_oauth_token"

    def test_api_key_client_unchanged(self):
        """API key mode client construction is identical to before."""
        provider = OpenAIProvider(api_key="sk-test123", config={"auth_mode": "api_key"})
        client = provider.client
        assert client.api_key == "sk-test123"
```

**Step 2: Run tests to verify they fail**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_subscription_auth.py::TestClientConstruction -v
```

Expected: FAIL — subscription client doesn't use the ChatGPT base URL yet.

**Step 3: Write the implementation**

Replace the `client` property in `__init__.py` (lines ~179-188) with:

```python
    @property
    def client(self) -> AsyncOpenAI:
        """Lazily initialize the OpenAI client on first access."""
        if self._client is None:
            if self._auth_mode == "subscription":
                if not self._access_token:
                    raise ValueError(
                        "OAuth access token not set. Run provider mount with subscription mode."
                    )
                self._client = AsyncOpenAI(
                    api_key=self._access_token,
                    base_url=oauth.CHATGPT_CODEX_BASE_URL,
                    default_headers={"ChatGPT-Account-Id": self._account_id or ""},
                    max_retries=0,
                )
            else:
                if self._api_key is None:
                    raise ValueError("api_key or client must be provided for API calls")
                self._client = AsyncOpenAI(
                    api_key=self._api_key, base_url=self.base_url, max_retries=0
                )
        return self._client
```

**Step 4: Run tests to verify they pass**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_subscription_auth.py::TestClientConstruction -v
```

Expected: All tests PASS.

**Step 5: Run full test suite**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/ -v
```

Expected: All existing tests PASS.

**Step 6: Commit**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
git add amplifier_module_provider_openai/__init__.py tests/test_subscription_auth.py
git commit -m "feat(subscription): conditional client construction for OAuth mode"
```

---

### Task 13: Modify `list_models()` for Subscription Mode

**Files:**
- Modify: `amplifier_module_provider_openai/__init__.py` (lines ~288-356)
- Modify: `tests/test_subscription_auth.py`

**Step 1: Write the failing tests**

Add to `tests/test_subscription_auth.py`:

```python
from amplifier_module_provider_openai.oauth import SUBSCRIPTION_MODELS


# ---------------------------------------------------------------------------
# list_models() — subscription mode
# ---------------------------------------------------------------------------


class TestListModelsSubscription:
    """list_models() returns hardcoded list in subscription mode."""

    def test_subscription_returns_hardcoded_models(self):
        provider = OpenAIProvider(config={"auth_mode": "subscription"})
        provider._access_token = "at_test"
        provider._account_id = "acct_test"

        models = asyncio.run(provider.list_models())
        model_ids = [m.id for m in models]

        for expected_id in SUBSCRIPTION_MODELS:
            assert expected_id in model_ids

    def test_subscription_includes_custom_option(self):
        provider = OpenAIProvider(config={"auth_mode": "subscription"})
        provider._access_token = "at_test"
        provider._account_id = "acct_test"

        models = asyncio.run(provider.list_models())
        model_ids = [m.id for m in models]

        assert "custom" in model_ids

    def test_subscription_model_count(self):
        """Should be exactly 5 models + custom = 6 total."""
        provider = OpenAIProvider(config={"auth_mode": "subscription"})
        provider._access_token = "at_test"
        provider._account_id = "acct_test"

        models = asyncio.run(provider.list_models())
        assert len(models) == 6  # 5 hardcoded + custom

    def test_subscription_models_have_correct_structure(self):
        provider = OpenAIProvider(config={"auth_mode": "subscription"})
        provider._access_token = "at_test"
        provider._account_id = "acct_test"

        models = asyncio.run(provider.list_models())

        for model in models:
            assert isinstance(model, ModelInfo)
            assert model.id
            assert model.display_name
            if model.id != "custom":
                assert model.context_window > 0
                assert model.max_output_tokens > 0

    def test_subscription_does_not_call_api(self):
        """Subscription mode must NOT call client.models.list()."""
        provider = OpenAIProvider(config={"auth_mode": "subscription"})
        provider._access_token = "at_test"
        provider._account_id = "acct_test"
        # Don't set up a client mock — if it tries to call the API, it should error
        # We set a mock that raises to prove it's not called
        mock_client = MagicMock()
        mock_client.models.list = AsyncMock(side_effect=RuntimeError("Should not be called"))
        provider._client = mock_client

        models = asyncio.run(provider.list_models())
        mock_client.models.list.assert_not_awaited()
        assert len(models) == 6
```

**Step 2: Run tests to verify they fail**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_subscription_auth.py::TestListModelsSubscription -v
```

Expected: FAIL — `list_models()` tries to call the API for subscription mode.

**Step 3: Write the implementation**

In `amplifier_module_provider_openai/__init__.py`, modify `list_models()` (around line 288). Add a conditional at the very beginning of the method, before the `models_response = await self.client.models.list()` call:

```python
    async def list_models(self) -> list[ModelInfo]:
        """
        List available OpenAI models.

        In subscription mode, returns a hardcoded list of known models
        (the ChatGPT backend has no /models endpoint).
        In API key mode, queries the OpenAI API dynamically.
        """
        # Subscription mode: return hardcoded model list
        if self._auth_mode == "subscription":
            return self._list_subscription_models()

        # API key mode: existing dynamic listing (unchanged below)
        # Query OpenAI models API - let exceptions propagate
        models_response = await self.client.models.list()
        # ... rest of existing code unchanged ...
```

Add the helper method to the `OpenAIProvider` class (right after `list_models`):

```python
    def _list_subscription_models(self) -> list[ModelInfo]:
        """Return the hardcoded model list for subscription (OAuth) mode."""
        models = []
        for model_id in oauth.SUBSCRIPTION_MODELS:
            display_name = self._model_id_to_display_name(model_id)
            caps = get_capabilities(model_id)
            if self.enable_long_context and caps.long_context_pricing_threshold:
                reported_context = caps.context_window
            else:
                reported_context = (
                    caps.long_context_pricing_threshold or caps.context_window
                )
            models.append(
                ModelInfo(
                    id=model_id,
                    display_name=display_name,
                    context_window=reported_context,
                    max_output_tokens=caps.max_output_tokens,
                    capabilities=list(caps.capability_tags),
                    defaults={"max_tokens": 16384, "reasoning_effort": "none"},
                )
            )
        # Add custom model option
        models.append(
            ModelInfo(
                id="custom",
                display_name="Custom Model",
                context_window=200_000,
                max_output_tokens=128_000,
                capabilities=["tools", "streaming"],
                defaults={"max_tokens": 16384},
            )
        )
        return sorted(models, key=lambda m: m.display_name.lower())
```

**Step 4: Run tests to verify they pass**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_subscription_auth.py::TestListModelsSubscription -v
```

Expected: All tests PASS.

**Step 5: Run full test suite**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/ -v
```

Expected: All existing tests PASS.

**Step 6: Commit**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
git add amplifier_module_provider_openai/__init__.py tests/test_subscription_auth.py
git commit -m "feat(subscription): hardcoded model list for subscription mode"
```

---

### Task 14: Add 401 Handler with Token Refresh and Retry

**Files:**
- Modify: `amplifier_module_provider_openai/__init__.py` (around line 1005)
- Modify: `tests/test_subscription_auth.py`

**Step 1: Write the failing tests**

Add to `tests/test_subscription_auth.py`:

```python
import openai
import httpx


def _mock_httpx_response(status_code: int = 401, headers: dict | None = None) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        headers=headers or {},
        request=httpx.Request("POST", "https://chatgpt.com/backend-api/codex/responses"),
    )


# ---------------------------------------------------------------------------
# 401 handling — subscription mode
# ---------------------------------------------------------------------------


class TestSubscription401Handler:
    """On 401 in subscription mode, refresh tokens and retry once."""

    def test_401_triggers_refresh_and_retry(self):
        """A 401 in subscription mode should refresh tokens and retry the request."""
        provider = OpenAIProvider(
            config={"auth_mode": "subscription", "use_streaming": False, "max_retries": 0}
        )
        provider._access_token = "old_token"
        provider._account_id = "acct_test"

        # First call: 401 error. Second call (after refresh): success.
        auth_error = openai.AuthenticationError(
            "Unauthorized",
            response=_mock_httpx_response(401),
            body=None,
        )
        mock_create = AsyncMock(side_effect=[auth_error, DummyResponse()])

        # Build the provider's client, then mock
        _ = provider.client
        provider.client.responses.create = mock_create

        refreshed_tokens = {
            "access_token": "new_token",
            "refresh_token": "new_rt",
            "account_id": "acct_test",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "auth_mode": "oauth",
            "id_token": "",
        }

        with patch("amplifier_module_provider_openai.oauth.refresh_tokens", new_callable=AsyncMock, return_value=refreshed_tokens):
            result = asyncio.run(provider.complete(_simple_request()))

        assert result is not None
        # The create mock should have been called twice (original + retry)
        assert mock_create.await_count == 2

    def test_401_refresh_failure_raises_auth_error(self):
        """If refresh fails on 401, raise AuthenticationError."""
        provider = OpenAIProvider(
            config={"auth_mode": "subscription", "use_streaming": False, "max_retries": 0}
        )
        provider._access_token = "expired_token"
        provider._account_id = "acct_test"

        auth_error = openai.AuthenticationError(
            "Unauthorized",
            response=_mock_httpx_response(401),
            body=None,
        )
        _ = provider.client
        provider.client.responses.create = AsyncMock(side_effect=auth_error)

        with patch("amplifier_module_provider_openai.oauth.refresh_tokens", new_callable=AsyncMock, return_value=None):
            with pytest.raises(kernel_errors.AuthenticationError):
                asyncio.run(provider.complete(_simple_request()))

    def test_401_in_api_key_mode_raises_immediately(self):
        """In API key mode, 401 raises AuthenticationError without refresh attempt."""
        provider = OpenAIProvider(
            api_key="sk-bad",
            config={"auth_mode": "api_key", "use_streaming": False, "max_retries": 0}
        )

        auth_error = openai.AuthenticationError(
            "Unauthorized",
            response=_mock_httpx_response(401),
            body=None,
        )
        provider.client.responses.create = AsyncMock(side_effect=auth_error)

        with pytest.raises(kernel_errors.AuthenticationError):
            asyncio.run(provider.complete(_simple_request()))
```

**Step 2: Run tests to verify they fail**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_subscription_auth.py::TestSubscription401Handler -v
```

Expected: FAIL — the 401 doesn't trigger refresh/retry yet.

**Step 3: Write the implementation**

In `amplifier_module_provider_openai/__init__.py`, find the `except openai.AuthenticationError as e:` block inside `_do_complete()` (around line 1005). Replace it with:

```python
            except openai.AuthenticationError as e:
                # In subscription mode, attempt token refresh and retry once
                if self._auth_mode == "subscription" and not getattr(self, "_401_retry_attempted", False):
                    self._401_retry_attempted = True
                    try:
                        tokens = load_tokens()
                        if tokens and tokens.get("refresh_token"):
                            refreshed = await oauth.refresh_tokens(tokens["refresh_token"])
                            if refreshed:
                                self._access_token = refreshed["access_token"]
                                # Rebuild the client with the new token
                                self._client = None  # Force lazy re-init
                                # Retry the request (recursive call to _do_complete)
                                return await _do_complete()
                    except Exception:
                        logger.warning("Token refresh failed during 401 handling", exc_info=True)
                    finally:
                        self._401_retry_attempted = False

                body = getattr(e, "body", None)
                error_msg = json.dumps(body) if body is not None else str(e)
                raise kernel_errors.AuthenticationError(
                    error_msg,
                    provider=self.name,
                    status_code=getattr(e, "status_code", 401),
                ) from e
```

Also add the necessary import at the top of the `_do_complete` function's scope. Find the `_do_complete()` function and add at the top of `_complete_chat_request()` (or at module level alongside other oauth imports):

```python
from .oauth import load_tokens
```

Or — since we already imported `from . import oauth` — use `oauth.load_tokens()` instead:

```python
                        tokens = oauth.load_tokens()
                        if tokens and tokens.get("refresh_token"):
                            refreshed = await oauth.refresh_tokens(tokens["refresh_token"])
```

**Step 4: Run tests to verify they pass**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_subscription_auth.py::TestSubscription401Handler -v
```

Expected: All tests PASS.

**Step 5: Run full test suite**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/ -v
```

Expected: All existing tests PASS.

**Step 6: Commit**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
git add amplifier_module_provider_openai/__init__.py tests/test_subscription_auth.py
git commit -m "feat(subscription): 401 handler with token refresh and retry"
```

---

### Task 15: Final Integration Tests and Full Suite Verification

**Files:**
- Modify: `tests/test_subscription_auth.py`

**Step 1: Write end-to-end integration tests**

Add to `tests/test_subscription_auth.py`:

```python
# ---------------------------------------------------------------------------
# End-to-end integration
# ---------------------------------------------------------------------------


class TestSubscriptionEndToEnd:
    """Integration tests for the full subscription auth path."""

    def test_subscription_provider_can_complete_request(self):
        """A subscription-mode provider can complete a chat request."""
        provider = OpenAIProvider(
            config={"auth_mode": "subscription", "use_streaming": False, "max_retries": 0}
        )
        provider._access_token = "at_valid"
        provider._account_id = "acct_123"

        # Mock the client's create method
        _ = provider.client
        provider.client.responses.create = AsyncMock(return_value=DummyResponse())

        result = asyncio.run(provider.complete(_simple_request()))
        assert result is not None

    def test_subscription_and_api_key_are_mutually_exclusive(self):
        """An api_key provider and subscription provider use different client configs."""
        api_provider = OpenAIProvider(api_key="sk-test", config={"auth_mode": "api_key"})
        sub_provider = OpenAIProvider(config={"auth_mode": "subscription"})
        sub_provider._access_token = "at_test"
        sub_provider._account_id = "acct_test"

        api_client = api_provider.client
        sub_client = sub_provider.client

        # Different base URLs
        assert "api.openai.com" in str(api_client.base_url)
        assert "chatgpt.com" in str(sub_client.base_url)

    def test_existing_api_key_tests_pattern_still_works(self):
        """The standard test pattern (OpenAIProvider(api_key='test-key')) still works."""
        provider = OpenAIProvider(api_key="test-key", config={"use_streaming": False})
        provider.client.responses.create = AsyncMock(return_value=DummyResponse())

        result = asyncio.run(provider.complete(_simple_request()))
        assert result is not None
```

**Step 2: Run the new tests**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/test_subscription_auth.py::TestSubscriptionEndToEnd -v
```

Expected: All tests PASS.

**Step 3: Run the FULL test suite one final time**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
uv run pytest tests/ -v
```

Expected: **Every single test passes** — all existing tests plus all new tests in `test_oauth.py` and `test_subscription_auth.py`.

**Step 4: Commit**

```bash
cd /home/robotdad/Work/openaisub/amplifier-module-provider-openai
git add tests/test_subscription_auth.py
git commit -m "feat(subscription): end-to-end integration tests"
```

---

## Final Summary

### Files Created
| File | Description |
|------|-------------|
| `amplifier_module_provider_openai/oauth.py` | OAuth module: constants, PKCE, device code flow, browser PKCE flow, dual-path login, token storage/load/refresh/validate |
| `tests/test_oauth.py` | Unit tests for all `oauth.py` functions |
| `tests/test_subscription_auth.py` | Integration tests for subscription auth path through the provider |

### Files Modified
| File | Changes |
|------|---------|
| `amplifier_module_provider_openai/__init__.py` | 5 touch points: `get_info()` ConfigField, `__init__()` + `mount()` conditional, `client` property conditional, `list_models()` conditional, 401 handler with refresh+retry |

### Subscription Model List
- `gpt-5.4` (GPT 5.4)
- `gpt-5.4-pro` (GPT 5.4 Pro)
- `gpt-5.4-mini` (GPT 5.4 mini)
- `gpt-5.4-nano` (GPT 5.4 nano)
- `gpt-5.3-codex` (GPT-5.3 codex)
- `custom` (Custom Model — user-provided ID)

### No New Dependencies
All OAuth implementation uses Python stdlib: `hashlib`, `secrets`, `base64`, `urllib.request`, `urllib.parse`, `json`, `http.server`, `webbrowser`, `asyncio`, `threading`, `os`, `stat`, `logging`.
