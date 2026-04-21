"""Tests for OAuth constants and PKCE helper functions."""

import asyncio
import base64
import hashlib
import json
import stat
from datetime import datetime, timezone, timedelta
from io import BytesIO
from unittest.mock import AsyncMock, MagicMock, patch

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
    exchange_code_for_tokens,
    extract_account_id,
    generate_pkce_pair,
    is_token_valid,
    load_tokens,
    refresh_tokens,
    save_tokens,
    start_device_code_flow,
)


class TestConstants:
    """Verify all OAuth constant values."""

    def test_oauth_issuer(self):
        assert OAUTH_ISSUER == "https://auth.openai.com"

    def test_oauth_authorize_url(self):
        assert OAUTH_AUTHORIZE_URL == "https://auth.openai.com/oauth/authorize"

    def test_oauth_token_url(self):
        assert OAUTH_TOKEN_URL == "https://auth.openai.com/oauth/token"

    def test_oauth_client_id(self):
        assert OAUTH_CLIENT_ID == "app_EMoamEEZ73f0CkXaXp7hrann"

    def test_oauth_scopes(self):
        assert OAUTH_SCOPES == "openid profile email offline_access"

    def test_oauth_callback_url(self):
        assert OAUTH_CALLBACK_URL == "http://localhost:1455/auth/callback"

    def test_oauth_callback_port(self):
        assert OAUTH_CALLBACK_PORT == 1455

    def test_device_code_usercode_url(self):
        assert (
            DEVICE_CODE_USERCODE_URL
            == "https://auth.openai.com/api/accounts/deviceauth/usercode"
        )

    def test_device_code_token_url(self):
        assert (
            DEVICE_CODE_TOKEN_URL
            == "https://auth.openai.com/api/accounts/deviceauth/token"
        )

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


class TestPKCE:
    """Verify PKCE helper functions per RFC 7636."""

    def test_returns_tuple_of_two_strings(self):
        result = generate_pkce_pair()
        assert isinstance(result, tuple)
        assert len(result) == 2
        verifier, challenge = result
        assert isinstance(verifier, str)
        assert isinstance(challenge, str)

    def test_verifier_length_in_range(self):
        verifier, _ = generate_pkce_pair()
        assert 43 <= len(verifier) <= 128

    def test_verifier_is_url_safe(self):
        """Verifier must only contain URL-safe characters: A-Z, a-z, 0-9, -, _, ., ~"""
        import re

        verifier, _ = generate_pkce_pair()
        # RFC 7636 unreserved chars: ALPHA / DIGIT / "-" / "." / "_" / "~"
        assert re.match(r"^[A-Za-z0-9\-._~]+$", verifier), (
            f"Verifier contains non-URL-safe characters: {verifier!r}"
        )

    def test_challenge_is_sha256_of_verifier(self):
        """Challenge must be BASE64URL(SHA256(verifier)) with no padding."""
        verifier, challenge = generate_pkce_pair()
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        assert challenge == expected

    def test_each_call_returns_unique_pair(self):
        pair1 = generate_pkce_pair()
        pair2 = generate_pkce_pair()
        assert pair1[0] != pair2[0], "Verifiers should be unique across calls"
        assert pair1[1] != pair2[1], "Challenges should be unique across calls"


class TestSaveTokens:
    """Verify save_tokens writes tokens to disk correctly."""

    def test_creates_file_with_correct_content(self, tmp_path):
        tokens = {"access_token": "abc", "refresh_token": "xyz"}
        path = str(tmp_path / "tokens.json")
        save_tokens(tokens, path)
        with open(path) as f:
            loaded = json.load(f)
        assert loaded == tokens

    def test_file_has_0600_permissions(self, tmp_path):
        tokens = {"access_token": "abc"}
        path = str(tmp_path / "tokens.json")
        save_tokens(tokens, path)
        file_stat = (tmp_path / "tokens.json").stat()
        permissions = stat.S_IMODE(file_stat.st_mode)
        assert permissions == 0o600

    def test_creates_parent_directory_if_missing(self, tmp_path):
        tokens = {"access_token": "abc"}
        path = str(tmp_path / "nested" / "dir" / "tokens.json")
        save_tokens(tokens, path)
        assert (tmp_path / "nested" / "dir" / "tokens.json").exists()

    def test_overwrites_existing_file(self, tmp_path):
        path = str(tmp_path / "tokens.json")
        save_tokens({"old": "data"}, path)
        new_tokens = {"new": "data"}
        save_tokens(new_tokens, path)
        with open(path) as f:
            loaded = json.load(f)
        assert loaded == new_tokens


class TestLoadTokens:
    """Verify load_tokens reads tokens from disk correctly."""

    def test_returns_dict_for_valid_file(self, tmp_path):
        tokens = {"access_token": "abc", "refresh_token": "xyz"}
        path = str(tmp_path / "tokens.json")
        with open(path, "w") as f:
            json.dump(tokens, f)
        result = load_tokens(path)
        assert result == tokens

    def test_returns_none_for_missing_file(self, tmp_path):
        path = str(tmp_path / "nonexistent.json")
        result = load_tokens(path)
        assert result is None

    def test_returns_none_for_malformed_json(self, tmp_path):
        path = str(tmp_path / "tokens.json")
        with open(path, "w") as f:
            f.write("not valid json {{{")
        result = load_tokens(path)
        assert result is None

    def test_returns_none_for_empty_file(self, tmp_path):
        path = str(tmp_path / "tokens.json")
        (tmp_path / "tokens.json").touch()
        result = load_tokens(path)
        assert result is None


class TestIsTokenValid:
    """Verify is_token_valid checks token existence and expiry."""

    def _future_expires_at(self) -> str:
        """Return an ISO 8601 timestamp one hour in the future (UTC)."""
        future = datetime.now(tz=timezone.utc) + timedelta(hours=1)
        return future.isoformat()

    def _past_expires_at(self) -> str:
        """Return an ISO 8601 timestamp one hour in the past (UTC)."""
        past = datetime.now(tz=timezone.utc) - timedelta(hours=1)
        return past.isoformat()

    def test_valid_token_not_expired_returns_true(self):
        tokens = {
            "access_token": "tok_abc",
            "expires_at": self._future_expires_at(),
        }
        assert is_token_valid(tokens) is True

    def test_expired_token_returns_false(self):
        tokens = {
            "access_token": "tok_abc",
            "expires_at": self._past_expires_at(),
        }
        assert is_token_valid(tokens) is False

    def test_none_tokens_returns_false(self):
        assert is_token_valid(None) is False

    def test_missing_access_token_returns_false(self):
        tokens = {"expires_at": self._future_expires_at()}
        assert is_token_valid(tokens) is False

    def test_missing_expires_at_returns_false(self):
        tokens = {"access_token": "tok_abc"}
        assert is_token_valid(tokens) is False

    def test_malformed_expires_at_returns_false(self):
        tokens = {
            "access_token": "tok_abc",
            "expires_at": "not-a-valid-datetime",
        }
        assert is_token_valid(tokens) is False


# ---------------------------------------------------------------------------
# Helpers shared by TestRefreshTokens
# ---------------------------------------------------------------------------


def _mock_urlopen_response(data: dict) -> MagicMock:
    """Create a mock urllib response that returns JSON-encoded *data*.

    The mock supports the context-manager protocol so it can be used with::

        with urlopen(req) as response:
            body = response.read()
    """
    encoded = json.dumps(data).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.read.return_value = encoded
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


class TestRefreshTokens:
    """Verify refresh_tokens() exchanges a refresh token for new credentials."""

    def test_successful_refresh_returns_new_tokens(self, tmp_path):
        """Successful refresh returns a dict with all required fields."""
        path = str(tmp_path / "tokens.json")
        # Seed an existing token file so account_id can be preserved.
        save_tokens({"account_id": "acct_123"}, path)

        mock_resp = _mock_urlopen_response(
            {
                "access_token": "new_access",
                "refresh_token": "new_refresh",
                "id_token": "new_id",
                "expires_in": 3600,
            }
        )
        with patch(
            "amplifier_module_provider_openai.oauth.urlopen", return_value=mock_resp
        ):
            result = asyncio.run(refresh_tokens("old_refresh", path=path))

        assert result is not None
        assert result["auth_mode"] == "oauth"
        assert result["access_token"] == "new_access"
        assert result["refresh_token"] == "new_refresh"
        assert result["id_token"] == "new_id"
        assert result["account_id"] == "acct_123"
        assert "expires_at" in result

    def test_refresh_saves_to_disk(self, tmp_path):
        """Successful refresh persists the new token dict to disk."""
        path = str(tmp_path / "tokens.json")

        mock_resp = _mock_urlopen_response(
            {
                "access_token": "saved_access",
                "refresh_token": "saved_refresh",
                "id_token": "saved_id",
                "expires_in": 3600,
            }
        )
        with patch(
            "amplifier_module_provider_openai.oauth.urlopen", return_value=mock_resp
        ):
            asyncio.run(refresh_tokens("old_refresh", path=path))

        assert (tmp_path / "tokens.json").exists()
        with open(path) as f:
            saved = json.load(f)
        assert saved["access_token"] == "saved_access"
        assert saved["auth_mode"] == "oauth"

    def test_refresh_sends_correct_request_params(self, tmp_path):
        """POST body contains grant_type, refresh_token, and client_id."""
        from urllib.parse import parse_qs

        path = str(tmp_path / "tokens.json")
        captured: list = []

        mock_resp = _mock_urlopen_response(
            {
                "access_token": "tok",
                "refresh_token": "ref",
                "id_token": "idtok",
                "expires_in": 3600,
            }
        )

        def capturing_urlopen(req):
            captured.append(req)
            return mock_resp

        with patch(
            "amplifier_module_provider_openai.oauth.urlopen",
            side_effect=capturing_urlopen,
        ):
            asyncio.run(refresh_tokens("my_refresh_token", path=path))

        assert len(captured) == 1
        req = captured[0]
        params = parse_qs(req.data.decode("utf-8"))
        assert params["grant_type"] == ["refresh_token"]
        assert params["refresh_token"] == ["my_refresh_token"]
        assert params["client_id"] == [OAUTH_CLIENT_ID]

    def test_refresh_failure_returns_none(self, tmp_path):
        """HTTP failure during refresh logs a warning and returns None."""
        from urllib.error import HTTPError

        path = str(tmp_path / "tokens.json")

        http_error = HTTPError(
            url=OAUTH_TOKEN_URL,
            code=401,
            msg="Unauthorized",
            hdrs={},  # type: ignore[arg-type]
            fp=BytesIO(b'{"error": "invalid_grant"}'),
        )

        with patch(
            "amplifier_module_provider_openai.oauth.urlopen", side_effect=http_error
        ):
            result = asyncio.run(refresh_tokens("bad_refresh", path=path))

        assert result is None


# ---------------------------------------------------------------------------
# Helper for TestExtractAccountId
# ---------------------------------------------------------------------------


def _make_jwt(payload: dict) -> str:
    """Create a minimal fake JWT with the given payload (unsigned)."""
    header_b64 = (
        base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}')
        .rstrip(b"=")
        .decode("ascii")
    )
    payload_bytes = json.dumps(payload).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii")
    return f"{header_b64}.{payload_b64}.fakesignature"


class TestExtractAccountId:
    """Verify extract_account_id decodes JWT payload and extracts account ID."""

    def test_extracts_account_id_from_openai_profile_claim(self):
        """Primary path: reads account_id from the OpenAI profile custom claim."""
        token = _make_jwt(
            {
                "sub": "some-sub-id",
                "https://api.openai.com/profile": {"account_id": "acct_profile_123"},
            }
        )
        assert extract_account_id(token) == "acct_profile_123"

    def test_falls_back_to_sub_claim(self):
        """Fallback path: returns sub when OpenAI profile claim is absent."""
        token = _make_jwt({"sub": "sub-fallback-id"})
        assert extract_account_id(token) == "sub-fallback-id"

    def test_returns_empty_string_for_invalid_jwt(self):
        """Returns empty string when the token cannot be decoded."""
        assert extract_account_id("invalid.jwt.token") == ""

    def test_returns_empty_string_for_empty_string_input(self):
        """Returns empty string for an empty input string."""
        assert extract_account_id("") == ""


class TestExchangeCodeForTokens:
    """Verify exchange_code_for_tokens() exchanges an authorization code for credentials."""

    def test_successful_exchange_returns_tokens_with_correct_fields(self, tmp_path):
        """Successful exchange returns a dict with all required fields."""
        path = str(tmp_path / "tokens.json")
        account_id = "acct_exchange_123"
        id_token = _make_jwt(
            {
                "sub": account_id,
                "https://api.openai.com/profile": {"account_id": account_id},
            }
        )
        mock_resp = _mock_urlopen_response(
            {
                "access_token": "new_access",
                "refresh_token": "new_refresh",
                "id_token": id_token,
                "expires_in": 3600,
            }
        )
        with patch(
            "amplifier_module_provider_openai.oauth.urlopen", return_value=mock_resp
        ):
            result = asyncio.run(
                exchange_code_for_tokens(
                    code="auth_code_abc",
                    code_verifier="verifier_xyz",
                    redirect_uri="http://localhost:1455/auth/callback",
                    token_file_path=path,
                )
            )

        assert result is not None
        assert result["auth_mode"] == "oauth"
        assert result["access_token"] == "new_access"
        assert result["refresh_token"] == "new_refresh"
        assert result["id_token"] == id_token
        assert result["account_id"] == account_id
        assert "expires_at" in result

    def test_exchange_saves_to_disk(self, tmp_path):
        """Successful exchange persists the new token dict to disk."""
        path = str(tmp_path / "tokens.json")
        id_token = _make_jwt({"sub": "acct_save_test"})
        mock_resp = _mock_urlopen_response(
            {
                "access_token": "saved_access",
                "refresh_token": "saved_refresh",
                "id_token": id_token,
                "expires_in": 3600,
            }
        )
        with patch(
            "amplifier_module_provider_openai.oauth.urlopen", return_value=mock_resp
        ):
            asyncio.run(
                exchange_code_for_tokens(
                    code="auth_code",
                    code_verifier="verifier",
                    redirect_uri="http://localhost:1455/auth/callback",
                    token_file_path=path,
                )
            )

        assert (tmp_path / "tokens.json").exists()
        with open(path) as f:
            saved = json.load(f)
        assert saved["access_token"] == "saved_access"
        assert saved["auth_mode"] == "oauth"

    def test_exchange_sends_correct_params(self, tmp_path):
        """POST body contains grant_type, code, code_verifier, client_id, redirect_uri."""
        from urllib.parse import parse_qs

        path = str(tmp_path / "tokens.json")
        captured: list = []
        id_token = _make_jwt({"sub": "acct_params_test"})
        mock_resp = _mock_urlopen_response(
            {
                "access_token": "tok",
                "refresh_token": "ref",
                "id_token": id_token,
                "expires_in": 3600,
            }
        )

        def capturing_urlopen(req):
            captured.append(req)
            return mock_resp

        with patch(
            "amplifier_module_provider_openai.oauth.urlopen",
            side_effect=capturing_urlopen,
        ):
            asyncio.run(
                exchange_code_for_tokens(
                    code="my_auth_code",
                    code_verifier="my_code_verifier",
                    redirect_uri="http://localhost:1455/auth/callback",
                    token_file_path=path,
                )
            )

        assert len(captured) == 1
        req = captured[0]
        params = parse_qs(req.data.decode("utf-8"))
        assert params["grant_type"] == ["authorization_code"]
        assert params["code"] == ["my_auth_code"]
        assert params["code_verifier"] == ["my_code_verifier"]
        assert params["client_id"] == [OAUTH_CLIENT_ID]
        assert params["redirect_uri"] == ["http://localhost:1455/auth/callback"]

    def test_exchange_failure_raises_exception(self, tmp_path):
        """HTTP failure during exchange raises an exception (does not swallow it)."""
        from urllib.error import HTTPError

        path = str(tmp_path / "tokens.json")

        http_error = HTTPError(
            url=OAUTH_TOKEN_URL,
            code=400,
            msg="Bad Request",
            hdrs={},  # type: ignore[arg-type]
            fp=BytesIO(b'{"error": "invalid_grant"}'),
        )

        with patch(
            "amplifier_module_provider_openai.oauth.urlopen", side_effect=http_error
        ):
            import pytest

            with pytest.raises(Exception):
                asyncio.run(
                    exchange_code_for_tokens(
                        code="bad_code",
                        code_verifier="bad_verifier",
                        redirect_uri="http://localhost:1455/auth/callback",
                        token_file_path=path,
                    )
                )


class TestDeviceCodeFlow:
    """Verify start_device_code_flow() performs device code authorization."""

    def test_requests_device_code_and_returns_auth_code_after_polling(self):
        """Happy path: requests device code, polls once, returns authorization_code and code_verifier."""
        usercode_response = _mock_urlopen_response(
            {
                "user_code": "ABCD-EFGH",
                "device_code": "dev_code_xyz",
                "interval": 5,
            }
        )
        token_response = _mock_urlopen_response(
            {
                "authorization_code": "auth_code_123",
            }
        )

        with patch(
            "amplifier_module_provider_openai.oauth.urlopen",
            side_effect=[usercode_response, token_response],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = asyncio.run(start_device_code_flow())

        assert "authorization_code" in result
        assert result["authorization_code"] == "auth_code_123"
        assert "code_verifier" in result
        assert isinstance(result["code_verifier"], str)

    def test_polls_through_multiple_authorization_pending_responses(self):
        """Verifies sleep is called once per authorization_pending response."""
        usercode_response = _mock_urlopen_response(
            {
                "user_code": "WXYZ-1234",
                "device_code": "dev_code_abc",
                "interval": 5,
            }
        )
        pending_response_1 = _mock_urlopen_response({"error": "authorization_pending"})
        pending_response_2 = _mock_urlopen_response({"error": "authorization_pending"})
        token_response = _mock_urlopen_response({"authorization_code": "auth_code_456"})

        with patch(
            "amplifier_module_provider_openai.oauth.urlopen",
            side_effect=[
                usercode_response,
                pending_response_1,
                pending_response_2,
                token_response,
            ],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                result = asyncio.run(start_device_code_flow())

        assert mock_sleep.call_count == 2
        assert "authorization_code" in result
        assert result["authorization_code"] == "auth_code_456"

    def test_expired_device_code_raises_runtime_error(self):
        """expired_token error raises RuntimeError with appropriate message."""
        import pytest

        usercode_response = _mock_urlopen_response(
            {
                "user_code": "ABCD-EFGH",
                "device_code": "dev_code_xyz",
                "interval": 5,
            }
        )
        expired_response = _mock_urlopen_response({"error": "expired_token"})

        with patch(
            "amplifier_module_provider_openai.oauth.urlopen",
            side_effect=[usercode_response, expired_response],
        ):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                with pytest.raises(RuntimeError, match="Device code expired"):
                    asyncio.run(start_device_code_flow())
