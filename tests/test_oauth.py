"""Tests for OAuth constants and PKCE helper functions."""

import base64
import hashlib
import json
import stat
from datetime import datetime, timezone, timedelta

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
    is_token_valid,
    load_tokens,
    save_tokens,
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
