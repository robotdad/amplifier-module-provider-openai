"""Tests for OAuth constants and PKCE helper functions."""

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
