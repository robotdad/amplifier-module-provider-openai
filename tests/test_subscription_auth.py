"""Tests for subscription authentication support (task-10 and task-11).

Tests for the auth_mode ConfigField added to get_info(), and for the
subscription mount path added to mount().
Note: ConfigField uses field_type='choice' and choices=[...], which is the
amplifier-core equivalent of the spec's conceptual 'select' + 'options'.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from amplifier_module_provider_openai import OpenAIProvider, mount


class DummyResponse:
    """Minimal response stub for provider tests."""

    def __init__(self, output=None):
        self.output = output or []
        self.usage = SimpleNamespace(
            prompt_tokens=0, completion_tokens=0, total_tokens=0
        )
        self.stop_reason = "stop"


class FakeHooks:
    def __init__(self):
        self.events: list[tuple[str, dict]] = []

    async def emit(self, name: str, payload: dict) -> None:
        self.events.append((name, payload))


class FakeCoordinator:
    def __init__(self):
        self.hooks = FakeHooks()


def _make_provider(**config_overrides) -> OpenAIProvider:
    config = {"max_retries": 0, **config_overrides}
    return OpenAIProvider(api_key="test-key", config=config)


class TestAuthModeConfigField:
    """auth_mode ConfigField must be present as the first field in get_info()."""

    def _get_auth_mode_field(self):
        provider = _make_provider()
        info = provider.get_info()
        fields = info.config_fields
        return next((f for f in fields if f.id == "auth_mode"), None)

    def test_auth_mode_field_present_in_config_fields(self):
        """auth_mode field must be present in config_fields."""
        field = self._get_auth_mode_field()
        assert field is not None, "auth_mode field not found in config_fields"

    def test_auth_mode_field_is_choice_type(self):
        """auth_mode field must use field_type='choice' (select equivalent in ConfigField)."""
        field = self._get_auth_mode_field()
        assert field is not None
        assert field.field_type == "choice", (
            f"Expected field_type='choice', got '{field.field_type}'"
        )

    def test_auth_mode_options_are_api_key_and_subscription(self):
        """auth_mode choices must be ['api_key', 'subscription']."""
        field = self._get_auth_mode_field()
        assert field is not None
        assert field.choices == ["api_key", "subscription"], (
            f"Expected choices=['api_key', 'subscription'], got {field.choices}"
        )

    def test_auth_mode_default_is_api_key(self):
        """auth_mode default must be 'api_key'."""
        field = self._get_auth_mode_field()
        assert field is not None
        assert field.default == "api_key", (
            f"Expected default='api_key', got '{field.default}'"
        )

    def test_auth_mode_field_is_first_config_field(self):
        """auth_mode must be the FIRST item in config_fields (before api_key)."""
        provider = _make_provider()
        info = provider.get_info()
        assert info.config_fields[0].id == "auth_mode", (
            f"Expected auth_mode to be first, got '{info.config_fields[0].id}'"
        )


# ---------------------------------------------------------------------------
# Helpers for mount() tests
# ---------------------------------------------------------------------------


class FakeMountCoordinator:
    """Coordinator stub that captures mount() calls for testing."""

    def __init__(self):
        self.hooks = FakeHooks()
        self.mounted: dict = {}

    async def mount(self, namespace: str, provider, *, name: str) -> None:
        self.mounted[name] = provider


def _make_valid_tokens() -> dict:
    """Return a token dict with a valid (future) expiry."""
    expires_at = (datetime.now(tz=timezone.utc) + timedelta(hours=1)).isoformat()
    return {
        "auth_mode": "oauth",
        "access_token": "test-access-token",
        "refresh_token": "test-refresh-token",
        "account_id": "user-123",
        "expires_at": expires_at,
    }


# ---------------------------------------------------------------------------
# TestMountSubscription — task-11
# ---------------------------------------------------------------------------


class TestMountSubscription:
    """Tests for the subscription auth_mode path in mount()."""

    @pytest.mark.asyncio
    async def test_subscription_mount_calls_load_tokens(self):
        """Subscription mount must call oauth.load_tokens to retrieve cached tokens."""
        coordinator = FakeMountCoordinator()
        tokens = _make_valid_tokens()

        with patch(
            "amplifier_module_provider_openai.oauth.load_tokens",
            return_value=tokens,
        ) as mock_load:
            await mount(coordinator, config={"auth_mode": "subscription"})

        mock_load.assert_called_once()

    @pytest.mark.asyncio
    async def test_api_key_mount_unchanged(self):
        """api_key mount path must still work when api_key is in config."""
        coordinator = FakeMountCoordinator()

        cleanup = await mount(
            coordinator, config={"api_key": "test-key", "max_retries": 0}
        )

        assert "openai" in coordinator.mounted, "Provider was not mounted"
        assert isinstance(coordinator.mounted["openai"], OpenAIProvider)
        assert callable(cleanup)

    @pytest.mark.asyncio
    async def test_subscription_mount_sets_auth_mode_on_provider(self):
        """Subscription mount must set _auth_mode='subscription' on the created provider."""
        coordinator = FakeMountCoordinator()
        tokens = _make_valid_tokens()

        with patch(
            "amplifier_module_provider_openai.oauth.load_tokens",
            return_value=tokens,
        ):
            await mount(coordinator, config={"auth_mode": "subscription"})

        provider = coordinator.mounted["openai"]
        assert provider._auth_mode == "subscription", (
            f"Expected _auth_mode='subscription', got '{provider._auth_mode}'"
        )


# ---------------------------------------------------------------------------
# TestClientConstruction — task-12
# ---------------------------------------------------------------------------


class TestClientConstruction:
    """Tests for the conditional client property (api_key vs subscription mode)."""

    def _make_subscription_provider(
        self,
        access_token: str | None = "test-access-token",
        account_id: str | None = "user-123",
    ) -> OpenAIProvider:
        """Return a provider configured for subscription auth mode."""
        provider = OpenAIProvider(
            config={"auth_mode": "subscription", "max_retries": 0}
        )
        provider._access_token = access_token
        provider._account_id = account_id
        return provider

    def test_subscription_client_uses_chatgpt_base_url(self):
        """Subscription client must use CHATGPT_CODEX_BASE_URL as base_url."""
        from amplifier_module_provider_openai import oauth
        from unittest.mock import MagicMock, patch

        provider = self._make_subscription_provider()
        mock_client = MagicMock()

        with patch(
            "amplifier_module_provider_openai.AsyncOpenAI", return_value=mock_client
        ) as mock_cls:
            _ = provider.client

        mock_cls.assert_called_once()
        call_kwargs = mock_cls.call_args.kwargs
        assert call_kwargs["base_url"] == oauth.CHATGPT_CODEX_BASE_URL, (
            f"Expected base_url={oauth.CHATGPT_CODEX_BASE_URL!r}, "
            f"got {call_kwargs.get('base_url')!r}"
        )

    def test_subscription_client_sends_chatgpt_account_id_header(self):
        """Subscription client must include ChatGPT-Account-Id in default_headers."""
        from unittest.mock import MagicMock, patch

        provider = self._make_subscription_provider(account_id="user-abc")
        mock_client = MagicMock()

        with patch(
            "amplifier_module_provider_openai.AsyncOpenAI", return_value=mock_client
        ) as mock_cls:
            _ = provider.client

        call_kwargs = mock_cls.call_args.kwargs
        headers = call_kwargs.get("default_headers", {})
        assert headers.get("ChatGPT-Account-Id") == "user-abc", (
            f"Expected ChatGPT-Account-Id='user-abc', "
            f"got {headers.get('ChatGPT-Account-Id')!r}"
        )

    def test_subscription_client_account_id_empty_when_none(self):
        """Subscription client uses empty string for ChatGPT-Account-Id when account_id is None."""
        from unittest.mock import MagicMock, patch

        provider = self._make_subscription_provider(account_id=None)
        mock_client = MagicMock()

        with patch(
            "amplifier_module_provider_openai.AsyncOpenAI", return_value=mock_client
        ) as mock_cls:
            _ = provider.client

        call_kwargs = mock_cls.call_args.kwargs
        headers = call_kwargs.get("default_headers", {})
        assert headers.get("ChatGPT-Account-Id") == "", (
            f"Expected ChatGPT-Account-Id='', got {headers.get('ChatGPT-Account-Id')!r}"
        )

    def test_subscription_client_uses_access_token_as_api_key(self):
        """Subscription client must use _access_token as the api_key."""
        from unittest.mock import MagicMock, patch

        provider = self._make_subscription_provider(access_token="my-oauth-token")
        mock_client = MagicMock()

        with patch(
            "amplifier_module_provider_openai.AsyncOpenAI", return_value=mock_client
        ) as mock_cls:
            _ = provider.client

        call_kwargs = mock_cls.call_args.kwargs
        assert call_kwargs["api_key"] == "my-oauth-token", (
            f"Expected api_key='my-oauth-token', got {call_kwargs.get('api_key')!r}"
        )

    def test_subscription_client_raises_if_no_access_token(self):
        """Subscription mode must raise ValueError when _access_token is not set."""
        import pytest as _pytest

        provider = self._make_subscription_provider(access_token=None)

        with _pytest.raises(ValueError, match="access_token"):
            _ = provider.client

    def test_api_key_client_uses_api_key(self):
        """API key client must pass _api_key as api_key (existing behavior unchanged)."""
        from unittest.mock import MagicMock, patch

        provider = OpenAIProvider(api_key="sk-test-key", config={"max_retries": 0})
        mock_client = MagicMock()

        with patch(
            "amplifier_module_provider_openai.AsyncOpenAI", return_value=mock_client
        ) as mock_cls:
            _ = provider.client

        call_kwargs = mock_cls.call_args.kwargs
        assert call_kwargs["api_key"] == "sk-test-key", (
            f"Expected api_key='sk-test-key', got {call_kwargs.get('api_key')!r}"
        )

    def test_api_key_client_raises_without_api_key(self):
        """API key mode must raise ValueError when _api_key is not set (existing behavior)."""
        import pytest as _pytest

        provider = OpenAIProvider(config={"max_retries": 0})  # No api_key

        with _pytest.raises(ValueError):
            _ = provider.client


# ---------------------------------------------------------------------------
# TestListModelsSubscription — task-13
# ---------------------------------------------------------------------------


class TestListModelsSubscription:
    """list_models() in subscription mode returns hardcoded model list."""

    def _make_subscription_provider(self) -> OpenAIProvider:
        """Return a provider configured for subscription auth mode."""
        provider = OpenAIProvider(
            config={"auth_mode": "subscription", "max_retries": 0}
        )
        provider._access_token = "test-access-token"
        provider._account_id = "user-123"
        return provider

    @pytest.mark.asyncio
    async def test_returns_all_subscription_model_ids(self):
        """list_models() in subscription mode must include all SUBSCRIPTION_MODELS ids."""
        from amplifier_module_provider_openai import oauth

        provider = self._make_subscription_provider()
        models = await provider.list_models()
        model_ids = {m.id for m in models}

        for model_id in oauth.SUBSCRIPTION_MODELS:
            assert model_id in model_ids, (
                f"Expected {model_id!r} in returned models, got {sorted(model_ids)}"
            )

    @pytest.mark.asyncio
    async def test_includes_custom_option(self):
        """list_models() in subscription mode must include a 'custom' model."""
        provider = self._make_subscription_provider()
        models = await provider.list_models()
        model_ids = [m.id for m in models]

        assert "custom" in model_ids, (
            f"Expected 'custom' in returned model IDs, got {model_ids}"
        )

    @pytest.mark.asyncio
    async def test_total_count_is_six(self):
        """list_models() in subscription mode must return exactly 6 models (5 + custom)."""
        provider = self._make_subscription_provider()
        models = await provider.list_models()

        assert len(models) == 6, (
            f"Expected 6 models (5 subscription + custom), got {len(models)}: "
            f"{[m.id for m in models]}"
        )

    @pytest.mark.asyncio
    async def test_models_have_correct_modelinfo_structure(self):
        """Each model must have id, display_name, context_window > 0, max_output_tokens > 0."""
        provider = self._make_subscription_provider()
        models = await provider.list_models()

        for model in models:
            assert model.id, f"Model missing id: {model!r}"
            assert model.display_name, f"Model missing display_name: {model!r}"
            assert model.context_window > 0, (
                f"Model {model.id!r} has context_window={model.context_window}"
            )
            assert model.max_output_tokens > 0, (
                f"Model {model.id!r} has max_output_tokens={model.max_output_tokens}"
            )

    @pytest.mark.asyncio
    async def test_subscription_mode_does_not_call_client_models_list(self):
        """Subscription mode list_models() must NOT call client.models.list()."""
        from unittest.mock import AsyncMock, MagicMock, patch

        provider = self._make_subscription_provider()

        mock_client = MagicMock()
        mock_client.models.list = AsyncMock(
            side_effect=AssertionError(
                "client.models.list() must NOT be called in subscription mode"
            )
        )

        with patch(
            "amplifier_module_provider_openai.AsyncOpenAI", return_value=mock_client
        ):
            # Should not raise — subscription mode short-circuits before calling the API
            await provider.list_models()

        mock_client.models.list.assert_not_called()
