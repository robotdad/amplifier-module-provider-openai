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
