"""Tests for subscription authentication support (task-10).

Tests for the auth_mode ConfigField added to get_info().
Note: ConfigField uses field_type='choice' and choices=[...], which is the
amplifier-core equivalent of the spec's conceptual 'select' + 'options'.
"""

from types import SimpleNamespace

from amplifier_module_provider_openai import OpenAIProvider


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
