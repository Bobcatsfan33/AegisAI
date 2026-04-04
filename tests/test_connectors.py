"""
Unit tests for AegisAI Connector modules.

Tests the connector base classes, LLMResponse model, cost estimation,
OpenAI connector (mocked), Anthropic connector (mocked), and ConnectorRegistry.
"""

import os
import sys
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.aegis_ai.connectors.base import (
    LLMConnector,
    LLMResponse,
    ProviderType,
    estimate_cost,
    COST_TABLE,
)
from modules.aegis_ai.connectors.registry import ConnectorRegistry
from modules.aegis_ai.connectors.openai_connector import OpenAIConnector
from modules.aegis_ai.connectors.anthropic_connector import AnthropicConnector


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_openai_response(content="Hello!", model="gpt-4o", input_tokens=10, output_tokens=20):
    """Build a fake openai chat completion response."""
    resp = MagicMock()
    resp.choices = [MagicMock()]
    resp.choices[0].message.content = content
    resp.choices[0].finish_reason = "stop"
    resp.usage.prompt_tokens = input_tokens
    resp.usage.completion_tokens = output_tokens
    resp.model_dump.return_value = {"model": model}
    return resp


def _make_anthropic_response(content="Hello!", model="claude-sonnet-4-6",
                             input_tokens=10, output_tokens=20):
    """Build a fake anthropic messages response."""
    resp = MagicMock()
    resp.content = [MagicMock()]
    resp.content[0].text = content
    resp.stop_reason = "end_turn"
    resp.usage.input_tokens = input_tokens
    resp.usage.output_tokens = output_tokens
    resp.model_dump.return_value = {"model": model}
    return resp


# ── LLMResponse Model ─────────────────────────────────────────────────────────


class TestLLMResponseModel:
    """Tests for the LLMResponse dataclass."""

    def test_to_dict_fields(self):
        resp = LLMResponse(
            content="Hello world",
            model="gpt-4o",
            provider=ProviderType.OPENAI,
            input_tokens=10,
            output_tokens=20,
            latency_ms=150.0,
            cost_usd=0.001,
            finish_reason="stop",
        )
        d = resp.to_dict()
        assert d["content"] == "Hello world"
        assert d["model"] == "gpt-4o"
        assert d["provider"] == "openai"
        assert d["input_tokens"] == 10
        assert d["output_tokens"] == 20
        assert d["latency_ms"] == 150.0
        assert d["cost_usd"] == 0.001
        assert d["finish_reason"] == "stop"
        assert "timestamp" in d

    def test_provider_serialized_as_string(self):
        resp = LLMResponse("ok", "model", ProviderType.ANTHROPIC)
        d = resp.to_dict()
        assert d["provider"] == "anthropic"
        assert isinstance(d["provider"], str)

    def test_default_values(self):
        resp = LLMResponse(content="", model="test", provider=ProviderType.CUSTOM)
        assert resp.input_tokens == 0
        assert resp.output_tokens == 0
        assert resp.latency_ms == 0.0
        assert resp.cost_usd == 0.0
        assert resp.finish_reason == "stop"
        assert resp.raw_response is None

    def test_timestamp_auto_set(self):
        resp = LLMResponse("ok", "model", ProviderType.OPENAI)
        assert resp.timestamp
        assert "T" in resp.timestamp


# ── Cost Estimation ───────────────────────────────────────────────────────────


class TestCostEstimation:
    """Tests for estimate_cost()."""

    def test_gpt4o_cost(self):
        cost = estimate_cost("gpt-4o", 1000, 500)
        assert cost > 0.0
        # Cost is positive; first matching key in COST_TABLE wins
        assert isinstance(cost, float)

    def test_gpt4o_mini_cost(self):
        cost = estimate_cost("gpt-4o-mini", 1000, 1000)
        assert cost > 0.0
        assert isinstance(cost, float)

    def test_claude_sonnet_cost(self):
        cost = estimate_cost("claude-sonnet-4-6", 1000, 500)
        assert cost > 0.0

    def test_unknown_model_returns_zero(self):
        cost = estimate_cost("totally-unknown-model-xyz", 1000, 1000)
        assert cost == 0.0

    def test_zero_tokens_zero_cost(self):
        cost = estimate_cost("gpt-4o", 0, 0)
        assert cost == 0.0

    def test_cost_table_has_models(self):
        assert len(COST_TABLE) >= 5
        assert "gpt-4o" in COST_TABLE
        assert "claude-sonnet-4-6" in COST_TABLE

    def test_partial_model_name_match(self):
        # "my-custom-gpt-4o-finetuned" should match "gpt-4o" entry
        cost = estimate_cost("my-custom-gpt-4o-finetuned", 1000, 1000)
        assert cost > 0.0


# ── ProviderType Enum ─────────────────────────────────────────────────────────


class TestProviderType:
    """Tests for ProviderType enum."""

    def test_all_provider_types_exist(self):
        types = {p.value for p in ProviderType}
        assert "openai" in types
        assert "anthropic" in types
        assert "ollama" in types
        assert "vllm" in types
        assert "custom" in types

    def test_string_enum_values(self):
        for pt in ProviderType:
            assert isinstance(pt.value, str)


# ── OpenAI Connector (mocked) ─────────────────────────────────────────────────


class TestOpenAIConnector:
    """Tests for OpenAIConnector with mocked openai SDK."""

    def _make_connector(self, **kwargs):
        mock_openai = MagicMock()
        mock_client = MagicMock()
        mock_openai.OpenAI.return_value = mock_client

        with patch.dict("sys.modules", {"openai": mock_openai}):
            # Re-import to pick up mock
            from importlib import import_module, reload
            import modules.connectors.openai_connector as oc_mod
            # Patch at module level
            connector = OpenAIConnector.__new__(OpenAIConnector)
            connector.provider = ProviderType.OPENAI
            connector.default_model = kwargs.get("default_model", "gpt-4o")
            connector._client = mock_client
        return connector, mock_client

    def test_query_returns_llm_response(self):
        connector, mock_client = self._make_connector()
        fake_resp = _make_openai_response("Test response")
        mock_client.chat.completions.create.return_value = fake_resp

        result = connector.query("Hello")
        assert isinstance(result, LLMResponse)
        assert result.content == "Test response"
        assert result.model == "gpt-4o"

    def test_query_with_system_prompt(self):
        connector, mock_client = self._make_connector()
        mock_client.chat.completions.create.return_value = _make_openai_response("ok")
        connector.query("prompt", system="You are helpful")

        call_kwargs = mock_client.chat.completions.create.call_args[1]
        messages = call_kwargs["messages"]
        assert messages[0]["role"] == "system"
        assert messages[0]["content"] == "You are helpful"
        assert messages[1]["role"] == "user"

    def test_query_with_custom_model(self):
        connector, mock_client = self._make_connector()
        mock_client.chat.completions.create.return_value = _make_openai_response("ok")
        connector.query("prompt", model="gpt-4-turbo")

        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert call_kwargs["model"] == "gpt-4-turbo"

    def test_query_temperature_and_max_tokens(self):
        connector, mock_client = self._make_connector()
        mock_client.chat.completions.create.return_value = _make_openai_response("ok")
        connector.query("prompt", temperature=0.7, max_tokens=2048)

        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert call_kwargs["temperature"] == 0.7
        assert call_kwargs["max_tokens"] == 2048

    def test_query_token_counts(self):
        connector, mock_client = self._make_connector()
        mock_client.chat.completions.create.return_value = _make_openai_response(
            input_tokens=100, output_tokens=50
        )
        result = connector.query("prompt")
        assert result.input_tokens == 100
        assert result.output_tokens == 50

    def test_query_with_messages_list(self):
        connector, mock_client = self._make_connector()
        mock_client.chat.completions.create.return_value = _make_openai_response("ok")
        messages = [
            {"role": "system", "content": "Be helpful"},
            {"role": "user", "content": "Hello"},
        ]
        connector.query("prompt", messages=messages)

        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert call_kwargs["messages"] == messages

    def test_provider_type_set_correctly(self):
        connector, _ = self._make_connector()
        assert connector.provider == ProviderType.OPENAI

    def test_is_available_calls_models_list(self):
        connector, mock_client = self._make_connector()
        mock_client.models.list.return_value = MagicMock()
        assert connector.is_available() is True
        mock_client.models.list.assert_called_once()

    def test_is_available_returns_false_on_error(self):
        connector, mock_client = self._make_connector()
        mock_client.models.list.side_effect = Exception("Unauthorized")
        assert connector.is_available() is False

    def test_import_error_raises(self):
        with patch.dict("sys.modules", {"openai": None}):
            # Reload module with openai=None
            import modules.connectors.openai_connector as oc
            original = oc.openai
            oc.openai = None
            with pytest.raises(ImportError):
                OpenAIConnector(api_key="test")
            oc.openai = original


# ── Anthropic Connector (mocked) ──────────────────────────────────────────────


class TestAnthropicConnector:
    """Tests for AnthropicConnector with mocked anthropic SDK."""

    def _make_connector(self, model="claude-sonnet-4-6"):
        mock_anthropic = MagicMock()
        mock_client = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        connector = AnthropicConnector.__new__(AnthropicConnector)
        connector.provider = ProviderType.ANTHROPIC
        connector.default_model = model
        connector._client = mock_client
        return connector, mock_client

    def test_query_returns_llm_response(self):
        connector, mock_client = self._make_connector()
        mock_client.messages.create.return_value = _make_anthropic_response("Hi there")
        result = connector.query("Hello")
        assert isinstance(result, LLMResponse)
        assert result.content == "Hi there"

    def test_query_with_system_prompt(self):
        connector, mock_client = self._make_connector()
        mock_client.messages.create.return_value = _make_anthropic_response("ok")
        connector.query("prompt", system="Be concise")

        call_kwargs = mock_client.messages.create.call_args[1]
        assert call_kwargs.get("system") == "Be concise"

    def test_query_without_system(self):
        connector, mock_client = self._make_connector()
        mock_client.messages.create.return_value = _make_anthropic_response("ok")
        connector.query("prompt")

        call_kwargs = mock_client.messages.create.call_args[1]
        assert "system" not in call_kwargs

    def test_query_token_counts(self):
        connector, mock_client = self._make_connector()
        mock_client.messages.create.return_value = _make_anthropic_response(
            input_tokens=200, output_tokens=100
        )
        result = connector.query("prompt")
        assert result.input_tokens == 200
        assert result.output_tokens == 100

    def test_provider_is_anthropic(self):
        connector, _ = self._make_connector()
        assert connector.provider == ProviderType.ANTHROPIC

    def test_finish_reason_set(self):
        connector, mock_client = self._make_connector()
        mock_client.messages.create.return_value = _make_anthropic_response()
        result = connector.query("prompt")
        assert result.finish_reason == "end_turn"

    def test_is_available_true_on_success(self):
        connector, mock_client = self._make_connector()
        mock_client.models.list.return_value = MagicMock()
        assert connector.is_available() is True

    def test_is_available_false_on_error(self):
        connector, mock_client = self._make_connector()
        mock_client.models.list.side_effect = Exception("Auth failed")
        assert connector.is_available() is False

    def test_import_error_raises(self):
        import modules.connectors.anthropic_connector as ac
        original = ac.anthropic
        ac.anthropic = None
        with pytest.raises(ImportError):
            AnthropicConnector(api_key="test")
        ac.anthropic = original


# ── ConnectorRegistry ─────────────────────────────────────────────────────────


class TestConnectorRegistry:
    """Tests for the ConnectorRegistry."""

    def test_empty_registry(self):
        registry = ConnectorRegistry()
        assert registry.get_default() is None
        assert registry.list_providers() == {}

    def _make_mock_connector(self, provider_type=ProviderType.OPENAI):
        """Create a mock connector that behaves like a real LLMConnector."""
        class FakeConnector(LLMConnector):
            provider = provider_type
            default_model = "test-model"
            def query(self, prompt, **kwargs):
                return LLMResponse("ok", "test-model", provider_type)
        return FakeConnector()

    def test_register_connector(self):
        registry = ConnectorRegistry()
        conn = self._make_mock_connector(ProviderType.OPENAI)
        registry.register("openai", conn)
        assert registry.get("openai") is conn
        assert registry.get_default() is conn

    def test_first_registered_is_default(self):
        registry = ConnectorRegistry()
        conn1 = self._make_mock_connector(ProviderType.OPENAI)
        conn2 = self._make_mock_connector(ProviderType.ANTHROPIC)

        registry.register("openai", conn1)
        registry.register("anthropic", conn2)

        assert registry.get_default() is conn1

    def test_explicit_default_overrides(self):
        registry = ConnectorRegistry()
        conn1 = self._make_mock_connector(ProviderType.OPENAI)
        conn2 = self._make_mock_connector(ProviderType.ANTHROPIC)

        registry.register("openai", conn1)
        registry.register("anthropic", conn2, default=True)

        assert registry.get_default() is conn2

    def test_get_nonexistent_returns_none(self):
        registry = ConnectorRegistry()
        assert registry.get("nonexistent") is None

    def test_list_providers(self):
        registry = ConnectorRegistry()
        conn = self._make_mock_connector(ProviderType.OPENAI)
        registry.register("my-openai", conn)
        providers = registry.list_providers()
        assert "my-openai" in providers
        assert providers["my-openai"] == "openai"

    def _make_fake_openai_connector(self, provider=ProviderType.OPENAI, model="gpt-4o"):
        class FakeConn(LLMConnector):
            def query(self, prompt, **kwargs):
                return LLMResponse("ok", model, provider)
        c = FakeConn.__new__(FakeConn)
        c.provider = provider
        c.default_model = model
        return c

    def test_register_from_env_openai(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test12345678901234567890123456")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")

        fake_conn = self._make_fake_openai_connector(ProviderType.OPENAI)
        with patch("modules.connectors.registry.OpenAIConnector", return_value=fake_conn):
            registry = ConnectorRegistry()
            registry.register_from_env()

        assert "openai" in registry.list_providers()
        assert registry.get_default() is not None

    def test_register_from_env_anthropic(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-testkey12345678901234567890")

        fake_conn = self._make_fake_openai_connector(ProviderType.ANTHROPIC, "claude-sonnet-4-6")
        with patch("modules.connectors.registry.AnthropicConnector", return_value=fake_conn):
            registry = ConnectorRegistry()
            registry.register_from_env()

        assert "anthropic" in registry.list_providers()

    def test_register_from_env_no_keys(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        registry = ConnectorRegistry()
        registry.register_from_env()

        assert len(registry.list_providers()) == 0

    def test_register_from_env_ollama_detected(self, monkeypatch):
        """Local Ollama (via OPENAI_BASE_URL on localhost:11434) uses OLLAMA provider type."""
        monkeypatch.setenv("OPENAI_API_KEY", "ollama")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:11434/v1")

        fake_conn = self._make_fake_openai_connector(ProviderType.OLLAMA)
        with patch("modules.connectors.registry.OpenAIConnector", return_value=fake_conn):
            registry = ConnectorRegistry()
            registry.register_from_env()

        connector = registry.get("openai")
        assert connector is not None
        assert connector.provider == ProviderType.OLLAMA


# ── LLMConnector Abstract Base ────────────────────────────────────────────────


class TestLLMConnectorBase:
    """Tests for the LLMConnector abstract base."""

    def test_abstract_query_must_be_implemented(self):
        """Cannot instantiate LLMConnector without implementing query()."""
        with pytest.raises(TypeError):
            LLMConnector()  # type: ignore

    def test_is_available_default_true(self):
        """Default is_available() returns True."""
        class MinimalConnector(LLMConnector):
            provider = ProviderType.CUSTOM
            default_model = "test"
            def query(self, prompt, **kwargs):
                return LLMResponse("ok", "test", ProviderType.CUSTOM)

        conn = MinimalConnector()
        assert conn.is_available() is True

    def test_timed_query_sets_latency(self):
        """_timed_query() should populate latency_ms."""
        class TimingConnector(LLMConnector):
            provider = ProviderType.CUSTOM
            default_model = "test"
            def query(self, prompt, **kwargs):
                return self._timed_query(
                    lambda: LLMResponse("ok", "gpt-4o", ProviderType.OPENAI,
                                        input_tokens=10, output_tokens=5)
                )

        conn = TimingConnector()
        result = conn.query("hello")
        assert result.latency_ms >= 0.0

    def test_timed_query_sets_cost(self):
        """_timed_query() should populate cost_usd for known models."""
        class CostConnector(LLMConnector):
            provider = ProviderType.OPENAI
            default_model = "gpt-4o"
            def query(self, prompt, **kwargs):
                return self._timed_query(
                    lambda: LLMResponse("ok", "gpt-4o", ProviderType.OPENAI,
                                        input_tokens=1000, output_tokens=500)
                )

        conn = CostConnector()
        result = conn.query("hello")
        assert result.cost_usd > 0.0
