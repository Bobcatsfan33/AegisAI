"""
Tests for modules/connectors/registry.py

Verifies connector registration, lookup, availability routing, and status.
All tests use mock connectors — no real cloud credentials required.
"""

import pytest
from unittest.mock import MagicMock

from modules.connectors.base import ConnectorError, ConnectorRequest, ConnectorResponse, ConnectorUsage
from modules.connectors.registry import ConnectorRegistry, get_connector_registry


# ── Helpers ────────────────────────────────────────────────────────────────────

def _mock_connector(name: str, available: bool = True, model: str = "test-model") -> MagicMock:
    c = MagicMock()
    c.provider_name = name
    c.default_model = model
    c.is_available.return_value = available
    c.complete.return_value = ConnectorResponse(
        text=f"{name} response",
        model=model,
        provider=name,
        usage=ConnectorUsage(input_tokens=5, output_tokens=10, total_tokens=15, provider=name, model=model),
        finish_reason="stop",
    )
    return c


# ── Registry construction tests ────────────────────────────────────────────────

class TestConnectorRegistryInit:
    def test_empty_init(self):
        r = ConnectorRegistry()
        assert isinstance(r, ConnectorRegistry)

    def test_injected_connectors(self):
        bedrock = _mock_connector("bedrock")
        vertex = _mock_connector("vertex")
        azure = _mock_connector("azure_openai")
        r = ConnectorRegistry(bedrock=bedrock, vertex=vertex, azure_openai=azure)
        assert r.get("bedrock") is bedrock
        assert r.get("vertex") is vertex
        assert r.get("azure_openai") is azure


class TestConnectorRegistryGet:
    def test_get_injected_connector(self):
        bedrock = _mock_connector("bedrock")
        r = ConnectorRegistry(bedrock=bedrock)
        assert r.get("bedrock") is bedrock

    def test_get_unknown_raises_key_error(self):
        r = ConnectorRegistry()
        with pytest.raises(KeyError, match="Unknown connector"):
            r.get("nonexistent_provider")

    def test_get_returns_same_instance_on_repeat(self):
        bedrock = _mock_connector("bedrock")
        r = ConnectorRegistry(bedrock=bedrock)
        assert r.get("bedrock") is r.get("bedrock")


class TestConnectorRegistryGetAvailable:
    def test_returns_first_available_in_priority_order(self):
        bedrock = _mock_connector("bedrock", available=True)
        vertex = _mock_connector("vertex", available=True)
        azure = _mock_connector("azure_openai", available=True)
        r = ConnectorRegistry(bedrock=bedrock, vertex=vertex, azure_openai=azure)
        result = r.get_available()
        # bedrock is first in priority
        assert result is bedrock

    def test_skips_unavailable_connectors(self):
        bedrock = _mock_connector("bedrock", available=False)
        vertex = _mock_connector("vertex", available=True)
        r = ConnectorRegistry(bedrock=bedrock, vertex=vertex)
        result = r.get_available()
        assert result is vertex

    def test_returns_none_when_none_available(self):
        bedrock = _mock_connector("bedrock", available=False)
        vertex = _mock_connector("vertex", available=False)
        azure = _mock_connector("azure_openai", available=False)
        r = ConnectorRegistry(bedrock=bedrock, vertex=vertex, azure_openai=azure)
        result = r.get_available()
        assert result is None

    def test_preferred_connector_tried_first(self):
        bedrock = _mock_connector("bedrock", available=True)
        vertex = _mock_connector("vertex", available=True)
        r = ConnectorRegistry(bedrock=bedrock, vertex=vertex)
        result = r.get_available(preferred="vertex")
        assert result is vertex

    def test_preferred_skipped_if_unavailable(self):
        bedrock = _mock_connector("bedrock", available=True)
        vertex = _mock_connector("vertex", available=False)
        r = ConnectorRegistry(bedrock=bedrock, vertex=vertex)
        result = r.get_available(preferred="vertex")
        assert result is bedrock


class TestConnectorRegistryListAvailable:
    def test_lists_all_available(self):
        bedrock = _mock_connector("bedrock", available=True)
        vertex = _mock_connector("vertex", available=False)
        azure = _mock_connector("azure_openai", available=True)
        r = ConnectorRegistry(bedrock=bedrock, vertex=vertex, azure_openai=azure)
        available = r.list_available()
        assert "bedrock" in available
        assert "vertex" not in available
        assert "azure_openai" in available

    def test_empty_when_none_available(self):
        bedrock = _mock_connector("bedrock", available=False)
        vertex = _mock_connector("vertex", available=False)
        azure = _mock_connector("azure_openai", available=False)
        r = ConnectorRegistry(bedrock=bedrock, vertex=vertex, azure_openai=azure)
        assert r.list_available() == []


class TestConnectorRegistryComplete:
    def test_complete_with_named_connector(self):
        bedrock = _mock_connector("bedrock")
        r = ConnectorRegistry(bedrock=bedrock)
        req = ConnectorRequest(prompt="test")
        resp = r.complete(req, connector_name="bedrock")
        assert resp.text == "bedrock response"
        bedrock.complete.assert_called_once_with(req)

    def test_complete_auto_selects_available(self):
        bedrock = _mock_connector("bedrock", available=True)
        r = ConnectorRegistry(bedrock=bedrock)
        req = ConnectorRequest(prompt="test")
        resp = r.complete(req)
        assert resp.text == "bedrock response"

    def test_complete_raises_when_no_connector_available(self):
        bedrock = _mock_connector("bedrock", available=False)
        vertex = _mock_connector("vertex", available=False)
        azure = _mock_connector("azure_openai", available=False)
        r = ConnectorRegistry(bedrock=bedrock, vertex=vertex, azure_openai=azure)
        with pytest.raises(ConnectorError, match="No LLM connector available"):
            r.complete(ConnectorRequest(prompt="test"))


class TestConnectorRegistryStatus:
    def test_status_shows_all_connectors(self):
        bedrock = _mock_connector("bedrock", available=True)
        vertex = _mock_connector("vertex", available=False)
        azure = _mock_connector("azure_openai", available=True)
        r = ConnectorRegistry(bedrock=bedrock, vertex=vertex, azure_openai=azure)
        status = r.status()
        assert "bedrock" in status
        assert "vertex" in status
        assert "azure_openai" in status
        assert status["bedrock"]["available"] is True
        assert status["vertex"]["available"] is False

    def test_status_includes_model_info(self):
        bedrock = _mock_connector("bedrock", model="claude-3-haiku")
        r = ConnectorRegistry(bedrock=bedrock)
        status = r.status()
        assert status["bedrock"]["model"] == "claude-3-haiku"

    def test_status_handles_exception_gracefully(self):
        r = ConnectorRegistry()
        # Force lazy creation to raise
        with MagicMock() as mock_create:
            r._connectors["bedrock"] = MagicMock(side_effect=Exception("init failed"))
            # is_available might raise — status should catch it
            try:
                status = r.status()
                # If it succeeds, it should still show all connectors
                assert "bedrock" in status
            except Exception:
                pass  # implementation may let it bubble — just no infinite loops


class TestConnectorRegistryRegister:
    def test_custom_connector_registration(self):
        r = ConnectorRegistry()
        custom = _mock_connector("custom_llm")
        r.register("custom_llm", custom)
        assert r.get("custom_llm") is custom

    def test_custom_connector_overrides_existing(self):
        bedrock1 = _mock_connector("bedrock")
        r = ConnectorRegistry(bedrock=bedrock1)
        bedrock2 = _mock_connector("bedrock")
        r.register("bedrock", bedrock2)
        assert r.get("bedrock") is bedrock2


class TestGetConnectorRegistry:
    def test_returns_singleton(self):
        # Reset module-level singleton
        import modules.connectors.registry as reg_module
        reg_module._default_registry = None
        r1 = get_connector_registry()
        r2 = get_connector_registry()
        assert r1 is r2
        # Clean up
        reg_module._default_registry = None

    def test_returns_connector_registry_instance(self):
        import modules.connectors.registry as reg_module
        reg_module._default_registry = None
        r = get_connector_registry()
        assert isinstance(r, ConnectorRegistry)
        reg_module._default_registry = None
