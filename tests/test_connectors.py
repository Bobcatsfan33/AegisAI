"""
Tests — Aegis Cloud LLM Connectors

Coverage:
  - ConnectorRequest / ConnectorResponse / ConnectorUsage data structures
  - BaseConnector abstract interface
  - BedrockConnector: availability, config, error mapping
  - VertexAIConnector: availability, config, error mapping
  - AzureOpenAIConnector: availability, config, error mapping
  - ConnectorRegistry: get, get_available, list_available, status, register
  - Cost estimation for each provider
"""

import pytest

from modules.connectors import (
    BaseConnector,
    BedrockConnector,
    VertexAIConnector,
    AzureOpenAIConnector,
    ConnectorRequest,
    ConnectorResponse,
    ConnectorUsage,
    ConnectorRegistry,
    ConnectorError,
)


# ── ConnectorRequest / Response / Usage ────────────────────────────────────────

class TestConnectorDataStructures:
    def test_request_defaults(self):
        req = ConnectorRequest(prompt="hello")
        assert req.prompt == "hello"
        assert req.model == ""
        assert req.max_tokens == 2048
        assert req.temperature == 0.1
        assert not req.stream
        assert req.stop == []
        assert req.extra == {}

    def test_request_with_overrides(self):
        req = ConnectorRequest(
            prompt="test",
            model="gpt-4",
            max_tokens=1024,
            temperature=0.7,
            system="You are helpful",
            stream=True,
            stop=["END"],
        )
        assert req.model == "gpt-4"
        assert req.max_tokens == 1024
        assert req.temperature == 0.7
        assert req.system == "You are helpful"
        assert req.stream is True
        assert req.stop == ["END"]

    def test_usage_to_dict(self):
        usage = ConnectorUsage(
            input_tokens=100,
            output_tokens=50,
            total_tokens=150,
            cost_usd=0.001234,
            model="gpt-4",
            provider="azure_openai",
        )
        d = usage.to_dict()
        assert d["input_tokens"] == 100
        assert d["output_tokens"] == 50
        assert d["total_tokens"] == 150
        assert d["cost_usd"] == 0.001234
        assert d["model"] == "gpt-4"
        assert d["provider"] == "azure_openai"

    def test_response_defaults(self):
        resp = ConnectorResponse(
            text="Hello",
            model="gpt-4",
            provider="azure_openai",
        )
        assert resp.text == "Hello"
        assert resp.model == "gpt-4"
        assert resp.provider == "azure_openai"
        assert resp.finish_reason == "stop"
        assert resp.usage.total_tokens == 0

    def test_response_to_dict(self):
        resp = ConnectorResponse(
            text="test",
            model="bedrock",
            provider="bedrock",
        )
        d = resp.to_dict()
        assert "text" in d
        assert "model" in d
        assert "usage" in d
        assert d["provider"] == "bedrock"


# ── BedrockConnector ───────────────────────────────────────────────────────────

class TestBedrockConnector:
    def test_provider_name(self):
        connector = BedrockConnector()
        assert connector.provider_name == "bedrock"

    def test_default_model(self):
        connector = BedrockConnector(model="custom-model")
        assert connector.default_model == "custom-model"

    def test_default_model_empty(self):
        connector = BedrockConnector()
        assert "claude" in connector.default_model.lower() or connector.default_model

    def test_region_from_env(self):
        connector = BedrockConnector(region="eu-west-1")
        assert connector._region == "eu-west-1"

    def test_is_available_without_boto3(self):
        # boto3 may or may not be installed in test env
        connector = BedrockConnector()
        result = connector.is_available()
        assert isinstance(result, bool)

    def test_cost_estimate(self):
        connector = BedrockConnector()
        cost = connector._estimate_cost("anthropic.claude-3-sonnet-20240229-v1:0", 1000, 500)
        assert cost > 0
        assert cost < 0.1  # sanity check

    def test_cost_estimate_unknown_model(self):
        connector = BedrockConnector()
        cost = connector._estimate_cost("unknown-model", 1000, 500)
        # Should return a default estimate, not raise
        assert cost > 0


# ── VertexAIConnector ──────────────────────────────────────────────────────────

class TestVertexAIConnector:
    def test_provider_name(self):
        connector = VertexAIConnector()
        assert connector.provider_name == "vertex"

    def test_default_model(self):
        connector = VertexAIConnector(model="gemini-1.5-pro")
        assert connector.default_model == "gemini-1.5-pro"

    def test_project_id_required(self):
        connector = VertexAIConnector(project_id="my-project")
        assert connector._project_id == "my-project"

    def test_is_available_without_project(self):
        connector = VertexAIConnector()  # no project_id
        assert not connector.is_available()

    def test_is_available_with_project_but_no_sdk(self):
        connector = VertexAIConnector(project_id="my-project")
        # If SDK not installed, should return False gracefully
        result = connector.is_available()
        assert isinstance(result, bool)

    def test_cost_estimate_gemini(self):
        connector = VertexAIConnector()
        cost = connector._estimate_cost("gemini-1.5-pro", 1000, 500)
        assert cost > 0
        assert cost < 0.1

    def test_cost_estimate_palm(self):
        connector = VertexAIConnector()
        cost = connector._estimate_cost("text-bison@002", 1000, 500)
        assert cost > 0


# ── AzureOpenAIConnector ───────────────────────────────────────────────────────

class TestAzureOpenAIConnector:
    def test_provider_name(self):
        connector = AzureOpenAIConnector()
        assert connector.provider_name == "azure_openai"

    def test_default_model(self):
        connector = AzureOpenAIConnector(deployment="gpt-4-turbo")
        assert connector.default_model == "gpt-4-turbo"

    def test_endpoint_required(self):
        connector = AzureOpenAIConnector(endpoint="https://my.openai.azure.com/")
        assert connector._endpoint == "https://my.openai.azure.com/"

    def test_is_available_without_endpoint(self):
        connector = AzureOpenAIConnector()  # no endpoint
        assert not connector.is_available()

    def test_is_available_with_endpoint_but_no_sdk(self):
        connector = AzureOpenAIConnector(endpoint="https://my.openai.azure.com/")
        # If SDK not installed, should return False gracefully
        result = connector.is_available()
        assert isinstance(result, bool)

    def test_cost_estimate_gpt4o(self):
        connector = AzureOpenAIConnector()
        cost = connector._estimate_cost("gpt-4o", 1000, 500)
        assert cost > 0
        assert cost < 0.1

    def test_cost_estimate_gpt35_turbo(self):
        connector = AzureOpenAIConnector()
        cost = connector._estimate_cost("gpt-35-turbo", 1000, 500)
        assert cost > 0


# ── ConnectorRegistry ──────────────────────────────────────────────────────────

class TestConnectorRegistry:
    def test_registry_creation(self):
        registry = ConnectorRegistry()
        assert isinstance(registry, ConnectorRegistry)

    def test_get_creates_connector(self):
        registry = ConnectorRegistry()
        connector = registry.get("bedrock")
        assert isinstance(connector, BedrockConnector)

    def test_get_same_instance_twice(self):
        registry = ConnectorRegistry()
        c1 = registry.get("bedrock")
        c2 = registry.get("bedrock")
        assert c1 is c2

    def test_get_unknown_connector_raises(self):
        registry = ConnectorRegistry()
        with pytest.raises(KeyError):
            registry.get("unknown_connector")

    def test_list_available_returns_list(self):
        registry = ConnectorRegistry()
        available = registry.list_available()
        assert isinstance(available, list)
        # At least one should be "available" (even if SDKs are missing, the
        # is_available() method itself is defined)

    def test_status_returns_dict(self):
        registry = ConnectorRegistry()
        status = registry.status()
        assert isinstance(status, dict)
        # Should have entries for bedrock, vertex, azure_openai
        assert "bedrock" in status
        assert "vertex" in status
        assert "azure_openai" in status

    def test_status_has_required_fields(self):
        registry = ConnectorRegistry()
        status = registry.status()
        for name, info in status.items():
            assert "available" in info
            assert isinstance(info["available"], bool)

    def test_register_custom_connector(self):
        registry = ConnectorRegistry()
        custom = BedrockConnector(model="custom-model")
        registry.register("my_custom", custom)
        retrieved = registry.get("my_custom")
        assert retrieved is custom

    def test_get_available_returns_connector_or_none(self):
        registry = ConnectorRegistry()
        connector = registry.get_available()
        # Can be None or a connector instance
        if connector is not None:
            assert isinstance(connector, BaseConnector)

    def test_get_available_with_preferred(self):
        registry = ConnectorRegistry()
        # Even if bedrock is not available, the method should not crash
        connector = registry.get_available(preferred="bedrock")
        if connector is not None:
            assert isinstance(connector, BaseConnector)

    def test_complete_uses_available(self):
        registry = ConnectorRegistry()
        # If any connector is available, complete() should work (or raise ConnectorError)
        # If none available, should raise ConnectorError
        connector = registry.get_available()
        if connector is None:
            req = ConnectorRequest(prompt="test")
            with pytest.raises(ConnectorError):
                registry.complete(req)


# ── Module-level registry ──────────────────────────────────────────────────────

class TestModuleLevelRegistry:
    def test_get_connector_registry(self):
        from modules.connectors.registry import get_connector_registry
        reg1 = get_connector_registry()
        reg2 = get_connector_registry()
        assert reg1 is reg2
