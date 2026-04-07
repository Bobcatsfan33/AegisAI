"""
Tests for modules/connectors/bedrock.py

All tests use unittest.mock — no real AWS credentials required.
"""

import json
import unittest
from io import BytesIO
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from modules.connectors.base import (
    ConnectorAuthError,
    ConnectorContentFilterError,
    ConnectorError,
    ConnectorRateLimitError,
    ConnectorRequest,
    ConnectorTimeoutError,
)
from modules.connectors.bedrock import BedrockConnector, _BEDROCK_PRICING


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_invoke_response(body_dict: dict) -> dict:
    """Return a mock invoke_model response with a streaming body."""
    raw_body = json.dumps(body_dict).encode()
    mock_body = MagicMock()
    mock_body.read.return_value = raw_body
    return {"body": mock_body}


def _claude_response(text: str = "OK", input_tokens: int = 10, output_tokens: int = 20) -> dict:
    return {
        "content": [{"type": "text", "text": text}],
        "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
        "stop_reason": "end_turn",
    }


def _titan_response(text: str = "OK") -> dict:
    return {
        "results": [{"outputText": text, "tokenCount": 20}],
        "inputTextTokenCount": 10,
    }


def _llama_response(text: str = "OK") -> dict:
    return {
        "generation": text,
        "prompt_token_count": 10,
        "generation_token_count": 20,
    }


# ── BedrockConnector basic tests ───────────────────────────────────────────────

class TestBedrockConnectorProperties:
    def test_provider_name(self):
        c = BedrockConnector()
        assert c.provider_name == "bedrock"

    def test_default_model_env_override(self, monkeypatch):
        monkeypatch.setenv("BEDROCK_MODEL", "anthropic.claude-3-opus-20240229-v1:0")
        c = BedrockConnector()
        assert c.default_model == "anthropic.claude-3-opus-20240229-v1:0"

    def test_explicit_constructor_args(self):
        c = BedrockConnector(region="us-west-2", model="meta.llama3-8b-instruct-v1:0", timeout=30, max_retries=2)
        assert c._region == "us-west-2"
        assert c._model == "meta.llama3-8b-instruct-v1:0"
        assert c._timeout == 30
        assert c._max_retries == 2


class TestBedrockIsAvailable:
    def test_available_when_boto3_and_credentials_ok(self):
        c = BedrockConnector()
        mock_boto3 = MagicMock()
        mock_bedrock_client = MagicMock()
        mock_bedrock_client.list_foundation_models.return_value = {"modelSummaries": []}
        mock_boto3.client.return_value = mock_bedrock_client
        mock_botocore_config = MagicMock()
        mock_botocore = MagicMock()
        mock_botocore.config.Config = mock_botocore_config
        with patch.dict("sys.modules", {"boto3": mock_boto3, "botocore": mock_botocore, "botocore.config": mock_botocore.config, "botocore.exceptions": MagicMock()}):
            c._client = mock_boto3.client("bedrock-runtime")
            assert c.is_available() is True

    def test_unavailable_when_boto3_missing(self):
        c = BedrockConnector()
        with patch.dict("sys.modules", {"boto3": None, "botocore": None}):
            result = c.is_available()
            assert result is False

    def test_unavailable_when_exception_raised(self):
        c = BedrockConnector()
        mock_boto3 = MagicMock()
        mock_boto3.client.side_effect = Exception("no credentials")
        mock_botocore = MagicMock()
        with patch.dict("sys.modules", {"boto3": mock_boto3, "botocore": mock_botocore, "botocore.config": mock_botocore.config, "botocore.exceptions": MagicMock()}):
            result = c.is_available()
            assert result is False


class TestBedrockBuildBody:
    def setup_method(self):
        self.c = BedrockConnector()

    def test_claude_body_basic(self):
        req = ConnectorRequest(prompt="Hello", max_tokens=100, temperature=0.5)
        body = self.c._build_body(req, "anthropic.claude-3-haiku-20240307-v1:0")
        assert body["anthropic_version"] == "bedrock-2023-05-31"
        assert body["messages"][0]["content"] == "Hello"
        assert body["max_tokens"] == 100
        assert body["temperature"] == 0.5
        assert "system" not in body

    def test_claude_body_with_system(self):
        req = ConnectorRequest(prompt="Hello", system="You are Aegis.", max_tokens=100)
        body = self.c._build_body(req, "anthropic.claude-3-haiku-20240307-v1:0")
        assert body["system"] == "You are Aegis."

    def test_claude_body_with_stop(self):
        req = ConnectorRequest(prompt="Hello", stop=["END"])
        body = self.c._build_body(req, "anthropic.claude-3-sonnet-20240229-v1:0")
        assert body["stop_sequences"] == ["END"]

    def test_titan_body(self):
        req = ConnectorRequest(prompt="Tell me", max_tokens=512)
        body = self.c._build_body(req, "amazon.titan-text-express-v1")
        assert "inputText" in body
        assert "textGenerationConfig" in body
        assert body["textGenerationConfig"]["maxTokenCount"] == 512

    def test_titan_body_with_system(self):
        req = ConnectorRequest(prompt="Tell me", system="Context:", max_tokens=512)
        body = self.c._build_body(req, "amazon.titan-text-express-v1")
        assert body["inputText"].startswith("Context:")

    def test_llama_body(self):
        req = ConnectorRequest(prompt="Explain", max_tokens=256)
        body = self.c._build_body(req, "meta.llama3-8b-instruct-v1:0")
        assert "[INST]" in body["prompt"]
        assert body["max_gen_len"] == 256

    def test_llama_body_with_system(self):
        req = ConnectorRequest(prompt="Explain", system="Expert mode", max_tokens=256)
        body = self.c._build_body(req, "meta.llama3-8b-instruct-v1:0")
        assert "<<SYS>>" in body["prompt"]

    def test_unknown_model_fallback(self):
        req = ConnectorRequest(prompt="Hello")
        body = self.c._build_body(req, "unknown.model-v1")
        # Falls through to Claude-format fallback
        assert "anthropic_version" in body


class TestBedrockParseResponse:
    def setup_method(self):
        self.c = BedrockConnector()

    def test_parse_claude(self):
        raw = _claude_response("Claude says hi", 15, 25)
        text, usage = self.c._parse_response(raw, "anthropic.claude-3-haiku-20240307-v1:0")
        assert text == "Claude says hi"
        assert usage.input_tokens == 15
        assert usage.output_tokens == 25
        assert usage.total_tokens == 40
        assert usage.provider == "bedrock"

    def test_parse_titan(self):
        raw = _titan_response("Titan says hi")
        text, usage = self.c._parse_response(raw, "amazon.titan-text-express-v1")
        assert text == "Titan says hi"
        assert usage.total_tokens > 0

    def test_parse_llama(self):
        raw = _llama_response("Llama says hi")
        text, usage = self.c._parse_response(raw, "meta.llama3-8b-instruct-v1:0")
        assert text == "Llama says hi"
        assert usage.input_tokens == 10
        assert usage.output_tokens == 20


class TestBedrockComplete:
    def setup_method(self):
        """Patch botocore.exceptions so complete() can import from it without boto3 installed."""
        mock_botocore_exc = MagicMock()
        mock_botocore_exc.ClientError = Exception
        mock_botocore_exc.NoCredentialsError = Exception
        mock_botocore_exc.ReadTimeoutError = Exception
        self._botocore_patch = patch.dict(
            "sys.modules",
            {
                "botocore": MagicMock(),
                "botocore.exceptions": mock_botocore_exc,
                "botocore.config": MagicMock(),
            }
        )
        self._botocore_patch.start()

    def teardown_method(self):
        self._botocore_patch.stop()

    def _make_connector_with_mock_client(self, response_body: dict):
        c = BedrockConnector()
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = _make_invoke_response(response_body)
        c._client = mock_client
        return c, mock_client

    def test_claude_complete_success(self):
        c, mock_client = self._make_connector_with_mock_client(
            _claude_response("Security analysis complete", 20, 50)
        )
        req = ConnectorRequest(prompt="Analyze this finding", model="anthropic.claude-3-haiku-20240307-v1:0")
        resp = c.complete(req)
        assert resp.text == "Security analysis complete"
        assert resp.provider == "bedrock"
        assert resp.model == "anthropic.claude-3-haiku-20240307-v1:0"
        assert resp.usage.input_tokens == 20
        assert resp.usage.output_tokens == 50
        assert resp.usage.cost_usd > 0
        mock_client.invoke_model.assert_called_once()

    def test_titan_complete_success(self):
        c, mock_client = self._make_connector_with_mock_client(_titan_response("Titan response"))
        req = ConnectorRequest(prompt="Hello Titan", model="amazon.titan-text-express-v1")
        resp = c.complete(req)
        assert resp.text == "Titan response"
        assert resp.provider == "bedrock"

    def test_llama_complete_success(self):
        c, mock_client = self._make_connector_with_mock_client(_llama_response("Llama response"))
        req = ConnectorRequest(prompt="Hello Llama", model="meta.llama3-8b-instruct-v1:0")
        resp = c.complete(req)
        assert resp.text == "Llama response"

    def test_uses_default_model_when_not_specified(self):
        c = BedrockConnector(model="anthropic.claude-3-haiku-20240307-v1:0")
        mock_client = MagicMock()
        mock_client.invoke_model.return_value = _make_invoke_response(_claude_response("hi"))
        c._client = mock_client
        req = ConnectorRequest(prompt="Hello")  # no model specified
        resp = c.complete(req)
        call_kwargs = mock_client.invoke_model.call_args[1]
        assert call_kwargs["modelId"] == "anthropic.claude-3-haiku-20240307-v1:0"

    def test_auth_error_on_no_credentials(self):
        c = BedrockConnector()
        mock_client = MagicMock()
        mock_client.invoke_model.side_effect = Exception("NoCredentialsError: credentials not found")
        c._client = mock_client
        with pytest.raises(ConnectorAuthError):
            c.complete(ConnectorRequest(prompt="Hello"))

    def test_rate_limit_error(self):
        c = BedrockConnector()
        mock_client = MagicMock()
        mock_client.invoke_model.side_effect = Exception("ThrottlingException: rate exceeded")
        c._client = mock_client
        with pytest.raises(ConnectorRateLimitError) as exc_info:
            c.complete(ConnectorRequest(prompt="Hello"))
        assert exc_info.value.retry_after == 30.0

    def test_timeout_error(self):
        c = BedrockConnector()
        mock_client = MagicMock()
        mock_client.invoke_model.side_effect = Exception("ReadTimeoutError: timed out")
        c._client = mock_client
        with pytest.raises(ConnectorTimeoutError):
            c.complete(ConnectorRequest(prompt="Hello"))

    def test_access_denied_error(self):
        c = BedrockConnector()
        mock_client = MagicMock()
        mock_client.invoke_model.side_effect = Exception("AccessDeniedException: access denied")
        c._client = mock_client
        with pytest.raises(ConnectorAuthError):
            c.complete(ConnectorRequest(prompt="Hello"))

    def test_content_filter_error(self):
        c = BedrockConnector()
        mock_client = MagicMock()
        mock_client.invoke_model.side_effect = Exception("ValidationException: content policy violation")
        c._client = mock_client
        with pytest.raises(ConnectorContentFilterError):
            c.complete(ConnectorRequest(prompt="Hello"))

    def test_generic_error_wrapped(self):
        c = BedrockConnector()
        mock_client = MagicMock()
        mock_client.invoke_model.side_effect = Exception("UnknownError: something weird")
        c._client = mock_client
        with pytest.raises(ConnectorError):
            c.complete(ConnectorRequest(prompt="Hello"))


class TestBedrockStream:
    def setup_method(self):
        mock_botocore_exc = MagicMock()
        mock_botocore_exc.ClientError = Exception
        mock_botocore_exc.NoCredentialsError = Exception
        mock_botocore_exc.ReadTimeoutError = Exception
        self._botocore_patch = patch.dict(
            "sys.modules",
            {
                "botocore": MagicMock(),
                "botocore.exceptions": mock_botocore_exc,
                "botocore.config": MagicMock(),
            }
        )
        self._botocore_patch.start()

    def teardown_method(self):
        self._botocore_patch.stop()

    def test_stream_yields_chunks(self):
        c = BedrockConnector(model="anthropic.claude-3-haiku-20240307-v1:0")
        mock_client = MagicMock()
        chunks = [
            {"type": "message_start", "message": {"usage": {"input_tokens": 10}}},
            {"type": "content_block_delta", "delta": {"text": "Hello"}},
            {"type": "content_block_delta", "delta": {"text": " World"}},
            {"type": "message_delta", "usage": {"output_tokens": 5}},
        ]
        mock_event_stream = [{"chunk": {"bytes": json.dumps(c).encode()}} for c in chunks]
        mock_client.invoke_model_with_response_stream.return_value = {"body": mock_event_stream}
        c._client = mock_client

        gen = c.stream(ConnectorRequest(prompt="Hello"))
        collected = list(gen)
        assert "Hello" in collected
        assert " World" in collected

    def test_stream_falls_back_on_error(self):
        """If streaming fails, should fall back to complete()."""
        c = BedrockConnector(model="anthropic.claude-3-haiku-20240307-v1:0")
        mock_client = MagicMock()
        mock_client.invoke_model_with_response_stream.side_effect = Exception("stream error")
        mock_client.invoke_model.return_value = _make_invoke_response(_claude_response("fallback text"))
        c._client = mock_client

        gen = c.stream(ConnectorRequest(prompt="Hello"))
        collected = list(gen)
        assert "fallback text" in collected


class TestBedrockCostEstimation:
    def setup_method(self):
        self.c = BedrockConnector()

    def test_known_model_pricing(self):
        cost = self.c._estimate_cost("anthropic.claude-3-sonnet-20240229-v1:0", 1000, 1000)
        expected = (1000 * 0.003 + 1000 * 0.015) / 1000
        assert abs(cost - expected) < 1e-9

    def test_unknown_model_uses_fallback(self):
        cost = self.c._estimate_cost("unknown.model", 1000, 1000)
        assert cost > 0  # fallback pricing applied

    def test_zero_tokens_zero_cost(self):
        cost = self.c._estimate_cost("anthropic.claude-3-haiku-20240307-v1:0", 0, 0)
        assert cost == 0.0

    def test_all_known_models_have_pricing(self):
        for model in _BEDROCK_PRICING:
            cost = self.c._estimate_cost(model, 1000, 1000)
            assert cost > 0, f"Zero cost for {model}"
