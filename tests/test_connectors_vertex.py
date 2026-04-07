"""
Tests for modules/connectors/vertex.py

All tests use unittest.mock — no real GCP credentials required.
"""

import unittest
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
from modules.connectors.vertex import VertexAIConnector, _VERTEX_PRICING


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_gemini_response(text: str, input_tokens: int = 10, output_tokens: int = 20):
    """Build a mock Gemini response object."""
    mock_candidate = MagicMock()
    mock_candidate.finish_reason = "STOP"

    mock_usage = MagicMock()
    mock_usage.prompt_token_count = input_tokens
    mock_usage.candidates_token_count = output_tokens
    mock_usage.total_token_count = input_tokens + output_tokens

    mock_response = MagicMock()
    mock_response.text = text
    mock_response.candidates = [mock_candidate]
    mock_response.usage_metadata = mock_usage
    return mock_response


def _make_palm_response(text: str):
    """Build a mock PaLM TextGenerationResponse."""
    mock_response = MagicMock()
    mock_response.text = text
    return mock_response


# ── Property tests ─────────────────────────────────────────────────────────────

class TestVertexAIConnectorProperties:
    def test_provider_name(self):
        c = VertexAIConnector(project_id="my-project")
        assert c.provider_name == "vertex"

    def test_default_model(self):
        c = VertexAIConnector(project_id="my-project", model="gemini-1.5-pro")
        assert c.default_model == "gemini-1.5-pro"

    def test_env_fallback(self, monkeypatch):
        monkeypatch.setenv("GCP_PROJECT_ID", "env-project")
        monkeypatch.setenv("GCP_REGION", "europe-west4")
        monkeypatch.setenv("VERTEX_MODEL", "gemini-1.0-pro")
        c = VertexAIConnector()
        assert c._project_id == "env-project"
        assert c._region == "europe-west4"
        assert c._model == "gemini-1.0-pro"


# ── Availability tests ─────────────────────────────────────────────────────────

class TestVertexAIIsAvailable:
    def test_unavailable_without_project_id(self):
        c = VertexAIConnector(project_id="")
        with patch.dict("os.environ", {}, clear=False):
            # Ensure no env var leaks from test environment
            import os
            os.environ.pop("GCP_PROJECT_ID", None)
            result = c.is_available()
            assert result is False

    def test_unavailable_when_sdk_missing(self, monkeypatch):
        monkeypatch.setenv("GCP_PROJECT_ID", "my-project")
        c = VertexAIConnector(project_id="my-project")
        with patch.dict("sys.modules", {"google.cloud.aiplatform": None}):
            result = c.is_available()
            assert result is False

    def test_available_when_project_id_set_and_sdk_present(self, monkeypatch):
        monkeypatch.setenv("GCP_PROJECT_ID", "my-project")
        c = VertexAIConnector(project_id="my-project")
        mock_aiplatform = MagicMock()
        with patch.dict("sys.modules", {"google.cloud.aiplatform": mock_aiplatform}):
            result = c.is_available()
            assert result is True


# ── Gemini complete tests ──────────────────────────────────────────────────────

class TestVertexAICallGemini:
    def _make_connector(self) -> VertexAIConnector:
        c = VertexAIConnector(project_id="test-project", model="gemini-1.5-flash")
        c._initialized = True  # skip SDK init
        return c

    def _mock_vertexai_modules(self, model_instance: MagicMock) -> dict:
        """Build sys.modules patches for vertexai so no real SDK is needed."""
        mock_gen_config = MagicMock()
        mock_generative_models = MagicMock()
        mock_generative_models.GenerativeModel.return_value = model_instance
        mock_generative_models.GenerationConfig = mock_gen_config
        mock_generative_models.Content = MagicMock()
        mock_generative_models.Part = MagicMock()
        return {
            "vertexai": MagicMock(),
            "vertexai.generative_models": mock_generative_models,
            "vertexai.language_models": MagicMock(),
            "google": MagicMock(),
            "google.api_core": MagicMock(),
            "google.api_core.exceptions": MagicMock(),
            "google.cloud": MagicMock(),
            "google.cloud.aiplatform": MagicMock(),
        }

    def test_gemini_complete_success(self):
        c = self._make_connector()
        mock_response = _make_gemini_response("Threat intelligence report", 15, 30)
        mock_model = MagicMock()
        mock_model.generate_content.return_value = mock_response

        with patch.dict("sys.modules", self._mock_vertexai_modules(mock_model)):
            req = ConnectorRequest(prompt="Analyze CVE-2024-1234", model="gemini-1.5-flash")
            resp = c._call_gemini(req, "gemini-1.5-flash")

        assert resp.text == "Threat intelligence report"
        assert resp.provider == "vertex"
        assert resp.model == "gemini-1.5-flash"
        assert resp.usage.input_tokens == 15
        assert resp.usage.output_tokens == 30
        assert resp.usage.cost_usd > 0

    def test_gemini_complete_with_system_prompt(self):
        c = self._make_connector()
        mock_response = _make_gemini_response("Analysis done")
        mock_model = MagicMock()
        mock_model.generate_content.return_value = mock_response

        mock_generative_models = MagicMock()
        mock_generative_models.GenerativeModel.return_value = mock_model
        mods = {
            "vertexai": MagicMock(),
            "vertexai.generative_models": mock_generative_models,
            "vertexai.language_models": MagicMock(),
            "google.api_core": MagicMock(),
            "google.api_core.exceptions": MagicMock(),
        }
        with patch.dict("sys.modules", mods):
            req = ConnectorRequest(prompt="Analyze", system="You are a security analyst.", model="gemini-1.5-flash")
            resp = c._call_gemini(req, "gemini-1.5-flash")

        # system_instruction should have been passed to GenerativeModel
        call_kwargs = mock_generative_models.GenerativeModel.call_args[1]
        assert call_kwargs.get("system_instruction") == "You are a security analyst."

    def test_gemini_no_candidates_returns_empty_text(self):
        c = self._make_connector()
        mock_response = MagicMock()
        mock_response.text = ""
        mock_response.candidates = []
        mock_response.usage_metadata = None
        mock_model = MagicMock()
        mock_model.generate_content.return_value = mock_response

        with patch.dict("sys.modules", self._mock_vertexai_modules(mock_model)):
            resp = c._call_gemini(ConnectorRequest(prompt="test"), "gemini-1.5-flash")

        assert resp.text == ""

    def _named_exc(self, class_name: str, msg: str):
        return type(class_name, (Exception,), {})(msg)

    def test_gemini_permission_denied_raises_auth_error(self):
        c = self._make_connector()
        mock_model = MagicMock()
        mock_model.generate_content.side_effect = Exception("403 IAM permission denied")

        with patch.dict("sys.modules", self._mock_vertexai_modules(mock_model)):
            with pytest.raises(ConnectorAuthError):
                c._call_gemini(ConnectorRequest(prompt="test"), "gemini-1.5-flash")

    def test_gemini_rate_limit_raises_rate_limit_error(self):
        c = self._make_connector()
        mock_model = MagicMock()
        mock_model.generate_content.side_effect = Exception("429 quota exceeded")

        with patch.dict("sys.modules", self._mock_vertexai_modules(mock_model)):
            with pytest.raises(ConnectorRateLimitError) as exc_info:
                c._call_gemini(ConnectorRequest(prompt="test"), "gemini-1.5-flash")
            assert exc_info.value.retry_after == 60.0

    def test_gemini_timeout_raises_timeout_error(self):
        c = self._make_connector()
        mock_model = MagicMock()
        mock_model.generate_content.side_effect = Exception("timeout after 60s")

        with patch.dict("sys.modules", self._mock_vertexai_modules(mock_model)):
            with pytest.raises(ConnectorTimeoutError):
                c._call_gemini(ConnectorRequest(prompt="test"), "gemini-1.5-flash")

    def test_gemini_safety_block_raises_content_filter_error(self):
        c = self._make_connector()
        mock_model = MagicMock()
        mock_model.generate_content.side_effect = Exception("SAFETY: content blocked by safety settings")

        with patch.dict("sys.modules", self._mock_vertexai_modules(mock_model)):
            with pytest.raises(ConnectorContentFilterError):
                c._call_gemini(ConnectorRequest(prompt="test"), "gemini-1.5-flash")

    def test_gemini_generic_error_wrapped(self):
        c = self._make_connector()
        mock_model = MagicMock()
        mock_model.generate_content.side_effect = Exception("UnknownError: weird thing happened")

        with patch.dict("sys.modules", self._mock_vertexai_modules(mock_model)):
            with pytest.raises(ConnectorError):
                c._call_gemini(ConnectorRequest(prompt="test"), "gemini-1.5-flash")


# ── PaLM complete tests ────────────────────────────────────────────────────────

class TestVertexAICallPalm:
    def _make_connector(self) -> VertexAIConnector:
        c = VertexAIConnector(project_id="test-project", model="text-bison@002")
        c._initialized = True
        return c

    def _mock_vertexai_language(self, model_instance: MagicMock) -> dict:
        mock_lang_models = MagicMock()
        mock_lang_models.TextGenerationModel.from_pretrained.return_value = model_instance
        return {
            "vertexai": MagicMock(),
            "vertexai.generative_models": MagicMock(),
            "vertexai.language_models": mock_lang_models,
            "google.api_core": MagicMock(),
            "google.api_core.exceptions": MagicMock(),
        }

    def test_palm_complete_success(self):
        c = self._make_connector()
        mock_response = _make_palm_response("PaLM response text")
        mock_model_instance = MagicMock()
        mock_model_instance.predict.return_value = mock_response

        with patch.dict("sys.modules", self._mock_vertexai_language(mock_model_instance)):
            req = ConnectorRequest(prompt="Summarize this finding", model="text-bison@002")
            resp = c._call_palm(req, "text-bison@002")

        assert resp.text == "PaLM response text"
        assert resp.provider == "vertex"
        assert resp.usage.input_tokens > 0  # approximated from char count

    def test_palm_with_system_prompt(self):
        c = self._make_connector()
        mock_response = _make_palm_response("response")
        mock_model_instance = MagicMock()
        mock_model_instance.predict.return_value = mock_response

        mock_lang_models = MagicMock()
        mock_lang_models.TextGenerationModel.from_pretrained.return_value = mock_model_instance
        mods = {
            "vertexai": MagicMock(),
            "vertexai.language_models": mock_lang_models,
            "google.api_core": MagicMock(),
            "google.api_core.exceptions": MagicMock(),
        }
        with patch.dict("sys.modules", mods):
            req = ConnectorRequest(prompt="Hello", system="Be precise", model="text-bison@002")
            c._call_palm(req, "text-bison@002")

        # prompt should be prepended with system
        call_args = mock_model_instance.predict.call_args
        assert "Be precise" in call_args[0][0]


# ── complete() routing tests ───────────────────────────────────────────────────

class TestVertexAICompleteRouting:
    def _make_connector(self, model="gemini-1.5-flash") -> VertexAIConnector:
        c = VertexAIConnector(project_id="test-project", model=model)
        c._initialized = True
        return c

    def test_gemini_model_routes_to_call_gemini(self):
        c = self._make_connector("gemini-1.5-flash")
        with patch.object(c, "_call_gemini", return_value=MagicMock()) as mock_gemini:
            c.complete(ConnectorRequest(prompt="test", model="gemini-1.5-pro"))
            mock_gemini.assert_called_once()

    def test_palm_model_routes_to_call_palm(self):
        c = self._make_connector("text-bison@002")
        with patch.object(c, "_call_palm", return_value=MagicMock()) as mock_palm:
            c.complete(ConnectorRequest(prompt="test", model="text-bison@002"))
            mock_palm.assert_called_once()

    def test_uses_default_model_when_not_specified(self):
        c = self._make_connector("gemini-1.5-flash")
        with patch.object(c, "_call_gemini", return_value=MagicMock()) as mock_gemini:
            c.complete(ConnectorRequest(prompt="test"))
            call_args = mock_gemini.call_args
            assert call_args[0][1] == "gemini-1.5-flash"  # model_name arg


# ── Streaming tests ────────────────────────────────────────────────────────────

class TestVertexAIStream:
    def _mock_vertexai(self, model_instance: MagicMock) -> dict:
        mock_gm = MagicMock()
        mock_gm.GenerativeModel.return_value = model_instance
        return {
            "vertexai": MagicMock(),
            "vertexai.generative_models": mock_gm,
            "vertexai.language_models": MagicMock(),
            "google.api_core": MagicMock(),
            "google.api_core.exceptions": MagicMock(),
        }

    def test_gemini_stream_yields_chunks(self):
        c = VertexAIConnector(project_id="test-project", model="gemini-1.5-flash")
        c._initialized = True

        chunk1 = MagicMock()
        chunk1.text = "Hello"
        chunk1.candidates = [MagicMock()]

        chunk2 = MagicMock()
        chunk2.text = " World"
        chunk2.candidates = [MagicMock()]

        mock_model = MagicMock()
        mock_model.generate_content.return_value = [chunk1, chunk2]

        with patch.dict("sys.modules", self._mock_vertexai(mock_model)):
            gen = c.stream(ConnectorRequest(prompt="Hello", model="gemini-1.5-flash"))
            chunks = list(gen)

        assert "Hello" in chunks
        assert " World" in chunks

    def test_palm_stream_falls_back_to_complete(self):
        c = VertexAIConnector(project_id="test-project", model="text-bison@002")
        mock_resp = MagicMock()
        mock_resp.text = "palm fallback"

        with patch.object(c, "complete", return_value=mock_resp):
            gen = c.stream(ConnectorRequest(prompt="test", model="text-bison@002"))
            chunks = list(gen)

        assert "palm fallback" in chunks

    def test_stream_falls_back_on_error(self):
        c = VertexAIConnector(project_id="test-project", model="gemini-1.5-flash")
        c._initialized = True
        mock_resp = MagicMock()
        mock_resp.text = "fallback"

        mock_model = MagicMock()
        mock_model.generate_content.side_effect = Exception("stream fail")

        with patch.dict("sys.modules", self._mock_vertexai(mock_model)):
            with patch.object(c, "complete", return_value=mock_resp):
                gen = c.stream(ConnectorRequest(prompt="test", model="gemini-1.5-flash"))
                chunks = list(gen)

        assert "fallback" in chunks


# ── Cost estimation tests ──────────────────────────────────────────────────────

class TestVertexAICostEstimation:
    def setup_method(self):
        self.c = VertexAIConnector(project_id="test-project")

    def test_known_model_pricing(self):
        cost = self.c._estimate_cost("gemini-1.5-pro", 1000, 1000)
        expected = (1000 * 0.00125 + 1000 * 0.005) / 1000
        assert abs(cost - expected) < 1e-9

    def test_unknown_model_uses_fallback(self):
        cost = self.c._estimate_cost("unknown-model-v99", 1000, 1000)
        assert cost > 0

    def test_zero_tokens(self):
        cost = self.c._estimate_cost("gemini-1.5-flash", 0, 0)
        assert cost == 0.0

    def test_all_known_models(self):
        for model in _VERTEX_PRICING:
            cost = self.c._estimate_cost(model, 1000, 1000)
            assert cost > 0, f"Zero cost for {model}"


# ── Exception mapping tests ────────────────────────────────────────────────────

class TestVertexAIExceptionMapping:
    def setup_method(self):
        self.c = VertexAIConnector(project_id="test-project")

    def _exc_with_name(self, class_name: str, msg: str):
        """Create an exception whose class name contains class_name."""
        exc_class = type(class_name, (Exception,), {})
        return exc_class(msg)

    def test_permission_denied_maps_to_auth_error(self):
        # Mapper checks exc_name for 'PermissionDenied'
        with pytest.raises(ConnectorAuthError):
            self.c._map_google_exception(self._exc_with_name("PermissionDenied", "no access"))

    def test_403_maps_to_auth_error(self):
        # Mapper checks exc_str for '403'
        with pytest.raises(ConnectorAuthError):
            self.c._map_google_exception(Exception("Error 403: forbidden"))

    def test_unauthenticated_maps_to_auth_error(self):
        # Mapper checks exc_name for 'Unauthenticated'
        with pytest.raises(ConnectorAuthError):
            self.c._map_google_exception(self._exc_with_name("Unauthenticated", "token missing"))

    def test_resource_exhausted_maps_to_rate_limit(self):
        # Mapper checks exc_name for 'ResourceExhausted'
        with pytest.raises(ConnectorRateLimitError):
            self.c._map_google_exception(self._exc_with_name("ResourceExhausted", "quota exceeded"))

    def test_429_maps_to_rate_limit(self):
        # Mapper checks exc_str for '429'
        with pytest.raises(ConnectorRateLimitError):
            self.c._map_google_exception(Exception("HTTP 429: too many requests"))

    def test_deadline_exceeded_maps_to_timeout(self):
        # Mapper checks exc_name for 'DeadlineExceeded'
        with pytest.raises(ConnectorTimeoutError):
            self.c._map_google_exception(self._exc_with_name("DeadlineExceeded", "deadline exceeded"))

    def test_safety_maps_to_content_filter(self):
        # Mapper checks exc_str for 'SAFETY'
        with pytest.raises(ConnectorContentFilterError):
            self.c._map_google_exception(Exception("SAFETY: content blocked"))

    def test_blocked_maps_to_content_filter(self):
        # Mapper checks exc_str for 'blocked'
        with pytest.raises(ConnectorContentFilterError):
            self.c._map_google_exception(Exception("Content was blocked by safety filter"))

    def test_generic_maps_to_connector_error(self):
        with pytest.raises(ConnectorError):
            self.c._map_google_exception(Exception("SomeRandomError: unknown"))
