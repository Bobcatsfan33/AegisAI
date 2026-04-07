"""
Aegis — GCP Vertex AI LLM Connector  (v2.11.0)

Real implementation using google-cloud-aiplatform SDK.

Supported models:
  - Gemini: gemini-1.5-pro, gemini-1.5-flash, gemini-1.0-pro
  - PaLM:   text-bison@002, text-bison@001 (deprecated but still available)

Authentication:
  - Service account key file: GOOGLE_APPLICATION_CREDENTIALS env var
  - Workload Identity (GKE) — automatic via gcloud metadata server
  - Application Default Credentials (ADC) — gcloud auth application-default login

Environment variables:
  GCP_PROJECT_ID              — GCP project ID (required)
  GCP_REGION                  — Vertex AI region (default: us-central1)
  VERTEX_MODEL                — override default model
  VERTEX_TIMEOUT              — request timeout in seconds (default: 60)
"""

import logging
import os
from typing import Any, Generator, Optional

from .base import (
    BaseConnector,
    ConnectorAuthError,
    ConnectorContentFilterError,
    ConnectorError,
    ConnectorRateLimitError,
    ConnectorRequest,
    ConnectorResponse,
    ConnectorTimeoutError,
    ConnectorUsage,
)

logger = logging.getLogger(__name__)

# ── Pricing (approximate, USD per 1K characters as of Q1 2025) ────────────────
# Vertex AI pricing is per character, not per token. We convert approx 4 chars/token.
_VERTEX_PRICING: dict[str, dict] = {
    "gemini-1.5-pro":     {"in": 0.00125,  "out": 0.005},    # per 1K tokens
    "gemini-1.5-flash":   {"in": 0.000075, "out": 0.0003},
    "gemini-1.0-pro":     {"in": 0.0005,   "out": 0.0015},
    "text-bison@002":     {"in": 0.000125, "out": 0.000125},
    "text-bison@001":     {"in": 0.000125, "out": 0.000125},
}


class VertexAIConnector(BaseConnector):
    """
    GCP Vertex AI connector supporting Gemini and PaLM models.
    """

    def __init__(
        self,
        project_id: str = "",
        region: str = "",
        model: str = "",
        timeout: int = 0,
    ):
        self._project_id = project_id or os.getenv("GCP_PROJECT_ID", "")
        self._region     = region or os.getenv("GCP_REGION", "us-central1")
        self._model      = model or os.getenv("VERTEX_MODEL", "gemini-1.5-flash")
        self._timeout    = timeout or int(os.getenv("VERTEX_TIMEOUT", "60"))
        self._initialized = False

    @property
    def provider_name(self) -> str:
        return "vertex"

    @property
    def default_model(self) -> str:
        return self._model

    def _init_sdk(self) -> None:
        """Initialize Vertex AI SDK (once)."""
        if self._initialized:
            return
        try:
            import vertexai
            vertexai.init(project=self._project_id, location=self._region)
            self._initialized = True
        except ImportError:
            raise ConnectorAuthError(
                "google-cloud-aiplatform not installed. "
                "Run: pip install google-cloud-aiplatform"
            )
        except Exception as exc:
            raise ConnectorAuthError(f"Vertex AI init failed: {exc}") from exc

    def is_available(self) -> bool:
        """Check if SDK is installed and project ID is configured."""
        if not self._project_id:
            logger.debug("[Vertex] GCP_PROJECT_ID not set")
            return False
        try:
            import google.cloud.aiplatform  # noqa: F401
            return True
        except ImportError:
            logger.debug("[Vertex] google-cloud-aiplatform not installed")
            return False

    def _call_gemini(self, request: ConnectorRequest, model_name: str) -> ConnectorResponse:
        """Call a Gemini model via the GenerativeModel API."""
        try:
            import vertexai
            from vertexai.generative_models import GenerativeModel, GenerationConfig, Content, Part
            from google.api_core import exceptions as google_exceptions

            self._init_sdk()

            gen_config = GenerationConfig(
                max_output_tokens=request.max_tokens,
                temperature=request.temperature,
                stop_sequences=request.stop or None,
            )

            gemini = GenerativeModel(
                model_name=model_name,
                system_instruction=request.system or None,
            )

            response = gemini.generate_content(
                request.prompt,
                generation_config=gen_config,
            )

            text = response.text if response.candidates else ""
            finish_reason = "stop"
            if response.candidates:
                finish_reason = str(response.candidates[0].finish_reason).lower().replace("finishreason.", "")

            # Token counts (available in usage_metadata)
            usage = ConnectorUsage(model=model_name, provider=self.provider_name)
            if hasattr(response, "usage_metadata") and response.usage_metadata:
                usage.input_tokens  = getattr(response.usage_metadata, "prompt_token_count", 0) or 0
                usage.output_tokens = getattr(response.usage_metadata, "candidates_token_count", 0) or 0
                usage.total_tokens  = getattr(response.usage_metadata, "total_token_count", 0) or (usage.input_tokens + usage.output_tokens)

            usage.cost_usd = self._estimate_cost(model_name, usage.input_tokens, usage.output_tokens)

            logger.debug(
                "[Vertex] Gemini model=%s in=%d out=%d cost=$%.6f",
                model_name, usage.input_tokens, usage.output_tokens, usage.cost_usd,
            )
            return ConnectorResponse(
                text=text,
                model=model_name,
                provider=self.provider_name,
                usage=usage,
                finish_reason=finish_reason,
                raw=response,
            )
        except ImportError as exc:
            raise ConnectorAuthError(f"Vertex AI SDK missing: {exc}") from exc
        except Exception as exc:
            self._map_google_exception(exc)

    def _call_palm(self, request: ConnectorRequest, model_name: str) -> ConnectorResponse:
        """Call a PaLM/text-bison model via the TextGenerationModel API."""
        try:
            from vertexai.language_models import TextGenerationModel

            self._init_sdk()

            model = TextGenerationModel.from_pretrained(model_name)
            prompt = f"{request.system}\n\n{request.prompt}" if request.system else request.prompt

            response = model.predict(
                prompt,
                max_output_tokens=request.max_tokens,
                temperature=request.temperature,
            )
            text = response.text

            usage = ConnectorUsage(model=model_name, provider=self.provider_name)
            # PaLM API doesn't return token counts directly — approximate from chars
            usage.input_tokens  = len(prompt) // 4
            usage.output_tokens = len(text) // 4
            usage.total_tokens  = usage.input_tokens + usage.output_tokens
            usage.cost_usd = self._estimate_cost(model_name, usage.input_tokens, usage.output_tokens)

            return ConnectorResponse(
                text=text,
                model=model_name,
                provider=self.provider_name,
                usage=usage,
                finish_reason="stop",
                raw=response,
            )
        except ImportError as exc:
            raise ConnectorAuthError(f"Vertex AI SDK missing: {exc}") from exc
        except Exception as exc:
            self._map_google_exception(exc)

    def _map_google_exception(self, exc: Exception) -> None:
        """Map google-api-core exceptions to connector errors. Always raises."""
        exc_name = type(exc).__name__
        exc_str  = str(exc)
        if "PermissionDenied" in exc_name or "403" in exc_str:
            raise ConnectorAuthError(f"Vertex AI permission denied: {exc}") from exc
        if "Unauthenticated" in exc_name or "401" in exc_str:
            raise ConnectorAuthError(f"Vertex AI unauthenticated: {exc}") from exc
        if "ResourceExhausted" in exc_name or "429" in exc_str:
            raise ConnectorRateLimitError(f"Vertex AI quota exceeded: {exc}", retry_after=60.0) from exc
        if "DeadlineExceeded" in exc_name or "timeout" in exc_str.lower():
            raise ConnectorTimeoutError(f"Vertex AI timed out: {exc}") from exc
        if "SafetyRating" in exc_str or "SAFETY" in exc_str or "blocked" in exc_str.lower():
            raise ConnectorContentFilterError(f"Vertex AI safety block: {exc}") from exc
        raise ConnectorError(f"Vertex AI error ({exc_name}): {exc}") from exc

    def complete(self, request: ConnectorRequest) -> ConnectorResponse:
        """Send a prompt to Vertex AI (Gemini or PaLM) and return a response."""
        model_name = request.model or self._model
        if "gemini" in model_name.lower():
            return self._call_gemini(request, model_name)
        else:
            return self._call_palm(request, model_name)

    def stream(self, request: ConnectorRequest) -> Generator:
        """Stream a Gemini response. Yields text chunks."""
        model_name = request.model or self._model
        if "gemini" not in model_name.lower():
            # PaLM doesn't support streaming — fall back
            response = self.complete(request)
            yield response.text
            return response

        try:
            import vertexai
            from vertexai.generative_models import GenerativeModel, GenerationConfig

            self._init_sdk()
            gen_config = GenerationConfig(
                max_output_tokens=request.max_tokens,
                temperature=request.temperature,
            )
            gemini = GenerativeModel(
                model_name=model_name,
                system_instruction=request.system or None,
            )
            full_text = ""
            for chunk in gemini.generate_content(
                request.prompt,
                generation_config=gen_config,
                stream=True,
            ):
                text = chunk.text if chunk.candidates else ""
                if text:
                    full_text += text
                    yield text

            return ConnectorResponse(
                text=full_text,
                model=model_name,
                provider=self.provider_name,
                usage=ConnectorUsage(model=model_name, provider=self.provider_name),
                finish_reason="stop",
            )
        except Exception as exc:
            logger.warning("[Vertex] Streaming failed (%s), falling back", exc)
            response = self.complete(request)
            yield response.text
            return response

    def _estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        pricing = _VERTEX_PRICING.get(model, {"in": 0.001, "out": 0.002})
        return (input_tokens * pricing["in"] + output_tokens * pricing["out"]) / 1000
