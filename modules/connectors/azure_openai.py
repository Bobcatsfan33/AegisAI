"""
Aegis — Azure OpenAI Connector  (v2.11.0)

Real implementation using the openai SDK with Azure endpoints.

Supported models (via Azure OpenAI deployment):
  - GPT-4o:        gpt-4o, gpt-4o-mini
  - GPT-4:         gpt-4, gpt-4-turbo
  - GPT-3.5-turbo: gpt-35-turbo, gpt-35-turbo-16k

Authentication:
  - API Key + endpoint (simplest): AZURE_OPENAI_KEY + AZURE_OPENAI_ENDPOINT
  - Azure AD / managed identity (recommended for production):
    Set AZURE_OPENAI_AD_TOKEN or rely on DefaultAzureCredential from azure-identity

Environment variables:
  AZURE_OPENAI_ENDPOINT    — Azure OpenAI resource endpoint (required)
                             e.g. https://my-resource.openai.azure.com/
  AZURE_OPENAI_KEY         — API key (or use AD auth below)
  AZURE_OPENAI_DEPLOYMENT  — deployment name (default: gpt-4o)
  AZURE_OPENAI_API_VERSION — API version (default: 2024-02-01)
  AZURE_OPENAI_AD_TOKEN    — Azure AD bearer token (alternative to API key)
  AZURE_OPENAI_TIMEOUT     — request timeout in seconds (default: 60)
  AZURE_CONTENT_FILTER_WARN — if "true", log content filter hits (default: raise)

Content Filtering:
  Azure OpenAI has built-in content filtering (hate, violence, sexual, self-harm).
  This connector integrates with AegisAI guardrails: content filter results are
  passed back in ConnectorResponse.raw for the guardrails engine to act on.
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

# ── Pricing (approximate USD per 1K tokens as of Q1 2025) ─────────────────────
_AZURE_PRICING: dict[str, dict] = {
    "gpt-4o":           {"in": 0.005,   "out": 0.015},
    "gpt-4o-mini":      {"in": 0.00015, "out": 0.0006},
    "gpt-4":            {"in": 0.03,    "out": 0.06},
    "gpt-4-turbo":      {"in": 0.01,    "out": 0.03},
    "gpt-35-turbo":     {"in": 0.0005,  "out": 0.0015},
    "gpt-35-turbo-16k": {"in": 0.003,   "out": 0.004},
}


class AzureOpenAIConnector(BaseConnector):
    """
    Azure OpenAI connector using the official openai Python SDK (v1.x).

    Supports GPT-4o, GPT-4, GPT-3.5 Turbo via Azure deployment names.
    Handles both API key and Azure AD (managed identity) authentication.
    Wraps Azure's content filter results and integrates with AegisAI guardrails.
    """

    def __init__(
        self,
        endpoint: str = "",
        api_key: str = "",
        deployment: str = "",
        api_version: str = "",
        timeout: int = 0,
    ):
        self._endpoint   = endpoint    or os.getenv("AZURE_OPENAI_ENDPOINT", "")
        self._api_key    = api_key     or os.getenv("AZURE_OPENAI_KEY", "")
        self._ad_token   = os.getenv("AZURE_OPENAI_AD_TOKEN", "")
        self._deployment = deployment  or os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        self._api_version = api_version or os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01")
        self._timeout    = timeout or int(os.getenv("AZURE_OPENAI_TIMEOUT", "60"))
        self._warn_only  = os.getenv("AZURE_CONTENT_FILTER_WARN", "false").lower() == "true"
        self._client: Optional[Any] = None

    @property
    def provider_name(self) -> str:
        return "azure_openai"

    @property
    def default_model(self) -> str:
        return self._deployment

    def _get_client(self):
        """Lazily initialize openai AzureOpenAI client."""
        if self._client is not None:
            return self._client
        try:
            from openai import AzureOpenAI
        except ImportError:
            raise ConnectorAuthError("openai package not installed. Run: pip install openai")

        if not self._endpoint:
            raise ConnectorAuthError("AZURE_OPENAI_ENDPOINT is required for Azure OpenAI connector")

        kwargs: dict = {
            "azure_endpoint": self._endpoint,
            "api_version": self._api_version,
            "timeout": self._timeout,
        }

        # Auth: prefer API key, fall back to AD token, fall back to DefaultAzureCredential
        if self._api_key:
            kwargs["api_key"] = self._api_key
        elif self._ad_token:
            # Use azure-identity for AD token refresh
            try:
                from azure.identity import DefaultAzureCredential
                from openai import AzureOpenAI
                credential = DefaultAzureCredential()
                token = credential.get_token("https://cognitiveservices.azure.com/.default")
                kwargs["azure_ad_token"] = token.token
            except ImportError:
                kwargs["api_key"] = self._ad_token   # use as-is if azure-identity not available
        else:
            # Try DefaultAzureCredential (managed identity, etc.)
            try:
                from azure.identity import DefaultAzureCredential
                credential = DefaultAzureCredential()
                token = credential.get_token("https://cognitiveservices.azure.com/.default")
                kwargs["azure_ad_token"] = token.token
                logger.debug("[AzureOpenAI] Using DefaultAzureCredential (managed identity)")
            except Exception as exc:
                raise ConnectorAuthError(
                    f"Azure OpenAI: no credentials configured. "
                    f"Set AZURE_OPENAI_KEY or configure managed identity. Error: {exc}"
                ) from exc

        self._client = AzureOpenAI(**kwargs)
        return self._client

    def is_available(self) -> bool:
        """Check if endpoint is configured and openai SDK is available."""
        if not self._endpoint:
            logger.debug("[AzureOpenAI] AZURE_OPENAI_ENDPOINT not set")
            return False
        try:
            from openai import AzureOpenAI  # noqa: F401
            return True
        except ImportError:
            logger.debug("[AzureOpenAI] openai package not installed")
            return False

    def _build_messages(self, request: ConnectorRequest) -> list:
        messages = []
        if request.system:
            messages.append({"role": "system", "content": request.system})
        messages.append({"role": "user", "content": request.prompt})
        return messages

    def _parse_content_filter(self, raw_response: Any) -> Optional[dict]:
        """Extract Azure content filter results from the response."""
        try:
            if raw_response and hasattr(raw_response, "choices") and raw_response.choices:
                choice = raw_response.choices[0]
                if hasattr(choice, "content_filter_results") and choice.content_filter_results:
                    return {
                        k: {"filtered": getattr(v, "filtered", False), "severity": getattr(v, "severity", "safe")}
                        for k, v in vars(choice.content_filter_results).items()
                        if v is not None
                    }
        except Exception:
            pass
        return None

    def complete(self, request: ConnectorRequest) -> ConnectorResponse:
        """
        Send a prompt to Azure OpenAI and return a full response.
        Includes content filter results in ConnectorResponse.raw for guardrails.
        """
        deployment = request.model or self._deployment
        client = self._get_client()
        messages = self._build_messages(request)

        try:
            kwargs: dict = {
                "model": deployment,
                "messages": messages,
                "max_tokens": request.max_tokens,
                "temperature": request.temperature,
            }
            if request.stop:
                kwargs["stop"] = request.stop

            response = client.chat.completions.create(**kwargs)

            text = ""
            finish_reason = "stop"
            if response.choices:
                text = response.choices[0].message.content or ""
                finish_reason = response.choices[0].finish_reason or "stop"

            # Check content filter
            if finish_reason == "content_filter":
                filter_results = self._parse_content_filter(response)
                if not self._warn_only:
                    raise ConnectorContentFilterError(
                        f"Azure content filter blocked response. Filters: {filter_results}"
                    )
                logger.warning("[AzureOpenAI] Content filter triggered: %s", filter_results)

            # Token usage and cost
            usage = ConnectorUsage(model=deployment, provider=self.provider_name)
            if response.usage:
                usage.input_tokens  = response.usage.prompt_tokens or 0
                usage.output_tokens = response.usage.completion_tokens or 0
                usage.total_tokens  = response.usage.total_tokens or 0
            usage.cost_usd = self._estimate_cost(deployment, usage.input_tokens, usage.output_tokens)

            # Content filter metadata for guardrails engine
            filter_meta = self._parse_content_filter(response)

            logger.debug(
                "[AzureOpenAI] deployment=%s in=%d out=%d cost=$%.6f filter=%s",
                deployment, usage.input_tokens, usage.output_tokens, usage.cost_usd, filter_meta,
            )
            return ConnectorResponse(
                text=text,
                model=deployment,
                provider=self.provider_name,
                usage=usage,
                finish_reason=finish_reason,
                raw={"response": response, "content_filter": filter_meta},
            )

        except ConnectorError:
            raise
        except Exception as exc:
            self._map_openai_exception(exc)

    def stream(self, request: ConnectorRequest) -> Generator:
        """Stream a response from Azure OpenAI. Yields text chunks."""
        deployment = request.model or self._deployment
        client = self._get_client()
        messages = self._build_messages(request)

        try:
            kwargs: dict = {
                "model": deployment,
                "messages": messages,
                "max_tokens": request.max_tokens,
                "temperature": request.temperature,
                "stream": True,
            }
            if request.stop:
                kwargs["stop"] = request.stop

            stream = client.chat.completions.create(**kwargs)
            full_text = ""
            for chunk in stream:
                if chunk.choices:
                    delta = chunk.choices[0].delta
                    if delta and delta.content:
                        full_text += delta.content
                        yield delta.content

            # Note: streaming responses don't include usage by default in Azure
            # Enable with stream_options={"include_usage": True} if needed
            return ConnectorResponse(
                text=full_text,
                model=deployment,
                provider=self.provider_name,
                usage=ConnectorUsage(model=deployment, provider=self.provider_name),
                finish_reason="stop",
            )
        except ConnectorError:
            raise
        except Exception as exc:
            logger.warning("[AzureOpenAI] Streaming failed (%s), falling back", exc)
            response = self.complete(request)
            yield response.text
            return response

    def _map_openai_exception(self, exc: Exception) -> None:
        """Map openai/httpx exceptions to ConnectorError subclasses. Always raises."""
        exc_name = type(exc).__name__
        exc_str  = str(exc)

        if "AuthenticationError" in exc_name or "401" in exc_str:
            raise ConnectorAuthError(f"Azure OpenAI auth failed: {exc}") from exc
        if "PermissionDeniedError" in exc_name or "403" in exc_str:
            raise ConnectorAuthError(f"Azure OpenAI permission denied: {exc}") from exc
        if "RateLimitError" in exc_name or "429" in exc_str:
            retry_after = 30.0
            raise ConnectorRateLimitError(f"Azure OpenAI rate limit: {exc}", retry_after=retry_after) from exc
        if "Timeout" in exc_name or "timeout" in exc_str.lower():
            raise ConnectorTimeoutError(f"Azure OpenAI timed out: {exc}") from exc
        if "ContentFilterError" in exc_name or "content_filter" in exc_str.lower():
            raise ConnectorContentFilterError(f"Azure OpenAI content filter: {exc}") from exc
        raise ConnectorError(f"Azure OpenAI error ({exc_name}): {exc}") from exc

    def _estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        # Try exact match, then prefix match
        pricing = _AZURE_PRICING.get(model)
        if pricing is None:
            for key, val in _AZURE_PRICING.items():
                if model.startswith(key):
                    pricing = val
                    break
        if pricing is None:
            pricing = {"in": 0.005, "out": 0.015}
        return (input_tokens * pricing["in"] + output_tokens * pricing["out"]) / 1000
