"""
Aegis — AWS Bedrock LLM Connector  (v2.11.0)

Real implementation using boto3 + Bedrock Runtime API.

Supported models (via Bedrock):
  - Anthropic Claude: anthropic.claude-3-* / anthropic.claude-3-5-*
  - Amazon Titan:     amazon.titan-text-express-v1 / amazon.titan-text-lite-v1
  - Meta Llama:       meta.llama2-13b-chat-v1 / meta.llama3-*

Authentication:
  - IAM role (EC2 instance profile, ECS task role, Lambda execution role) — preferred
  - AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY environment variables
  - AWS_PROFILE for named profile in ~/.aws/credentials

Environment variables:
  AWS_REGION          — AWS region for Bedrock (default: us-east-1)
  BEDROCK_MODEL       — override default model
  BEDROCK_TIMEOUT     — request timeout in seconds (default: 60)
  BEDROCK_MAX_RETRIES — max retry attempts on throttle (default: 3)
"""

import json
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

# ── Pricing (approximate, USD per 1K tokens as of Q1 2025) ────────────────────
# Update periodically from https://aws.amazon.com/bedrock/pricing/
_BEDROCK_PRICING: dict[str, dict] = {
    "anthropic.claude-3-sonnet-20240229-v1:0":        {"in": 0.003,  "out": 0.015},
    "anthropic.claude-3-haiku-20240307-v1:0":         {"in": 0.00025,"out": 0.00125},
    "anthropic.claude-3-opus-20240229-v1:0":          {"in": 0.015,  "out": 0.075},
    "anthropic.claude-3-5-sonnet-20241022-v2:0":      {"in": 0.003,  "out": 0.015},
    "amazon.titan-text-express-v1":                   {"in": 0.0008, "out": 0.0016},
    "amazon.titan-text-lite-v1":                      {"in": 0.0003, "out": 0.0004},
    "meta.llama2-13b-chat-v1":                        {"in": 0.00075,"out": 0.001},
    "meta.llama3-8b-instruct-v1:0":                   {"in": 0.0004, "out": 0.0006},
    "meta.llama3-70b-instruct-v1:0":                  {"in": 0.00265,"out": 0.0035},
}


class BedrockConnector(BaseConnector):
    """
    AWS Bedrock Runtime connector.

    Supports Claude, Titan, and Llama models via the unified
    InvokeModel / InvokeModelWithResponseStream APIs.
    """

    def __init__(
        self,
        region: str = "",
        model: str = "",
        timeout: int = 0,
        max_retries: int = 0,
    ):
        self._region      = region or os.getenv("AWS_REGION", "us-east-1")
        self._model       = model or os.getenv("BEDROCK_MODEL", "anthropic.claude-3-haiku-20240307-v1:0")
        self._timeout     = timeout or int(os.getenv("BEDROCK_TIMEOUT", "60"))
        self._max_retries = max_retries or int(os.getenv("BEDROCK_MAX_RETRIES", "3"))
        self._client: Optional[Any] = None

    @property
    def provider_name(self) -> str:
        return "bedrock"

    @property
    def default_model(self) -> str:
        return self._model

    def _get_client(self):
        """Lazily initialize boto3 Bedrock Runtime client."""
        if self._client is not None:
            return self._client
        try:
            import boto3
            from botocore.config import Config
            config = Config(
                region_name=self._region,
                retries={"max_attempts": self._max_retries, "mode": "adaptive"},
                read_timeout=self._timeout,
                connect_timeout=10,
            )
            self._client = boto3.client("bedrock-runtime", config=config)
            return self._client
        except ImportError:
            raise ConnectorAuthError("boto3 not installed. Run: pip install boto3")

    def is_available(self) -> bool:
        """Check if boto3 is available and AWS credentials are configured."""
        try:
            import boto3
            from botocore.exceptions import NoCredentialsError, NoRegionError
            client = self._get_client()
            # Lightweight check: list foundation models (just validate credentials)
            bedrock = boto3.client("bedrock", region_name=self._region)
            bedrock.list_foundation_models(byOutputModality="TEXT")
            return True
        except ImportError:
            logger.debug("[Bedrock] boto3 not available")
            return False
        except Exception as exc:
            logger.debug("[Bedrock] availability check failed: %s", exc)
            return False

    def _build_body(self, request: ConnectorRequest, model: str) -> dict:
        """Build provider-specific request body based on model family."""
        prompt = request.prompt
        system = request.system

        if model.startswith("anthropic.claude"):
            messages = []
            if system:
                # Claude 3 uses system as top-level field in Messages API
                pass
            messages.append({"role": "user", "content": prompt})
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": request.max_tokens,
                "messages": messages,
                "temperature": request.temperature,
            }
            if system:
                body["system"] = system
            if request.stop:
                body["stop_sequences"] = request.stop
            return body

        elif model.startswith("amazon.titan"):
            full_prompt = f"{system}\n\n{prompt}" if system else prompt
            return {
                "inputText": full_prompt,
                "textGenerationConfig": {
                    "maxTokenCount": request.max_tokens,
                    "temperature": request.temperature,
                    "stopSequences": request.stop or [],
                },
            }

        elif model.startswith("meta.llama"):
            full_prompt = f"[INST] <<SYS>>{system}<</SYS>>\n\n{prompt} [/INST]" if system else f"[INST] {prompt} [/INST]"
            return {
                "prompt": full_prompt,
                "max_gen_len": request.max_tokens,
                "temperature": request.temperature,
            }

        else:
            # Generic fallback — try Claude format
            return {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": request.max_tokens,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": request.temperature,
            }

    def _parse_response(self, raw: dict, model: str) -> tuple[str, ConnectorUsage]:
        """Parse provider-specific response into (text, usage)."""
        text = ""
        usage = ConnectorUsage(model=model, provider=self.provider_name)

        if model.startswith("anthropic.claude"):
            content = raw.get("content", [])
            if content and isinstance(content, list):
                text = content[0].get("text", "")
            u = raw.get("usage", {})
            usage.input_tokens  = u.get("input_tokens", 0)
            usage.output_tokens = u.get("output_tokens", 0)
            usage.total_tokens  = usage.input_tokens + usage.output_tokens

        elif model.startswith("amazon.titan"):
            results = raw.get("results", [])
            if results:
                text = results[0].get("outputText", "")
            usage.input_tokens  = raw.get("inputTextTokenCount", 0)
            usage.output_tokens = raw.get("results", [{}])[0].get("tokenCount", 0) if raw.get("results") else 0
            usage.total_tokens  = usage.input_tokens + usage.output_tokens

        elif model.startswith("meta.llama"):
            text = raw.get("generation", "")
            usage.input_tokens  = raw.get("prompt_token_count", 0)
            usage.output_tokens = raw.get("generation_token_count", 0)
            usage.total_tokens  = usage.input_tokens + usage.output_tokens

        usage.cost_usd = self._estimate_cost(model, usage.input_tokens, usage.output_tokens)
        return text, usage

    def complete(self, request: ConnectorRequest) -> ConnectorResponse:
        """
        Invoke a Bedrock model (non-streaming) and return a ConnectorResponse.

        Raises:
          ConnectorAuthError       — credentials missing or invalid
          ConnectorRateLimitError  — ThrottlingException
          ConnectorTimeoutError    — ReadTimeoutError
          ConnectorContentFilterError — content blocked
        """
        model = request.model or self._model
        client = self._get_client()
        body = self._build_body(request, model)

        try:
            from botocore.exceptions import (
                ClientError,
                NoCredentialsError,
                ReadTimeoutError,
            )

            resp = client.invoke_model(
                modelId=model,
                body=json.dumps(body),
                contentType="application/json",
                accept="application/json",
            )
            raw_bytes = resp["body"].read()
            raw = json.loads(raw_bytes)
            text, usage = self._parse_response(raw, model)
            finish_reason = raw.get("stop_reason", "stop")

            logger.debug(
                "[Bedrock] model=%s in=%d out=%d cost=$%.6f",
                model, usage.input_tokens, usage.output_tokens, usage.cost_usd,
            )
            return ConnectorResponse(
                text=text,
                model=model,
                provider=self.provider_name,
                usage=usage,
                finish_reason=finish_reason,
                raw=raw,
            )

        except ImportError:
            raise ConnectorAuthError("boto3/botocore not installed")
        except Exception as exc:
            exc_name = type(exc).__name__
            exc_str  = str(exc)
            if "NoCredentialsError" in exc_name or "credential" in exc_str.lower():
                raise ConnectorAuthError(f"AWS credentials not configured: {exc}") from exc
            if "ThrottlingException" in exc_str or "TooManyRequests" in exc_str:
                raise ConnectorRateLimitError(f"Bedrock rate limit: {exc}", retry_after=30.0) from exc
            if "ReadTimeoutError" in exc_name or "timeout" in exc_str.lower():
                raise ConnectorTimeoutError(f"Bedrock request timed out: {exc}") from exc
            if "AccessDeniedException" in exc_str or "UnauthorizedException" in exc_str:
                raise ConnectorAuthError(f"Bedrock access denied: {exc}") from exc
            if "ValidationException" in exc_str and "content" in exc_str.lower():
                raise ConnectorContentFilterError(f"Bedrock content filter: {exc}") from exc
            raise ConnectorError(f"Bedrock error ({exc_name}): {exc}") from exc

    def stream(self, request: ConnectorRequest) -> Generator:
        """
        Stream a response from Bedrock (Claude models only).
        Yields text chunks. Returns final ConnectorResponse.
        """
        model = request.model or self._model
        client = self._get_client()
        body = self._build_body(request, model)

        try:
            resp = client.invoke_model_with_response_stream(
                modelId=model,
                body=json.dumps(body),
                contentType="application/json",
                accept="application/json",
            )
            full_text = ""
            final_usage = ConnectorUsage(model=model, provider=self.provider_name)

            for event in resp["body"]:
                chunk = json.loads(event["chunk"]["bytes"])
                chunk_type = chunk.get("type", "")

                if chunk_type == "content_block_delta":
                    text = chunk.get("delta", {}).get("text", "")
                    if text:
                        full_text += text
                        yield text
                elif chunk_type == "message_delta":
                    usage_data = chunk.get("usage", {})
                    final_usage.output_tokens = usage_data.get("output_tokens", 0)
                elif chunk_type == "message_start":
                    usage_data = chunk.get("message", {}).get("usage", {})
                    final_usage.input_tokens = usage_data.get("input_tokens", 0)

            final_usage.total_tokens = final_usage.input_tokens + final_usage.output_tokens
            final_usage.cost_usd = self._estimate_cost(model, final_usage.input_tokens, final_usage.output_tokens)

            return ConnectorResponse(
                text=full_text,
                model=model,
                provider=self.provider_name,
                usage=final_usage,
                finish_reason="stop",
            )

        except Exception as exc:
            # Fall back to non-streaming
            logger.warning("[Bedrock] Streaming failed (%s), falling back to complete()", exc)
            response = self.complete(request)
            yield response.text
            return response

    def _estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        pricing = _BEDROCK_PRICING.get(model, {"in": 0.001, "out": 0.003})
        return (input_tokens * pricing["in"] + output_tokens * pricing["out"]) / 1000
