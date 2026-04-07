"""
Aegis — Cloud LLM Connector Base  (v2.11.0)

Abstract base class and shared data structures for all LLM provider connectors.
Every connector implementation extends BaseConnector and fits into the
ConnectorRegistry / guardrails pipeline.

Cost tracking:
  Each ConnectorResponse includes token counts and estimated cost.
  Cost data is fed into the telemetry engine for budget tracking and alerting.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Generator, Optional


# ── Errors ─────────────────────────────────────────────────────────────────────


class ConnectorError(Exception):
    """Base error for all connector operations."""


class ConnectorAuthError(ConnectorError):
    """Authentication/credential error."""


class ConnectorRateLimitError(ConnectorError):
    """Rate limit exceeded. Retry after backoff."""

    def __init__(self, message: str = "", retry_after: float = 0.0):
        super().__init__(message)
        self.retry_after = retry_after


class ConnectorTimeoutError(ConnectorError):
    """Request timed out."""


class ConnectorContentFilterError(ConnectorError):
    """Content was blocked by the provider's content filter."""


# ── Data structures ────────────────────────────────────────────────────────────


@dataclass
class ConnectorRequest:
    """Unified request format for all LLM connectors."""
    prompt:      str
    model:       str = ""            # model override; empty = use connector default
    max_tokens:  int = 2048
    temperature: float = 0.1
    system:      str = ""            # system prompt
    stream:      bool = False
    stop:        list = field(default_factory=list)
    extra:       dict = field(default_factory=dict)  # provider-specific extras


@dataclass
class ConnectorUsage:
    """Token usage and cost tracking per response."""
    input_tokens:  int = 0
    output_tokens: int = 0
    total_tokens:  int = 0
    cost_usd:      float = 0.0
    model:         str = ""
    provider:      str = ""

    def to_dict(self) -> dict:
        return {
            "input_tokens":  self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens":  self.total_tokens,
            "cost_usd":      round(self.cost_usd, 6),
            "model":         self.model,
            "provider":      self.provider,
        }


@dataclass
class ConnectorResponse:
    """Unified response from any LLM connector."""
    text:      str
    model:     str
    provider:  str
    usage:     ConnectorUsage = field(default_factory=ConnectorUsage)
    finish_reason: str = "stop"
    raw:       Any = field(default=None, repr=False)  # raw provider response

    def to_dict(self) -> dict:
        return {
            "text":          self.text,
            "model":         self.model,
            "provider":      self.provider,
            "finish_reason": self.finish_reason,
            "usage":         self.usage.to_dict(),
        }


# ── Base Connector ─────────────────────────────────────────────────────────────


class BaseConnector(ABC):
    """
    Abstract base class for all Cloud LLM connectors.

    Subclasses implement:
      complete(request)          → ConnectorResponse (blocking)
      stream(request)            → Generator[str, None, ConnectorResponse] (streaming)
      is_available()             → bool (quick availability check)
      provider_name              → str (e.g. "bedrock", "vertex", "azure_openai")
      default_model              → str (e.g. "anthropic.claude-3-sonnet-20240229-v1:0")
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Short identifier for this provider, e.g. 'bedrock'."""

    @property
    @abstractmethod
    def default_model(self) -> str:
        """Default model to use when request.model is empty."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the connector has valid credentials and required SDKs."""

    @abstractmethod
    def complete(self, request: ConnectorRequest) -> ConnectorResponse:
        """
        Send a prompt to the LLM and return a full (non-streaming) response.

        Raises ConnectorError subclasses on auth failures, rate limits, timeouts.
        """

    def stream(self, request: ConnectorRequest) -> Generator:
        """
        Stream a response token by token. Yields str chunks.
        Default implementation falls back to non-streaming.
        """
        response = self.complete(request)
        yield response.text
        return response

    def _estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """
        Estimate USD cost for a request. Override in subclasses for accurate pricing.
        Default returns 0 (no pricing data available).
        """
        return 0.0
