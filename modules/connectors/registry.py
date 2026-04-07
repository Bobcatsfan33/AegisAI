"""
Aegis — LLM Connector Registry  (v2.11.0)

Central registry for all LLM provider connectors.
The guardrails engine and AI orchestrator route through this registry.

Usage:
    from modules.connectors.registry import ConnectorRegistry

    registry = ConnectorRegistry()
    connector = registry.get("bedrock")           # raises if not available
    connector = registry.get_available()          # returns first available connector
    connectors = registry.list_available()        # returns all available connectors
    info = registry.status()                      # health check for all connectors
"""

import logging
import os
from typing import Optional

from .base import BaseConnector, ConnectorRequest, ConnectorResponse
from .bedrock import BedrockConnector
from .vertex import VertexAIConnector
from .azure_openai import AzureOpenAIConnector

logger = logging.getLogger(__name__)


class ConnectorRegistry:
    """
    Registry for Cloud LLM connectors.

    All connectors are lazily instantiated on first access.
    Connectors that are not available (missing credentials or SDK) are skipped
    when calling get_available() — they are never silently removed, so
    explicit calls to get("bedrock") will still raise if Bedrock is unavailable.
    """

    # Priority order for get_available()
    _CONNECTOR_PRIORITY = ["bedrock", "vertex", "azure_openai"]

    def __init__(
        self,
        bedrock: Optional[BedrockConnector] = None,
        vertex: Optional[VertexAIConnector] = None,
        azure_openai: Optional[AzureOpenAIConnector] = None,
    ):
        self._connectors: dict[str, BaseConnector] = {}

        # Allow injection (for testing) or default instances
        if bedrock is not None:
            self._connectors["bedrock"] = bedrock
        if vertex is not None:
            self._connectors["vertex"] = vertex
        if azure_openai is not None:
            self._connectors["azure_openai"] = azure_openai

    def _get_or_create(self, name: str) -> BaseConnector:
        """Get or lazily create a connector instance."""
        if name not in self._connectors:
            if name == "bedrock":
                self._connectors[name] = BedrockConnector()
            elif name == "vertex":
                self._connectors[name] = VertexAIConnector()
            elif name == "azure_openai":
                self._connectors[name] = AzureOpenAIConnector()
            else:
                raise KeyError(f"Unknown connector: {name!r}. Available: {self._CONNECTOR_PRIORITY}")
        return self._connectors[name]

    def get(self, name: str) -> BaseConnector:
        """
        Get a connector by name.

        Raises KeyError if the name is unknown.
        Does NOT check availability — use is_available() or get_available()
        if you need automatic fallback.
        """
        return self._get_or_create(name)

    def get_available(self, preferred: str = "") -> Optional[BaseConnector]:
        """
        Return the first available connector, optionally starting with preferred.

        Connector availability is determined by is_available() (SDK installed + credentials set).
        Returns None if no connector is available.
        """
        order = ([preferred] + [n for n in self._CONNECTOR_PRIORITY if n != preferred]) if preferred else self._CONNECTOR_PRIORITY
        for name in order:
            try:
                connector = self._get_or_create(name)
                if connector.is_available():
                    logger.debug("[Registry] Using connector: %s", name)
                    return connector
            except Exception as exc:
                logger.debug("[Registry] Connector %s unavailable: %s", name, exc)
        return None

    def list_available(self) -> list:
        """Return list of connector names that are currently available."""
        available = []
        for name in self._CONNECTOR_PRIORITY:
            try:
                connector = self._get_or_create(name)
                if connector.is_available():
                    available.append(name)
            except Exception:
                pass
        return available

    def complete(self, request: ConnectorRequest, connector_name: str = "") -> ConnectorResponse:
        """
        Send a completion request to a specific (or auto-selected) connector.

        If connector_name is empty, uses get_available() to find the first
        available connector.

        Raises ConnectorError if no connector is available.
        """
        if connector_name:
            return self.get(connector_name).complete(request)

        connector = self.get_available()
        if connector is None:
            from .base import ConnectorError
            raise ConnectorError(
                "No LLM connector available. Configure at least one of: "
                "BEDROCK (set AWS credentials), VERTEX (set GCP_PROJECT_ID), "
                "or AZURE_OPENAI (set AZURE_OPENAI_ENDPOINT + AZURE_OPENAI_KEY)."
            )
        return connector.complete(request)

    def status(self) -> dict:
        """Return health status for all registered connectors."""
        result = {}
        for name in self._CONNECTOR_PRIORITY:
            try:
                connector = self._get_or_create(name)
                available = connector.is_available()
                result[name] = {
                    "available": available,
                    "provider":  connector.provider_name,
                    "model":     connector.default_model,
                }
            except Exception as exc:
                result[name] = {
                    "available": False,
                    "error":     str(exc),
                }
        return result

    def register(self, name: str, connector: BaseConnector) -> None:
        """Register a custom connector under a given name."""
        self._connectors[name] = connector
        logger.info("[Registry] Registered custom connector: %s (%s)", name, connector.provider_name)


# ── Module-level default registry ─────────────────────────────────────────────

_default_registry: Optional[ConnectorRegistry] = None


def get_connector_registry() -> ConnectorRegistry:
    """Return the module-level default ConnectorRegistry (lazily created)."""
    global _default_registry
    if _default_registry is None:
        _default_registry = ConnectorRegistry()
    return _default_registry
