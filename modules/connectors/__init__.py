"""
Aegis — Cloud LLM Provider Connectors  (v2.11.0)

Real implementations for AWS Bedrock, GCP Vertex AI, and Azure OpenAI.

Usage:
    from modules.connectors import ConnectorRegistry

    registry = ConnectorRegistry()
    connector = registry.get("bedrock")
    response = connector.complete("Hello, analyze this finding: ...")
"""

from .base import BaseConnector, ConnectorRequest, ConnectorResponse, ConnectorError
from .bedrock import BedrockConnector
from .vertex import VertexAIConnector
from .azure_openai import AzureOpenAIConnector
from .registry import ConnectorRegistry

__all__ = [
    "BaseConnector",
    "ConnectorRequest",
    "ConnectorResponse",
    "ConnectorError",
    "BedrockConnector",
    "VertexAIConnector",
    "AzureOpenAIConnector",
    "ConnectorRegistry",
]
