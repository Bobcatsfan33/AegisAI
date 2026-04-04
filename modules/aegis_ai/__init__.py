"""
AegisAI — AI Security Layer (subcomponent of AegisAI)

Modules:
  connectors   Multi-provider LLM abstraction (OpenAI, Anthropic, Ollama, vLLM)
  discovery    AI asset inventory (API keys, endpoints, vector DBs, model registries)
  guardrails   Runtime LLM I/O enforcement (PII, secrets, injection detection)
  policy       AI governance rules, risk scoring (NIST AI RMF, EU AI Act, OWASP LLM)
  redteam      Automated adversarial testing (prompt injection, jailbreaks, 20+ attacks)
  telemetry    ClickHouse-backed event analytics with materialized views
"""

from modules.aegis_ai.connectors import ConnectorRegistry
from modules.aegis_ai.discovery import DiscoveryEngine, AIAsset
from modules.aegis_ai.guardrails import GuardrailsEngine, GuardrailVerdict
from modules.aegis_ai.policy import PolicyEngine, RiskAssessment
from modules.aegis_ai.redteam import RedTeamEngine, AttackResult, AttackCategory
from modules.aegis_ai.telemetry import TelemetryEngine, AIEvent, EventType

__all__ = [
    "ConnectorRegistry",
    "DiscoveryEngine", "AIAsset",
    "GuardrailsEngine", "GuardrailVerdict",
    "PolicyEngine", "RiskAssessment",
    "RedTeamEngine", "AttackResult", "AttackCategory",
    "TelemetryEngine", "AIEvent", "EventType",
]
