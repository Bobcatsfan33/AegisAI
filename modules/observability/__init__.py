"""
Observability Engine — AegisAI v3.1.0

DataDog-feel observability built on ClickHouse economics.

Capabilities:
  - Real-time streaming dashboard (WebSocket delta push)
  - Service topology auto-map from telemetry
  - AI anomaly overlay (ML-detected spikes, drift, silent failures)
  - Security correlation: supply chain risk ↔ deployment ↔ telemetry events
  - Cost-per-service transparency in real time
  - Alert fatigue reducer (ML noise grouping + severity trending)
  - One-click runbook suggestions inline with alerts

ClickHouse advantages over DataDog's backend:
  - Columnar compression: 10-100x cheaper storage at equivalent query speed
  - Sub-second aggregations over billions of events (no sampling)
  - Native materialized views for instant dashboard refresh
  - Real SQL — no proprietary DQL lock-in
  - Open source core — no vendor lock-in

NIST 800-53: SI-4 (System Monitoring), AU-6 (Audit Review), CA-7 (Continuous Monitoring).
"""

from .engine import (
    ObservabilityEngine,
    MetricPoint,
    ServiceNode,
    Alert,
    AlertSeverity,
    AnomalySignal,
    Dashboard,
    RunbookSuggestion,
    get_engine,
)

__all__ = [
    "ObservabilityEngine",
    "MetricPoint",
    "ServiceNode",
    "Alert",
    "AlertSeverity",
    "AnomalySignal",
    "Dashboard",
    "RunbookSuggestion",
    "get_engine",
]
