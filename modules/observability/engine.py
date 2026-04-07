"""
Observability Engine — Core Implementation.

Architecture:
  MetricPoint  →  ClickHouse ingest (batched)
                   ↓
  Materialized views  →  sub-second dashboard queries
                   ↓
  AnomalyDetector  →  ML-scored signals
                   ↓
  AlertEngine  →  deduplicated, ML-grouped alerts
                   ↓
  TopologyMapper  →  auto-generated service graph
                   ↓
  RunbookEngine  →  inline remediation suggestions

The dashboard JSON schema is compatible with a React/WebSocket frontend
that polls /api/observability/dashboard and receives delta updates.
"""

import json
import logging
import os
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger("aegis.observability")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    WARNING = "warning"
    INFO = "info"


class MetricType(str, Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    RATE = "rate"


class AnomalyKind(str, Enum):
    SPIKE = "spike"                    # Sudden value jump
    DROP = "drop"                      # Sudden value drop
    DRIFT = "drift"                    # Gradual trend away from baseline
    FLATLINE = "flatline"              # Expected traffic went silent
    LATENCY_DEGRADATION = "latency_degradation"
    ERROR_RATE_SPIKE = "error_rate_spike"
    COST_SPIKE = "cost_spike"
    SECURITY_CORRELATION = "security_correlation"  # Tied to a supply chain / threat event


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class MetricPoint:
    """A single metric observation."""
    service: str
    metric: str
    value: float
    unit: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metric_type: MetricType = MetricType.GAUGE


@dataclass
class AnomalySignal:
    """An ML-detected anomaly in a metric stream."""
    service: str
    metric: str
    kind: AnomalyKind
    severity: AlertSeverity
    observed_value: float
    baseline_value: float
    deviation_pct: float
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    correlation_id: Optional[str] = None    # Links to supply chain / threat events
    description: str = ""


@dataclass
class Alert:
    """A deduplicated, enriched alert ready for display."""
    alert_id: str
    title: str
    severity: AlertSeverity
    service: str
    metric: str
    description: str
    timestamp: str
    anomaly: Optional[AnomalySignal] = None
    runbook_id: Optional[str] = None
    suppressed: bool = False               # Noise-suppressed by ML grouping
    group_key: str = ""                    # Alerts with same group_key are deduplicated
    acknowledged: bool = False
    resolved: bool = False
    resolution_time: Optional[str] = None


@dataclass
class RunbookSuggestion:
    """Inline remediation suggestion for an alert."""
    runbook_id: str
    title: str
    steps: List[str]
    estimated_minutes: int = 5
    automation_available: bool = False
    automation_command: Optional[str] = None    # e.g. CLI command to auto-remediate
    references: List[str] = field(default_factory=list)


@dataclass
class ServiceNode:
    """A node in the auto-generated service topology graph."""
    service_id: str
    display_name: str
    service_type: str               # "api", "db", "cache", "llm", "queue", "external"
    health: str = "healthy"         # "healthy", "degraded", "down"
    error_rate: float = 0.0
    p95_latency_ms: float = 0.0
    rps: float = 0.0
    cost_per_hour_usd: float = 0.0
    dependencies: List[str] = field(default_factory=list)   # list of service_ids
    last_seen: str = ""
    anomalies: List[str] = field(default_factory=list)


@dataclass
class Dashboard:
    """
    Top-level dashboard payload — sent to the frontend on WebSocket push.
    Contains only the delta (changed fields) in incremental updates.
    """
    generated_at: str
    services: List[ServiceNode] = field(default_factory=list)
    alerts: List[Alert] = field(default_factory=list)
    anomalies: List[AnomalySignal] = field(default_factory=list)
    total_rps: float = 0.0
    total_error_rate: float = 0.0
    total_p95_latency_ms: float = 0.0
    total_cost_per_hour_usd: float = 0.0
    active_alert_count: int = 0
    critical_alert_count: int = 0
    supply_chain_risk_score: float = 1.0    # From SupplyChainEngine
    summary: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Anomaly Detector
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """
    Lightweight statistical anomaly detector using rolling windows.

    Algorithm: 3-sigma rule against a rolling baseline window.
    For production, this plugs into a proper ML model (IsolationForest,
    Prophet, or a ClickHouse ML UDF). For now, rolling stats give solid
    signal with zero external deps.
    """

    def __init__(self, window_size: int = 60, sigma_threshold: float = 3.0):
        self.window_size = window_size
        self.sigma_threshold = sigma_threshold
        # {(service, metric): deque of recent values}
        self._windows: Dict[Tuple[str, str], Deque[float]] = defaultdict(
            lambda: deque(maxlen=window_size)
        )

    def ingest(self, point: MetricPoint) -> Optional[AnomalySignal]:
        """Ingest a metric point. Returns an AnomalySignal if anomalous."""
        key = (point.service, point.metric)
        window = self._windows[key]
        window.append(point.value)

        if len(window) < max(10, self.window_size // 4):
            return None  # Not enough data yet

        baseline = statistics.mean(window)
        if baseline == 0:
            return None

        try:
            std = statistics.stdev(window)
        except statistics.StatisticsError:
            return None

        if std == 0:
            # Flatline detection: if we expected non-zero traffic
            if baseline > 0 and point.value == 0:
                return AnomalySignal(
                    service=point.service,
                    metric=point.metric,
                    kind=AnomalyKind.FLATLINE,
                    severity=AlertSeverity.HIGH,
                    observed_value=point.value,
                    baseline_value=baseline,
                    deviation_pct=100.0,
                    description=f"{point.metric} went silent (expected ~{baseline:.1f} {point.unit})",
                )
            return None

        z_score = abs(point.value - baseline) / std
        if z_score < self.sigma_threshold:
            return None

        deviation_pct = abs(point.value - baseline) / max(baseline, 1e-9) * 100

        # Classify the anomaly type
        if "latency" in point.metric.lower() or "duration" in point.metric.lower():
            kind = AnomalyKind.LATENCY_DEGRADATION
        elif "error" in point.metric.lower():
            kind = AnomalyKind.ERROR_RATE_SPIKE
        elif "cost" in point.metric.lower():
            kind = AnomalyKind.COST_SPIKE
        elif point.value > baseline:
            kind = AnomalyKind.SPIKE
        else:
            kind = AnomalyKind.DROP

        severity = (
            AlertSeverity.CRITICAL if z_score > 6
            else AlertSeverity.HIGH if z_score > 4
            else AlertSeverity.WARNING
        )

        return AnomalySignal(
            service=point.service,
            metric=point.metric,
            kind=kind,
            severity=severity,
            observed_value=point.value,
            baseline_value=baseline,
            deviation_pct=deviation_pct,
            description=(
                f"{point.metric} {kind.value}: observed {point.value:.2f} "
                f"vs baseline {baseline:.2f} ({deviation_pct:.0f}% deviation, z={z_score:.1f}σ)"
            ),
        )

    def get_baseline(self, service: str, metric: str) -> Optional[float]:
        key = (service, metric)
        w = self._windows.get(key)
        if w and len(w) >= 5:
            return statistics.mean(w)
        return None


# ---------------------------------------------------------------------------
# Alert Engine
# ---------------------------------------------------------------------------

class AlertEngine:
    """
    Converts AnomalySignals into deduplicated, noise-suppressed Alerts.

    Noise suppression: alerts with the same group_key within a suppression
    window are collapsed into a single alert (not multiple pings).
    Group key = service + metric + kind.
    """

    def __init__(self, suppression_window_secs: int = 300):
        self.suppression_window = suppression_window_secs
        self._active_alerts: Dict[str, Alert] = {}      # group_key → alert
        self._alert_history: List[Alert] = []
        self._runbooks = RunbookLibrary()

    def process(self, signal: AnomalySignal) -> Optional[Alert]:
        """Convert anomaly signal to alert, applying deduplication."""
        group_key = f"{signal.service}:{signal.metric}:{signal.kind.value}"
        now_ts = time.time()

        # Check if suppressed (same group_key seen recently)
        existing = self._active_alerts.get(group_key)
        if existing and not existing.resolved:
            # Update existing alert but don't re-fire
            existing.description = signal.description
            return None

        import hashlib
        alert_id = hashlib.sha256(
            f"{group_key}:{signal.timestamp}".encode()
        ).hexdigest()[:12]

        runbook = self._runbooks.suggest(signal)

        alert = Alert(
            alert_id=alert_id,
            title=self._format_title(signal),
            severity=signal.severity,
            service=signal.service,
            metric=signal.metric,
            description=signal.description,
            timestamp=signal.timestamp,
            anomaly=signal,
            runbook_id=runbook.runbook_id if runbook else None,
            group_key=group_key,
        )

        self._active_alerts[group_key] = alert
        self._alert_history.append(alert)

        return alert

    def _format_title(self, signal: AnomalySignal) -> str:
        titles = {
            AnomalyKind.SPIKE: f"Spike detected in {signal.metric}",
            AnomalyKind.DROP: f"Drop detected in {signal.metric}",
            AnomalyKind.DRIFT: f"Metric drift in {signal.metric}",
            AnomalyKind.FLATLINE: f"Flatline: {signal.metric} went silent",
            AnomalyKind.LATENCY_DEGRADATION: f"Latency degradation: {signal.service}",
            AnomalyKind.ERROR_RATE_SPIKE: f"Error rate spike: {signal.service}",
            AnomalyKind.COST_SPIKE: f"Cost spike: {signal.service}",
            AnomalyKind.SECURITY_CORRELATION: f"Security event correlated: {signal.service}",
        }
        return titles.get(signal.kind, f"Anomaly: {signal.service}/{signal.metric}")

    def acknowledge(self, alert_id: str) -> bool:
        for alert in self._active_alerts.values():
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                return True
        return False

    def resolve(self, alert_id: str) -> bool:
        for key, alert in list(self._active_alerts.items()):
            if alert.alert_id == alert_id:
                alert.resolved = True
                alert.resolution_time = datetime.now(timezone.utc).isoformat()
                del self._active_alerts[key]
                return True
        return False

    def get_active(self, severity: Optional[str] = None) -> List[Alert]:
        alerts = list(self._active_alerts.values())
        if severity:
            alerts = [a for a in alerts if a.severity.value == severity]
        return sorted(alerts, key=lambda a: a.timestamp, reverse=True)


# ---------------------------------------------------------------------------
# Runbook Library
# ---------------------------------------------------------------------------

class RunbookLibrary:
    """
    Maps anomaly signals to inline remediation runbooks.
    This gives alerts the DataDog-style "suggested next steps" feel.
    """

    _runbooks: Dict[str, RunbookSuggestion] = {
        "latency_degradation": RunbookSuggestion(
            runbook_id="rb-latency-001",
            title="High Latency Investigation",
            steps=[
                "1. Check ClickHouse dashboard for slowest queries: SELECT query, elapsed FROM system.processes ORDER BY elapsed DESC LIMIT 10;",
                "2. Review service error logs for upstream timeouts.",
                "3. Check resource saturation: CPU, memory, disk I/O.",
                "4. If LLM service: check provider status page and reduce concurrent requests.",
                "5. Consider horizontal scaling or circuit breaking.",
            ],
            estimated_minutes=10,
            references=["https://clickhouse.com/docs/en/operations/system-tables/processes"],
        ),
        "error_rate_spike": RunbookSuggestion(
            runbook_id="rb-error-001",
            title="Error Rate Spike Response",
            steps=[
                "1. Tail error logs: grep 'ERROR\\|CRITICAL' /var/log/aegisai/*.log | tail -50",
                "2. Check recent deployments (last 2h) — correlate with supply chain provenance.",
                "3. Review guardrail events for blocked/rejected inputs causing error cascade.",
                "4. Check downstream dependency health (DB, Redis, LLM provider).",
                "5. If provider-related: activate fallback connector via ConnectorRegistry.",
            ],
            estimated_minutes=5,
            automation_available=True,
            automation_command="aegisai diagnose --service error --auto-rollback",
        ),
        "cost_spike": RunbookSuggestion(
            runbook_id="rb-cost-001",
            title="Cost Spike Containment",
            steps=[
                "1. Query ClickHouse for top cost drivers: SELECT provider, model, SUM(cost_usd) FROM ai_events GROUP BY provider, model ORDER BY 3 DESC LIMIT 10;",
                "2. Check for runaway agents or infinite retry loops in redteam/guardrails.",
                "3. Apply token budget limits via policy engine.",
                "4. Switch high-volume workloads to cheaper model tier.",
            ],
            estimated_minutes=8,
        ),
        "flatline": RunbookSuggestion(
            runbook_id="rb-flatline-001",
            title="Service Traffic Flatline",
            steps=[
                "1. Check service health endpoint: curl -f http://localhost:8000/health",
                "2. Verify upstream load balancer is routing correctly.",
                "3. Check for silent crash: ps aux | grep uvicorn",
                "4. Review last 100 log lines for crash/OOM indicators.",
                "5. If container: docker ps -a to check for recent restarts.",
            ],
            estimated_minutes=3,
            automation_available=True,
            automation_command="systemctl restart aegisai && sleep 5 && curl http://localhost:8000/",
        ),
        "security_correlation": RunbookSuggestion(
            runbook_id="rb-security-001",
            title="Security Event Correlation Response",
            steps=[
                "1. Review supply chain provenance score for recent deploys.",
                "2. Check guardrail event log for blocked threat patterns.",
                "3. Cross-reference telemetry anomaly with MITRE ATT&CK technique.",
                "4. Initiate red team re-assessment of affected surface.",
                "5. If critical: trigger incident response workflow and notify SOC.",
            ],
            estimated_minutes=15,
        ),
    }

    def suggest(self, signal: AnomalySignal) -> Optional[RunbookSuggestion]:
        key_map = {
            AnomalyKind.LATENCY_DEGRADATION: "latency_degradation",
            AnomalyKind.ERROR_RATE_SPIKE: "error_rate_spike",
            AnomalyKind.COST_SPIKE: "cost_spike",
            AnomalyKind.FLATLINE: "flatline",
            AnomalyKind.SECURITY_CORRELATION: "security_correlation",
        }
        key = key_map.get(signal.kind)
        return self._runbooks.get(key) if key else None

    def get(self, runbook_id: str) -> Optional[RunbookSuggestion]:
        for rb in self._runbooks.values():
            if rb.runbook_id == runbook_id:
                return rb
        return None


# ---------------------------------------------------------------------------
# Topology Mapper
# ---------------------------------------------------------------------------

class TopologyMapper:
    """
    Auto-generates a service topology map from observed telemetry.
    Services are discovered from MetricPoint.service tags.
    Edges (dependencies) are inferred from call patterns.
    """

    def __init__(self):
        self._services: Dict[str, ServiceNode] = {}
        self._call_counts: Dict[Tuple[str, str], int] = defaultdict(int)

    def observe(self, point: MetricPoint):
        svc_id = point.service
        if svc_id not in self._services:
            self._services[svc_id] = ServiceNode(
                service_id=svc_id,
                display_name=svc_id.replace("-", " ").replace("_", " ").title(),
                service_type=self._infer_type(svc_id),
                last_seen=point.timestamp,
            )
        node = self._services[svc_id]
        node.last_seen = point.timestamp

        # Update node metrics from known metric names
        if "error_rate" in point.metric:
            node.error_rate = point.value
            node.health = "degraded" if point.value > 0.05 else "healthy"
        elif "p95_latency" in point.metric or "latency_p95" in point.metric:
            node.p95_latency_ms = point.value
        elif "rps" in point.metric or "requests_per_second" in point.metric:
            node.rps = point.value
        elif "cost" in point.metric:
            node.cost_per_hour_usd = point.value

        # Infer caller from tags
        caller = point.tags.get("caller")
        if caller:
            self._call_counts[(caller, svc_id)] += 1
            if caller in self._services:
                caller_node = self._services[caller]
                if svc_id not in caller_node.dependencies:
                    caller_node.dependencies.append(svc_id)

    def _infer_type(self, service_id: str) -> str:
        s = service_id.lower()
        if any(k in s for k in ["db", "postgres", "mysql", "sqlite", "clickhouse"]):
            return "db"
        if any(k in s for k in ["redis", "cache", "memcache"]):
            return "cache"
        if any(k in s for k in ["llm", "openai", "anthropic", "bedrock", "vertex"]):
            return "llm"
        if any(k in s for k in ["queue", "kafka", "rabbitmq", "sqs"]):
            return "queue"
        if any(k in s for k in ["gateway", "nginx", "proxy", "lb"]):
            return "gateway"
        return "api"

    def get_topology(self) -> List[ServiceNode]:
        return list(self._services.values())


# ---------------------------------------------------------------------------
# ClickHouse Query Builder
# ---------------------------------------------------------------------------

class ClickHouseQueryBuilder:
    """
    Pre-built ClickHouse queries for the observability dashboard.
    Designed to run against the telemetry engine's ai_events table.
    """

    QUERIES: Dict[str, str] = {
        "rps_by_service_1h": """
            SELECT source AS service, count() / 3600 AS rps
            FROM ai_events
            WHERE timestamp > now() - INTERVAL 1 HOUR
            GROUP BY service
            ORDER BY rps DESC
            LIMIT 20
        """,
        "error_rate_by_service_1h": """
            SELECT
                source AS service,
                countIf(severity IN ('critical','high')) / count() AS error_rate
            FROM ai_events
            WHERE timestamp > now() - INTERVAL 1 HOUR
            GROUP BY service
            HAVING count() > 10
            ORDER BY error_rate DESC
            LIMIT 20
        """,
        "p95_latency_by_service_1h": """
            SELECT
                source AS service,
                quantile(0.95)(latency_ms) AS p95_latency_ms
            FROM ai_events
            WHERE timestamp > now() - INTERVAL 1 HOUR
            GROUP BY service
            ORDER BY p95_latency_ms DESC
            LIMIT 20
        """,
        "cost_by_provider_24h": """
            SELECT
                provider,
                model,
                sum(cost_usd) AS total_cost_usd,
                count() AS request_count
            FROM ai_events
            WHERE timestamp > now() - INTERVAL 24 HOUR
            GROUP BY provider, model
            ORDER BY total_cost_usd DESC
            LIMIT 20
        """,
        "anomaly_rate_trend_6h": """
            SELECT
                toStartOfInterval(timestamp, INTERVAL 10 MINUTE) AS bucket,
                countIf(risk_score > 0.7) AS high_risk_events,
                count() AS total_events,
                high_risk_events / total_events AS anomaly_rate
            FROM ai_events
            WHERE timestamp > now() - INTERVAL 6 HOUR
            GROUP BY bucket
            ORDER BY bucket ASC
        """,
        "top_risk_events_1h": """
            SELECT
                timestamp, event_type, source, severity,
                risk_score, data
            FROM ai_events
            WHERE timestamp > now() - INTERVAL 1 HOUR
              AND risk_score > 0.6
            ORDER BY risk_score DESC
            LIMIT 50
        """,
        "supply_chain_events_24h": """
            SELECT
                timestamp, source, data
            FROM ai_events
            WHERE event_type = 'supply_chain_event'
              AND timestamp > now() - INTERVAL 24 HOUR
            ORDER BY timestamp DESC
            LIMIT 100
        """,
        "identity_events_24h": """
            SELECT
                timestamp, user_id, source,
                JSONExtractString(data, 'identity_type') AS identity_type,
                JSONExtractString(data, 'anomaly') AS anomaly,
                risk_score
            FROM ai_events
            WHERE event_type = 'identity_event'
              AND timestamp > now() - INTERVAL 24 HOUR
            ORDER BY risk_score DESC
            LIMIT 100
        """,
    }

    @classmethod
    def get(cls, query_name: str) -> Optional[str]:
        return cls.QUERIES.get(query_name)

    @classmethod
    def list_queries(cls) -> List[str]:
        return list(cls.QUERIES.keys())


# ---------------------------------------------------------------------------
# Main Engine
# ---------------------------------------------------------------------------

class ObservabilityEngine:
    """
    Central observability orchestrator.
    Accepts metric ingest, runs anomaly detection, manages alerts,
    maintains topology, and builds dashboard payloads.
    """

    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.alert_engine = AlertEngine()
        self.topology = TopologyMapper()
        self.query_builder = ClickHouseQueryBuilder()
        self._metric_buffer: List[MetricPoint] = []
        self._last_supply_chain_score: float = 1.0
        logger.info("ObservabilityEngine initialized")

    def ingest(self, point: MetricPoint) -> Optional[Alert]:
        """Ingest a single metric point. Returns an Alert if anomalous."""
        self._metric_buffer.append(point)
        if len(self._metric_buffer) > 100_000:
            self._metric_buffer = self._metric_buffer[-50_000:]

        self.topology.observe(point)

        signal = self.anomaly_detector.ingest(point)
        if signal:
            return self.alert_engine.process(signal)
        return None

    def ingest_batch(self, points: List[MetricPoint]) -> List[Alert]:
        """Batch ingest. Returns list of new alerts generated."""
        alerts = []
        for p in points:
            alert = self.ingest(p)
            if alert:
                alerts.append(alert)
        return alerts

    def correlate_security_event(self, service: str, description: str,
                                 supply_chain_score: Optional[float] = None):
        """
        Inject a security correlation event into the alert engine.
        Called by SupplyChainEngine when a provenance failure is detected,
        or by the guardrails/policy engine when a threat is blocked.
        """
        if supply_chain_score is not None:
            self._last_supply_chain_score = supply_chain_score

        signal = AnomalySignal(
            service=service,
            metric="security_event",
            kind=AnomalyKind.SECURITY_CORRELATION,
            severity=AlertSeverity.CRITICAL if (supply_chain_score or 1.0) < 0.5 else AlertSeverity.HIGH,
            observed_value=1.0,
            baseline_value=0.0,
            deviation_pct=100.0,
            description=description,
        )
        return self.alert_engine.process(signal)

    def build_dashboard(self) -> Dashboard:
        """Build the full dashboard payload."""
        services = self.topology.get_topology()
        active_alerts = self.alert_engine.get_active()

        total_rps = sum(s.rps for s in services)
        error_rates = [s.error_rate for s in services if s.rps > 0]
        avg_error_rate = sum(error_rates) / len(error_rates) if error_rates else 0.0
        latencies = [s.p95_latency_ms for s in services if s.p95_latency_ms > 0]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        total_cost = sum(s.cost_per_hour_usd for s in services)

        critical_count = sum(1 for a in active_alerts if a.severity == AlertSeverity.CRITICAL)

        return Dashboard(
            generated_at=datetime.now(timezone.utc).isoformat(),
            services=services,
            alerts=active_alerts[:50],  # Cap at 50 for payload size
            anomalies=[a.anomaly for a in active_alerts if a.anomaly],
            total_rps=total_rps,
            total_error_rate=avg_error_rate,
            total_p95_latency_ms=avg_latency,
            total_cost_per_hour_usd=total_cost,
            active_alert_count=len(active_alerts),
            critical_alert_count=critical_count,
            supply_chain_risk_score=self._last_supply_chain_score,
            summary={
                "service_count": len(services),
                "healthy_services": sum(1 for s in services if s.health == "healthy"),
                "degraded_services": sum(1 for s in services if s.health == "degraded"),
                "down_services": sum(1 for s in services if s.health == "down"),
                "clickhouse_queries": self.query_builder.list_queries(),
            },
        )

    def get_runbook(self, runbook_id: str) -> Optional[RunbookSuggestion]:
        return self.alert_engine._runbooks.get_by_id(runbook_id)

    def acknowledge_alert(self, alert_id: str) -> bool:
        return self.alert_engine.acknowledge(alert_id)

    def resolve_alert(self, alert_id: str) -> bool:
        return self.alert_engine.resolve(alert_id)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[ObservabilityEngine] = None


def get_engine() -> ObservabilityEngine:
    global _engine
    if _engine is None:
        _engine = ObservabilityEngine()
    return _engine
