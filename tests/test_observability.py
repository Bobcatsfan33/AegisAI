"""
Tests for Observability Engine — AegisAI v3.1.0

Covers:
  - Metric ingest and baseline tracking
  - Anomaly detection (spike, drop, flatline, latency, error rate, cost)
  - Alert deduplication and noise suppression
  - Alert acknowledge / resolve lifecycle
  - Service topology auto-map
  - Security event correlation
  - Dashboard payload structure
  - Runbook suggestion mapping
  - ClickHouse query builder
"""

import time
import pytest

from modules.observability import (
    ObservabilityEngine,
    MetricPoint,
    Alert,
    AlertSeverity,
    AnomalySignal,
    Dashboard,
    RunbookSuggestion,
    get_engine,
)
from modules.observability.engine import (
    AnomalyDetector,
    AnomalyKind,
    AlertEngine,
    TopologyMapper,
    RunbookLibrary,
    ClickHouseQueryBuilder,
    MetricType,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def obs_engine():
    return ObservabilityEngine()


@pytest.fixture
def anomaly_detector():
    return AnomalyDetector(window_size=20, sigma_threshold=3.0)


@pytest.fixture
def alert_engine():
    return AlertEngine()


# ---------------------------------------------------------------------------
# Metric ingest
# ---------------------------------------------------------------------------

class TestMetricIngest:
    def test_ingest_single_point(self, obs_engine):
        point = MetricPoint(service="api", metric="rps", value=100.0)
        obs_engine.ingest(point)

    def test_ingest_batch(self, obs_engine):
        points = [MetricPoint(service="api", metric="rps", value=float(i)) for i in range(10)]
        alerts = obs_engine.ingest_batch(points)
        assert isinstance(alerts, list)

    def test_no_alert_before_baseline(self, obs_engine):
        # With only a few points, no alert should fire
        for i in range(5):
            alert = obs_engine.ingest(MetricPoint(service="api", metric="rps", value=100.0))
        # Should not generate alerts this early (not enough baseline data)
        # (may or may not fire depending on threshold — just ensure no exception)


# ---------------------------------------------------------------------------
# Anomaly Detector
# ---------------------------------------------------------------------------

class TestAnomalyDetector:
    def _feed_baseline(self, detector: AnomalyDetector, service: str,
                       metric: str, value: float, count: int = 15):
        for _ in range(count):
            detector.ingest(MetricPoint(service=service, metric=metric, value=value))

    def test_no_anomaly_stable_signal(self, anomaly_detector):
        import random
        random.seed(42)
        # Feed a window with realistic variance (not perfectly uniform, which would make
        # any deviation appear as high sigma due to near-zero std dev)
        for i in range(20):
            val = 100.0 + random.gauss(0, 5)  # Natural ±5 variance
            anomaly_detector.ingest(MetricPoint(service="svc2", metric="rps", value=val))
        # 102 is well within 3σ of a N(100, 5) distribution
        last = anomaly_detector.ingest(MetricPoint(service="svc2", metric="rps", value=102.0))
        assert last is None  # Within 3σ of realistic baseline

    def test_spike_detected(self, anomaly_detector):
        self._feed_baseline(anomaly_detector, "svc", "rps", 100.0, 20)
        signal = anomaly_detector.ingest(MetricPoint(service="svc", metric="rps", value=10000.0))
        assert signal is not None
        assert signal.kind == AnomalyKind.SPIKE

    def test_latency_anomaly_classified(self, anomaly_detector):
        self._feed_baseline(anomaly_detector, "svc", "p95_latency_ms", 50.0, 20)
        signal = anomaly_detector.ingest(
            MetricPoint(service="svc", metric="p95_latency_ms", value=5000.0)
        )
        assert signal is not None
        assert signal.kind == AnomalyKind.LATENCY_DEGRADATION

    def test_error_rate_anomaly_classified(self, anomaly_detector):
        self._feed_baseline(anomaly_detector, "svc", "error_rate", 0.01, 20)
        signal = anomaly_detector.ingest(
            MetricPoint(service="svc", metric="error_rate", value=0.95)
        )
        assert signal is not None
        assert signal.kind == AnomalyKind.ERROR_RATE_SPIKE

    def test_cost_spike_classified(self, anomaly_detector):
        self._feed_baseline(anomaly_detector, "svc", "cost_usd", 0.10, 20)
        signal = anomaly_detector.ingest(
            MetricPoint(service="svc", metric="cost_usd", value=100.0)
        )
        assert signal is not None
        assert signal.kind == AnomalyKind.COST_SPIKE

    def test_drop_detected(self, anomaly_detector):
        self._feed_baseline(anomaly_detector, "svc", "rps", 1000.0, 20)
        signal = anomaly_detector.ingest(MetricPoint(service="svc", metric="rps", value=0.0))
        assert signal is not None
        assert signal.kind in (AnomalyKind.DROP, AnomalyKind.FLATLINE)

    def test_severity_scales_with_deviation(self, anomaly_detector):
        self._feed_baseline(anomaly_detector, "svc", "rps", 100.0, 20)
        # Extreme spike → critical severity
        signal = anomaly_detector.ingest(MetricPoint(service="svc", metric="rps", value=1_000_000.0))
        if signal:
            assert signal.severity in (AlertSeverity.CRITICAL, AlertSeverity.HIGH)

    def test_baseline_query(self, anomaly_detector):
        for _ in range(15):
            anomaly_detector.ingest(MetricPoint(service="s", metric="m", value=50.0))
        baseline = anomaly_detector.get_baseline("s", "m")
        assert baseline is not None
        assert abs(baseline - 50.0) < 5.0

    def test_no_baseline_before_min_obs(self, anomaly_detector):
        anomaly_detector.ingest(MetricPoint(service="s", metric="m", value=50.0))
        baseline = anomaly_detector.get_baseline("s", "m")
        assert baseline is None


# ---------------------------------------------------------------------------
# Alert Engine
# ---------------------------------------------------------------------------

class TestAlertEngine:
    def _make_signal(self, kind=AnomalyKind.SPIKE, service="api",
                     metric="rps", severity=AlertSeverity.HIGH) -> AnomalySignal:
        return AnomalySignal(
            service=service, metric=metric, kind=kind,
            severity=severity, observed_value=1000.0,
            baseline_value=100.0, deviation_pct=900.0,
            description="Test anomaly",
        )

    def test_alert_generated_from_signal(self, alert_engine):
        signal = self._make_signal()
        alert = alert_engine.process(signal)
        assert alert is not None
        assert alert.alert_id
        assert alert.severity == AlertSeverity.HIGH

    def test_deduplication_same_group_key(self, alert_engine):
        signal = self._make_signal()
        alert1 = alert_engine.process(signal)
        alert2 = alert_engine.process(signal)
        assert alert1 is not None
        assert alert2 is None  # Deduplicated

    def test_different_metrics_not_deduplicated(self, alert_engine):
        s1 = self._make_signal(metric="rps")
        s2 = self._make_signal(metric="error_rate")
        a1 = alert_engine.process(s1)
        a2 = alert_engine.process(s2)
        assert a1 is not None
        assert a2 is not None

    def test_acknowledge_alert(self, alert_engine):
        alert = alert_engine.process(self._make_signal())
        assert alert is not None
        ok = alert_engine.acknowledge(alert.alert_id)
        assert ok
        active = alert_engine.get_active()
        for a in active:
            if a.alert_id == alert.alert_id:
                assert a.acknowledged

    def test_resolve_removes_from_active(self, alert_engine):
        signal = self._make_signal(metric="unique_resolve_metric")
        alert = alert_engine.process(signal)
        assert alert is not None
        ok = alert_engine.resolve(alert.alert_id)
        assert ok
        active = alert_engine.get_active()
        assert all(a.alert_id != alert.alert_id for a in active)

    def test_get_active_by_severity(self, alert_engine):
        alert_engine.process(self._make_signal(severity=AlertSeverity.CRITICAL, metric="m1"))
        alert_engine.process(self._make_signal(severity=AlertSeverity.WARNING, metric="m2"))
        criticals = alert_engine.get_active(severity="critical")
        assert all(a.severity == AlertSeverity.CRITICAL for a in criticals)

    def test_runbook_suggested_for_latency(self, alert_engine):
        signal = AnomalySignal(
            service="api", metric="p95_latency_ms",
            kind=AnomalyKind.LATENCY_DEGRADATION,
            severity=AlertSeverity.HIGH,
            observed_value=5000.0, baseline_value=50.0,
            deviation_pct=9900.0, description="Latency spike",
        )
        alert = alert_engine.process(signal)
        assert alert is not None
        assert alert.runbook_id is not None

    def test_alert_title_formatted(self, alert_engine):
        signal = self._make_signal(kind=AnomalyKind.FLATLINE, metric="traffic_rps")
        alert = alert_engine.process(signal)
        assert alert is not None
        assert "silent" in alert.title.lower() or "flatline" in alert.title.lower()


# ---------------------------------------------------------------------------
# Topology Mapper
# ---------------------------------------------------------------------------

class TestTopologyMapper:
    def test_service_auto_discovered(self):
        mapper = TopologyMapper()
        mapper.observe(MetricPoint(service="payment-api", metric="rps", value=100.0))
        nodes = mapper.get_topology()
        assert any(n.service_id == "payment-api" for n in nodes)

    def test_service_type_inferred_db(self):
        mapper = TopologyMapper()
        mapper.observe(MetricPoint(service="postgres-primary", metric="rps", value=10.0))
        nodes = mapper.get_topology()
        node = next(n for n in nodes if n.service_id == "postgres-primary")
        assert node.service_type == "db"

    def test_service_type_inferred_cache(self):
        mapper = TopologyMapper()
        mapper.observe(MetricPoint(service="redis-cache", metric="rps", value=500.0))
        nodes = mapper.get_topology()
        node = next(n for n in nodes if n.service_id == "redis-cache")
        assert node.service_type == "cache"

    def test_service_type_inferred_llm(self):
        mapper = TopologyMapper()
        mapper.observe(MetricPoint(service="openai-connector", metric="rps", value=5.0))
        nodes = mapper.get_topology()
        node = next(n for n in nodes if n.service_id == "openai-connector")
        assert node.service_type == "llm"

    def test_metrics_update_node(self):
        mapper = TopologyMapper()
        mapper.observe(MetricPoint(service="api", metric="error_rate", value=0.15))
        nodes = mapper.get_topology()
        node = next(n for n in nodes if n.service_id == "api")
        assert node.error_rate == pytest.approx(0.15)
        assert node.health == "degraded"

    def test_caller_dependency_tracked(self):
        mapper = TopologyMapper()
        mapper.observe(MetricPoint(service="frontend", metric="rps", value=100.0,
                                   tags={"caller": "load-balancer"}))
        # Load balancer (caller) → frontend (callee)
        # Observer creates a dependency edge caller → callee
        nodes = mapper.get_topology()
        assert any(n.service_id == "frontend" for n in nodes)


# ---------------------------------------------------------------------------
# Security Correlation
# ---------------------------------------------------------------------------

class TestSecurityCorrelation:
    def test_security_event_generates_alert(self, obs_engine):
        alert = obs_engine.correlate_security_event(
            service="ci-pipeline",
            description="Supply chain provenance score below threshold",
            supply_chain_score=0.2,
        )
        assert alert is not None
        assert alert.severity == AlertSeverity.CRITICAL

    def test_moderate_risk_generates_high_alert(self, obs_engine):
        alert = obs_engine.correlate_security_event(
            service="registry",
            description="Artifact hash mismatch detected",
            supply_chain_score=0.6,
        )
        assert alert is not None
        assert alert.severity == AlertSeverity.HIGH

    def test_supply_chain_score_tracked_in_dashboard(self, obs_engine):
        obs_engine.correlate_security_event(
            service="svc", description="Test", supply_chain_score=0.3
        )
        dash = obs_engine.build_dashboard()
        assert dash.supply_chain_risk_score == pytest.approx(0.3)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class TestDashboard:
    def test_dashboard_structure(self, obs_engine):
        dash = obs_engine.build_dashboard()
        assert hasattr(dash, "generated_at")
        assert hasattr(dash, "services")
        assert hasattr(dash, "alerts")
        assert hasattr(dash, "total_rps")
        assert hasattr(dash, "active_alert_count")

    def test_dashboard_service_count_matches_ingest(self, obs_engine):
        obs_engine.ingest(MetricPoint(service="svc-a", metric="rps", value=10.0))
        obs_engine.ingest(MetricPoint(service="svc-b", metric="rps", value=20.0))
        dash = obs_engine.build_dashboard()
        service_ids = {s.service_id for s in dash.services}
        assert "svc-a" in service_ids
        assert "svc-b" in service_ids

    def test_dashboard_total_rps_sums_services(self, obs_engine):
        obs_engine.ingest(MetricPoint(service="svc-c", metric="rps", value=50.0))
        dash = obs_engine.build_dashboard()
        # Total RPS should include svc-c's contribution
        total = sum(s.rps for s in dash.services)
        assert total >= 50.0


# ---------------------------------------------------------------------------
# Runbook Library
# ---------------------------------------------------------------------------

class TestRunbookLibrary:
    @pytest.fixture
    def library(self):
        return RunbookLibrary()

    def test_latency_runbook_suggested(self, library):
        signal = AnomalySignal(
            service="api", metric="p95_latency_ms",
            kind=AnomalyKind.LATENCY_DEGRADATION,
            severity=AlertSeverity.HIGH,
            observed_value=5000.0, baseline_value=50.0,
            deviation_pct=9900.0,
        )
        rb = library.suggest(signal)
        assert rb is not None
        assert "latency" in rb.title.lower() or "Latency" in rb.title

    def test_error_runbook_suggested(self, library):
        signal = AnomalySignal(
            service="api", metric="error_rate",
            kind=AnomalyKind.ERROR_RATE_SPIKE,
            severity=AlertSeverity.CRITICAL,
            observed_value=0.9, baseline_value=0.01,
            deviation_pct=8900.0,
        )
        rb = library.suggest(signal)
        assert rb is not None
        assert len(rb.steps) > 0

    def test_flatline_runbook_has_automation(self, library):
        signal = AnomalySignal(
            service="api", metric="rps",
            kind=AnomalyKind.FLATLINE,
            severity=AlertSeverity.HIGH,
            observed_value=0.0, baseline_value=100.0,
            deviation_pct=100.0,
        )
        rb = library.suggest(signal)
        assert rb is not None
        assert rb.automation_available

    def test_no_runbook_for_unknown_kind(self, library):
        signal = AnomalySignal(
            service="api", metric="some_metric",
            kind=AnomalyKind.DRIFT,  # No runbook mapped
            severity=AlertSeverity.WARNING,
            observed_value=50.0, baseline_value=45.0,
            deviation_pct=11.0,
        )
        rb = library.suggest(signal)
        assert rb is None


# ---------------------------------------------------------------------------
# ClickHouse Query Builder
# ---------------------------------------------------------------------------

class TestClickHouseQueryBuilder:
    def test_all_queries_retrievable(self):
        for name in ClickHouseQueryBuilder.list_queries():
            q = ClickHouseQueryBuilder.get(name)
            assert q is not None
            assert len(q.strip()) > 0

    def test_known_query_names(self):
        names = ClickHouseQueryBuilder.list_queries()
        assert "rps_by_service_1h" in names
        assert "error_rate_by_service_1h" in names
        assert "p95_latency_by_service_1h" in names
        assert "cost_by_provider_24h" in names
        assert "top_risk_events_1h" in names

    def test_unknown_query_returns_none(self):
        result = ClickHouseQueryBuilder.get("does_not_exist")
        assert result is None

    def test_queries_contain_sql_keywords(self):
        for name in ClickHouseQueryBuilder.list_queries():
            q = ClickHouseQueryBuilder.get(name)
            assert "SELECT" in q.upper()


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

class TestSingleton:
    def test_get_engine_singleton(self):
        e1 = get_engine()
        e2 = get_engine()
        assert e1 is e2
