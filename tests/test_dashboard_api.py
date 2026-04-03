"""
Tests for Dashboard & Reporting API endpoints.

Covers:
  GET /dashboard               → HTML page
  GET /api/dashboard/summary   → JSON summary
  GET /api/dashboard/events    → JSON events list
  GET /api/reports/compliance  → JSON compliance report
  GET /api/reports/compliance/pdf  → PDF bytes
  GET /api/reports/compliance/docx → DOCX bytes
  GET /api/reports/ai          → AI framework JSON report
  GET /api/reports/ai/pdf      → AI compliance PDF
  GET /api/reports/ai/docx     → AI compliance DOCX

All ClickHouse / telemetry calls are mocked.
Uses a minimal FastAPI test app (not the full api.py) to avoid Python 3.9
incompatibilities with str | None type hints in api.py.
"""
from __future__ import annotations

import io
import os
import sys
import zipfile
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ---------------------------------------------------------------------------
# Patch heavyweight external modules before any project imports
# ---------------------------------------------------------------------------
_MOCK_MODULES = [
    "clickhouse_driver",
    "redis",
    "redis.asyncio",
    "boto3",
    "botocore",
    "botocore.exceptions",
    "azure.identity",
    "azure.mgmt.resource",
    "google.cloud.asset_v1",
    "google.cloud.resourcemanager_v3",
    "kubernetes",
    "kubernetes.client",
    "kubernetes.config",
    "nmap",
    "paramiko",
]
for _mod in _MOCK_MODULES:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

# Patch RBAC so all endpoints pass auth
import modules.security.rbac as _rbac_module  # noqa: E402

_rbac_module.require_role = lambda role=None: (lambda: {"sub": "test", "role": "ADMIN"})  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Build a minimal FastAPI app with only the routes under test
# ---------------------------------------------------------------------------
from fastapi import FastAPI  # noqa: E402
from fastapi.responses import FileResponse  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from modules.analytics.routes import dashboard_router  # noqa: E402

_test_app = FastAPI()
_test_app.include_router(dashboard_router)

# Wire the /dashboard HTML route
_DASHBOARD_HTML = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "modules", "analytics", "dashboard.html",
)


@_test_app.get("/dashboard", include_in_schema=False)
async def _dashboard_html():
    return FileResponse(_DASHBOARD_HTML, media_type="text/html")


client = TestClient(_test_app, raise_server_exceptions=True)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MOCK_EVENTS: List[Dict[str, Any]] = [
    {"event_type": "prompt_injection", "severity": "high",     "tenant_id": "t1"},
    {"event_type": "pii_detected",     "severity": "medium",   "tenant_id": "t1"},
    {"event_type": "policy_violation", "severity": "low",      "tenant_id": "t2"},
]

_MOCK_STATS: Dict[str, Any] = {
    "total_events": 42,
    "events_last_24h": 10,
    "risk_score": 75,
    "active_tenants": 3,
}


def _mock_engine(events=None, stats=None):
    eng = MagicMock()
    eng.get_recent_events.return_value = events if events is not None else []
    eng.get_stats.return_value = stats or _MOCK_STATS
    return eng


# ---------------------------------------------------------------------------
# /dashboard
# ---------------------------------------------------------------------------


class TestDashboardHTML:
    def test_dashboard_returns_200(self):
        resp = client.get("/dashboard")
        assert resp.status_code == 200

    def test_dashboard_content_type_html(self):
        resp = client.get("/dashboard")
        assert "text/html" in resp.headers["content-type"]

    def test_dashboard_nonempty(self):
        resp = client.get("/dashboard")
        assert len(resp.content) > 100


# ---------------------------------------------------------------------------
# /api/dashboard/summary
# ---------------------------------------------------------------------------


class TestDashboardSummary:
    def test_summary_200(self):
        with patch(
            "modules.analytics.routes._get_telemetry_engine",
            return_value=_mock_engine(events=_MOCK_EVENTS),
        ):
            resp = client.get("/api/dashboard/summary")
        assert resp.status_code == 200

    def test_summary_json_shape(self):
        with patch(
            "modules.analytics.routes._get_telemetry_engine",
            return_value=_mock_engine(events=_MOCK_EVENTS),
        ):
            data = client.get("/api/dashboard/summary").json()
        assert "total_events" in data
        assert "total_violations" in data
        assert "risk_score" in data
        assert "active_tenants" in data

    def test_summary_fallback_when_engine_none(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            data = client.get("/api/dashboard/summary").json()
        assert data["total_events"] == 0
        assert data["source"] == "fallback"

    def test_summary_fallback_when_engine_raises(self):
        eng = MagicMock()
        eng.get_stats.side_effect = RuntimeError("clickhouse down")
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=eng):
            data = client.get("/api/dashboard/summary").json()
        assert data["source"] == "fallback"

    def test_summary_violations_counted(self):
        events = [
            {"event_type": "prompt_injection", "severity": "critical"},
            {"event_type": "pii_detected",     "severity": "high"},
            {"event_type": "unknown_event",     "severity": "low"},
        ]
        with patch(
            "modules.analytics.routes._get_telemetry_engine",
            return_value=_mock_engine(events=events),
        ):
            data = client.get("/api/dashboard/summary").json()
        # prompt_injection and pii_detected are violation types
        assert data["total_violations"] >= 2

    def test_summary_source_is_telemetry_when_available(self):
        with patch(
            "modules.analytics.routes._get_telemetry_engine",
            return_value=_mock_engine(events=_MOCK_EVENTS),
        ):
            data = client.get("/api/dashboard/summary").json()
        assert data["source"] == "telemetry"


# ---------------------------------------------------------------------------
# /api/dashboard/events
# ---------------------------------------------------------------------------


class TestDashboardEvents:
    def test_events_200(self):
        with patch(
            "modules.analytics.routes._get_telemetry_engine",
            return_value=_mock_engine(events=_MOCK_EVENTS),
        ):
            resp = client.get("/api/dashboard/events")
        assert resp.status_code == 200

    def test_events_returns_list(self):
        with patch(
            "modules.analytics.routes._get_telemetry_engine",
            return_value=_mock_engine(events=_MOCK_EVENTS),
        ):
            data = client.get("/api/dashboard/events").json()
        assert "events" in data
        assert isinstance(data["events"], list)

    def test_events_empty_when_engine_unavailable(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            data = client.get("/api/dashboard/events").json()
        assert data["events"] == []

    def test_events_limit_param(self):
        events = [{"event_type": f"ev{i}", "severity": "info"} for i in range(20)]
        with patch(
            "modules.analytics.routes._get_telemetry_engine",
            return_value=_mock_engine(events=events),
        ):
            data = client.get("/api/dashboard/events?limit=5").json()
        assert len(data["events"]) <= 5

    def test_events_includes_total(self):
        with patch(
            "modules.analytics.routes._get_telemetry_engine",
            return_value=_mock_engine(events=_MOCK_EVENTS),
        ):
            data = client.get("/api/dashboard/events").json()
        assert "total" in data

    def test_events_count_matches(self):
        with patch(
            "modules.analytics.routes._get_telemetry_engine",
            return_value=_mock_engine(events=_MOCK_EVENTS),
        ):
            data = client.get("/api/dashboard/events").json()
        assert data["total"] == len(data["events"])

    def test_events_includes_limit_and_offset(self):
        with patch(
            "modules.analytics.routes._get_telemetry_engine",
            return_value=_mock_engine(events=_MOCK_EVENTS),
        ):
            data = client.get("/api/dashboard/events").json()
        assert "limit" in data
        assert "offset" in data


# ---------------------------------------------------------------------------
# /api/reports/compliance  (JSON)
# ---------------------------------------------------------------------------


class TestComplianceReportJSON:
    def test_compliance_json_200(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/compliance")
        assert resp.status_code == 200

    def test_compliance_json_has_framework_key(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            data = client.get("/api/reports/compliance").json()
        assert "framework" in data

    def test_compliance_json_nist_800_53(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            data = client.get("/api/reports/compliance?framework=NIST_800_53").json()
        assert data.get("framework") == "NIST_800_53"

    def test_compliance_json_nist_ai_rmf(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            data = client.get("/api/reports/compliance?framework=NIST_AI_RMF").json()
        assert data.get("framework") == "NIST_AI_RMF"

    def test_compliance_json_invalid_framework_400(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/compliance?framework=HIPAA")
        assert resp.status_code == 400

    def test_compliance_json_empty_score_100(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            data = client.get("/api/reports/compliance?framework=NIST_800_53").json()
        assert data.get("overall_score") == 100.0

    def test_compliance_json_has_sections(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            data = client.get("/api/reports/compliance?framework=NIST_AI_RMF").json()
        assert "sections" in data
        assert len(data["sections"]) > 0


# ---------------------------------------------------------------------------
# /api/reports/compliance/pdf
# ---------------------------------------------------------------------------


class TestComplianceReportPDF:
    def test_pdf_200(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/compliance/pdf")
        assert resp.status_code == 200

    def test_pdf_content_type(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/compliance/pdf")
        assert resp.headers["content-type"] == "application/pdf"

    def test_pdf_starts_with_pdf_header(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/compliance/pdf")
        assert resp.content[:4] == b"%PDF"

    def test_pdf_nonempty(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/compliance/pdf")
        assert len(resp.content) > 100

    def test_pdf_invalid_framework_400(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/compliance/pdf?framework=HIPAA")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /api/reports/compliance/docx
# ---------------------------------------------------------------------------


class TestComplianceReportDOCX:
    def test_docx_200(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/compliance/docx")
        assert resp.status_code == 200

    def test_docx_content_type(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/compliance/docx")
        assert "wordprocessingml" in resp.headers["content-type"]

    def test_docx_starts_with_pk_magic(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/compliance/docx")
        assert resp.content[:2] == b"PK"

    def test_docx_is_valid_zip(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/compliance/docx")
        assert zipfile.is_zipfile(io.BytesIO(resp.content))

    def test_docx_nonempty(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/compliance/docx")
        assert len(resp.content) > 100


# ---------------------------------------------------------------------------
# /api/reports/ai  (JSON)
# ---------------------------------------------------------------------------


class TestAIComplianceReportJSON:
    def test_ai_json_200(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/ai")
        assert resp.status_code == 200

    def test_ai_json_shape(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            data = client.get("/api/reports/ai").json()
        assert "frameworks" in data
        assert "overall_risk_score" in data
        assert "event_count" in data
        assert "violation_count" in data

    def test_ai_json_frameworks_present(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            data = client.get("/api/reports/ai").json()
        fw = data["frameworks"]
        assert "NIST_AI_RMF" in fw
        assert "OWASP_LLM" in fw
        assert "EU_AI_ACT" in fw
        assert "ISO_42001" in fw

    def test_ai_json_empty_score_100(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            data = client.get("/api/reports/ai").json()
        assert data["overall_risk_score"] == 100.0

    def test_ai_json_with_violations(self):
        events = [
            {"event_type": "prompt_injection", "severity": "critical"},
            {"event_type": "data_exfiltration", "severity": "high"},
        ]
        with patch(
            "modules.analytics.routes._get_telemetry_engine",
            return_value=_mock_engine(events=events),
        ):
            data = client.get("/api/reports/ai").json()
        assert data["violation_count"] == 2
        assert data["overall_risk_score"] < 100.0


# ---------------------------------------------------------------------------
# /api/reports/ai/pdf
# ---------------------------------------------------------------------------


class TestAIComplianceReportPDF:
    def test_ai_pdf_200(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/ai/pdf")
        assert resp.status_code == 200

    def test_ai_pdf_content_type(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/ai/pdf")
        assert resp.headers["content-type"] == "application/pdf"

    def test_ai_pdf_starts_with_pdf_header(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/ai/pdf")
        assert resp.content[:4] == b"%PDF"

    def test_ai_pdf_nonempty(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/ai/pdf")
        assert len(resp.content) > 200


# ---------------------------------------------------------------------------
# /api/reports/ai/docx
# ---------------------------------------------------------------------------


class TestAIComplianceReportDOCX:
    def test_ai_docx_200(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/ai/docx")
        assert resp.status_code == 200

    def test_ai_docx_starts_with_pk_magic(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/ai/docx")
        assert resp.content[:2] == b"PK"

    def test_ai_docx_content_type(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/ai/docx")
        assert "wordprocessingml" in resp.headers["content-type"]

    def test_ai_docx_valid_zip(self):
        with patch("modules.analytics.routes._get_telemetry_engine", return_value=None):
            resp = client.get("/api/reports/ai/docx")
        assert zipfile.is_zipfile(io.BytesIO(resp.content))
