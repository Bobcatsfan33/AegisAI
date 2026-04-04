"""
AegisAI — Dashboard & Reporting API Routes

Endpoints:
  GET /api/dashboard/summary      → Counts: events, violations, risk score, tenants
  GET /api/dashboard/events       → Recent AI events (paginated)
  GET /api/reports/compliance     → NIST 800-53 JSON report
  GET /api/reports/compliance/pdf → PDF bytes (Content-Type: application/pdf)
  GET /api/reports/compliance/docx→ DOCX bytes
  GET /api/reports/ai             → AI framework compliance JSON report
  GET /api/reports/ai/pdf         → AI compliance PDF
  GET /api/reports/ai/docx        → AI compliance DOCX

All endpoints gracefully handle missing ClickHouse / telemetry engine
(return empty/mock data instead of 500).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from modules.security.rbac import Role, require_role

logger = logging.getLogger("aegis.analytics")

dashboard_router = APIRouter(prefix="/api", tags=["Dashboard"])

# ── lazy imports to avoid circular deps ──────────────────────────────────────


def _get_telemetry_engine():
    """Return the shared TelemetryEngine instance (imported lazily)."""
    try:
        from modules.aegis_ai.routes import _telemetry_engine  # type: ignore[attr-defined]
        return _telemetry_engine
    except Exception:
        return None


def _get_compliance_reporter(tenant_id: str = "default"):
    from modules.reports.compliance import ComplianceReporter
    return ComplianceReporter(tenant_id=tenant_id)


def _get_ai_compliance_reporter(tenant_id: str = "default"):
    from modules.reports.compliance import AIComplianceReporter
    return AIComplianceReporter(tenant_id=tenant_id)


def _get_compliance_report_generator():
    from modules.reports.compliance import ComplianceReportGenerator
    return ComplianceReportGenerator()


# ── /api/dashboard/summary ───────────────────────────────────────────────────


@dashboard_router.get(
    "/dashboard/summary",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def dashboard_summary() -> Dict[str, Any]:
    """
    Return high-level dashboard metrics.

    Queries the telemetry engine for aggregated counts.
    Returns empty/zero values if telemetry is unavailable.
    """
    engine = _get_telemetry_engine()
    try:
        if engine is not None:
            stats = engine.get_stats()
            # Try to get recent events for violation count
            recent: List[Dict[str, Any]] = []
            try:
                recent = engine.get_recent_events(limit=1000) or []
            except Exception:
                pass

            violations = sum(
                1 for e in recent
                if (
                    e.get("blocked") is True
                    or e.get("event_type") in {
                        "prompt_injection", "jailbreak", "data_exfiltration",
                        "pii_detected", "policy_violation",
                    }
                )
            )

            return {
                "total_events": stats.get("total_events", 0),
                "total_violations": violations,
                "risk_score": stats.get("risk_score", 100),
                "active_tenants": stats.get("active_tenants", 1),
                "events_last_24h": stats.get("events_last_24h", 0),
                "source": "telemetry",
            }
    except Exception as exc:
        logger.warning("dashboard_summary: telemetry unavailable: %s", exc)

    # Graceful fallback
    return {
        "total_events": 0,
        "total_violations": 0,
        "risk_score": 100,
        "active_tenants": 0,
        "events_last_24h": 0,
        "source": "fallback",
    }


# ── /api/dashboard/events ────────────────────────────────────────────────────


@dashboard_router.get(
    "/dashboard/events",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def dashboard_events(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """
    Return recent AI security events (paginated).

    Query params:
      limit  — number of events to return (1-1000, default 100)
      offset — pagination offset (default 0)
    """
    engine = _get_telemetry_engine()
    events: List[Dict[str, Any]] = []

    try:
        if engine is not None:
            raw = engine.get_recent_events(limit=limit + offset) or []
            events = raw[offset : offset + limit]
    except Exception as exc:
        logger.warning("dashboard_events: telemetry unavailable: %s", exc)

    return {
        "events": events,
        "total": len(events),
        "limit": limit,
        "offset": offset,
    }


# ── /api/reports/compliance ──────────────────────────────────────────────────


@dashboard_router.get(
    "/reports/compliance",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def compliance_report_json(
    framework: str = Query(default="NIST_800_53"),
    tenant_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """
    Generate a compliance report for *framework* and return as JSON.

    Supported frameworks: NIST_800_53, NIST_AI_RMF, OWASP_LLM, EU_AI_ACT, ISO_42001
    """
    engine = _get_telemetry_engine()
    events: List[Any] = []
    try:
        if engine is not None:
            events = engine.get_recent_events(limit=10000) or []
    except Exception as exc:
        logger.warning("compliance_report_json: telemetry unavailable: %s", exc)

    reporter = _get_compliance_reporter(tenant_id=tenant_id)
    try:
        report = reporter.generate(events, framework=framework)
        return report.to_dict()
    except ValueError as exc:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=str(exc))


@dashboard_router.get(
    "/reports/compliance/pdf",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def compliance_report_pdf(
    framework: str = Query(default="NIST_800_53"),
    tenant_id: str = Query(default="default"),
) -> Response:
    """Return a compliance report as PDF (Content-Type: application/pdf)."""
    engine = _get_telemetry_engine()
    events: List[Any] = []
    try:
        if engine is not None:
            events = engine.get_recent_events(limit=10000) or []
    except Exception as exc:
        logger.warning("compliance_report_pdf: telemetry unavailable: %s", exc)

    reporter = _get_compliance_reporter(tenant_id=tenant_id)
    try:
        report = reporter.generate(events, framework=framework)
    except ValueError as exc:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=str(exc))

    pdf_bytes = report.to_pdf_bytes()
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=compliance_{framework}.pdf"
        },
    )


@dashboard_router.get(
    "/reports/compliance/docx",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def compliance_report_docx(
    framework: str = Query(default="NIST_800_53"),
    tenant_id: str = Query(default="default"),
) -> Response:
    """Return a compliance report as DOCX (Office Open XML)."""
    engine = _get_telemetry_engine()
    events: List[Any] = []
    try:
        if engine is not None:
            events = engine.get_recent_events(limit=10000) or []
    except Exception as exc:
        logger.warning("compliance_report_docx: telemetry unavailable: %s", exc)

    reporter = _get_compliance_reporter(tenant_id=tenant_id)
    try:
        report = reporter.generate(events, framework=framework)
    except ValueError as exc:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=str(exc))

    docx_bytes = report.to_docx_bytes()
    return Response(
        content=docx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={
            "Content-Disposition": f"attachment; filename=compliance_{framework}.docx"
        },
    )


# ── /api/reports/ai ──────────────────────────────────────────────────────────


@dashboard_router.get(
    "/reports/ai",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def ai_compliance_report_json(
    tenant_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """
    Generate an AI security compliance report spanning NIST AI RMF,
    OWASP LLM Top 10, EU AI Act, and ISO 42001.  Returns JSON.
    """
    engine = _get_telemetry_engine()
    events: List[Any] = []
    try:
        if engine is not None:
            events = engine.get_recent_events(limit=10000) or []
    except Exception as exc:
        logger.warning("ai_compliance_report_json: telemetry unavailable: %s", exc)

    reporter = _get_ai_compliance_reporter(tenant_id=tenant_id)
    report = reporter.generate(events)
    return report.to_dict()


@dashboard_router.get(
    "/reports/ai/pdf",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def ai_compliance_report_pdf(
    tenant_id: str = Query(default="default"),
) -> Response:
    """Return the AI compliance report as PDF."""
    engine = _get_telemetry_engine()
    events: List[Any] = []
    try:
        if engine is not None:
            events = engine.get_recent_events(limit=10000) or []
    except Exception as exc:
        logger.warning("ai_compliance_report_pdf: telemetry unavailable: %s", exc)

    reporter = _get_ai_compliance_reporter(tenant_id=tenant_id)
    report = reporter.generate(events)
    return Response(
        content=report.to_pdf_bytes(),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=ai_compliance.pdf"},
    )


@dashboard_router.get(
    "/reports/ai/docx",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def ai_compliance_report_docx(
    tenant_id: str = Query(default="default"),
) -> Response:
    """Return the AI compliance report as DOCX."""
    engine = _get_telemetry_engine()
    events: List[Any] = []
    try:
        if engine is not None:
            events = engine.get_recent_events(limit=10000) or []
    except Exception as exc:
        logger.warning("ai_compliance_report_docx: telemetry unavailable: %s", exc)

    reporter = _get_ai_compliance_reporter(tenant_id=tenant_id)
    report = reporter.generate(events)
    return Response(
        content=report.to_docx_bytes(),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": "attachment; filename=ai_compliance.docx"},
    )
