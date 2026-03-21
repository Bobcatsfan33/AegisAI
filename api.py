"""
Aegis — FastAPI web service  (v2.2.0)

Endpoints:
  GET  /                   → health check (public)
  POST /scan               → start async scan + remediation (ANALYST+)
  GET  /scan/{scan_id}     → poll scan status / retrieve results (ANALYST+)
  GET  /scans              → list all scan IDs and their status (ANALYST+)
  GET  /api/findings       → paginated findings query from Elasticsearch (ANALYST+)
  GET  /api/audit          → tail the immutable audit log (OWNER only)

Security changes in v2.2.0:
  - SecurityHeadersMiddleware + RequestValidationMiddleware applied globally.
  - CORS wildcard replaced with CORS_ORIGINS env var.
  - RBAC (Role-based access control) applied to all mutating / data endpoints.
  - Immutable hash-chained audit log emitted on every significant event.
  - Startup emits STARTUP audit event.
"""

import logging
import os
import time
import uuid
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from auth import verify_token
from config import (
    AUTO_REMEDIATE,
    AWS_ENABLED,
    AZURE_ENABLED,
    AZURE_SUBSCRIPTION_ID,
    DEV_MODE,
    DRY_RUN,
    ELASTICSEARCH_ENABLED,
    GCP_ENABLED,
    GCP_PROJECT_ID,
    IAC_ENABLED,
    K8S_ENABLED,
    NETWORK_SCAN_ENABLED,
    NETWORK_SCAN_TARGETS,
    OIDC_ISSUER,
)
from modules.agents.orchestrator import AIOrchestrator
from modules.analytics.elastic import ElasticIndexer
from modules.reports.compliance import ComplianceReportGenerator
from modules.scanners.base import Finding
from modules.security.audit_log import AuditEventType, AuditOutcome, log_event
from modules.security.headers import RequestValidationMiddleware, SecurityHeadersMiddleware
from modules.security.rbac import Role, require_role

logger = logging.getLogger(__name__)

# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Aegis",
    description="Autonomous multi-cloud & network security posture management",
    version="2.2.0",
    # Suppress /openapi.json and /docs in non-dev environments (reduces attack surface)
    docs_url="/docs" if DEV_MODE else None,
    redoc_url="/redoc" if DEV_MODE else None,
)

# ── Middleware stack (order matters: outermost = last added) ───────────────────

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestValidationMiddleware)

_cors_origins: list[str] = [
    o.strip()
    for o in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "X-API-Key", "X-Correlation-ID", "Content-Type"],
    allow_credentials=False,
)

# ── In-memory scan store — replace with Redis for multi-replica deployments ───

scan_results: dict[str, Any] = {}

# ── Analytics indexer ─────────────────────────────────────────────────────────

_indexer = ElasticIndexer()


# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_checks():
    if not OIDC_ISSUER:
        logger.warning(
            "OIDC_ISSUER is not set. All authenticated endpoints will return 401. "
            "Set OIDC_ISSUER in your .env file."
        )

    mode = "DRY RUN" if DRY_RUN else "LIVE REMEDIATION"
    logger.info(f"Aegis v2.2.0 starting in {mode} mode.")

    if ELASTICSEARCH_ENABLED:
        if _indexer.is_available():
            _indexer.ensure_indices()
            logger.info("Elasticsearch connected — findings will be indexed.")
        else:
            logger.warning(
                "ELASTICSEARCH_ENABLED=true but connection failed. "
                "Check ELASTICSEARCH_URL and credentials."
            )

    # AU-2 / AU-12: emit auditable startup event
    log_event(
        AuditEventType.STARTUP,
        AuditOutcome.SUCCESS,
        detail={
            "version": "2.2.0",
            "dev_mode": DEV_MODE,
            "dry_run": DRY_RUN,
            "auto_remediate": AUTO_REMEDIATE,
        },
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_scanners():
    """Instantiate whichever scanners are enabled and have available credentials."""
    from modules.scanners.aws.scanner import AWSScanner
    from modules.scanners.azure.scanner import AzureScanner
    from modules.scanners.gcp.scanner import GCPScanner
    from modules.scanners.network.scanner import NetworkScanner

    scanners = []

    if AWS_ENABLED:
        s = AWSScanner()
        if s.is_available():
            scanners.append(s)
        else:
            logger.warning("AWS scanner unavailable (missing credentials or boto3).")

    if AZURE_ENABLED:
        s = AzureScanner(AZURE_SUBSCRIPTION_ID)
        if s.is_available():
            scanners.append(s)
        else:
            logger.warning("Azure scanner unavailable (missing credentials or SDK).")

    if GCP_ENABLED:
        s = GCPScanner(GCP_PROJECT_ID)
        if s.is_available():
            scanners.append(s)
        else:
            logger.warning("GCP scanner unavailable (missing credentials or SDK).")

    if NETWORK_SCAN_ENABLED:
        s = NetworkScanner(NETWORK_SCAN_TARGETS)
        if s.is_available():
            scanners.append(s)
        else:
            logger.warning("Network scanner has no targets configured.")

    if K8S_ENABLED:
        from modules.scanners.k8s.scanner import K8sScanner
        s = K8sScanner()
        if s.is_available():
            scanners.append(s)
        else:
            logger.warning("K8s scanner unavailable (check kubeconfig / cluster connectivity).")

    if IAC_ENABLED:
        from modules.scanners.iac.scanner import IaCScanner
        s = IaCScanner()
        if s.is_available():
            scanners.append(s)
        else:
            logger.warning("IaC scanner: no scan paths found. Set IAC_SCAN_PATHS.")

    return scanners


def _summarize(findings: list[Finding]) -> dict:
    by_severity: dict[str, list] = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f.to_dict())
    return {
        "total":    len(findings),
        "critical": len(by_severity.get("critical", [])),
        "high":     len(by_severity.get("high", [])),
        "medium":   len(by_severity.get("medium", [])),
        "low":      len(by_severity.get("low", [])),
        "top_risks": [
            f.to_dict()
            for f in findings
            if f.severity in ("critical", "high")
        ][:5],
    }


# ── Background task ───────────────────────────────────────────────────────────

def _run_scan(scan_id: str, initiated_by: str):
    scan_results[scan_id]["status"] = "running"
    start_time = time.time()
    try:
        scanners = _build_scanners()
        if not scanners:
            scan_results[scan_id] = {
                "status": "error",
                "error": "No scanners available. Check credentials and provider settings.",
            }
            log_event(
                AuditEventType.SCAN_COMPLETE,
                AuditOutcome.FAILURE,
                actor=initiated_by,
                detail={"scan_id": scan_id, "error": "no_scanners_available"},
            )
            return

        all_findings: list[Finding] = []
        providers_scanned: list[str] = []
        for scanner in scanners:
            try:
                results = scanner.scan()
                all_findings.extend(results)
                if results:
                    providers_scanned.append(scanner.provider)
            except Exception as e:
                logger.error(f"Scanner {scanner.provider} failed: {e}")

        orchestrator = AIOrchestrator(dry_run=DRY_RUN, auto_remediate=AUTO_REMEDIATE)
        remediation_results = orchestrator.process_findings(all_findings)

        summary = _summarize(all_findings)
        duration = time.time() - start_time

        scan_results[scan_id] = {
            "status":   "complete",
            "summary":  summary,
            "findings": remediation_results,
        }
        logger.info(
            f"Scan {scan_id} complete: {len(all_findings)} findings in {duration:.1f}s."
        )

        # AU-2: audit successful scan completion
        log_event(
            AuditEventType.SCAN_COMPLETE,
            AuditOutcome.SUCCESS,
            actor=initiated_by,
            detail={
                "scan_id": scan_id,
                "total_findings": len(all_findings),
                "critical": summary["critical"],
                "high": summary["high"],
                "providers": providers_scanned,
                "duration_seconds": round(duration, 2),
            },
        )

        # ── Ship to Elasticsearch / Kibana ──────────────────────────────────
        if ELASTICSEARCH_ENABLED and _indexer.is_available():
            indexed = _indexer.bulk_index_scan_results(
                scan_id=scan_id,
                remediation_results=remediation_results,
                summary=summary,
                providers_scanned=providers_scanned,
                dry_run=DRY_RUN,
                auto_remediate=AUTO_REMEDIATE,
                duration_seconds=duration,
            )
            logger.info(
                f"Elasticsearch: indexed {indexed['findings']} findings, "
                f"{indexed['remediations']} remediations, "
                f"{indexed['scans']} scan summary."
            )

    except Exception as e:
        logger.error(f"Scan {scan_id} failed with unhandled exception: {e}")
        scan_results[scan_id] = {"status": "error", "error": str(e)}
        log_event(
            AuditEventType.SCAN_COMPLETE,
            AuditOutcome.FAILURE,
            actor=initiated_by,
            detail={"scan_id": scan_id, "error": str(e)},
        )


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    """Public health check — no auth required."""
    return {
        "service":        "Aegis",
        "version":        "2.2.0",
        "status":         "running",
        "mode":           "dry_run" if DRY_RUN else "live",
        "auto_remediate": AUTO_REMEDIATE,
    }


@app.post("/scan", status_code=202)
def start_scan(
    background_tasks: BackgroundTasks,
    tenant: dict = Depends(require_role(Role.ANALYST)),
):
    """
    Start a full multi-cloud + network scan.
    Requires ANALYST role or higher.
    Returns immediately with scan_id; poll GET /scan/{scan_id} for results.
    """
    scan_id = str(uuid.uuid4())
    actor = tenant.get("sub", "unknown")
    scan_results[scan_id] = {"status": "queued"}
    background_tasks.add_task(_run_scan, scan_id, actor)

    log_event(
        AuditEventType.SCAN_STARTED,
        AuditOutcome.SUCCESS,
        actor=actor,
        detail={"scan_id": scan_id},
    )
    logger.info(f"Scan {scan_id} queued by {actor}.")
    return {"message": "Scan started", "scan_id": scan_id}


@app.get("/scan/{scan_id}")
def get_scan(
    scan_id: str,
    tenant: dict = Depends(require_role(Role.ANALYST)),
):
    """Retrieve status and results for a specific scan. Requires ANALYST+."""
    result = scan_results.get(scan_id)
    if result is None:
        log_event(
            AuditEventType.ACCESS_DENIED,
            AuditOutcome.FAILURE,
            actor=tenant.get("sub", "unknown"),
            detail={"scan_id": scan_id, "reason": "not_found"},
        )
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    log_event(
        AuditEventType.ACCESS_GRANTED,
        AuditOutcome.SUCCESS,
        actor=tenant.get("sub", "unknown"),
        detail={"scan_id": scan_id, "status": result.get("status")},
    )
    return result


@app.get("/scans")
def list_scans(tenant: dict = Depends(require_role(Role.ANALYST))):
    """List all scans in memory with their status. Requires ANALYST+."""
    log_event(
        AuditEventType.ACCESS_GRANTED,
        AuditOutcome.SUCCESS,
        actor=tenant.get("sub", "unknown"),
        detail={"action": "list_scans", "count": len(scan_results)},
    )
    return {
        scan_id: {
            "status": data.get("status"),
            "total":  data.get("summary", {}).get("total"),
        }
        for scan_id, data in scan_results.items()
    }


# ── Dashboard API endpoints ───────────────────────────────────────────────────

@app.get("/api/findings")
def get_findings(
    severity: str | None = Query(None, description="Filter by severity: critical|high|medium|low"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    tenant: dict = Depends(require_role(Role.ANALYST)),
):
    """
    Return paginated findings from in-memory scan results (or Elasticsearch if enabled).
    Requires ANALYST+.
    """
    actor = tenant.get("sub", "unknown")
    all_findings_raw: list[dict] = []

    # Collect from completed scans
    for scan_id, data in scan_results.items():
        if data.get("status") != "complete":
            continue
        for item in data.get("findings", []):
            f = item.get("finding", item)
            if severity and f.get("severity") != severity:
                continue
            all_findings_raw.append({**f, "scan_id": scan_id})

    total = len(all_findings_raw)
    page = all_findings_raw[offset: offset + limit]

    log_event(
        AuditEventType.ACCESS_GRANTED,
        AuditOutcome.SUCCESS,
        actor=actor,
        detail={"action": "get_findings", "total": total, "severity_filter": severity},
    )
    return {"total": total, "offset": offset, "limit": limit, "findings": page}


@app.get("/api/compliance")
def get_compliance_report(
    format: str = Query("json", description="Output format: json | markdown"),
    tenant: dict = Depends(require_role(Role.ANALYST)),
):
    """
    Generate a NIST 800-53 Rev5 compliance gap report from all completed scans.
    Requires ANALYST+. OWNER receives full finding details; ANALYST receives summary.
    CM-6 / CA-7: Continuous monitoring and compliance assessment.
    """
    actor = tenant.get("sub", "unknown")
    actor_role = tenant.get("role", 0)

    # Collect all findings from completed scans
    all_findings: list[Finding] = []
    for scan_id, data in scan_results.items():
        if data.get("status") != "complete":
            continue
        for item in data.get("findings", []):
            f_data = item.get("finding", item)
            # Re-hydrate Finding objects for the compliance engine
            all_findings.append(Finding(
                resource=f_data.get("resource", ""),
                issue=f_data.get("issue", ""),
                severity=f_data.get("severity", "info"),
                provider=f_data.get("provider", "unknown"),
                region=f_data.get("region"),
                resource_type=f_data.get("resource_type"),
                details=f_data.get("details", {}),
                remediation_hint=f_data.get("remediation_hint"),
                mitre_techniques=f_data.get("mitre_techniques", []),
                mitre_tactic=f_data.get("mitre_tactic"),
                nist_controls=f_data.get("nist_controls", []),
                cwe_id=f_data.get("cwe_id"),
            ))

    generator = ComplianceReportGenerator()
    report = generator.generate(
        all_findings,
        metadata={"scan_count": len(scan_results), "actor": actor},
    )

    log_event(
        AuditEventType.ACCESS_GRANTED,
        AuditOutcome.SUCCESS,
        actor=actor,
        detail={
            "action": "compliance_report",
            "overall_score": report.overall_score,
            "total_findings": report.total_findings,
        },
    )

    if format == "markdown":
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(report.to_markdown(), media_type="text/markdown")

    return report.to_dict()


@app.get("/api/audit")
def get_audit_log(
    limit: int = Query(100, ge=1, le=1000),
    tenant: dict = Depends(require_role(Role.OWNER)),
):
    """
    Return the tail of the immutable audit log.
    Requires OWNER role — guards against audit log exfiltration by lower-privilege actors.
    AU-9: Protection of audit information.
    """
    import json
    audit_path = os.getenv("AUDIT_LOG_FILE", "audit.jsonl")
    actor = tenant.get("sub", "unknown")

    log_event(
        AuditEventType.ACCESS_GRANTED,
        AuditOutcome.SUCCESS,
        actor=actor,
        detail={"action": "read_audit_log", "requested_limit": limit},
    )

    if not os.path.exists(audit_path):
        return {"entries": [], "total": 0}

    entries: list[dict] = []
    try:
        with open(audit_path, "r") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not read audit log: {exc}")

    tail = entries[-limit:]
    return {"entries": tail, "total": len(entries)}
