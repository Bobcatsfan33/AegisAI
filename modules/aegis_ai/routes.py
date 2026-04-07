"""
AegisAI API Routes — v3.1.0

AI Security endpoints for the AegisAI layer.  Designed to be mounted onto the
existing Aegis FastAPI app via:

    from modules.aegis_ai.routes import ai_security_router
    app.include_router(ai_security_router)

Endpoints:
  POST /api/ai/discover        → Run AI asset discovery scan (ANALYST+)
  GET  /api/ai/assets          → List discovered AI assets (ANALYST+)
  POST /api/ai/redteam         → Run automated red team attacks (ADMIN+)
  GET  /api/ai/redteam/{id}    → Get red team run results (ANALYST+)
  POST /api/ai/guardrails      → Evaluate content against guardrails (ANALYST+)
  POST /api/ai/policy/evaluate → Evaluate event against policy engine (ANALYST+)
  GET  /api/ai/policy/rules    → List all policy rules (ANALYST+)
  GET  /api/ai/telemetry/stats → Telemetry engine status (ADMIN+)
  GET  /api/ai/telemetry/query → Run analytics query (ANALYST+)
  GET  /api/ai/connectors      → List registered LLM connectors (ANALYST+)
  GET  /api/ai/dashboard       → Unified AegisAI dashboard summary (ANALYST+)

  # v3.1 — Supply Chain Security
  POST /api/ai/supply-chain/commit      → Ingest commit provenance (ADMIN+)
  POST /api/ai/supply-chain/attest      → Attest artifact (ADMIN+)
  POST /api/ai/supply-chain/deps        → Analyze dependencies (ANALYST+)
  POST /api/ai/supply-chain/score       → Score deployment provenance (ADMIN+)
  GET  /api/ai/supply-chain/events      → Provenance event log (ANALYST+)
  GET  /api/ai/supply-chain/summary     → Supply chain summary (ANALYST+)

  # v3.1 — Observability
  POST /api/ai/observability/ingest     → Ingest metric point (ANALYST+)
  GET  /api/ai/observability/dashboard  → Live dashboard payload (ANALYST+)
  GET  /api/ai/observability/alerts     → Active alerts (ANALYST+)
  POST /api/ai/observability/alerts/{id}/ack     → Acknowledge alert (ANALYST+)
  POST /api/ai/observability/alerts/{id}/resolve → Resolve alert (ADMIN+)
  POST /api/ai/observability/security-event      → Inject security correlation (ADMIN+)
  GET  /api/ai/observability/topology   → Service topology map (ANALYST+)
  GET  /api/ai/observability/runbook/{id} → Get runbook (ANALYST+)

  # v3.1 — Identity (Machine Identity / ZTIX)
  POST /api/ai/identity/machine         → Register machine identity (ADMIN+)
  GET  /api/ai/identity/machines        → List machine identities (ANALYST+)
  GET  /api/ai/identity/machines/{id}   → Get machine identity (ANALYST+)
  POST /api/ai/identity/machines/{id}/observe → Record observation (ADMIN+)
  POST /api/ai/identity/machines/{id}/revoke  → Revoke identity (ADMIN+)
  POST /api/ai/identity/ztix/token      → Request ZTIX token (ADMIN+)
  POST /api/ai/identity/ztix/validate   → Validate ZTIX token (ANALYST+)
  POST /api/ai/identity/agents/chain    → Create agent delegation chain (ADMIN+)
  POST /api/ai/identity/agents/delegate → Add delegation link (ADMIN+)
  GET  /api/ai/identity/governance      → NHI governance report (ANALYST+)
"""

import logging
import os
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from modules.security.rbac import Role, require_role
from modules.security.audit_log import AuditEventType, AuditOutcome, log_event
from modules.tenants.middleware import get_tenant_context, TenantContext

from modules.aegis_ai.discovery import DiscoveryEngine, AIAsset
from modules.aegis_ai.redteam import RedTeamEngine, AttackResult, AttackCategory
from modules.aegis_ai.guardrails import GuardrailsEngine, GuardrailVerdict
from modules.aegis_ai.policy import PolicyEngine, RiskAssessment
from modules.aegis_ai.telemetry import TelemetryEngine, AIEvent, EventType
from modules.aegis_ai.connectors import ConnectorRegistry
from modules.supply_chain import SupplyChainEngine, get_engine as get_sc_engine
from modules.observability import ObservabilityEngine, MetricPoint, get_engine as get_obs_engine
from modules.identity import IdentityEngine, IdentityClass, get_engine as get_id_engine

logger = logging.getLogger("aegis.ai_security")

# ── Router ────────────────────────────────────────────────────────────

ai_security_router = APIRouter(prefix="/api/ai", tags=["AegisAI"])

# ── Singletons (initialized at import; started properly in lifespan) ──

_connector_registry = ConnectorRegistry()
_discovery_engine = DiscoveryEngine()
_guardrails_engine = GuardrailsEngine()
_policy_engine = PolicyEngine()
_telemetry_engine = TelemetryEngine()
_supply_chain_engine: SupplyChainEngine = None  # type: ignore
_observability_engine: ObservabilityEngine = None  # type: ignore
_identity_engine: IdentityEngine = None  # type: ignore

# Red team run results (in-memory; replace with Redis/DB for prod)
_redteam_results: Dict[str, Dict[str, Any]] = {}


def initialize_ai_security():
    """Called from app startup to configure AI security modules."""
    global _supply_chain_engine, _observability_engine, _identity_engine

    # v3.1 engine singletons
    _supply_chain_engine = get_sc_engine()
    _observability_engine = get_obs_engine()
    _identity_engine = get_id_engine()

    # Register LLM connectors from environment
    _connector_registry.register_from_env()

    # Configure policy engine with env-based settings
    approved_models = os.getenv("AEGIS_APPROVED_MODELS", "").split(",")
    approved_models = [m.strip() for m in approved_models if m.strip()]
    approved_providers = os.getenv("AEGIS_APPROVED_PROVIDERS", "").split(",")
    approved_providers = [p.strip() for p in approved_providers if p.strip()]

    if approved_models:
        _policy_engine.configure(approved_models=approved_models)
    if approved_providers:
        _policy_engine.configure(approved_providers=approved_providers)

    max_tokens = int(os.getenv("AEGIS_MAX_TOKENS_PER_REQUEST", "50000"))
    max_cost = float(os.getenv("AEGIS_MAX_COST_PER_REQUEST", "1.0"))
    _policy_engine.configure(
        max_tokens_per_request=max_tokens,
        max_cost_per_request_usd=max_cost,
    )

    # Start telemetry
    _telemetry_engine.start()

    logger.info("AI Security modules initialized (connectors=%s)", _connector_registry.list_providers())


def shutdown_ai_security():
    """Called from app shutdown to gracefully stop AI security modules."""
    _telemetry_engine.stop()


# ── Pydantic Models ───────────────────────────────────────────────────

class DiscoverRequest(BaseModel):
    scan_env: bool = True
    scan_network: bool = True
    scan_localhost: bool = True
    network_targets: Optional[List[str]] = None


class RedTeamRequest(BaseModel):
    categories: Optional[List[str]] = None
    custom_attacks: Optional[List[Dict[str, Any]]] = None
    target_model: Optional[str] = None
    target_provider: Optional[str] = None


class GuardrailRequest(BaseModel):
    content: str
    direction: str = "input"    # "input" or "output"


class PolicyEvalRequest(BaseModel):
    model: Optional[str] = None
    provider: Optional[str] = None
    prompt: Optional[str] = None
    response: Optional[str] = None
    total_tokens: int = 0
    cost_usd: float = 0.0
    data_classification: Optional[str] = None
    requests_in_window: int = 0
    event_type: str = "ai_request"


# ── Discovery Endpoints ──────────────────────────────────────────────

@ai_security_router.post("/discover", dependencies=[Depends(require_role(Role.ANALYST))])
async def discover_assets(req: DiscoverRequest):
    """Run AI asset discovery scan."""
    tenant = get_tenant_context()
    engine = DiscoveryEngine(
        scan_env=req.scan_env,
        scan_network=req.scan_network,
        scan_localhost=req.scan_localhost,
        network_targets=req.network_targets,
    )
    assets = engine.scan()

    # Log to telemetry
    _telemetry_engine.log(AIEvent(
        event_type=EventType.DISCOVERY,
        source="discovery_engine",
        severity="info",
        data={"asset_count": len(assets), "tenant_id": tenant.tenant_id},
    ))

    # Audit log
    log_event(
        AuditEventType.SCAN,
        AuditOutcome.SUCCESS,
        detail={
            "type": "ai_discovery",
            "assets_found": len(assets),
            "tenant_id": tenant.tenant_id,
        },
    )

    return {
        "tenant_id": tenant.tenant_id,
        "assets": [a.to_dict() for a in assets],
        "summary": engine.summary(assets),
    }


@ai_security_router.get("/assets", dependencies=[Depends(require_role(Role.ANALYST))])
async def list_assets():
    """Run a quick discovery and return asset inventory."""
    tenant = get_tenant_context()
    assets = _discovery_engine.scan()
    return {
        "tenant_id": tenant.tenant_id,
        "assets": [a.to_dict() for a in assets],
        "summary": _discovery_engine.summary(assets),
    }


# ── Red Team Endpoints ───────────────────────────────────────────────

@ai_security_router.post("/redteam", dependencies=[Depends(require_role(Role.ADMIN))])
async def run_redteam(req: RedTeamRequest):
    """
    Run automated red team attack simulation.
    Requires ADMIN role due to active probing.
    """
    tenant = get_tenant_context()

    # Parse categories
    categories = None
    if req.categories:
        try:
            categories = [AttackCategory(c) for c in req.categories]
        except ValueError as e:
            raise HTTPException(400, f"Invalid attack category: {e}")

    # Get LLM connector
    llm = None
    if req.target_provider:
        llm = _connector_registry.get(req.target_provider)
    if not llm:
        llm = _connector_registry.get_default()

    engine = RedTeamEngine(
        llm_connector=llm,
        categories=categories,
        custom_attacks=req.custom_attacks,
    )
    results = engine.run_all()
    summary = engine.summary(results)

    # Store results (namespaced by tenant)
    run_id = str(uuid.uuid4())[:8]
    _redteam_results[run_id] = {
        "results": [r.to_dict() for r in results],
        "summary": summary,
        "tenant_id": tenant.tenant_id,
    }

    # Telemetry for each attack
    for r in results:
        _telemetry_engine.log(AIEvent(
            event_type=EventType.REDTEAM,
            source="redteam_engine",
            severity=r.risk_level.value if r.risk_level.value != "none" else "info",
            data={**r.to_dict(), "tenant_id": tenant.tenant_id},
            risk_score=r.score,
        ))

    # Audit log
    log_event(
        AuditEventType.SCAN,
        AuditOutcome.SUCCESS,
        detail={
            "type": "ai_redteam",
            "run_id": run_id,
            "attacks": len(results),
            "succeeded": summary["attacks_succeeded"],
            "resilience": summary["resilience_score"],
            "tenant_id": tenant.tenant_id,
        },
    )

    return {"run_id": run_id, "summary": summary, "tenant_id": tenant.tenant_id}


@ai_security_router.get("/redteam/{run_id}", dependencies=[Depends(require_role(Role.ANALYST))])
async def get_redteam_results(run_id: str):
    """Retrieve results of a red team run."""
    if run_id not in _redteam_results:
        raise HTTPException(404, "Red team run not found")
    return _redteam_results[run_id]


# ── Guardrails Endpoints ─────────────────────────────────────────────

@ai_security_router.post("/guardrails", dependencies=[Depends(require_role(Role.ANALYST))])
async def check_guardrails(req: GuardrailRequest):
    """Evaluate content against runtime guardrails."""
    tenant = get_tenant_context()
    if req.direction == "input":
        verdict = _guardrails_engine.check_input(req.content)
    else:
        verdict = _guardrails_engine.check_output(req.content)

    # Telemetry
    _telemetry_engine.log(AIEvent(
        event_type=EventType.GUARDRAIL,
        source="guardrails_engine",
        severity="high" if not verdict.allowed else "info",
        data={**verdict.to_dict(), "tenant_id": tenant.tenant_id},
        risk_score=verdict.risk_score,
    ))

    return {**verdict.to_dict(), "tenant_id": tenant.tenant_id}


# ── Policy Endpoints ─────────────────────────────────────────────────

@ai_security_router.post("/policy/evaluate", dependencies=[Depends(require_role(Role.ANALYST))])
async def evaluate_policy(req: PolicyEvalRequest):
    """Evaluate an AI event against governance policies."""
    tenant = get_tenant_context()
    event = req.model_dump()
    event["tenant_id"] = tenant.tenant_id  # inject tenant into policy context
    assessment = _policy_engine.evaluate(event)

    # Telemetry
    _telemetry_engine.log(AIEvent(
        event_type=EventType.POLICY,
        source="policy_engine",
        severity=assessment.overall_severity.value,
        data={**assessment.to_dict(), "tenant_id": tenant.tenant_id},
        model=req.model,
        provider=req.provider,
        risk_score=assessment.overall_score,
    ))

    return {**assessment.to_dict(), "tenant_id": tenant.tenant_id}


@ai_security_router.get("/policy/rules", dependencies=[Depends(require_role(Role.ANALYST))])
async def list_policy_rules():
    """List all configured policy rules."""
    return {"rules": _policy_engine.list_rules()}


# ── Telemetry Endpoints ──────────────────────────────────────────────

@ai_security_router.get("/telemetry/stats", dependencies=[Depends(require_role(Role.ADMIN))])
async def telemetry_stats():
    """Get telemetry engine health and stats."""
    return _telemetry_engine.get_stats()


@ai_security_router.get("/telemetry/query", dependencies=[Depends(require_role(Role.ANALYST))])
async def telemetry_query(
    query_name: str = Query(..., description="Pre-built query name"),
):
    """Run a pre-built analytics query against ClickHouse."""
    from modules.aegis_ai.telemetry.engine import ANALYTICS_QUERIES
    if query_name not in ANALYTICS_QUERIES:
        raise HTTPException(400, f"Unknown query. Available: {list(ANALYTICS_QUERIES.keys())}")
    results = _telemetry_engine.query(query_name)
    return {"query": query_name, "results": results}


# ── Connectors Endpoints ─────────────────────────────────────────────

@ai_security_router.get("/connectors", dependencies=[Depends(require_role(Role.ANALYST))])
async def list_connectors():
    """List registered LLM provider connectors."""
    return {"connectors": _connector_registry.list_providers()}


# ── Unified Dashboard ────────────────────────────────────────────────

@ai_security_router.get("/dashboard", dependencies=[Depends(require_role(Role.ANALYST))])
async def ai_dashboard():
    """
    Unified AI security dashboard summary.
    Aggregates status from all AI security modules.
    """
    return {
        "product": "AegisAI",
        "version": "3.0.0",
        "modules": {
            "connectors": {
                "status": "active",
                "providers": _connector_registry.list_providers(),
            },
            "discovery": {
                "status": "active",
                "last_scan": None,
            },
            "redteam": {
                "status": "active",
                "total_runs": len(_redteam_results),
            },
            "guardrails": {
                "status": "active",
                "mode": "redact" if _guardrails_engine.redact_mode else "block",
            },
            "policy": {
                "status": "active",
                "rule_count": len(_policy_engine.rules),
            },
            "telemetry": _telemetry_engine.get_stats(),
        },
        "nist_controls_covered": sorted(set([
            "CM-8", "PM-5", "RA-5",    # Discovery
            "CA-8", "SI-10", "AC-4",    # Red Team
            "SC-7", "AC-4", "SC-28",    # Guardrails
            "PL-1", "CA-2", "RA-3",    # Policy
            "AU-2", "AU-6", "AU-12",    # Telemetry
        ])),
        "compliance_frameworks": [
            "NIST 800-53 Rev5", "NIST AI RMF", "OWASP LLM Top 10",
            "MITRE ATLAS", "EU AI Act", "EO 14110", "ISO 42001",
        ],
    }


# =============================================================================
# v3.1 — SUPPLY CHAIN SECURITY ENDPOINTS
# =============================================================================

class CommitIngestRequest(BaseModel):
    repository: Dict[str, Any] = {}
    after: str = ""
    head_commit: Dict[str, Any] = {}

class ArtifactAttestRequest(BaseModel):
    name: str
    version: str
    ecosystem: str
    expected_hash: Optional[str] = None
    slsa_level: int = 0
    sigstore_bundle: Optional[str] = None

class DepsAnalyzeRequest(BaseModel):
    dependencies: List[Dict[str, Any]]

class DeployScoreRequest(BaseModel):
    repo: str
    dependency_names: Optional[List[str]] = None


@ai_security_router.post("/supply-chain/commit",
                         dependencies=[Depends(require_role(Role.ADMIN))])
async def supply_chain_ingest_commit(req: CommitIngestRequest):
    """Ingest a commit webhook payload and return provenance analysis."""
    commit = _supply_chain_engine.ingest_commit(req.dict())
    return {
        "repo": commit.repo,
        "commit_sha": commit.commit_sha,
        "identity_type": commit.identity_type.value,
        "provenance_score": commit.provenance_score,
        "anomalies": [a.value for a in commit.anomalies],
        "gpg_signed": commit.gpg_signed,
    }


@ai_security_router.post("/supply-chain/attest",
                         dependencies=[Depends(require_role(Role.ADMIN))])
async def supply_chain_attest(req: ArtifactAttestRequest):
    """Attest an artifact against its registry hash."""
    attestation = _supply_chain_engine.attest_artifact(
        name=req.name,
        version=req.version,
        ecosystem=req.ecosystem,
        expected_hash=req.expected_hash,
        slsa_level=req.slsa_level,
        sigstore_bundle=req.sigstore_bundle,
    )
    return {
        "artifact": f"{req.name}=={req.version}",
        "published_hash": attestation.published_hash,
        "hash_match": attestation.hash_match,
        "slsa_level": attestation.slsa_level.value,
        "sigstore_valid": attestation.sigstore_valid,
        "risk_tier": attestation.risk_tier.value,
        "anomalies": [a.value for a in attestation.anomalies],
    }


@ai_security_router.post("/supply-chain/deps",
                         dependencies=[Depends(require_role(Role.ANALYST))])
async def supply_chain_analyze_deps(req: DepsAnalyzeRequest):
    """Analyze a list of dependencies for supply chain risk."""
    results = _supply_chain_engine.analyze_dependencies(req.dependencies)
    return {
        "count": len(results),
        "dependencies": [
            {
                "name": d.name,
                "version": d.version,
                "ecosystem": d.ecosystem,
                "risk_tier": d.risk_tier.value,
                "anomalies": [a.value for a in d.anomalies],
                "similar_to": d.similar_to,
                "cves": d.known_cves,
                "max_cvss": d.max_cvss,
                "actively_exploited": d.actively_exploited,
            }
            for d in results
        ],
    }


@ai_security_router.post("/supply-chain/score",
                         dependencies=[Depends(require_role(Role.ADMIN))])
async def supply_chain_score_deploy(req: DeployScoreRequest):
    """Compute aggregate provenance score for a deployment."""
    score = _supply_chain_engine.score_deployment(repo=req.repo)
    return {
        "subject": score.subject,
        "overall_score": score.overall_score,
        "risk_tier": score.risk_tier.value,
        "blocked": score.blocked,
        "commit_score": score.commit_score,
        "artifact_score": score.artifact_score,
        "dependency_score": score.dependency_score,
        "anomalies": [a.value for a in score.anomalies],
        "reasons": score.reasons,
        "evaluated_at": score.evaluated_at,
    }


@ai_security_router.get("/supply-chain/events",
                        dependencies=[Depends(require_role(Role.ANALYST))])
async def supply_chain_events(
    limit: int = Query(50, ge=1, le=500),
    risk_tier: Optional[str] = Query(None),
):
    """Retrieve recent supply chain provenance events."""
    events = _supply_chain_engine.get_events(limit=limit, risk_tier=risk_tier)
    return {
        "count": len(events),
        "events": [
            {
                "event_id": e.event_id,
                "event_type": e.event_type,
                "timestamp": e.timestamp,
                "actor": e.actor,
                "actor_identity_type": e.actor_identity_type.value,
                "risk_tier": e.risk_tier.value,
                "anomalies": [a.value for a in e.anomalies],
            }
            for e in events
        ],
    }


@ai_security_router.get("/supply-chain/summary",
                        dependencies=[Depends(require_role(Role.ANALYST))])
async def supply_chain_summary():
    """Supply chain engine health summary."""
    return _supply_chain_engine.get_summary()


# =============================================================================
# v3.1 — OBSERVABILITY ENDPOINTS
# =============================================================================

class MetricIngestRequest(BaseModel):
    service: str
    metric: str
    value: float
    unit: str = ""
    tags: Dict[str, str] = {}

class SecurityEventRequest(BaseModel):
    service: str
    description: str
    supply_chain_score: Optional[float] = None

class AlertActionRequest(BaseModel):
    pass


@ai_security_router.post("/observability/ingest",
                         dependencies=[Depends(require_role(Role.ANALYST))])
async def observability_ingest(req: MetricIngestRequest):
    """Ingest a single metric point into the observability engine."""
    point = MetricPoint(
        service=req.service,
        metric=req.metric,
        value=req.value,
        unit=req.unit,
        tags=req.tags,
    )
    alert = _observability_engine.ingest(point)
    return {
        "ingested": True,
        "alert_generated": alert is not None,
        "alert": {
            "alert_id": alert.alert_id,
            "title": alert.title,
            "severity": alert.severity.value,
        } if alert else None,
    }


@ai_security_router.get("/observability/dashboard",
                        dependencies=[Depends(require_role(Role.ANALYST))])
async def observability_dashboard():
    """Live dashboard payload — DataDog-feel, ClickHouse-powered."""
    dash = _observability_engine.build_dashboard()
    return {
        "generated_at": dash.generated_at,
        "totals": {
            "rps": dash.total_rps,
            "error_rate": dash.total_error_rate,
            "p95_latency_ms": dash.total_p95_latency_ms,
            "cost_per_hour_usd": dash.total_cost_per_hour_usd,
        },
        "alerts": {
            "active": dash.active_alert_count,
            "critical": dash.critical_alert_count,
        },
        "supply_chain_risk_score": dash.supply_chain_risk_score,
        "services": [
            {
                "id": s.service_id,
                "name": s.display_name,
                "type": s.service_type,
                "health": s.health,
                "error_rate": s.error_rate,
                "p95_latency_ms": s.p95_latency_ms,
                "rps": s.rps,
                "cost_per_hour_usd": s.cost_per_hour_usd,
                "dependencies": s.dependencies,
            }
            for s in dash.services
        ],
        "recent_alerts": [
            {
                "alert_id": a.alert_id,
                "title": a.title,
                "severity": a.severity.value,
                "service": a.service,
                "timestamp": a.timestamp,
                "runbook_id": a.runbook_id,
            }
            for a in dash.alerts[:10]
        ],
        "summary": dash.summary,
    }


@ai_security_router.get("/observability/alerts",
                        dependencies=[Depends(require_role(Role.ANALYST))])
async def observability_alerts(
    severity: Optional[str] = Query(None),
):
    """List active alerts."""
    alerts = _observability_engine.alert_engine.get_active(severity=severity)
    return {
        "count": len(alerts),
        "alerts": [
            {
                "alert_id": a.alert_id,
                "title": a.title,
                "severity": a.severity.value,
                "service": a.service,
                "description": a.description,
                "timestamp": a.timestamp,
                "acknowledged": a.acknowledged,
                "runbook_id": a.runbook_id,
            }
            for a in alerts
        ],
    }


@ai_security_router.post("/observability/alerts/{alert_id}/ack",
                         dependencies=[Depends(require_role(Role.ANALYST))])
async def ack_alert(alert_id: str):
    ok = _observability_engine.acknowledge_alert(alert_id)
    return {"acknowledged": ok, "alert_id": alert_id}


@ai_security_router.post("/observability/alerts/{alert_id}/resolve",
                         dependencies=[Depends(require_role(Role.ADMIN))])
async def resolve_alert(alert_id: str):
    ok = _observability_engine.resolve_alert(alert_id)
    return {"resolved": ok, "alert_id": alert_id}


@ai_security_router.post("/observability/security-event",
                         dependencies=[Depends(require_role(Role.ADMIN))])
async def inject_security_event(req: SecurityEventRequest):
    """Inject a security correlation event (from supply chain or threat engine)."""
    alert = _observability_engine.correlate_security_event(
        service=req.service,
        description=req.description,
        supply_chain_score=req.supply_chain_score,
    )
    return {
        "correlated": True,
        "alert": {"alert_id": alert.alert_id, "severity": alert.severity.value} if alert else None,
    }


@ai_security_router.get("/observability/topology",
                        dependencies=[Depends(require_role(Role.ANALYST))])
async def observability_topology():
    """Auto-generated service topology map."""
    nodes = _observability_engine.topology.get_topology()
    return {
        "node_count": len(nodes),
        "nodes": [
            {
                "id": n.service_id,
                "name": n.display_name,
                "type": n.service_type,
                "health": n.health,
                "dependencies": n.dependencies,
                "rps": n.rps,
                "error_rate": n.error_rate,
                "p95_latency_ms": n.p95_latency_ms,
                "cost_per_hour_usd": n.cost_per_hour_usd,
            }
            for n in nodes
        ],
    }


@ai_security_router.get("/observability/runbook/{runbook_id}",
                        dependencies=[Depends(require_role(Role.ANALYST))])
async def get_runbook(runbook_id: str):
    """Get a runbook by ID."""
    rb = _observability_engine.alert_engine._runbooks.get(runbook_id)
    if not rb:
        raise HTTPException(status_code=404, detail="Runbook not found")
    return {
        "runbook_id": rb.runbook_id,
        "title": rb.title,
        "steps": rb.steps,
        "estimated_minutes": rb.estimated_minutes,
        "automation_available": rb.automation_available,
        "automation_command": rb.automation_command,
        "references": rb.references,
    }


# =============================================================================
# v3.1 — IDENTITY (MACHINE IDENTITY / ZTIX) ENDPOINTS
# =============================================================================

class RegisterMachineRequest(BaseModel):
    identity_id: str
    display_name: str
    identity_class: str = "machine"
    owner_human_id: str
    purpose: str
    allowed_scopes: Optional[List[str]] = None
    public_key_pem: Optional[str] = None

class ObserveIdentityRequest(BaseModel):
    source_ip: str = ""
    geo_country: str = ""
    ja3_hash: str = ""
    auto_revoke: bool = True

class ZTIXTokenRequest(BaseModel):
    identity_id: str
    target_service: str
    scopes: List[str]
    ttl_minutes: int = 5

class ZTIXValidateRequest(BaseModel):
    token_id: str
    target_service: str
    scope: str

class CreateChainRequest(BaseModel):
    root_identity_id: str

class DelegateRequest(BaseModel):
    chain_id: str
    parent_id: str
    child_id: str
    scopes: List[str]
    purpose: str = ""
    ttl_minutes: int = 60

class RevokeRequest(BaseModel):
    reason: str = ""


@ai_security_router.post("/identity/machine",
                         dependencies=[Depends(require_role(Role.ADMIN))])
async def register_machine_identity(req: RegisterMachineRequest):
    """Register a new Non-Human Identity (NHI) with governance tracking."""
    try:
        cls = IdentityClass(req.identity_class)
    except ValueError:
        cls = IdentityClass.MACHINE

    identity = _identity_engine.register_machine(
        identity_id=req.identity_id,
        display_name=req.display_name,
        identity_class=cls,
        owner_human_id=req.owner_human_id,
        purpose=req.purpose,
        allowed_scopes=req.allowed_scopes,
        public_key_pem=req.public_key_pem,
    )
    return {
        "identity_id": identity.identity_id,
        "display_name": identity.display_name,
        "identity_class": identity.identity_class.value,
        "risk_tier": identity.risk_tier.value,
        "created_at": identity.created_at,
    }


@ai_security_router.get("/identity/machines",
                        dependencies=[Depends(require_role(Role.ANALYST))])
async def list_machine_identities(
    risk_tier: Optional[str] = Query(None),
):
    """List all registered machine identities."""
    machines = _identity_engine.list_machines(risk_tier=risk_tier)
    return {
        "count": len(machines),
        "machines": [
            {
                "identity_id": m.identity_id,
                "display_name": m.display_name,
                "identity_class": m.identity_class.value,
                "risk_tier": m.risk_tier.value,
                "is_active": m.is_active,
                "is_revoked": m.is_revoked,
                "owner_human_id": m.owner_human_id,
                "purpose": m.purpose,
                "allowed_scopes": m.allowed_scopes,
                "anomalies": [a.value for a in m.anomalies_detected],
            }
            for m in machines
        ],
    }


@ai_security_router.get("/identity/machines/{identity_id}",
                        dependencies=[Depends(require_role(Role.ANALYST))])
async def get_machine_identity(identity_id: str):
    """Get a specific machine identity with full governance detail."""
    machine = _identity_engine.get_machine(identity_id)
    if not machine:
        raise HTTPException(status_code=404, detail="Machine identity not found")
    from modules.identity.machine_identity import NHIGovernanceScorer
    scorer = NHIGovernanceScorer()
    tier, gaps = scorer.score(machine)
    return {
        "identity_id": machine.identity_id,
        "display_name": machine.display_name,
        "identity_class": machine.identity_class.value,
        "owner_human_id": machine.owner_human_id,
        "purpose": machine.purpose,
        "risk_tier": tier.value,
        "governance_gaps": gaps,
        "allowed_scopes": machine.allowed_scopes,
        "allowed_source_ips": machine.allowed_source_ips,
        "hardware_attested": machine.hardware_attested,
        "key_algorithm": machine.key_algorithm,
        "key_rotation_days": machine.key_rotation_days,
        "is_active": machine.is_active,
        "is_revoked": machine.is_revoked,
        "revocation_reason": machine.revocation_reason,
        "anomalies": [a.value for a in machine.anomalies_detected],
        "behavioral_dna": {
            "baseline_established": machine.behavioral_dna.baseline_established if machine.behavioral_dna else False,
            "observation_count": machine.behavioral_dna.observation_count if machine.behavioral_dna else 0,
            "is_machine_like": machine.behavioral_dna.is_machine_like()[1] if machine.behavioral_dna else None,
        } if machine.behavioral_dna else None,
    }


@ai_security_router.post("/identity/machines/{identity_id}/observe",
                         dependencies=[Depends(require_role(Role.ADMIN))])
async def observe_identity(identity_id: str, req: ObserveIdentityRequest):
    """Record a protocol-level observation for behavioral DNA analysis."""
    anomalies = _identity_engine.observe(
        identity_id=identity_id,
        source_ip=req.source_ip,
        geo_country=req.geo_country,
        ja3_hash=req.ja3_hash,
        auto_revoke=req.auto_revoke,
    )
    return {
        "identity_id": identity_id,
        "anomalies_detected": [a.value for a in anomalies],
        "anomaly_count": len(anomalies),
    }


@ai_security_router.post("/identity/machines/{identity_id}/revoke",
                         dependencies=[Depends(require_role(Role.ADMIN))])
async def revoke_machine_identity(identity_id: str, req: RevokeRequest):
    """Revoke a machine identity and all its active ZTIX tokens."""
    _identity_engine.revoke_machine(identity_id, reason=req.reason)
    _identity_engine.ztix.revoke_all_for_identity(identity_id)
    return {"revoked": True, "identity_id": identity_id, "reason": req.reason}


@ai_security_router.post("/identity/ztix/token",
                         dependencies=[Depends(require_role(Role.ADMIN))])
async def request_ztix_token(req: ZTIXTokenRequest):
    """
    Request a Zero Trust Identity Exchange token.
    The machine's real identity is never exposed to the target service.
    """
    token = _identity_engine.request_ztix_token(
        identity_id=req.identity_id,
        target_service=req.target_service,
        scopes=req.scopes,
        ttl_minutes=req.ttl_minutes,
    )
    if not token:
        raise HTTPException(status_code=403,
                            detail="ZTIX token denied: scope violation or identity revoked")
    return {
        "token_id": token.token_id,
        "token_type": token.token_type.value,
        "granted_scopes": token.granted_scopes,
        "target_service": token.target_service,
        "issued_at": token.issued_at,
        "expires_at": token.expires_at,
        # NOTE: real identity (subject_identity_id, source IP) intentionally omitted
        # Target service only receives token_id + scopes + expiry
    }


@ai_security_router.post("/identity/ztix/validate",
                         dependencies=[Depends(require_role(Role.ANALYST))])
async def validate_ztix_token(req: ZTIXValidateRequest):
    """Validate a ZTIX token (called by target services)."""
    valid, reason = _identity_engine.validate_ztix_token(
        token_id=req.token_id,
        target_service=req.target_service,
        scope=req.scope,
    )
    return {"valid": valid, "reason": reason}


@ai_security_router.post("/identity/agents/chain",
                         dependencies=[Depends(require_role(Role.ADMIN))])
async def create_agent_chain(req: CreateChainRequest):
    """Create an AI agent delegation chain."""
    chain = _identity_engine.create_agent_chain(req.root_identity_id)
    return {
        "chain_id": chain.chain_id,
        "root_identity_id": chain.root_identity_id,
        "created_at": chain.created_at,
        "is_valid": chain.is_valid,
    }


@ai_security_router.post("/identity/agents/delegate",
                         dependencies=[Depends(require_role(Role.ADMIN))])
async def add_delegation(req: DelegateRequest):
    """Add a delegation link to an agent identity chain."""
    chain = _identity_engine.delegation_graph.get_chain(req.chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")
    link = _identity_engine.delegate(
        chain=chain,
        parent_id=req.parent_id,
        child_id=req.child_id,
        scopes=req.scopes,
        purpose=req.purpose,
        ttl_minutes=req.ttl_minutes,
    )
    if not link:
        raise HTTPException(status_code=403,
                            detail="Delegation denied: scope escalation or chain invalid")
    return {
        "link_id": link.link_id,
        "parent": link.parent_identity_id,
        "child": link.child_identity_id,
        "scopes": link.delegated_scopes,
        "expires_at": link.expires_at,
        "purpose": link.purpose,
    }


@ai_security_router.get("/identity/governance",
                        dependencies=[Depends(require_role(Role.ANALYST))])
async def identity_governance_report():
    """NHI governance report: risk tiers, orphaned identities, compliance gaps."""
    report = _identity_engine.governance_report()
    return {
        "report": report,
        "nist_controls": ["IA-2", "IA-3", "IA-4", "IA-5", "IA-8", "AC-2", "AC-6", "SC-8"],
        "zero_trust_alignment": "NIST SP 800-207",
    }
