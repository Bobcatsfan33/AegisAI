"""
Tests for Identity Engine — AegisAI v3.1.0 / TokenDNA Integration

Covers:
  - Machine identity registration and governance scoring
  - Human vs machine behavioral classification
  - Behavioral DNA baseline establishment and anomaly detection
  - Zero Trust Identity Exchange (ZTIX) token issuance and validation
  - ZTIX scope enforcement and revocation
  - AI agent delegation chain management
  - Delegation scope escalation prevention
  - NHI governance report
  - Auto-revocation on critical anomaly
"""

import pytest
import time

from modules.identity import (
    IdentityEngine,
    MachineIdentity,
    HumanIdentity,
    IdentityClass,
    BehavioralDNA,
    ZTIXToken,
    DelegationLink,
    AgentIdentityChain,
    IdentityAnomaly,
    NHIRiskTier,
    get_engine,
)
from modules.identity.machine_identity import (
    ZTIXExchange,
    DelegationGraph,
    BehavioralDNAAnalyzer,
    NHIGovernanceScorer,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine():
    return IdentityEngine()


@pytest.fixture
def ztix():
    return ZTIXExchange()


@pytest.fixture
def delegation_graph():
    return DelegationGraph(signing_secret="test_secret_32bytes_long_enough!")


@pytest.fixture
def governance_scorer():
    return NHIGovernanceScorer()


@pytest.fixture
def compliant_machine(engine) -> MachineIdentity:
    """A well-governed machine identity."""
    from datetime import datetime, timezone, timedelta
    last_rotation = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    identity = engine.register_machine(
        identity_id="svc-001",
        display_name="Payment Microservice",
        identity_class=IdentityClass.MACHINE,
        owner_human_id="alice@company.com",
        purpose="Process payment events via payment gateway API",
        allowed_scopes=["payments:read", "payments:write", "audit:log"],
        public_key_pem="-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE\n-----END PUBLIC KEY-----",
    )
    identity.last_key_rotation = last_rotation
    return identity


# ---------------------------------------------------------------------------
# Machine Identity Registration
# ---------------------------------------------------------------------------

class TestMachineIdentityRegistration:
    def test_register_machine(self, engine):
        identity = engine.register_machine(
            identity_id="bot-001",
            display_name="CI Bot",
            identity_class=IdentityClass.MACHINE,
            owner_human_id="devops@co.com",
            purpose="Run CI pipelines",
            allowed_scopes=["ci:run"],
        )
        assert identity.identity_id == "bot-001"
        assert identity.identity_class == IdentityClass.MACHINE
        assert identity.owner_human_id == "devops@co.com"
        assert identity.is_active

    def test_register_ai_agent(self, engine):
        identity = engine.register_machine(
            identity_id="agent-001",
            display_name="Security Analysis Agent",
            identity_class=IdentityClass.AI_AGENT,
            owner_human_id="security@co.com",
            purpose="Run automated security scans",
            allowed_scopes=["security:scan", "reports:read"],
        )
        assert identity.identity_class == IdentityClass.AI_AGENT

    def test_registered_identity_retrievable(self, engine):
        engine.register_machine(
            identity_id="retrieve-001",
            display_name="Test Service",
            identity_class=IdentityClass.MACHINE,
            owner_human_id="owner@co.com",
            purpose="Testing",
        )
        machine = engine.get_machine("retrieve-001")
        assert machine is not None
        assert machine.identity_id == "retrieve-001"

    def test_behavioral_dna_initialized(self, engine):
        identity = engine.register_machine(
            identity_id="dna-001",
            display_name="DNA Test",
            identity_class=IdentityClass.MACHINE,
            owner_human_id="owner@co.com",
            purpose="Test",
        )
        assert identity.behavioral_dna is not None
        assert not identity.behavioral_dna.baseline_established

    def test_risk_tier_assigned_on_registration(self, engine):
        identity = engine.register_machine(
            identity_id="tier-001",
            display_name="Tier Test",
            identity_class=IdentityClass.MACHINE,
            owner_human_id="owner@co.com",
            purpose="Test",
        )
        assert isinstance(identity.risk_tier, NHIRiskTier)


# ---------------------------------------------------------------------------
# NHI Governance Scoring
# ---------------------------------------------------------------------------

class TestNHIGovernanceScoring:
    def test_missing_public_key_flagged(self, governance_scorer):
        machine = MachineIdentity(
            identity_id="test",
            display_name="Test",
            identity_class=IdentityClass.MACHINE,
            owner_human_id="owner@co.com",
            purpose="Test",
            public_key_pem=None,
        )
        tier, gaps = governance_scorer.score(machine)
        assert any("cryptographic" in g.lower() or "key" in g.lower() for g in gaps)
        assert tier in (NHIRiskTier.HIGH, NHIRiskTier.CRITICAL)

    def test_no_owner_flagged(self, governance_scorer):
        machine = MachineIdentity(
            identity_id="test2",
            display_name="Orphan",
            identity_class=IdentityClass.MACHINE,
            owner_human_id="",
            purpose="Test",
        )
        tier, gaps = governance_scorer.score(machine)
        assert any("owner" in g.lower() or "orphan" in g.lower() for g in gaps)

    def test_no_scope_constraints_flagged(self, governance_scorer):
        machine = MachineIdentity(
            identity_id="test3",
            display_name="No Scope",
            identity_class=IdentityClass.MACHINE,
            owner_human_id="owner@co.com",
            purpose="Test",
            allowed_scopes=[],
        )
        _, gaps = governance_scorer.score(machine)
        assert any("scope" in g.lower() for g in gaps)

    def test_compliant_machine_scores_compliant(self, governance_scorer, compliant_machine):
        tier, gaps = governance_scorer.score(compliant_machine)
        # Should be low risk or compliant given public key + owner + scopes
        assert tier in (NHIRiskTier.COMPLIANT, NHIRiskTier.LOW, NHIRiskTier.MEDIUM)

    def test_overdue_key_rotation_flagged(self, governance_scorer):
        from datetime import datetime, timezone, timedelta
        machine = MachineIdentity(
            identity_id="key-overdue",
            display_name="Overdue",
            identity_class=IdentityClass.MACHINE,
            owner_human_id="owner@co.com",
            purpose="Test",
            public_key_pem="-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----",
            key_rotation_days=90,
            last_key_rotation=(datetime.now(timezone.utc) - timedelta(days=120)).isoformat(),
        )
        _, gaps = governance_scorer.score(machine)
        assert any("rotation" in g.lower() or "overdue" in g.lower() for g in gaps)


# ---------------------------------------------------------------------------
# Human vs Machine Classification
# ---------------------------------------------------------------------------

class TestIdentityClassification:
    def test_registered_machine_classified_as_machine(self, engine):
        engine.register_machine(
            identity_id="cls-machine-001",
            display_name="Clf Machine",
            identity_class=IdentityClass.MACHINE,
            owner_human_id="owner@co.com",
            purpose="Test",
        )
        cls, confidence = engine.classify_identity("cls-machine-001")
        assert cls == IdentityClass.MACHINE
        assert confidence == 1.0

    def test_registered_human_classified_as_human(self, engine):
        engine.register_human(
            identity_id="cls-human-001",
            username="alice",
            email="alice@co.com",
        )
        cls, confidence = engine.classify_identity("cls-human-001")
        assert cls == IdentityClass.HUMAN
        assert confidence == 1.0

    def test_unknown_identity_returns_unknown(self, engine):
        cls, confidence = engine.classify_identity("nonexistent-999")
        assert cls == IdentityClass.UNKNOWN
        assert confidence == 0.0

    def test_behavioral_dna_machine_classification(self):
        """Machine-like behavioral DNA should classify as machine."""
        dna = BehavioralDNA(
            identity_id="dna-cls",
            identity_class=IdentityClass.UNKNOWN,
            baseline_established=True,
            call_interval_ms_avg=60_000.0,    # 1 minute interval
            call_interval_ms_std=5.0,          # Very precise → machine
            known_source_ips={"10.0.0.1"},
            known_geo_countries={"US"},
            ja3_fingerprints={"abc123"},
        )
        is_machine, confidence = dna.is_machine_like()
        assert is_machine
        assert confidence >= 0.60

    def test_behavioral_dna_human_classification(self):
        """Human-like behavioral DNA should not classify as machine."""
        dna = BehavioralDNA(
            identity_id="dna-human",
            identity_class=IdentityClass.UNKNOWN,
            baseline_established=True,
            call_interval_ms_avg=3_600_000.0,   # 1 hour average
            call_interval_ms_std=5_000_000.0,   # Huge variance → human
            known_source_ips={"192.168.1.1", "10.0.0.1", "172.16.0.1",
                              "8.8.8.8", "1.1.1.1", "203.0.113.1"},
            known_geo_countries={"US", "GB", "DE", "FR"},
            ja3_fingerprints={"abc", "def", "ghi"},
        )
        is_machine, confidence = dna.is_machine_like()
        assert not is_machine

    def test_no_baseline_returns_false(self):
        dna = BehavioralDNA(
            identity_id="no-baseline",
            identity_class=IdentityClass.UNKNOWN,
            baseline_established=False,
        )
        is_machine, confidence = dna.is_machine_like()
        assert not is_machine
        assert confidence == 0.0


# ---------------------------------------------------------------------------
# ZTIX Exchange
# ---------------------------------------------------------------------------

class TestZTIXExchange:
    def test_token_issued(self, ztix):
        token = ztix.request_token(
            identity_id="svc-001",
            target_service="payment-api",
            requested_scopes=["payments:read"],
        )
        assert token is not None
        assert token.token_id
        assert token.target_service == "payment-api"
        assert "payments:read" in token.granted_scopes

    def test_token_valid(self, ztix):
        token = ztix.request_token(
            identity_id="svc-001",
            target_service="payment-api",
            requested_scopes=["payments:read"],
        )
        assert token is not None
        valid, reason = ztix.validate_token(token.token_id, "payment-api", "payments:read")
        assert valid
        assert reason == "ok"

    def test_wrong_target_fails(self, ztix):
        token = ztix.request_token(
            identity_id="svc-001",
            target_service="payment-api",
            requested_scopes=["payments:read"],
        )
        assert token is not None
        valid, reason = ztix.validate_token(token.token_id, "wrong-service", "payments:read")
        assert not valid
        assert "target" in reason

    def test_wrong_scope_fails(self, ztix):
        token = ztix.request_token(
            identity_id="svc-001",
            target_service="payment-api",
            requested_scopes=["payments:read"],
        )
        assert token is not None
        valid, reason = ztix.validate_token(token.token_id, "payment-api", "payments:write")
        assert not valid

    def test_revoked_token_fails(self, ztix):
        token = ztix.request_token(
            identity_id="svc-001",
            target_service="payment-api",
            requested_scopes=["payments:read"],
        )
        assert token is not None
        ztix.revoke_token(token.token_id)
        valid, reason = ztix.validate_token(token.token_id, "payment-api", "payments:read")
        assert not valid
        assert "revoked" in reason

    def test_scope_violation_denied(self):
        """Requesting scopes beyond allowed_scopes should be denied."""
        ztix = ZTIXExchange()
        machine = MachineIdentity(
            identity_id="constrained-svc",
            display_name="Constrained Service",
            identity_class=IdentityClass.MACHINE,
            owner_human_id="owner@co.com",
            purpose="Test",
            allowed_scopes=["payments:read"],
        )
        # Request a scope not in allowed_scopes
        token = ztix.request_token(
            identity_id="constrained-svc",
            target_service="payment-api",
            requested_scopes=["admin:delete"],
            machine_identity=machine,
        )
        assert token is None

    def test_revoked_identity_denied(self):
        ztix = ZTIXExchange()
        machine = MachineIdentity(
            identity_id="revoked-svc",
            display_name="Revoked",
            identity_class=IdentityClass.MACHINE,
            owner_human_id="owner@co.com",
            purpose="Test",
            allowed_scopes=["read"],
            is_revoked=True,
        )
        token = ztix.request_token(
            identity_id="revoked-svc",
            target_service="api",
            requested_scopes=["read"],
            machine_identity=machine,
        )
        assert token is None

    def test_revoke_all_for_identity(self, ztix):
        t1 = ztix.request_token("svc-A", "api-1", ["read"])
        t2 = ztix.request_token("svc-A", "api-2", ["write"])
        count = ztix.revoke_all_for_identity("svc-A")
        assert count == 2

    def test_single_use_token_exhausted(self, ztix):
        token = ztix.request_token("svc-001", "api", ["read"], max_uses=1)
        assert token is not None
        # First use: valid
        valid1, _ = ztix.validate_token(token.token_id, "api", "read")
        assert valid1
        # Second use: exhausted
        valid2, reason2 = ztix.validate_token(token.token_id, "api", "read")
        assert not valid2
        assert "exhausted" in reason2

    def test_token_not_found(self, ztix):
        valid, reason = ztix.validate_token("nonexistent-token-id", "api", "read")
        assert not valid
        assert "not_found" in reason

    def test_real_identity_not_in_token(self, ztix):
        """The token should not expose the real identity's source IP or full ID."""
        token = ztix.request_token("svc-secret-001", "target-api", ["read"])
        assert token is not None
        # Token exposes token_id, scopes, target — not the source identity details
        # This is enforced at the API layer; here we verify the token_id ≠ identity_id
        assert token.token_id != token.subject_identity_id


# ---------------------------------------------------------------------------
# Engine-level ZTIX integration
# ---------------------------------------------------------------------------

class TestEngineZTIX:
    def test_engine_issues_ztix_token(self, engine, compliant_machine):
        token = engine.request_ztix_token(
            identity_id="svc-001",
            target_service="payment-api",
            scopes=["payments:read"],
        )
        assert token is not None

    def test_engine_validates_ztix_token(self, engine, compliant_machine):
        token = engine.request_ztix_token("svc-001", "payment-api", ["payments:read"])
        assert token is not None
        valid, reason = engine.validate_ztix_token(token.token_id, "payment-api", "payments:read")
        assert valid

    def test_engine_scope_enforcement(self, engine, compliant_machine):
        # "payments:delete" is not in compliant_machine.allowed_scopes
        token = engine.request_ztix_token("svc-001", "payment-api", ["payments:delete"])
        assert token is None  # Denied


# ---------------------------------------------------------------------------
# Delegation Graph
# ---------------------------------------------------------------------------

class TestDelegationGraph:
    def test_create_chain(self, delegation_graph):
        chain = delegation_graph.create_chain("root-agent-001")
        assert chain.chain_id
        assert chain.root_identity_id == "root-agent-001"
        assert chain.is_valid

    def test_add_delegation_link(self, delegation_graph):
        chain = delegation_graph.create_chain("root-001")
        link = delegation_graph.delegate(
            chain=chain,
            parent_identity_id="root-001",
            child_identity_id="subagent-001",
            delegated_scopes=["scan:run", "reports:read"],
            purpose="Security scan delegation",
        )
        assert link is not None
        assert link.link_id
        assert link.child_identity_id == "subagent-001"
        assert "scan:run" in link.delegated_scopes

    def test_delegation_signed(self, delegation_graph):
        chain = delegation_graph.create_chain("root-001")
        link = delegation_graph.delegate(
            chain, "root-001", "sub-001", ["read"], "test"
        )
        assert link is not None
        assert link.signature != ""

    def test_scope_escalation_prevented(self, delegation_graph):
        """Sub-agent cannot be delegated more scopes than the parent has."""
        chain = delegation_graph.create_chain("root-001")
        # Add first link: root → sub with limited scopes
        delegation_graph.delegate(
            chain, "root-001", "sub-001", ["read"], "first delegation"
        )
        # Attempt: sub-001 tries to delegate admin:delete which it doesn't have
        result = delegation_graph.delegate(
            chain, "sub-001", "sub-002", ["admin:delete"], "escalation attempt"
        )
        assert result is None

    def test_chain_integrity_verified(self, delegation_graph):
        chain = delegation_graph.create_chain("root-001")
        delegation_graph.delegate(chain, "root-001", "sub-001", ["read"], "test")
        is_valid = chain.verify_integrity(delegation_graph._secret)
        assert is_valid

    def test_chain_integrity_fails_on_tampering(self, delegation_graph):
        chain = delegation_graph.create_chain("root-001")
        link = delegation_graph.delegate(chain, "root-001", "sub-001", ["read"], "test")
        # Tamper with the link
        if link:
            link.delegated_scopes = ["admin:delete"]
            is_valid = chain.verify_integrity(delegation_graph._secret)
            assert not is_valid

    def test_revoke_chain(self, delegation_graph):
        chain = delegation_graph.create_chain("root-001")
        delegation_graph.delegate(chain, "root-001", "sub-001", ["read"], "test")
        delegation_graph.revoke_chain(chain.chain_id)
        assert not chain.is_valid
        for link in chain.links:
            assert link.is_revoked

    def test_get_leaf_identity(self, delegation_graph):
        chain = delegation_graph.create_chain("root-001")
        delegation_graph.delegate(chain, "root-001", "sub-001", ["read"], "p1")
        delegation_graph.delegate(chain, "sub-001", "sub-002", ["read"], "p2")
        assert chain.get_leaf_identity() == "sub-002"

    def test_leaf_identity_is_root_when_no_links(self, delegation_graph):
        chain = delegation_graph.create_chain("root-001")
        assert chain.get_leaf_identity() == "root-001"

    def test_scope_for_leaf(self, delegation_graph):
        chain = delegation_graph.create_chain("root-001")
        delegation_graph.delegate(chain, "root-001", "sub-001", ["read", "write"], "p1")
        scopes = chain.scope_for_leaf()
        assert "read" in scopes
        assert "write" in scopes


# ---------------------------------------------------------------------------
# Engine Delegation Integration
# ---------------------------------------------------------------------------

class TestEngineDelegation:
    def test_create_and_delegate_via_engine(self, engine):
        engine.register_machine("orch-001", "Orchestrator", IdentityClass.AI_AGENT,
                                "owner@co.com", "Root orchestration agent",
                                allowed_scopes=["scan:run", "reports:read"])
        engine.register_machine("sub-001", "Sub Scanner", IdentityClass.AI_SUBAGENT,
                                "owner@co.com", "Sub-scan agent")
        chain = engine.create_agent_chain("orch-001")
        link = engine.delegate(chain, "orch-001", "sub-001", ["scan:run"],
                               purpose="Delegate scanning task")
        assert link is not None
        assert link.child_identity_id == "sub-001"


# ---------------------------------------------------------------------------
# Behavioral Observation and Auto-revocation
# ---------------------------------------------------------------------------

class TestBehavioralObservation:
    def test_observation_recorded_without_anomaly_initially(self, engine):
        engine.register_machine("obs-001", "Observed Svc", IdentityClass.MACHINE,
                                "owner@co.com", "Test")
        anomalies = engine.observe("obs-001", source_ip="10.0.0.1",
                                   geo_country="US", auto_revoke=False)
        assert isinstance(anomalies, list)

    def test_geo_shift_detected(self, engine):
        engine.register_machine("geo-001", "Geo Test", IdentityClass.MACHINE,
                                "owner@co.com", "Test")
        machine = engine.get_machine("geo-001")
        if machine and machine.behavioral_dna:
            # Force baseline to include known geo
            machine.behavioral_dna.baseline_established = True
            machine.behavioral_dna.known_geo_countries = {"US"}
            machine.behavioral_dna.known_source_ips = {"10.0.0.1"}
            machine.behavioral_dna.call_interval_ms_avg = 60_000.0
            machine.behavioral_dna.call_interval_ms_std = 5.0

        anomalies = engine.observe("geo-001", source_ip="10.0.0.1",
                                   geo_country="KP", auto_revoke=False)
        assert IdentityAnomaly.GEO_SHIFT in anomalies

    def test_unknown_source_ip_flagged(self, engine):
        engine.register_machine("ip-001", "IP Test", IdentityClass.MACHINE,
                                "owner@co.com", "Test")
        machine = engine.get_machine("ip-001")
        if machine and machine.behavioral_dna:
            machine.behavioral_dna.baseline_established = True
            machine.behavioral_dna.known_source_ips = {"10.0.0.1"}
            machine.behavioral_dna.known_geo_countries = {"US"}
            machine.behavioral_dna.call_interval_ms_avg = 60_000.0
            machine.behavioral_dna.call_interval_ms_std = 5.0

        anomalies = engine.observe("ip-001", source_ip="192.168.99.99",
                                   geo_country="US", auto_revoke=False)
        assert IdentityAnomaly.UNKNOWN_SOURCE in anomalies


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------

class TestRevocation:
    def test_manual_revocation(self, engine):
        engine.register_machine("rev-001", "Revoke Test", IdentityClass.MACHINE,
                                "owner@co.com", "Test")
        engine.revoke_machine("rev-001", reason="Test revocation")
        machine = engine.get_machine("rev-001")
        assert machine is not None
        assert machine.is_revoked
        assert machine.revocation_reason == "Test revocation"

    def test_revoked_identity_denied_ztix(self, engine):
        engine.register_machine("rev-ztix-001", "Revoke ZTIX", IdentityClass.MACHINE,
                                "owner@co.com", "Test", allowed_scopes=["read"])
        engine.revoke_machine("rev-ztix-001", reason="Compromised")
        token = engine.request_ztix_token("rev-ztix-001", "api", ["read"])
        assert token is None


# ---------------------------------------------------------------------------
# Governance Report
# ---------------------------------------------------------------------------

class TestGovernanceReport:
    def test_report_structure(self, engine):
        report = engine.governance_report()
        assert "total_machine_identities" in report
        assert "total_human_identities" in report
        assert "nhi_by_risk_tier" in report
        assert "machine_to_human_ratio" in report

    def test_report_counts_accurate(self, engine):
        engine.register_machine("g-001", "G1", IdentityClass.MACHINE,
                                "owner@co.com", "Test")
        engine.register_machine("g-002", "G2", IdentityClass.MACHINE,
                                "owner@co.com", "Test")
        engine.register_human("h-001", "alice", "alice@co.com")
        report = engine.governance_report()
        assert report["total_machine_identities"] >= 2
        assert report["total_human_identities"] >= 1

    def test_ratio_calculated(self, engine):
        engine.register_machine("ratio-m-001", "M1", IdentityClass.MACHINE,
                                "owner@co.com", "Test")
        engine.register_human("ratio-h-001", "bob", "bob@co.com")
        report = engine.governance_report()
        assert report["machine_to_human_ratio"] >= 1.0

    def test_list_machines_all(self, engine):
        engine.register_machine("list-001", "L1", IdentityClass.MACHINE,
                                "owner@co.com", "Test")
        machines = engine.list_machines()
        assert any(m.identity_id == "list-001" for m in machines)

    def test_list_machines_filter_by_tier(self, engine):
        machines = engine.list_machines(risk_tier="critical")
        for m in machines:
            assert m.risk_tier == NHIRiskTier.CRITICAL


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

class TestSingleton:
    def test_get_engine_returns_same_instance(self):
        e1 = get_engine()
        e2 = get_engine()
        assert e1 is e2
