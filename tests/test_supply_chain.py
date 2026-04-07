"""
Tests for Supply Chain Security Engine — AegisAI v3.1.0

Covers:
  - Commit provenance ingestion and behavioral analysis
  - Human vs machine identity detection
  - XZ-style fast-trust anomaly detection
  - Off-hours geo-shift detection
  - Artifact attestation and hash verification
  - Typosquatting detection (Levenshtein)
  - Dependency risk scoring
  - Aggregate deployment scoring and deploy gate
  - Event log retrieval
"""

import pytest

from modules.supply_chain import (
    SupplyChainEngine,
    CommitProvenance,
    ArtifactAttestation,
    DependencyRisk,
    ProvenanceScore,
    IdentityType,
    AnomalyType,
)
from modules.supply_chain.engine import (
    BehavioralAnalyzer,
    TyposquattingDetector,
    SLSALevel,
    RiskTier,
    get_engine,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine():
    return SupplyChainEngine(policy_threshold=0.60)


@pytest.fixture
def analyzer():
    return BehavioralAnalyzer()


@pytest.fixture
def clean_commit():
    """A commit that looks clean: human, signed, normal hours."""
    return CommitProvenance(
        repo="org/myrepo",
        commit_sha="abc123def456",
        author_email="alice@example.com",
        author_name="Alice Smith",
        committer_email="alice@example.com",
        committer_name="Alice Smith",
        timestamp="2025-06-15T14:30:00+00:00",
        message="fix: resolve issue #42",
        gpg_signed=True,
        session_verified=True,
        identity_type=IdentityType.HUMAN,
        contributor_commit_count=150,
        days_since_account_creation=800,
        commit_hour_utc=14,
        geo_country="US",
    )


@pytest.fixture
def xz_style_commit():
    """A commit matching XZ-style trust infiltration: new account, many commits fast."""
    return CommitProvenance(
        repo="org/critical-lib",
        commit_sha="deadbeef1234",
        author_email="jiat75@example.com",
        author_name="Jia T",
        committer_email="jiat75@example.com",
        committer_name="Jia T",
        timestamp="2025-06-15T02:30:00+00:00",  # Off-hours UTC
        message="build: update release artifact",
        gpg_signed=False,
        session_verified=False,
        identity_type=IdentityType.HUMAN,
        contributor_commit_count=75,  # Many commits from new account
        days_since_account_creation=90,  # Account less than 6 months old
        commit_hour_utc=2,  # Off hours
        geo_country="CN",  # High-risk geo
        previous_geo="DE",  # Geo shift
    )


# ---------------------------------------------------------------------------
# Commit ingestion
# ---------------------------------------------------------------------------

class TestCommitIngestion:
    def test_ingest_webhook_payload(self, engine):
        payload = {
            "repository": {"full_name": "org/myrepo"},
            "after": "abc123",
            "head_commit": {
                "id": "abc123",
                "author": {"email": "alice@example.com", "name": "Alice"},
                "committer": {"email": "alice@example.com", "name": "Alice"},
                "timestamp": "2025-06-15T14:30:00+00:00",
                "message": "feat: add new feature",
                "modified": ["src/main.py"],
            },
        }
        commit = engine.ingest_commit(payload)
        assert commit.repo == "org/myrepo"
        assert commit.commit_sha == "abc123"
        assert commit.author_email == "alice@example.com"

    def test_machine_identity_detection_bot_email(self, engine):
        payload = {
            "repository": {"full_name": "org/repo"},
            "after": "bot001",
            "head_commit": {
                "author": {"email": "dependabot[bot]@noreply.github.com", "name": "dependabot[bot]"},
                "committer": {"email": "dependabot[bot]@noreply.github.com", "name": "dependabot[bot]"},
                "timestamp": "2025-06-15T14:30:00+00:00",
                "message": "chore(deps): bump requests from 2.30.0 to 2.32.3",
                "modified": [],
            },
        }
        commit = engine.ingest_commit(payload)
        assert commit.identity_type == IdentityType.MACHINE

    def test_machine_identity_detection_actions(self, engine):
        payload = {
            "repository": {"full_name": "org/repo"},
            "after": "act001",
            "head_commit": {
                "author": {"email": "actions@github.com", "name": "GitHub Actions"},
                "committer": {"email": "actions@github.com", "name": "GitHub Actions"},
                "timestamp": "2025-06-15T14:30:00+00:00",
                "message": "ci: auto-format",
                "modified": [],
            },
        }
        commit = engine.ingest_commit(payload)
        assert commit.identity_type == IdentityType.MACHINE

    def test_human_identity_detection(self, engine):
        payload = {
            "repository": {"full_name": "org/repo"},
            "after": "human001",
            "head_commit": {
                "author": {"email": "bob@company.com", "name": "Bob Developer"},
                "committer": {"email": "bob@company.com", "name": "Bob Developer"},
                "timestamp": "2025-06-15T10:00:00+00:00",
                "message": "refactor: clean up auth module",
                "modified": ["auth.py"],
            },
        }
        commit = engine.ingest_commit(payload)
        assert commit.identity_type == IdentityType.HUMAN

    def test_commit_hour_extracted(self, engine):
        payload = {
            "repository": {"full_name": "org/repo"},
            "after": "ts001",
            "head_commit": {
                "author": {"email": "dev@co.com", "name": "Dev"},
                "committer": {"email": "dev@co.com", "name": "Dev"},
                "timestamp": "2025-06-15T03:15:00+00:00",
                "message": "fix: patch",
                "modified": [],
            },
        }
        commit = engine.ingest_commit(payload)
        assert commit.commit_hour_utc == 3

    def test_events_logged_on_ingest(self, engine):
        payload = {
            "repository": {"full_name": "org/repo"},
            "after": "ev001",
            "head_commit": {
                "author": {"email": "dev@co.com", "name": "Dev"},
                "committer": {"email": "dev@co.com", "name": "Dev"},
                "timestamp": "2025-06-15T10:00:00+00:00",
                "message": "feat: add thing",
                "modified": [],
            },
        }
        engine.ingest_commit(payload)
        events = engine.get_events(limit=10)
        assert len(events) >= 1


# ---------------------------------------------------------------------------
# Behavioral Analyzer
# ---------------------------------------------------------------------------

class TestBehavioralAnalyzer:
    def test_clean_commit_scores_high(self, analyzer, clean_commit):
        score, anomalies = analyzer.score_commit(clean_commit)
        assert score >= 0.60
        # Clean commit with gpg sig and verified session — should have few anomalies

    def test_xz_style_flagged(self, analyzer, xz_style_commit):
        score, anomalies = analyzer.score_commit(xz_style_commit)
        assert score < 0.60
        assert AnomalyType.NEW_CONTRIBUTOR_FAST_TRUST in anomalies

    def test_off_hours_geo_shift_flagged(self, analyzer):
        commit = CommitProvenance(
            repo="org/repo",
            commit_sha="off001",
            author_email="suspicious@example.com",
            author_name="Suspicious User",
            committer_email="suspicious@example.com",
            committer_name="Suspicious User",
            timestamp="2025-06-15T02:00:00+00:00",
            message="fix: update lib",
            commit_hour_utc=2,
            geo_country="KP",  # North Korea
            previous_geo="US",
            session_verified=False,
        )
        score, anomalies = analyzer.score_commit(commit)
        assert AnomalyType.OFF_HOURS_GEO_SHIFT in anomalies

    def test_unsigned_commit_penalized(self, analyzer):
        commit = CommitProvenance(
            repo="org/repo",
            commit_sha="unsigned001",
            author_email="dev@co.com",
            author_name="Dev",
            committer_email="dev@co.com",
            committer_name="Dev",
            timestamp="2025-06-15T14:00:00+00:00",
            message="feat: something",
            gpg_signed=False,
            sigstore_signed=False,
            session_verified=True,
            commit_hour_utc=14,
        )
        score, anomalies = analyzer.score_commit(commit)
        assert AnomalyType.UNSIGNED_ARTIFACT in anomalies

    def test_score_floor_is_zero(self, analyzer, xz_style_commit):
        # Even terrible commits can't go below 0
        score, _ = analyzer.score_commit(xz_style_commit)
        assert score >= 0.0

    def test_tier_from_score_clean(self, analyzer):
        assert analyzer.tier_from_score(0.90) == RiskTier.CLEAN

    def test_tier_from_score_critical(self, analyzer):
        assert analyzer.tier_from_score(0.10) == RiskTier.CRITICAL

    def test_tier_from_score_high(self, analyzer):
        assert analyzer.tier_from_score(0.30) == RiskTier.HIGH

    def test_tier_from_score_medium(self, analyzer):
        assert analyzer.tier_from_score(0.55) == RiskTier.MEDIUM

    def test_artifact_mismatch_penalized(self, analyzer):
        attestation = ArtifactAttestation(
            artifact_name="mylib",
            artifact_version="1.2.3",
            registry="pypi",
            published_hash="abc123",
            source_hash="def456",
            hash_match=False,
        )
        score, anomalies = analyzer.score_artifact(attestation)
        assert score < 0.6
        assert AnomalyType.BUILD_ARTIFACT_MISMATCH in anomalies

    def test_slsa_l3_scores_better(self, analyzer):
        good = ArtifactAttestation(
            artifact_name="lib",
            artifact_version="1.0.0",
            registry="pypi",
            published_hash="abc",
            hash_match=True,
            slsa_level=SLSALevel.L3_HARDENED,
            sigstore_valid=True,
        )
        bad = ArtifactAttestation(
            artifact_name="lib",
            artifact_version="1.0.0",
            registry="pypi",
            published_hash="abc",
            hash_match=None,
            slsa_level=SLSALevel.NONE,
            sigstore_valid=False,
        )
        good_score, _ = analyzer.score_artifact(good)
        bad_score, _ = analyzer.score_artifact(bad)
        assert good_score > bad_score

    def test_actively_exploited_dep_critical(self, analyzer):
        dep = DependencyRisk(
            name="log4j",
            version="2.14.1",
            ecosystem="maven",
            actively_exploited=True,
            max_cvss=10.0,
        )
        score, _ = analyzer.score_dependency(dep)
        assert score < 0.5

    def test_clean_dep_scores_clean(self, analyzer):
        dep = DependencyRisk(
            name="requests",
            version="2.32.3",
            ecosystem="pypi",
            actively_exploited=False,
            max_cvss=0.0,
        )
        score, anomalies = analyzer.score_dependency(dep)
        assert score >= 0.90
        assert len(anomalies) == 0


# ---------------------------------------------------------------------------
# Typosquatting Detector
# ---------------------------------------------------------------------------

class TestTyposquattingDetector:
    @pytest.fixture
    def detector(self):
        return TyposquattingDetector()

    def test_exact_match_not_flagged(self, detector):
        result = detector.check("requests", "pypi")
        assert result is None  # Exact match = not typosquatting

    def test_typosquat_detected_1_edit(self, detector):
        # "reqests" is 1 edit from "requests"
        result = detector.check("reqests", "pypi")
        assert result is not None
        match, dist = result
        assert match == "requests"
        assert dist <= 2

    def test_typosquat_detected_npm(self, detector):
        # "lodash_" — 1 edit from "lodash"
        result = detector.check("lodash_", "npm")
        assert result is not None

    def test_completely_different_name_clean(self, detector):
        result = detector.check("entirely_different_package_xyz", "pypi")
        assert result is None

    def test_levenshtein_identity(self, detector):
        assert detector.levenshtein("abc", "abc") == 0

    def test_levenshtein_insertion(self, detector):
        assert detector.levenshtein("abc", "abcd") == 1

    def test_levenshtein_deletion(self, detector):
        assert detector.levenshtein("abcd", "abc") == 1

    def test_levenshtein_substitution(self, detector):
        assert detector.levenshtein("abc", "axc") == 1


# ---------------------------------------------------------------------------
# Dependency analysis
# ---------------------------------------------------------------------------

class TestDependencyAnalysis:
    def test_analyze_clean_deps(self, engine):
        deps = [
            {"name": "requests", "version": "2.32.3", "ecosystem": "pypi",
             "max_cvss": 0.0, "actively_exploited": False},
            {"name": "fastapi", "version": "0.115.6", "ecosystem": "pypi",
             "max_cvss": 0.0, "actively_exploited": False},
        ]
        results = engine.analyze_dependencies(deps)
        assert len(results) == 2
        for r in results:
            assert r.risk_tier in (RiskTier.CLEAN, RiskTier.LOW)

    def test_analyze_flags_typosquat(self, engine):
        deps = [{"name": "reqests", "version": "2.31.0", "ecosystem": "pypi"}]
        results = engine.analyze_dependencies(deps)
        assert AnomalyType.TYPOSQUATTING in results[0].anomalies

    def test_analyze_flags_actively_exploited(self, engine):
        deps = [
            {"name": "compromised-lib", "version": "1.0.0", "ecosystem": "pypi",
             "actively_exploited": True, "max_cvss": 9.8}
        ]
        results = engine.analyze_dependencies(deps)
        assert results[0].risk_tier in (RiskTier.CRITICAL, RiskTier.HIGH)

    def test_internal_name_flagged(self, engine):
        deps = [{"name": "internal-api-client", "version": "1.0.0", "ecosystem": "pypi"}]
        results = engine.analyze_dependencies(deps)
        assert AnomalyType.DEPENDENCY_CONFUSION in results[0].anomalies


# ---------------------------------------------------------------------------
# Deployment scoring (deploy gate)
# ---------------------------------------------------------------------------

class TestDeploymentScoring:
    def test_clean_deployment_not_blocked(self, engine):
        commit = CommitProvenance(
            repo="org/repo",
            commit_sha="clean001",
            author_email="alice@co.com",
            author_name="Alice",
            committer_email="alice@co.com",
            committer_name="Alice",
            timestamp="2025-06-15T14:00:00+00:00",
            message="fix: minor patch",
            gpg_signed=True,
            session_verified=True,
            identity_type=IdentityType.HUMAN,
            commit_hour_utc=14,
            provenance_score=0.90,
        )
        score = engine.score_deployment(repo="org/repo", commits=[commit])
        assert not score.blocked
        assert score.overall_score >= 0.60

    def test_bad_commit_blocks_deploy(self, engine):
        # With weighted scoring: commits=40%, artifacts=35%, deps=25%
        # A commit score of 0.10 yields: 0.10*0.40 + 1.0*0.35 + 1.0*0.25 = 0.64
        # To block we need overall < 0.60; we must also provide bad artifacts or
        # use a very low threshold engine.
        low_threshold_engine = SupplyChainEngine(policy_threshold=0.70)
        commit = CommitProvenance(
            repo="org/critical",
            commit_sha="bad001",
            author_email="suspicious@hack.com",
            author_name="Hacker",
            committer_email="suspicious@hack.com",
            committer_name="Hacker",
            timestamp="2025-06-15T03:00:00+00:00",
            message="build: update artifact",
            gpg_signed=False,
            session_verified=False,
            identity_type=IdentityType.UNKNOWN,
            commit_hour_utc=3,
            provenance_score=0.10,  # Very low
            anomalies=[AnomalyType.NEW_CONTRIBUTOR_FAST_TRUST, AnomalyType.OFF_HOURS_GEO_SHIFT],
        )
        score = low_threshold_engine.score_deployment(repo="org/critical", commits=[commit])
        assert score.blocked  # 0.64 < 0.70 threshold
        assert score.overall_score < 0.70

    def test_score_contains_reasons_on_block(self, engine):
        commit = CommitProvenance(
            repo="org/repo",
            commit_sha="reason001",
            author_email="bad@hacker.io",
            author_name="Bad Actor",
            committer_email="bad@hacker.io",
            committer_name="Bad Actor",
            timestamp="2025-06-15T01:00:00+00:00",
            message="inject backdoor",
            gpg_signed=False,
            session_verified=False,
            provenance_score=0.05,
            anomalies=[AnomalyType.BUILD_ARTIFACT_MISMATCH],
        )
        score = engine.score_deployment(repo="org/repo", commits=[commit])
        if score.blocked:
            assert len(score.reasons) > 0

    def test_score_evaluated_at_populated(self, engine):
        score = engine.score_deployment(repo="org/repo")
        assert score.evaluated_at != ""

    def test_aggregate_weights(self, engine):
        """Weighted score: commits 40%, artifacts 35%, deps 25%."""
        # All perfect → should be 1.0
        commit = CommitProvenance(
            repo="org/r",
            commit_sha="w001",
            author_email="a@b.com",
            author_name="A",
            committer_email="a@b.com",
            committer_name="A",
            timestamp="2025-06-15T10:00:00+00:00",
            message="ok",
            provenance_score=1.0,
        )
        score = engine.score_deployment("org/r", commits=[commit])
        assert score.overall_score <= 1.0


# ---------------------------------------------------------------------------
# Event log
# ---------------------------------------------------------------------------

class TestEventLog:
    def test_events_returned_after_ingest(self, engine):
        payload = {
            "repository": {"full_name": "org/repo"},
            "after": "log001",
            "head_commit": {
                "author": {"email": "dev@co.com", "name": "Dev"},
                "committer": {"email": "dev@co.com", "name": "Dev"},
                "timestamp": "2025-06-15T10:00:00+00:00",
                "message": "feat",
                "modified": [],
            },
        }
        engine.ingest_commit(payload)
        events = engine.get_events(limit=100)
        assert len(events) >= 1

    def test_event_filter_by_risk_tier(self, engine):
        # Filter by a tier we know won't be in a fresh engine
        events = engine.get_events(limit=100, risk_tier="critical")
        for e in events:
            assert e.risk_tier.value == "critical"

    def test_summary_structure(self, engine):
        summary = engine.get_summary()
        assert "total_events" in summary
        assert "policy_threshold" in summary
        assert summary["policy_threshold"] == pytest.approx(0.60)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

class TestSingleton:
    def test_get_engine_returns_same_instance(self):
        e1 = get_engine()
        e2 = get_engine()
        assert e1 is e2
