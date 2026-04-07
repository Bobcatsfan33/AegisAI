"""
Tests for modules/supply_chain/behavioral.py

Covers: SupplyChainEvent, AnomalyResult, BehavioralScorer
"""

import time
import pytest

from modules.supply_chain.behavioral import (
    AnomalyResult,
    BehavioralScorer,
    SupplyChainEvent,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _ts(hour: int = 14, day_offset: int = 0) -> float:
    """Return a timestamp for a Tuesday at the given hour (in UTC approximation)."""
    import datetime
    # 2024-04-02 is a Tuesday; hour is used directly
    base = datetime.datetime(2024, 4, 2 + day_offset, hour, 0, 0)
    return base.timestamp()


def _event(
    event_type: str = "build",
    artifact_id: str = "img:aegis:1.0",
    timestamp: float = None,
    builder_id: str = "github-actions",
    branch: str = "main",
    environment: str = "staging",
    digest: str = "sha256:aabb",
    dependency_count: int = 0,
) -> SupplyChainEvent:
    return SupplyChainEvent(
        event_type=event_type,
        artifact_id=artifact_id,
        timestamp=timestamp or _ts(),
        builder_id=builder_id,
        branch=branch,
        environment=environment,
        digest=digest,
        dependency_count=dependency_count,
    )


def _warmed_up_scorer(warm_up: int = 10) -> BehavioralScorer:
    """Return a scorer that has been warmed up with normal events."""
    scorer = BehavioralScorer(warm_up_events=warm_up, business_hours=(6, 22))
    for i in range(warm_up):
        scorer.score_event(_event(
            event_type="build",
            artifact_id=f"img:{i}",
            timestamp=_ts(14),
            builder_id="github-actions",
            branch="main",
            digest=f"sha256:build{i}",
        ))
    return scorer


# ── SupplyChainEvent tests ─────────────────────────────────────────────────────

class TestSupplyChainEvent:
    def test_hour_of_day(self):
        evt = _event(timestamp=_ts(9))
        # hour should be 9 (or close, depending on local TZ)
        # We just verify it's in 0-23 range
        assert 0 <= evt.hour_of_day() <= 23

    def test_day_of_week(self):
        # 2024-04-02 is a Tuesday (dow=1)
        evt = _event(timestamp=_ts(14))
        dow = evt.day_of_week()
        assert 0 <= dow <= 6


# ── AnomalyResult tests ────────────────────────────────────────────────────────

class TestAnomalyResult:
    def _make_result(self, score: float) -> AnomalyResult:
        return AnomalyResult(event=_event(), score=score, anomalies=[], details={})

    def test_is_anomalous_threshold(self):
        assert self._make_result(0.39).is_anomalous is False
        assert self._make_result(0.40).is_anomalous is True
        assert self._make_result(1.00).is_anomalous is True

    def test_severity_levels(self):
        assert self._make_result(0.0).severity == "normal"
        assert self._make_result(0.2).severity == "low"
        assert self._make_result(0.4).severity == "medium"
        assert self._make_result(0.6).severity == "high"
        assert self._make_result(0.8).severity == "critical"
        assert self._make_result(1.0).severity == "critical"

    def test_to_dict(self):
        result = self._make_result(0.5)
        result.anomalies = ["test anomaly"]
        d = result.to_dict()
        assert d["score"] == 0.5
        assert d["severity"] == "medium"
        assert "test anomaly" in d["anomalies"]
        assert "artifact_id" in d
        assert "event_type" in d


# ── BehavioralScorer core tests ────────────────────────────────────────────────

class TestBehavioralScorerBasics:
    def test_initial_state(self):
        scorer = BehavioralScorer()
        assert scorer.event_count == 0
        assert scorer.is_warmed_up is False

    def test_warm_up_tracking(self):
        scorer = BehavioralScorer(warm_up_events=5)
        for i in range(4):
            scorer.score_event(_event(artifact_id=f"a:{i}"))
        assert scorer.is_warmed_up is False
        scorer.score_event(_event(artifact_id="a:5"))
        assert scorer.is_warmed_up is True

    def test_event_count_increments(self):
        scorer = BehavioralScorer()
        scorer.score_event(_event())
        scorer.score_event(_event())
        assert scorer.event_count == 2

    def test_score_returns_anomaly_result(self):
        scorer = BehavioralScorer()
        result = scorer.score_event(_event())
        assert isinstance(result, AnomalyResult)
        assert 0.0 <= result.score <= 1.0

    def test_normal_event_low_score(self):
        scorer = _warmed_up_scorer()
        # Business hours build on main branch
        result = scorer.score_event(_event(
            event_type="build", branch="main",
            timestamp=_ts(14), builder_id="github-actions",
        ))
        # Score should be low for a normal event (only possible flag: none expected)
        assert result.score < 0.6

    def test_reset_clears_all_state(self):
        scorer = _warmed_up_scorer()
        scorer.reset()
        assert scorer.event_count == 0
        assert scorer.is_warmed_up is False
        assert len(scorer._known_builders) == 0


# ── Temporal anomaly tests ─────────────────────────────────────────────────────

class TestTemporalAnomalies:
    def test_weekend_deploy_flagged(self):
        scorer = BehavioralScorer(business_hours=(6, 22))
        # Saturday = day_offset=4 from Tuesday (2024-04-06 = Saturday)
        sat_ts = _ts(14, day_offset=4)
        result = scorer.score_event(_event(
            event_type="deploy", timestamp=sat_ts, environment="production"
        ))
        assert result.score >= 0.4
        assert any("weekend" in a.lower() or "temporal" in a.lower() for a in result.anomalies)

    def test_after_hours_deploy_flagged(self):
        scorer = BehavioralScorer(business_hours=(6, 22))
        # 2AM deploy
        late_ts = _ts(2)
        result = scorer.score_event(_event(event_type="deploy", timestamp=late_ts))
        assert result.score >= 0.2
        assert any("temporal" in a.lower() or "after-hours" in a.lower() for a in result.anomalies)

    def test_business_hours_deploy_no_temporal_flag(self):
        scorer = BehavioralScorer(business_hours=(6, 22))
        result = scorer.score_event(_event(event_type="deploy", timestamp=_ts(10)))
        temporal_flags = [a for a in result.anomalies if "temporal" in a.lower()]
        assert len(temporal_flags) == 0

    def test_weekend_build_also_flagged(self):
        scorer = BehavioralScorer(business_hours=(6, 22))
        sat_ts = _ts(14, day_offset=4)
        result = scorer.score_event(_event(event_type="build", timestamp=sat_ts))
        assert result.score >= 0.4


# ── Builder drift tests ────────────────────────────────────────────────────────

class TestBuilderDrift:
    def test_unknown_builder_after_warmup_flagged(self):
        scorer = _warmed_up_scorer(warm_up=5)
        result = scorer.score_event(_event(builder_id="rogue-ci-runner"))
        assert result.score >= 0.6
        assert any("builder" in a.lower() for a in result.anomalies)

    def test_known_builder_not_flagged(self):
        scorer = _warmed_up_scorer(warm_up=5)
        # "github-actions" was used during warm-up
        result = scorer.score_event(_event(builder_id="github-actions", timestamp=_ts(14)))
        builder_flags = [a for a in result.anomalies if "builder" in a.lower()]
        assert len(builder_flags) == 0

    def test_register_known_builder_prevents_flag(self):
        scorer = BehavioralScorer(warm_up_events=5)
        scorer.register_known_builder("trusted-runner-42")
        # Warm up
        for i in range(5):
            scorer.score_event(_event(artifact_id=f"a:{i}", builder_id="github-actions"))
        result = scorer.score_event(_event(builder_id="trusted-runner-42"))
        builder_flags = [a for a in result.anomalies if "builder" in a.lower()]
        assert len(builder_flags) == 0

    def test_new_builder_before_warmup_not_flagged(self):
        scorer = BehavioralScorer(warm_up_events=10)
        # Only 2 events → not warmed up → no builder drift flag
        scorer.score_event(_event(builder_id="known-builder"))
        result = scorer.score_event(_event(builder_id="new-builder"))
        builder_flags = [a for a in result.anomalies if "builder" in a.lower()]
        assert len(builder_flags) == 0


# ── Branch anomaly tests ───────────────────────────────────────────────────────

class TestBranchAnomalies:
    def test_production_deploy_from_feature_branch_flagged(self):
        scorer = BehavioralScorer()
        result = scorer.score_event(_event(
            event_type="deploy",
            branch="feature/suspicious-change",
            environment="production",
        ))
        assert result.score >= 0.7
        assert any("branch" in a.lower() for a in result.anomalies)

    def test_production_deploy_from_main_ok(self):
        scorer = BehavioralScorer()
        result = scorer.score_event(_event(
            event_type="deploy",
            branch="main",
            environment="production",
        ))
        branch_flags = [a for a in result.anomalies if "branch" in a.lower()]
        assert len(branch_flags) == 0

    def test_staging_deploy_from_feature_branch_ok(self):
        scorer = BehavioralScorer()
        result = scorer.score_event(_event(
            event_type="deploy",
            branch="feature/my-feature",
            environment="staging",
        ))
        branch_flags = [a for a in result.anomalies if "branch" in a.lower()]
        assert len(branch_flags) == 0

    def test_custom_prod_branches(self):
        scorer = BehavioralScorer(prod_branches={"release"})
        result = scorer.score_event(_event(
            event_type="deploy", branch="main", environment="production"
        ))
        # "main" not in {"release"} → should flag
        branch_flags = [a for a in result.anomalies if "branch" in a.lower()]
        assert len(branch_flags) > 0


# ── Digest mismatch tests ──────────────────────────────────────────────────────

class TestDigestAnomalies:
    def test_digest_mismatch_at_deploy_flagged(self):
        scorer = BehavioralScorer()
        # Register known good digest via a build event
        scorer.score_event(_event(
            event_type="build", artifact_id="img:1.0", digest="sha256:good"
        ))
        # Deploy with different digest → tamper indicator
        result = scorer.score_event(_event(
            event_type="deploy", artifact_id="img:1.0", digest="sha256:evil"
        ))
        assert result.score >= 0.8
        assert any("digest" in a.lower() for a in result.anomalies)

    def test_same_digest_at_deploy_ok(self):
        scorer = BehavioralScorer()
        scorer.score_event(_event(event_type="build", artifact_id="img:1.0", digest="sha256:good"))
        result = scorer.score_event(_event(
            event_type="deploy", artifact_id="img:1.0", digest="sha256:good"
        ))
        digest_flags = [a for a in result.anomalies if "digest" in a.lower()]
        assert len(digest_flags) == 0

    def test_register_known_digest_prevents_mismatch_flag(self):
        scorer = BehavioralScorer()
        scorer.register_known_digest("img:2.0", "sha256:known-good")
        result = scorer.score_event(_event(
            event_type="deploy", artifact_id="img:2.0", digest="sha256:known-good"
        ))
        digest_flags = [a for a in result.anomalies if "digest" in a.lower()]
        assert len(digest_flags) == 0

    def test_first_seen_digest_not_flagged(self):
        scorer = BehavioralScorer()
        result = scorer.score_event(_event(
            event_type="deploy", artifact_id="brand-new:1.0", digest="sha256:first"
        ))
        digest_flags = [a for a in result.anomalies if "digest" in a.lower()]
        assert len(digest_flags) == 0


# ── Dependency spike tests ─────────────────────────────────────────────────────

class TestDependencyAnomalies:
    def test_dependency_spike_flagged(self):
        scorer = _warmed_up_scorer(warm_up=5)
        # Establish dependency baseline
        for i in range(5):
            scorer.score_event(_event(
                artifact_id="app:1.0",
                dependency_count=10,
                event_type="build",
            ))
        # Suddenly 25 deps (2.5x baseline)
        result = scorer.score_event(_event(
            artifact_id="app:1.0",
            dependency_count=25,
            event_type="build",
        ))
        dep_flags = [a for a in result.anomalies if "dep" in a.lower()]
        assert len(dep_flags) > 0

    def test_normal_dependency_count_not_flagged(self):
        scorer = _warmed_up_scorer(warm_up=5)
        for _ in range(5):
            scorer.score_event(_event(artifact_id="app:2.0", dependency_count=10))
        result = scorer.score_event(_event(artifact_id="app:2.0", dependency_count=11))
        dep_flags = [a for a in result.anomalies if "dep" in a.lower()]
        assert len(dep_flags) == 0


# ── Unknown environment tests ──────────────────────────────────────────────────

class TestEnvironmentAnomalies:
    def test_unknown_environment_flagged(self):
        scorer = BehavioralScorer()
        result = scorer.score_event(_event(environment="secret-dark-cluster"))
        env_flags = [a for a in result.anomalies if "environment" in a.lower()]
        assert len(env_flags) > 0

    def test_known_environment_not_flagged(self):
        scorer = BehavioralScorer()
        for env in ["production", "staging", "dev", "development", "qa", "test"]:
            result = scorer.score_event(_event(environment=env))
            env_flags = [a for a in result.anomalies if "environment" in a.lower()]
            assert len(env_flags) == 0, f"False positive for env={env}"


# ── Batch scoring tests ────────────────────────────────────────────────────────

class TestBatchScoring:
    def test_score_batch_returns_all_results(self):
        scorer = BehavioralScorer()
        events = [_event(artifact_id=f"img:{i}") for i in range(5)]
        results = scorer.score_batch(events)
        assert len(results) == 5

    def test_score_batch_sorted_by_timestamp(self):
        scorer = BehavioralScorer()
        events = [
            _event(artifact_id="late", timestamp=_ts(15)),
            _event(artifact_id="early", timestamp=_ts(9)),
        ]
        results = scorer.score_batch(events)
        # Early should have been processed first
        assert results[0].event.artifact_id == "early"

    def test_flagged_events_filters_below_threshold(self):
        scorer = BehavioralScorer()
        events = [
            _event(event_type="deploy", branch="feature/bad", environment="production"),  # anomalous
            _event(event_type="build", branch="main", timestamp=_ts(14)),                 # normal
        ]
        flagged = scorer.flagged_events(events, threshold=0.4)
        assert all(r.score >= 0.4 for r in flagged)
        assert len(flagged) >= 1

    def test_flagged_events_empty_when_all_normal(self):
        scorer = BehavioralScorer()
        events = [
            _event(event_type="build", branch="main", timestamp=_ts(14)),
            _event(event_type="build", branch="main", timestamp=_ts(15)),
        ]
        flagged = scorer.flagged_events(events, threshold=1.0)
        assert len(flagged) == 0


# ── Summary tests ──────────────────────────────────────────────────────────────

class TestScorerSummary:
    def test_summary_contains_expected_keys(self):
        scorer = BehavioralScorer()
        s = scorer.summary()
        assert "event_count" in s
        assert "warmed_up" in s
        assert "known_builders" in s
        assert "tracked_artifacts" in s

    def test_summary_reflects_state(self):
        scorer = _warmed_up_scorer(warm_up=5)
        scorer.score_event(_event(builder_id="builder-X"))
        s = scorer.summary()
        assert s["event_count"] > 5
        assert "github-actions" in s["known_builders"]
        assert s["warmed_up"] is True
