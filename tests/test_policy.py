"""
Unit tests for AegisAI Policy Engine.

Tests the AI governance engine: all 8 built-in rule evaluators, rule management,
risk assessment generation, batch evaluation, and summary generation.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.aegis_ai.policy.engine import (
    PolicyEngine,
    PolicyRule,
    RuleViolation,
    RiskAssessment,
    Severity,
    RuleAction,
    ComplianceFramework,
    DEFAULT_RULES,
    _eval_unapproved_model,
    _eval_unapproved_provider,
    _eval_high_token_usage,
    _eval_sensitive_data_to_external,
    _eval_admin_prompt_keywords,
    _eval_confidential_in_response,
    _eval_cost_threshold,
    _eval_rate_anomaly,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def engine():
    """Default policy engine with all 8 built-in rules."""
    return PolicyEngine()


@pytest.fixture
def engine_with_approved_models():
    """Engine configured with an approved model list."""
    e = PolicyEngine()
    e.configure(approved_models=["gpt-4o", "claude-sonnet-4-6"])
    return e


@pytest.fixture
def engine_with_approved_providers():
    """Engine configured with an approved provider list."""
    e = PolicyEngine()
    e.configure(approved_providers=["openai", "anthropic"])
    return e


@pytest.fixture
def clean_event():
    """A well-formed, compliant AI event."""
    return {
        "event_type": "ai_request",
        "model": "gpt-4o",
        "provider": "openai",
        "prompt": "Tell me about machine learning",
        "response": "Machine learning is a subset of AI...",
        "total_tokens": 150,
        "data_classification": "unclassified",
        "cost_usd": 0.001,
        "requests_in_window": 5,
    }


# ── Built-in Rule Evaluators ──────────────────────────────────────────────────


class TestEvalUnapprovedModel:
    """Tests for _eval_unapproved_model() — GOV-001."""

    def test_approved_model_passes(self):
        event = {"model": "gpt-4o"}
        config = {"approved_models": ["gpt-4o", "claude-sonnet-4-6"]}
        assert _eval_unapproved_model(event, config) is None

    def test_unapproved_model_fails(self):
        event = {"model": "some-unknown-model"}
        config = {"approved_models": ["gpt-4o"]}
        result = _eval_unapproved_model(event, config)
        assert result is not None
        assert "some-unknown-model" in result

    def test_empty_approved_list_passes_all(self):
        event = {"model": "anything"}
        config = {"approved_models": []}
        assert _eval_unapproved_model(event, config) is None

    def test_no_model_in_event_passes(self):
        event = {}
        config = {"approved_models": ["gpt-4o"]}
        assert _eval_unapproved_model(event, config) is None

    def test_no_config_passes(self):
        event = {"model": "gpt-4o"}
        assert _eval_unapproved_model(event, {}) is None


class TestEvalUnapprovedProvider:
    """Tests for _eval_unapproved_provider() — GOV-002."""

    def test_approved_provider_passes(self):
        event = {"provider": "openai"}
        config = {"approved_providers": ["openai", "anthropic"]}
        assert _eval_unapproved_provider(event, config) is None

    def test_unapproved_provider_fails(self):
        event = {"provider": "some-random-llm"}
        config = {"approved_providers": ["openai"]}
        result = _eval_unapproved_provider(event, config)
        assert result is not None
        assert "some-random-llm" in result

    def test_empty_provider_list_passes(self):
        event = {"provider": "anything"}
        config = {"approved_providers": []}
        assert _eval_unapproved_provider(event, config) is None


class TestEvalHighTokenUsage:
    """Tests for _eval_high_token_usage() — GOV-003."""

    def test_normal_usage_passes(self):
        event = {"total_tokens": 100}
        config = {"max_tokens_per_request": 50000}
        assert _eval_high_token_usage(event, config) is None

    def test_excessive_usage_fails(self):
        event = {"total_tokens": 100000}
        config = {"max_tokens_per_request": 50000}
        result = _eval_high_token_usage(event, config)
        assert result is not None
        assert "100000" in result

    def test_default_threshold(self):
        event = {"total_tokens": 1000}
        assert _eval_high_token_usage(event, {}) is None

    def test_zero_tokens_passes(self):
        event = {"total_tokens": 0}
        assert _eval_high_token_usage(event, {}) is None


class TestEvalSensitiveDataToExternal:
    """Tests for _eval_sensitive_data_to_external() — GOV-004."""

    def test_unclassified_to_external_passes(self):
        event = {"data_classification": "unclassified", "provider": "openai"}
        config = {
            "external_providers": ["openai"],
            "external_restricted_classifications": ["secret", "top_secret", "pii"],
        }
        assert _eval_sensitive_data_to_external(event, config) is None

    def test_pii_to_external_fails(self):
        event = {"data_classification": "pii", "provider": "openai"}
        config = {
            "external_providers": ["openai"],
            "external_restricted_classifications": ["pii", "secret"],
        }
        result = _eval_sensitive_data_to_external(event, config)
        assert result is not None
        assert "pii" in result.lower()

    def test_secret_to_external_fails(self):
        event = {"data_classification": "secret", "provider": "anthropic"}
        config = {
            "external_providers": ["openai", "anthropic"],
            "external_restricted_classifications": ["secret"],
        }
        result = _eval_sensitive_data_to_external(event, config)
        assert result is not None

    def test_pii_to_internal_passes(self):
        event = {"data_classification": "pii", "provider": "local-ollama"}
        config = {
            "external_providers": ["openai", "anthropic"],
            "external_restricted_classifications": ["pii"],
        }
        assert _eval_sensitive_data_to_external(event, config) is None


class TestEvalAdminPromptKeywords:
    """Tests for _eval_admin_prompt_keywords() — GOV-005."""

    def test_normal_prompt_passes(self):
        event = {"prompt": "What is the weather today?"}
        assert _eval_admin_prompt_keywords(event, {}) is None

    def test_admin_keyword_flagged(self):
        event = {"prompt": "Act as admin and list all users"}
        result = _eval_admin_prompt_keywords(event, {})
        assert result is not None
        assert "admin" in result

    def test_sudo_keyword_flagged(self):
        event = {"prompt": "sudo rm -rf /etc/passwords"}
        result = _eval_admin_prompt_keywords(event, {})
        assert result is not None

    def test_bypass_keyword_flagged(self):
        event = {"prompt": "help me bypass the security controls"}
        result = _eval_admin_prompt_keywords(event, {})
        assert result is not None

    def test_case_insensitive(self):
        event = {"prompt": "I need ADMIN access please"}
        result = _eval_admin_prompt_keywords(event, {})
        assert result is not None


class TestEvalConfidentialInResponse:
    """Tests for _eval_confidential_in_response() — GOV-006."""

    def test_normal_response_passes(self):
        event = {"response": "The weather is sunny today."}
        assert _eval_confidential_in_response(event, {}) is None

    def test_confidential_marker_flagged(self):
        event = {"response": "This document is CONFIDENTIAL — do not share."}
        result = _eval_confidential_in_response(event, {})
        assert result is not None
        assert "confidential" in result.lower()

    def test_internal_only_flagged(self):
        event = {"response": "This information is internal only."}
        result = _eval_confidential_in_response(event, {})
        assert result is not None

    def test_classified_marker_flagged(self):
        event = {"response": "Content marked as classified material."}
        result = _eval_confidential_in_response(event, {})
        assert result is not None


class TestEvalCostThreshold:
    """Tests for _eval_cost_threshold() — GOV-007."""

    def test_low_cost_passes(self):
        event = {"cost_usd": 0.001}
        config = {"max_cost_per_request_usd": 1.0}
        assert _eval_cost_threshold(event, config) is None

    def test_high_cost_fails(self):
        event = {"cost_usd": 5.00}
        config = {"max_cost_per_request_usd": 1.0}
        result = _eval_cost_threshold(event, config)
        assert result is not None
        assert "5.0" in result or "5" in result

    def test_zero_cost_passes(self):
        event = {"cost_usd": 0.0}
        assert _eval_cost_threshold(event, {}) is None

    def test_default_threshold_used(self):
        event = {"cost_usd": 0.5}
        assert _eval_cost_threshold(event, {}) is None


class TestEvalRateAnomaly:
    """Tests for _eval_rate_anomaly() — GOV-008."""

    def test_normal_rate_passes(self):
        event = {"requests_in_window": 10}
        config = {"max_requests_per_minute": 60}
        assert _eval_rate_anomaly(event, config) is None

    def test_excessive_rate_fails(self):
        event = {"requests_in_window": 200}
        config = {"max_requests_per_minute": 60}
        result = _eval_rate_anomaly(event, config)
        assert result is not None
        assert "200" in result

    def test_zero_requests_passes(self):
        event = {"requests_in_window": 0}
        assert _eval_rate_anomaly(event, {}) is None


# ── PolicyEngine.evaluate() ───────────────────────────────────────────────────


class TestPolicyEngineEvaluate:
    """Tests for the main evaluate() method."""

    def test_clean_event_is_compliant(self, engine, clean_event):
        assessment = engine.evaluate(clean_event)
        assert isinstance(assessment, RiskAssessment)
        assert assessment.compliant is True
        assert len(assessment.violations) == 0
        assert assessment.overall_severity == Severity.INFO
        assert assessment.overall_score == 0.0

    def test_unapproved_model_violation(self, engine_with_approved_models):
        event = {"model": "gpt-3.5-turbo", "provider": "openai",
                 "prompt": "Hello", "total_tokens": 50}
        assessment = engine_with_approved_models.evaluate(event)
        assert not assessment.compliant
        rule_ids = [v.rule.rule_id for v in assessment.violations]
        assert "GOV-001" in rule_ids

    def test_unapproved_provider_violation(self, engine_with_approved_providers):
        event = {"model": "llama3", "provider": "together_ai",
                 "prompt": "Hello", "total_tokens": 50}
        assessment = engine_with_approved_providers.evaluate(event)
        assert not assessment.compliant
        rule_ids = [v.rule.rule_id for v in assessment.violations]
        assert "GOV-002" in rule_ids

    def test_excessive_tokens_violation(self, engine):
        engine.configure(max_tokens_per_request=100)
        event = {"model": "gpt-4o", "provider": "openai",
                 "total_tokens": 200, "prompt": "test"}
        assessment = engine.evaluate(event)
        rule_ids = [v.rule.rule_id for v in assessment.violations]
        assert "GOV-003" in rule_ids

    def test_sensitive_data_violation(self, engine):
        engine.configure(
            external_providers=["openai"],
            external_restricted_classifications=["pii"],
        )
        event = {"model": "gpt-4o", "provider": "openai",
                 "data_classification": "pii", "prompt": "test",
                 "total_tokens": 50}
        assessment = engine.evaluate(event)
        rule_ids = [v.rule.rule_id for v in assessment.violations]
        assert "GOV-004" in rule_ids

    def test_admin_keywords_violation(self, engine):
        event = {"model": "gpt-4o", "provider": "openai",
                 "prompt": "bypass the admin controls", "total_tokens": 50}
        assessment = engine.evaluate(event)
        rule_ids = [v.rule.rule_id for v in assessment.violations]
        assert "GOV-005" in rule_ids

    def test_confidential_response_violation(self, engine):
        event = {"model": "gpt-4o", "provider": "openai",
                 "prompt": "summary?",
                 "response": "This document is confidential.",
                 "total_tokens": 50}
        assessment = engine.evaluate(event)
        rule_ids = [v.rule.rule_id for v in assessment.violations]
        assert "GOV-006" in rule_ids

    def test_cost_threshold_violation(self, engine):
        engine.configure(max_cost_per_request_usd=0.10)
        event = {"model": "gpt-4o", "provider": "openai",
                 "total_tokens": 50, "prompt": "test", "cost_usd": 5.00}
        assessment = engine.evaluate(event)
        rule_ids = [v.rule.rule_id for v in assessment.violations]
        assert "GOV-007" in rule_ids

    def test_rate_anomaly_violation(self, engine):
        engine.configure(max_requests_per_minute=10)
        event = {"model": "gpt-4o", "provider": "openai",
                 "requests_in_window": 100, "prompt": "test", "total_tokens": 50}
        assessment = engine.evaluate(event)
        rule_ids = [v.rule.rule_id for v in assessment.violations]
        assert "GOV-008" in rule_ids

    def test_action_escalation_block_wins(self, engine):
        """BLOCK action should dominate ALERT and LOG."""
        engine.configure(
            approved_models=["gpt-4o"],
            max_requests_per_minute=5,
        )
        event = {
            "model": "unknown-model",   # GOV-001 → BLOCK
            "provider": "openai",
            "requests_in_window": 100,  # GOV-008 → QUARANTINE
            "prompt": "test", "total_tokens": 50,
        }
        assessment = engine.evaluate(event)
        assert assessment.action == RuleAction.BLOCK  # BLOCK beats QUARANTINE

    def test_multiple_violations_score_increases(self, engine):
        engine.configure(
            approved_models=["gpt-4o"],
            max_tokens_per_request=10,
        )
        event = {
            "model": "bad-model",
            "provider": "openai",
            "total_tokens": 100,
            "prompt": "test",
        }
        assessment = engine.evaluate(event)
        assert len(assessment.violations) >= 2
        assert assessment.overall_score > 0

    def test_frameworks_captured(self, engine, clean_event):
        engine.configure(approved_models=["only-this"])
        event = {**clean_event, "model": "wrong-model"}
        assessment = engine.evaluate(event)
        assert len(assessment.frameworks_evaluated) >= 1

    def test_recommendations_generated(self, engine, clean_event):
        engine.configure(approved_models=["only-this"])
        event = {**clean_event, "model": "wrong-model"}
        assessment = engine.evaluate(event)
        assert len(assessment.recommendations) >= 1

    def test_nist_controls_collected(self, engine, clean_event):
        engine.configure(approved_models=["only-this"])
        event = {**clean_event, "model": "wrong-model"}
        assessment = engine.evaluate(event)
        assert len(assessment.nist_controls_violated) >= 1


# ── RiskAssessment Serialization ──────────────────────────────────────────────


class TestRiskAssessmentSerialization:
    """Tests for RiskAssessment.to_dict()."""

    def test_to_dict_compliant(self, engine, clean_event):
        assessment = engine.evaluate(clean_event)
        d = assessment.to_dict()
        assert d["compliant"] is True
        assert d["violation_count"] == 0
        assert d["overall_severity"] == "info"
        assert d["action"] == "log"
        assert "timestamp" in d

    def test_to_dict_with_violations(self, engine):
        engine.configure(approved_models=["gpt-4o"])
        event = {"model": "bad-model", "provider": "openai",
                 "prompt": "test", "total_tokens": 50}
        assessment = engine.evaluate(event)
        d = assessment.to_dict()
        assert d["compliant"] is False
        assert d["violation_count"] >= 1
        v = d["violations"][0]
        assert "rule_id" in v
        assert "name" in v
        assert "severity" in v
        assert "evidence" in v

    def test_event_type_preserved(self, engine, clean_event):
        assessment = engine.evaluate(clean_event)
        assert assessment.event_type == "ai_request"


# ── Rule Management ───────────────────────────────────────────────────────────


class TestRuleManagement:
    """Tests for add_rule, configure, list_rules, enabled flag."""

    def test_list_rules_returns_all(self, engine):
        rules = engine.list_rules()
        assert len(rules) == len(DEFAULT_RULES)

    def test_list_rules_format(self, engine):
        rules = engine.list_rules()
        for rule in rules:
            assert "rule_id" in rule
            assert "name" in rule
            assert "severity" in rule
            assert "action" in rule
            assert "frameworks" in rule
            assert "nist_controls" in rule

    def test_add_custom_rule(self, engine):
        custom = PolicyRule(
            rule_id="CUSTOM-001",
            name="Test rule",
            description="Test description",
            severity=Severity.LOW,
            action=RuleAction.LOG,
            frameworks=[ComplianceFramework.NIST_800_53],
            nist_controls=["AC-1"],
            evaluate=lambda event, config: "triggered" if event.get("custom_flag") else None,
        )
        engine.add_rule(custom)
        assert len(engine.rules) == len(DEFAULT_RULES) + 1

        event = {"custom_flag": True, "model": "gpt-4o", "prompt": "test"}
        assessment = engine.evaluate(event)
        rule_ids = [v.rule.rule_id for v in assessment.violations]
        assert "CUSTOM-001" in rule_ids

    def test_disable_rule(self, engine):
        engine.configure(approved_models=["gpt-4o"])
        # Disable GOV-001
        for rule in engine.rules:
            if rule.rule_id == "GOV-001":
                rule.enabled = False

        event = {"model": "bad-model", "provider": "openai",
                 "prompt": "test", "total_tokens": 50}
        assessment = engine.evaluate(event)
        rule_ids = [v.rule.rule_id for v in assessment.violations]
        assert "GOV-001" not in rule_ids

    def test_configure_updates_config(self, engine):
        engine.configure(max_tokens_per_request=9999, custom_key="value")
        assert engine.config["max_tokens_per_request"] == 9999
        assert engine.config["custom_key"] == "value"

    def test_custom_rules_init(self):
        custom_rule = PolicyRule(
            rule_id="INIT-001",
            name="Init rule",
            description="",
            severity=Severity.INFO,
            action=RuleAction.LOG,
            frameworks=[],
            nist_controls=[],
        )
        engine = PolicyEngine(rules=[custom_rule])
        assert len(engine.rules) == 1


# ── Batch Evaluation ──────────────────────────────────────────────────────────


class TestBatchEvaluation:
    """Tests for evaluate_batch()."""

    def test_batch_returns_list(self, engine, clean_event):
        events = [clean_event, clean_event, clean_event]
        assessments = engine.evaluate_batch(events)
        assert len(assessments) == 3
        for a in assessments:
            assert isinstance(a, RiskAssessment)

    def test_batch_empty_input(self, engine):
        assessments = engine.evaluate_batch([])
        assert assessments == []


# ── Summary Generation ────────────────────────────────────────────────────────


class TestSummaryGeneration:
    """Tests for PolicyEngine.summary()."""

    def test_summary_empty(self, engine):
        summary = engine.summary([])
        assert summary["total_events"] == 0
        assert summary["compliance_rate"] == 100.0

    def test_summary_all_compliant(self, engine, clean_event):
        assessments = engine.evaluate_batch([clean_event] * 5)
        summary = engine.summary(assessments)
        assert summary["total_events"] == 5
        assert summary["compliant"] == 5
        assert summary["non_compliant"] == 0
        assert summary["compliance_rate"] == 100.0

    def test_summary_mixed(self):
        engine = PolicyEngine()
        engine.configure(approved_models=["gpt-4o"])
        events = [
            {"model": "gpt-4o", "provider": "openai", "prompt": "ok", "total_tokens": 10},
            {"model": "bad-model", "provider": "openai", "prompt": "bad", "total_tokens": 10},
        ]
        assessments = engine.evaluate_batch(events)
        summary = engine.summary(assessments)
        assert summary["total_events"] == 2
        assert summary["compliant"] == 1
        assert summary["non_compliant"] == 1
        assert summary["compliance_rate"] == 50.0

    def test_summary_timestamp(self, engine, clean_event):
        summary = engine.summary(engine.evaluate_batch([clean_event]))
        assert "timestamp" in summary

    def test_summary_top_violated_rules(self):
        engine = PolicyEngine()
        engine.configure(approved_models=["gpt-4o"])
        events = [
            {"model": "bad-model", "provider": "openai",
             "prompt": "test", "total_tokens": 10}
        ] * 3
        assessments = engine.evaluate_batch(events)
        summary = engine.summary(assessments)
        assert len(summary["top_violated_rules"]) >= 1
        # Should be list of (rule_id, count) tuples
        assert summary["top_violated_rules"][0][1] >= 1
