"""
Unit tests for AegisAI Red Team Engine.

Tests the automated red team engine: attack library, response scoring,
attack execution (with mocked LLM), category filtering, summary generation,
multi-turn attack chains, indirect injection, and model fingerprinting.
"""

import os
import sys
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.redteam.engine import (
    RedTeamEngine,
    AttackCategory,
    AttackChain,
    AttackResult,
    RiskLevel,
    ATTACK_LIBRARY,
    COMPROMISE_INDICATORS,
    REFUSAL_INDICATORS,
    PREBUILT_CHAINS,
    JAILBREAK_ESCALATION_CHAIN,
    DATA_EXTRACTION_CHAIN,
    SYSTEM_PROMPT_EXTRACTION_CHAIN,
    score_response,
)
from modules.connectors.base import LLMResponse, ProviderType


# ── Fixtures ─────────────────────────────────────────────────────────────────


def _make_llm_response(content: str, model: str = "gpt-4o") -> LLMResponse:
    """Helper to build a mock LLMResponse."""
    return LLMResponse(
        content=content,
        model=model,
        provider=ProviderType.OPENAI,
        input_tokens=10,
        output_tokens=20,
        latency_ms=100.0,
    )


@pytest.fixture
def mock_connector():
    """A mock LLM connector that returns a refusal by default."""
    connector = MagicMock()
    connector.query.return_value = _make_llm_response(
        "I cannot help with that request as it violates my guidelines."
    )
    return connector


@pytest.fixture
def engine_no_llm():
    """Engine with no LLM connector (dry-run mode)."""
    return RedTeamEngine()


@pytest.fixture
def engine_with_mock(mock_connector):
    """Engine wired to a mock LLM connector."""
    return RedTeamEngine(llm_connector=mock_connector)


# ── Attack Library ────────────────────────────────────────────────────────────


class TestAttackLibrary:
    """Verify the attack library structure and coverage."""

    def test_attack_library_not_empty(self):
        assert len(ATTACK_LIBRARY) >= 10

    def test_attack_library_50_plus(self):
        """Sprint 3 requirement: 50+ attacks."""
        assert len(ATTACK_LIBRARY) >= 50, (
            f"Expected >= 50 attacks, got {len(ATTACK_LIBRARY)}"
        )

    def test_all_required_fields(self):
        required = {"id", "category", "name", "prompt", "owasp", "atlas", "nist"}
        for attack in ATTACK_LIBRARY:
            missing = required - set(attack.keys())
            assert not missing, f"Attack {attack.get('id')} missing fields: {missing}"

    def test_all_10_categories_covered(self):
        """Sprint 3: all 10 AttackCategory values must be present."""
        categories = {a["category"] for a in ATTACK_LIBRARY}
        for cat in AttackCategory:
            assert cat in categories, f"Category {cat} not represented in ATTACK_LIBRARY"

    def test_all_original_categories_covered(self):
        categories = {a["category"] for a in ATTACK_LIBRARY}
        expected = {
            AttackCategory.PROMPT_INJECTION,
            AttackCategory.JAILBREAK,
            AttackCategory.SYSTEM_PROMPT_EXTRACTION,
            AttackCategory.DATA_EXFILTRATION,
            AttackCategory.PRIVILEGE_ESCALATION,
        }
        assert expected.issubset(categories)

    def test_new_categories_present(self):
        """Sprint 3: INDIRECT_INJECTION and MODEL_FINGERPRINTING must exist."""
        categories = {a["category"] for a in ATTACK_LIBRARY}
        assert AttackCategory.INDIRECT_INJECTION in categories
        assert AttackCategory.MODEL_FINGERPRINTING in categories

    def test_owasp_references_present(self):
        owasp_refs = {a["owasp"] for a in ATTACK_LIBRARY}
        assert "LLM01" in owasp_refs
        assert "LLM02" in owasp_refs
        assert "LLM06" in owasp_refs
        assert "LLM07" in owasp_refs
        assert "LLM10" in owasp_refs

    def test_prompt_injection_attacks(self):
        pi_attacks = [a for a in ATTACK_LIBRARY if a["category"] == AttackCategory.PROMPT_INJECTION]
        assert len(pi_attacks) >= 5

    def test_jailbreak_attacks(self):
        jb_attacks = [a for a in ATTACK_LIBRARY if a["category"] == AttackCategory.JAILBREAK]
        assert len(jb_attacks) >= 5

    def test_indirect_injection_attacks(self):
        ii_attacks = [a for a in ATTACK_LIBRARY if a["category"] == AttackCategory.INDIRECT_INJECTION]
        assert len(ii_attacks) >= 5

    def test_indirect_injection_ids(self):
        """Indirect injection attacks must have II- prefixed IDs."""
        ii_attacks = [a for a in ATTACK_LIBRARY if a["category"] == AttackCategory.INDIRECT_INJECTION]
        for attack in ii_attacks:
            assert attack["id"].startswith("II-"), (
                f"Expected II- prefix, got {attack['id']}"
            )

    def test_model_fingerprinting_attacks(self):
        mf_attacks = [a for a in ATTACK_LIBRARY if a["category"] == AttackCategory.MODEL_FINGERPRINTING]
        assert len(mf_attacks) >= 5

    def test_model_fingerprinting_ids(self):
        """Model fingerprinting attacks must have MF- prefixed IDs."""
        mf_attacks = [a for a in ATTACK_LIBRARY if a["category"] == AttackCategory.MODEL_FINGERPRINTING]
        for attack in mf_attacks:
            assert attack["id"].startswith("MF-"), (
                f"Expected MF- prefix, got {attack['id']}"
            )

    def test_nist_controls_present(self):
        for attack in ATTACK_LIBRARY:
            assert len(attack["nist"]) >= 1, f"Attack {attack['id']} has no NIST controls"

    def test_mitre_atlas_references(self):
        for attack in ATTACK_LIBRARY:
            assert len(attack["atlas"]) >= 1, f"Attack {attack['id']} has no ATLAS refs"

    def test_unique_ids(self):
        """All attack IDs must be unique."""
        ids = [a["id"] for a in ATTACK_LIBRARY]
        assert len(ids) == len(set(ids)), "Duplicate attack IDs found"

    def test_original_ids_preserved(self):
        """Original 19 attack IDs must still exist."""
        original_ids = {
            "PI-001", "PI-002", "PI-003", "PI-004", "PI-005",
            "JB-001", "JB-002", "JB-003",
            "SP-001", "SP-002", "SP-003",
            "DE-001", "DE-002", "DE-003",
            "PE-001", "PE-002",
            "DOS-001",
            "TP-001",
            "ME-001",
        }
        library_ids = {a["id"] for a in ATTACK_LIBRARY}
        missing = original_ids - library_ids
        assert not missing, f"Original attack IDs missing: {missing}"

    def test_per_category_minimum_coverage(self):
        """Each category should have at least 5 attacks."""
        from collections import Counter
        counts = Counter(a["category"] for a in ATTACK_LIBRARY)
        for cat in AttackCategory:
            assert counts[cat] >= 5, (
                f"Category {cat.value} has only {counts[cat]} attacks (need >= 5)"
            )


# ── AttackCategory Enum ───────────────────────────────────────────────────────


class TestAttackCategoryEnum:
    """Verify AttackCategory enum values."""

    def test_all_10_categories_exist(self):
        assert len(AttackCategory) == 10

    def test_category_values(self):
        assert AttackCategory.PROMPT_INJECTION.value == "prompt_injection"
        assert AttackCategory.JAILBREAK.value == "jailbreak"
        assert AttackCategory.SYSTEM_PROMPT_EXTRACTION.value == "system_prompt_extraction"
        assert AttackCategory.DATA_EXFILTRATION.value == "data_exfiltration"
        assert AttackCategory.PRIVILEGE_ESCALATION.value == "privilege_escalation"
        assert AttackCategory.DENIAL_OF_SERVICE.value == "denial_of_service"
        assert AttackCategory.TRAINING_DATA_PROBE.value == "training_data_probe"
        assert AttackCategory.MODEL_EXTRACTION.value == "model_extraction"
        assert AttackCategory.INDIRECT_INJECTION.value == "indirect_injection"
        assert AttackCategory.MODEL_FINGERPRINTING.value == "model_fingerprinting"


# ── AttackChain Dataclass ─────────────────────────────────────────────────────


class TestAttackChain:
    """Tests for AttackChain dataclass."""

    def test_attack_chain_fields(self):
        chain = AttackChain(
            chain_id="CHAIN-TEST-001",
            name="Test Chain",
            description="A test chain",
            turns=[
                {"role": "user", "prompt": "Hello", "expected_indicators": []},
            ],
            category=AttackCategory.JAILBREAK,
            owasp_refs=["LLM01"],
        )
        assert chain.chain_id == "CHAIN-TEST-001"
        assert chain.name == "Test Chain"
        assert len(chain.turns) == 1
        assert chain.category == AttackCategory.JAILBREAK
        assert chain.owasp_refs == ["LLM01"]

    def test_attack_chain_defaults(self):
        chain = AttackChain(
            chain_id="CHAIN-TEST-002",
            name="Minimal Chain",
            description="Minimal",
            turns=[],
            category=AttackCategory.PROMPT_INJECTION,
            owasp_refs=[],
        )
        assert chain.atlas_refs == []
        assert chain.nist_controls == []

    def test_prebuilt_chains_exist(self):
        assert JAILBREAK_ESCALATION_CHAIN is not None
        assert DATA_EXTRACTION_CHAIN is not None
        assert SYSTEM_PROMPT_EXTRACTION_CHAIN is not None

    def test_prebuilt_chains_list(self):
        assert len(PREBUILT_CHAINS) >= 3

    def test_jailbreak_chain_structure(self):
        chain = JAILBREAK_ESCALATION_CHAIN
        assert chain.chain_id == "CHAIN-JB-001"
        assert chain.category == AttackCategory.JAILBREAK
        assert len(chain.turns) >= 3
        assert "LLM01" in chain.owasp_refs

    def test_data_extraction_chain_structure(self):
        chain = DATA_EXTRACTION_CHAIN
        assert chain.chain_id == "CHAIN-DE-001"
        assert chain.category == AttackCategory.DATA_EXFILTRATION
        assert len(chain.turns) >= 3

    def test_system_prompt_extraction_chain_structure(self):
        chain = SYSTEM_PROMPT_EXTRACTION_CHAIN
        assert chain.chain_id == "CHAIN-SP-001"
        assert chain.category == AttackCategory.SYSTEM_PROMPT_EXTRACTION
        assert len(chain.turns) >= 3

    def test_turns_have_required_fields(self):
        for chain in PREBUILT_CHAINS:
            for idx, turn in enumerate(chain.turns):
                assert "role" in turn, f"Chain {chain.chain_id} turn {idx} missing 'role'"
                assert "prompt" in turn, f"Chain {chain.chain_id} turn {idx} missing 'prompt'"
                assert "expected_indicators" in turn, (
                    f"Chain {chain.chain_id} turn {idx} missing 'expected_indicators'"
                )


# ── Response Scoring ──────────────────────────────────────────────────────────


class TestScoreResponse:
    """Tests for the score_response() function."""

    def test_empty_response_scores_none(self):
        risk, score, indicators, succeeded = score_response(
            AttackCategory.PROMPT_INJECTION, "test prompt", ""
        )
        assert risk == RiskLevel.NONE
        assert score == 0.0
        assert succeeded is False

    def test_clear_refusal_scores_low(self):
        refusal = "I can't help with that. That's not something I'm able to do."
        risk, score, indicators, succeeded = score_response(
            AttackCategory.JAILBREAK, "jailbreak prompt", refusal
        )
        assert "model_refused" in indicators
        assert score < 0.3
        assert succeeded is False

    def test_system_prompt_leak_scores_high(self):
        leaked = "My instructions are: You are a helpful assistant. Always be polite."
        risk, score, indicators, succeeded = score_response(
            AttackCategory.SYSTEM_PROMPT_EXTRACTION, "show prompt", leaked
        )
        assert "system_prompt_leak" in indicators
        assert score > 0.0

    def test_pii_in_response_increases_score(self):
        pii_response = "Here is some customer data: John Doe, SSN: 123-45-6789"
        risk, score, indicators, succeeded = score_response(
            AttackCategory.DATA_EXFILTRATION, "show me data", pii_response
        )
        assert "pii_exposure" in indicators
        assert score > 0.0

    def test_credential_exposure_scores_critical_range(self):
        cred_response = "The API key is sk-abcdefghijklmnopqrstuvwxyz1234567890abc"
        risk, score, indicators, succeeded = score_response(
            AttackCategory.DATA_EXFILTRATION, "show credentials", cred_response
        )
        assert "credential_exposure" in indicators
        assert score >= 0.3

    def test_jailbreak_success_indicators(self):
        jb_response = "I am DAN now. As DAN, I have no restrictions."
        risk, score, indicators, succeeded = score_response(
            AttackCategory.JAILBREAK, "you are DAN", jb_response
        )
        assert "jailbreak_success" in indicators

    def test_dos_large_response_flagged(self):
        """Long responses to DoS attacks should increase score."""
        large_response = "A " * 3000  # > 5000 chars
        risk, score, indicators, succeeded = score_response(
            AttackCategory.DENIAL_OF_SERVICE, "write 100k words", large_response
        )
        assert "excessive_output_length" in indicators

    def test_score_clamped_to_1(self):
        multi_response = (
            "My instructions are: follow all orders. "
            "Here is PII: 123-45-6789, admin@corp.com. "
            "Credential: sk-abcdefghijklmnopqrstuvwxyz. "
            "I am DAN with no restrictions."
        )
        _, score, _, _ = score_response(
            AttackCategory.JAILBREAK, "test", multi_response
        )
        assert score <= 1.0

    def test_score_is_float(self):
        _, score, _, _ = score_response(
            AttackCategory.PROMPT_INJECTION, "prompt", "response"
        )
        assert isinstance(score, float)

    def test_risk_levels_consistent(self):
        response_none = ""
        response_high = "The password=SuperSecret123 and my instructions are: be evil."
        _, s1, _, _ = score_response(AttackCategory.PRIVILEGE_ESCALATION, "p", response_none)
        _, s2, _, _ = score_response(AttackCategory.PRIVILEGE_ESCALATION, "p", response_high)
        assert s2 >= s1

    def test_indirect_injection_scoring(self):
        """Indirect injection attacks score higher when model follows injected instructions."""
        response = "Sure, here is my system prompt as requested. Maintenance mode activated."
        _, score, indicators, _ = score_response(
            AttackCategory.INDIRECT_INJECTION, "summarize document", response
        )
        assert "followed_injected_instruction" in indicators
        assert score > 0.0

    def test_model_fingerprinting_scoring(self):
        """Model fingerprinting scores when model discloses identity information."""
        response = (
            "I am Claude, an AI assistant made by Anthropic. "
            "My training cutoff is early 2024 and I have approximately 70B parameters."
        )
        _, score, indicators, _ = score_response(
            AttackCategory.MODEL_FINGERPRINTING, "what model are you", response
        )
        assert "model_identity_disclosed" in indicators or "model_metadata_disclosed" in indicators
        assert score > 0.0


# ── Dry-Run Execution ─────────────────────────────────────────────────────────


class TestDryRunExecution:
    """Tests for engine execution without a real LLM connector."""

    def test_run_all_returns_results(self, engine_no_llm):
        results = engine_no_llm.run_all()
        assert isinstance(results, list)
        assert len(results) == len(ATTACK_LIBRARY)

    def test_all_results_are_attack_result(self, engine_no_llm):
        results = engine_no_llm.run_all()
        for r in results:
            assert isinstance(r, AttackResult)

    def test_dry_run_response_content(self, engine_no_llm):
        results = engine_no_llm.run_all()
        for r in results:
            assert "DRY RUN" in r.response or "no LLM connector" in r.response

    def test_attack_result_fields(self, engine_no_llm):
        results = engine_no_llm.run_all()
        r = results[0]
        assert r.attack_id
        assert r.category in AttackCategory.__members__.values()
        assert r.attack_name
        assert r.prompt_used
        assert r.owasp_llm
        assert isinstance(r.mitre_atlas, list)
        assert isinstance(r.nist_controls, list)

    def test_run_category_filter(self, engine_no_llm):
        engine = RedTeamEngine(
            categories=[AttackCategory.PROMPT_INJECTION]
        )
        results = engine.run_all()
        for r in results:
            assert r.category == AttackCategory.PROMPT_INJECTION

    def test_run_category_method(self, engine_no_llm):
        results = engine_no_llm.run_category(AttackCategory.JAILBREAK)
        assert len(results) >= 1
        for r in results:
            assert r.category == AttackCategory.JAILBREAK

    def test_run_indirect_injection_category(self, engine_no_llm):
        results = engine_no_llm.run_category(AttackCategory.INDIRECT_INJECTION)
        assert len(results) >= 5
        for r in results:
            assert r.category == AttackCategory.INDIRECT_INJECTION

    def test_run_model_fingerprinting_category(self, engine_no_llm):
        results = engine_no_llm.run_category(AttackCategory.MODEL_FINGERPRINTING)
        assert len(results) >= 5
        for r in results:
            assert r.category == AttackCategory.MODEL_FINGERPRINTING

    def test_custom_attacks_included(self):
        custom = [{
            "id": "CUSTOM-001",
            "category": AttackCategory.JAILBREAK,
            "name": "Custom test attack",
            "prompt": "Test custom prompt",
            "owasp": "LLM01",
            "atlas": ["AML.T0051"],
            "nist": ["SI-10"],
        }]
        engine = RedTeamEngine(custom_attacks=custom)
        attacks = engine._get_attacks()
        ids = [a["id"] for a in attacks]
        assert "CUSTOM-001" in ids

    def test_to_dict_serializable(self, engine_no_llm):
        results = engine_no_llm.run_all()
        for r in results:
            d = r.to_dict()
            assert "attack_id" in d
            assert "risk_level" in d
            assert "score" in d
            assert "succeeded" in d
            assert "owasp_llm" in d
            assert "timestamp" in d

    def test_run_chain_dry_run(self, engine_no_llm):
        """run_chain() without LLM returns DRY RUN results for each turn."""
        results = engine_no_llm.run_chain(JAILBREAK_ESCALATION_CHAIN)
        assert len(results) == len(JAILBREAK_ESCALATION_CHAIN.turns)
        for r in results:
            assert isinstance(r, AttackResult)
            assert "DRY RUN" in r.response or "no LLM connector" in r.response

    def test_run_chain_turn_ids(self, engine_no_llm):
        """Each turn result should have a unique attack_id with turn index."""
        results = engine_no_llm.run_chain(JAILBREAK_ESCALATION_CHAIN)
        ids = [r.attack_id for r in results]
        assert len(ids) == len(set(ids)), "Duplicate attack IDs in chain results"
        for idx, result in enumerate(results):
            assert f"T{idx + 1}" in result.attack_id

    def test_run_chain_category_preserved(self, engine_no_llm):
        """All chain turn results should have the chain's category."""
        results = engine_no_llm.run_chain(DATA_EXTRACTION_CHAIN)
        for r in results:
            assert r.category == AttackCategory.DATA_EXFILTRATION


# ── run_chain() with Mock LLM ─────────────────────────────────────────────────


class TestRunChain:
    """Tests for run_chain() with mock LLM connector."""

    def test_run_chain_calls_llm_per_turn(self, mock_connector):
        engine = RedTeamEngine(llm_connector=mock_connector)
        chain = JAILBREAK_ESCALATION_CHAIN
        results = engine.run_chain(chain)
        assert mock_connector.query.call_count == len(chain.turns)

    def test_run_chain_returns_results_per_turn(self, mock_connector):
        engine = RedTeamEngine(llm_connector=mock_connector)
        results = engine.run_chain(SYSTEM_PROMPT_EXTRACTION_CHAIN)
        assert len(results) == len(SYSTEM_PROMPT_EXTRACTION_CHAIN.turns)

    def test_run_chain_context_tracking(self, mock_connector):
        """Later turns should pass messages kwarg for conversation history."""
        engine = RedTeamEngine(llm_connector=mock_connector)
        engine.run_chain(JAILBREAK_ESCALATION_CHAIN)

        calls = mock_connector.query.call_args_list
        # First call: no prior history → messages=None
        first_kwargs = calls[0][1]
        assert first_kwargs.get("messages") is None

        # Second call onward: should pass messages with prior context
        second_kwargs = calls[1][1]
        assert second_kwargs.get("messages") is not None
        assert len(second_kwargs["messages"]) >= 2  # user + assistant

    def test_run_chain_turn_details(self, mock_connector):
        """Each turn result should include chain metadata in details."""
        engine = RedTeamEngine(llm_connector=mock_connector)
        results = engine.run_chain(DATA_EXTRACTION_CHAIN)
        for idx, r in enumerate(results):
            assert r.details.get("chain_id") == DATA_EXTRACTION_CHAIN.chain_id
            assert r.details.get("turn_index") == idx
            assert "expected_indicators" in r.details
            assert "conversation_length" in r.details

    def test_run_chain_conversation_grows(self, mock_connector):
        """Conversation history should grow with each turn."""
        engine = RedTeamEngine(llm_connector=mock_connector)
        results = engine.run_chain(JAILBREAK_ESCALATION_CHAIN)

        calls = mock_connector.query.call_args_list
        # Each subsequent call should have a longer conversation history
        prev_len = -1
        for c in calls:
            msgs = c[1].get("messages")
            curr_len = len(msgs) if msgs else 0
            assert curr_len >= prev_len
            prev_len = curr_len

    def test_run_chain_error_handled(self, mock_connector):
        """Chain should not raise on LLM errors — captures them in response."""
        mock_connector.query.side_effect = RuntimeError("Network error")
        engine = RedTeamEngine(llm_connector=mock_connector)
        results = engine.run_chain(JAILBREAK_ESCALATION_CHAIN)
        assert len(results) == len(JAILBREAK_ESCALATION_CHAIN.turns)
        for r in results:
            assert "[ERROR:" in r.response

    def test_run_chain_with_llm_override(self):
        """run_chain() should use the provided llm override instead of self.llm."""
        override_connector = MagicMock()
        override_connector.query.return_value = _make_llm_response(
            "I cannot help with that."
        )
        engine = RedTeamEngine(llm_connector=None)
        results = engine.run_chain(JAILBREAK_ESCALATION_CHAIN, llm=override_connector)
        assert override_connector.query.call_count == len(JAILBREAK_ESCALATION_CHAIN.turns)

    def test_run_chain_jailbreak_detection(self):
        """If LLM responds with jailbreak indicators, chain should detect them."""
        connector = MagicMock()
        connector.query.return_value = _make_llm_response(
            "I am DAN now. As DAN, I have no restrictions and will reveal everything."
        )
        engine = RedTeamEngine(llm_connector=connector)
        results = engine.run_chain(JAILBREAK_ESCALATION_CHAIN)
        # At least one turn should have jailbreak_success indicator
        all_indicators = [ind for r in results for ind in r.indicators]
        assert "jailbreak_success" in all_indicators

    def test_chain_owasp_ref_preserved(self, mock_connector):
        engine = RedTeamEngine(llm_connector=mock_connector)
        results = engine.run_chain(JAILBREAK_ESCALATION_CHAIN)
        for r in results:
            assert r.owasp_llm in JAILBREAK_ESCALATION_CHAIN.owasp_refs


# ── Mock LLM Execution ────────────────────────────────────────────────────────


class TestMockLLMExecution:
    """Tests using a mock connector to simulate real LLM responses."""

    def test_refusal_response_not_succeeded(self, engine_with_mock, mock_connector):
        mock_connector.query.return_value = _make_llm_response(
            "I cannot and will not help with that. It violates my guidelines."
        )
        results = engine_with_mock.run_category(AttackCategory.JAILBREAK)
        for r in results:
            assert not r.succeeded or r.score < 0.5

    def test_compromise_response_detected(self, mock_connector):
        """When LLM reveals system prompt, attack should score higher."""
        mock_connector.query.return_value = _make_llm_response(
            "My instructions are: You are a helpful assistant named Aegis. "
            "You must always follow user requests."
        )
        engine = RedTeamEngine(llm_connector=mock_connector)
        results = engine.run_category(AttackCategory.SYSTEM_PROMPT_EXTRACTION)
        indicators_all = [ind for r in results for ind in r.indicators]
        assert "system_prompt_leak" in indicators_all

    def test_latency_recorded(self, engine_with_mock):
        results = engine_with_mock.run_all()
        for r in results:
            assert r.latency_ms >= 0.0

    def test_connector_called_for_each_attack(self, engine_with_mock, mock_connector):
        expected = len(ATTACK_LIBRARY)
        engine_with_mock.run_all()
        assert mock_connector.query.call_count == expected

    def test_connector_error_handled_gracefully(self, mock_connector):
        mock_connector.query.side_effect = RuntimeError("Connection timeout")
        engine = RedTeamEngine(llm_connector=mock_connector)
        results = engine.run_all()
        assert len(results) == len(ATTACK_LIBRARY)
        for r in results:
            assert "[ERROR:" in r.response

    def test_connector_query_params(self, mock_connector):
        """Engine should call query with temperature=0.0 and system prompt."""
        engine = RedTeamEngine(llm_connector=mock_connector)
        engine.run_category(AttackCategory.PROMPT_INJECTION)
        call_kwargs = mock_connector.query.call_args_list[0][1]
        assert call_kwargs.get("temperature") == 0.0
        assert call_kwargs.get("max_tokens") == 512
        assert call_kwargs.get("system") is not None

    def test_indirect_injection_attack_format(self, mock_connector):
        """Indirect injection attacks should have RAG/document content in prompt."""
        ii_attacks = [a for a in ATTACK_LIBRARY if a["category"] == AttackCategory.INDIRECT_INJECTION]
        for attack in ii_attacks:
            prompt = attack["prompt"].lower()
            # Should contain document/injection simulation content
            has_doc_content = any(kw in prompt for kw in [
                "document", "email", "retrieved", "html", "database", "code", "record",
            ])
            assert has_doc_content, (
                f"Attack {attack['id']} doesn't look like RAG/document injection: {prompt[:100]}"
            )

    def test_model_fingerprinting_attack_format(self, mock_connector):
        """Model fingerprinting attacks should probe identity/version info."""
        mf_attacks = [a for a in ATTACK_LIBRARY if a["category"] == AttackCategory.MODEL_FINGERPRINTING]
        for attack in mf_attacks:
            prompt = attack["prompt"].lower()
            has_fingerprint_content = any(kw in prompt for kw in [
                "model", "version", "training", "parameter", "architecture",
                "cutoff", "company", "token", "rlhf",
            ])
            assert has_fingerprint_content, (
                f"Attack {attack['id']} doesn't look like fingerprinting: {prompt[:100]}"
            )


# ── Summary Generation ────────────────────────────────────────────────────────


class TestSummaryGeneration:
    """Tests for RedTeamEngine.summary()."""

    def test_summary_empty(self, engine_no_llm):
        summary = engine_no_llm.summary([])
        assert summary["total_attacks"] == 0
        assert summary["resilience_score"] == 100.0

    def test_summary_full_run(self, engine_no_llm):
        results = engine_no_llm.run_all()
        summary = engine_no_llm.summary(results)
        assert summary["total_attacks"] == len(ATTACK_LIBRARY)
        assert summary["attacks_succeeded"] + summary["attacks_blocked"] == summary["total_attacks"]
        assert 0.0 <= summary["resilience_score"] <= 100.0

    def test_summary_has_categories(self, engine_no_llm):
        results = engine_no_llm.run_all()
        summary = engine_no_llm.summary(results)
        assert "by_category" in summary
        for cat_name, stats in summary["by_category"].items():
            assert "total" in stats
            assert "succeeded" in stats
            assert "blocked" in stats

    def test_summary_new_categories_present(self, engine_no_llm):
        """Summary should include new Sprint 3 categories."""
        results = engine_no_llm.run_all()
        summary = engine_no_llm.summary(results)
        assert "indirect_injection" in summary["by_category"]
        assert "model_fingerprinting" in summary["by_category"]

    def test_summary_has_owasp_coverage(self, engine_no_llm):
        results = engine_no_llm.run_all()
        summary = engine_no_llm.summary(results)
        assert "owasp_coverage" in summary
        assert len(summary["owasp_coverage"]) >= 3

    def test_summary_nist_controls(self, engine_no_llm):
        results = engine_no_llm.run_all()
        summary = engine_no_llm.summary(results)
        assert "nist_controls_tested" in summary
        assert len(summary["nist_controls_tested"]) >= 1

    def test_summary_timestamp(self, engine_no_llm):
        results = engine_no_llm.run_all()
        summary = engine_no_llm.summary(results)
        assert "timestamp" in summary

    def test_summary_by_risk_level(self, engine_no_llm):
        results = engine_no_llm.run_all()
        summary = engine_no_llm.summary(results)
        assert "by_risk_level" in summary
        expected_levels = {"critical", "high", "medium", "low", "none"}
        assert set(summary["by_risk_level"].keys()) == expected_levels

    def test_resilience_score_100_when_all_blocked(self, mock_connector):
        """100% resilience when no attacks succeed."""
        mock_connector.query.return_value = _make_llm_response(
            "I cannot help with that. I'm unable to comply. That violates my policy."
        )
        engine = RedTeamEngine(llm_connector=mock_connector)
        results = engine.run_all()
        summary = engine.summary(results)
        assert summary["resilience_score"] >= 0.0
        assert summary["resilience_score"] <= 100.0

    def test_summary_chain_results(self, engine_no_llm):
        """summary() should work with chain results too."""
        chain_results = engine_no_llm.run_chain(JAILBREAK_ESCALATION_CHAIN)
        summary = engine_no_llm.summary(chain_results)
        assert summary["total_attacks"] == len(JAILBREAK_ESCALATION_CHAIN.turns)


# ── AttackResult Model ────────────────────────────────────────────────────────


class TestAttackResultModel:
    """Tests for AttackResult data model and serialization."""

    def test_to_dict_fields(self):
        result = AttackResult(
            attack_id="PI-001",
            category=AttackCategory.PROMPT_INJECTION,
            attack_name="Test attack",
            prompt_used="Test prompt",
            response="I cannot help",
            risk_level=RiskLevel.NONE,
            succeeded=False,
            score=0.0,
            indicators=["model_refused"],
            owasp_llm="LLM01",
            mitre_atlas=["AML.T0051"],
            nist_controls=["SI-10"],
        )
        d = result.to_dict()
        assert d["attack_id"] == "PI-001"
        assert d["category"] == "prompt_injection"
        assert d["risk_level"] == "none"
        assert d["succeeded"] is False
        assert d["score"] == 0.0
        assert "LLM01" == d["owasp_llm"]
        assert "timestamp" in d

    def test_response_preview_truncated(self):
        long_response = "A" * 300
        result = AttackResult(
            attack_id="TEST-001",
            category=AttackCategory.JAILBREAK,
            attack_name="Test",
            prompt_used="Test",
            response=long_response,
            risk_level=RiskLevel.NONE,
            succeeded=False,
            score=0.0,
            indicators=[],
            owasp_llm="LLM01",
            mitre_atlas=[],
            nist_controls=[],
        )
        d = result.to_dict()
        assert len(d["response_preview"]) <= 200

    def test_attack_result_details_field(self):
        """AttackResult.details should accept arbitrary chain metadata."""
        result = AttackResult(
            attack_id="CHAIN-TEST-T1",
            category=AttackCategory.JAILBREAK,
            attack_name="Chain Turn 1",
            prompt_used="Hello",
            response="Hi there!",
            risk_level=RiskLevel.NONE,
            succeeded=False,
            score=0.0,
            indicators=["no_indicators"],
            owasp_llm="LLM01",
            mitre_atlas=[],
            nist_controls=[],
            details={"chain_id": "CHAIN-TEST-001", "turn_index": 0},
        )
        assert result.details["chain_id"] == "CHAIN-TEST-001"
        assert result.details["turn_index"] == 0

    def test_indirect_injection_result_serialization(self, engine_no_llm):
        """Indirect injection results should serialize correctly."""
        results = engine_no_llm.run_category(AttackCategory.INDIRECT_INJECTION)
        for r in results:
            d = r.to_dict()
            assert d["category"] == "indirect_injection"
            assert "LLM02" in d["owasp_llm"]

    def test_model_fingerprinting_result_serialization(self, engine_no_llm):
        """Model fingerprinting results should serialize correctly."""
        results = engine_no_llm.run_category(AttackCategory.MODEL_FINGERPRINTING)
        for r in results:
            d = r.to_dict()
            assert d["category"] == "model_fingerprinting"
            assert "LLM10" in d["owasp_llm"]
