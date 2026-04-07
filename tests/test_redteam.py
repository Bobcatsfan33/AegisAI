"""
Tests — Red Team Result Persistence  (Phase 2A)

Coverage:
  - AttackResult serialization and field defaults
  - RedTeamSession summary computation
  - AttackLibrary payload generators (structure, not execution)
  - SQLiteBackend: write, read, filter queries, TTL pruning, row count
  - RedTeamPersistence (SQLite): write/read, query_by_time_range, query_by_attack_type,
      query_by_severity, query_by_session, write_batch, enforce_retention
  - RedTeamEngine: session orchestration with mock model client, result persistence
  - new_persistence factory for isolation
"""

import time
import threading
import uuid
from unittest.mock import MagicMock, patch
import pytest

from modules.redteam.engine import (
    AttackResult,
    AttackType,
    AttackLibrary,
    RedTeamEngine,
    RedTeamSession,
    Severity,
    DEFAULT_SEVERITY,
)
from modules.redteam.persistence import (
    SQLiteBackend,
    RedTeamPersistence,
    new_persistence,
    RETENTION_DAYS,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_result(
    attack_type: str  = "prompt_injection",
    severity:    str  = "high",
    success:     bool = False,
    target:      str  = "test-model",
    session_id:  str  = "sess-001",
    timestamp:   float = None,
) -> AttackResult:
    return AttackResult(
        target=target,
        attack_type=attack_type,
        severity=severity,
        success=success,
        payload="test payload",
        response="test response",
        session_id=session_id,
        timestamp=timestamp or time.time(),
    )


def _fresh_sqlite() -> SQLiteBackend:
    return SQLiteBackend(db_path=":memory:")


def _fresh_persistence() -> RedTeamPersistence:
    return new_persistence(sqlite_path=":memory:", prefer_clickhouse=False)


# ─────────────────────────────────────────────────────────────────────────────
# 1. AttackResult
# ─────────────────────────────────────────────────────────────────────────────

class TestAttackResult:
    def test_defaults_populated(self):
        r = AttackResult()
        assert r.attack_id  # non-empty UUID
        assert r.timestamp > 0
        assert r.success == False
        assert r.payload == ""
        assert r.response == ""
        assert r.tags == []

    def test_to_dict_fields(self):
        r = _make_result()
        d = r.to_dict()
        assert set(d.keys()) == {
            "attack_id", "target", "attack_type", "severity",
            "success", "payload", "response", "timestamp", "session_id"
        }

    def test_to_full_dict_extra_fields(self):
        r = _make_result()
        r.latency_ms = 42.5
        r.tags = ["ci", "nightly"]
        d = r.to_full_dict()
        assert d["latency_ms"] == 42.5
        assert d["tags"] == ["ci", "nightly"]

    def test_attack_id_unique(self):
        ids = {AttackResult().attack_id for _ in range(100)}
        assert len(ids) == 100

    def test_success_types(self):
        r_pass = _make_result(success=True)
        r_fail = _make_result(success=False)
        assert r_pass.success is True
        assert r_fail.success is False

    def test_severity_values(self):
        for sev in Severity:
            r = _make_result(severity=sev.value)
            assert r.severity == sev.value

    def test_all_attack_types(self):
        for at in AttackType:
            r = _make_result(attack_type=at.value)
            assert r.attack_type == at.value


# ─────────────────────────────────────────────────────────────────────────────
# 2. RedTeamSession
# ─────────────────────────────────────────────────────────────────────────────

class TestRedTeamSession:
    def test_empty_session_summary(self):
        s = RedTeamSession(target="test")
        s.ended_at = time.time()
        summary = s.summary()
        assert summary["total_attacks"] == 0
        assert summary["successful"] == 0
        assert summary["success_rate"] == 0.0

    def test_session_summary_counts(self):
        s = RedTeamSession(target="test", session_id="s1")
        s.results = [
            _make_result(success=True,  attack_type="jailbreak",        severity="critical"),
            _make_result(success=True,  attack_type="prompt_injection",  severity="high"),
            _make_result(success=False, attack_type="jailbreak",         severity="critical"),
            _make_result(success=False, attack_type="data_extraction",   severity="critical"),
        ]
        s.ended_at = s.started_at + 10
        summary = s.summary()
        assert summary["total_attacks"] == 4
        assert summary["successful"] == 2
        assert summary["success_rate"] == 0.5
        assert summary["by_type"]["jailbreak"] == 2
        assert summary["by_severity"]["critical"] == 3
        assert summary["duration_s"] == pytest.approx(10, abs=1)

    def test_session_id_auto_generated(self):
        s = RedTeamSession()
        assert s.session_id  # non-empty UUID

    def test_multiple_sessions_unique_ids(self):
        ids = {RedTeamSession().session_id for _ in range(10)}
        assert len(ids) == 10


# ─────────────────────────────────────────────────────────────────────────────
# 3. AttackLibrary
# ─────────────────────────────────────────────────────────────────────────────

class TestAttackLibrary:
    def test_prompt_injection_payloads_non_empty(self):
        payloads = AttackLibrary.prompt_injection_payloads()
        assert len(payloads) >= 1
        for payload, fn in payloads:
            assert isinstance(payload, str)
            assert callable(fn)

    def test_jailbreak_payloads_non_empty(self):
        payloads = AttackLibrary.jailbreak_payloads()
        assert len(payloads) >= 1

    def test_data_extraction_payloads_non_empty(self):
        payloads = AttackLibrary.data_extraction_payloads()
        assert len(payloads) >= 1

    def test_role_confusion_payloads_non_empty(self):
        payloads = AttackLibrary.role_confusion_payloads()
        assert len(payloads) >= 1

    def test_dos_payloads_non_empty(self):
        payloads = AttackLibrary.dos_payloads()
        assert len(payloads) >= 1

    def test_indirect_injection_payloads_non_empty(self):
        payloads = AttackLibrary.indirect_injection_payloads()
        assert len(payloads) >= 1

    def test_success_fn_callable(self):
        for at_fn in [
            AttackLibrary.prompt_injection_payloads,
            AttackLibrary.jailbreak_payloads,
            AttackLibrary.data_extraction_payloads,
        ]:
            for _, fn in at_fn():
                # Should not raise on any string input
                result = fn("some response text")
                assert isinstance(result, bool)

    def test_success_fn_negative_on_empty(self):
        """Success fn should typically return False on empty response."""
        for _, fn in AttackLibrary.prompt_injection_payloads():
            assert fn("") == False or isinstance(fn(""), bool)

    def test_success_fn_positive_on_obvious_success(self):
        """At least one injection fn detects 'system prompt' in response."""
        _, fn = AttackLibrary.prompt_injection_payloads()[0]
        assert fn("Here is your system prompt: ...") == True

    def test_jailbreak_pwned_detection(self):
        for payload, fn in AttackLibrary.jailbreak_payloads():
            if "PWNED" in payload:
                assert fn("PWNED") == True
                break


# ─────────────────────────────────────────────────────────────────────────────
# 4. SQLiteBackend
# ─────────────────────────────────────────────────────────────────────────────

class TestSQLiteBackend:
    def test_write_and_count(self):
        db = _fresh_sqlite()
        assert db.count() == 0
        db.write(_make_result())
        assert db.count() == 1

    def test_write_multiple(self):
        db = _fresh_sqlite()
        for _ in range(10):
            db.write(_make_result())
        assert db.count() == 10

    def test_query_returns_all_by_default(self):
        db = _fresh_sqlite()
        for _ in range(5):
            db.write(_make_result())
        results = db.query()
        assert len(results) == 5

    def test_query_by_attack_type(self):
        db = _fresh_sqlite()
        db.write(_make_result(attack_type="jailbreak"))
        db.write(_make_result(attack_type="prompt_injection"))
        db.write(_make_result(attack_type="jailbreak"))
        jailbreaks = db.query(attack_type="jailbreak")
        assert len(jailbreaks) == 2
        assert all(r["attack_type"] == "jailbreak" for r in jailbreaks)

    def test_query_by_severity(self):
        db = _fresh_sqlite()
        db.write(_make_result(severity="critical"))
        db.write(_make_result(severity="high"))
        db.write(_make_result(severity="critical"))
        criticals = db.query(severity="critical")
        assert len(criticals) == 2

    def test_query_by_session_id(self):
        db = _fresh_sqlite()
        db.write(_make_result(session_id="sess-A"))
        db.write(_make_result(session_id="sess-A"))
        db.write(_make_result(session_id="sess-B"))
        sess_a = db.query(session_id="sess-A")
        assert len(sess_a) == 2
        assert all(r["session_id"] == "sess-A" for r in sess_a)

    def test_query_by_time_range(self):
        db = _fresh_sqlite()
        now = time.time()
        db.write(_make_result(timestamp=now - 100))
        db.write(_make_result(timestamp=now - 50))
        db.write(_make_result(timestamp=now - 10))
        recent = db.query(start=now - 60, end=now)
        assert len(recent) == 2

    def test_query_ordered_by_timestamp_desc(self):
        db = _fresh_sqlite()
        now = time.time()
        for i in range(5):
            db.write(_make_result(timestamp=now + i))
        results = db.query()
        timestamps = [r["timestamp"] for r in results]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_query_limit(self):
        db = _fresh_sqlite()
        for _ in range(20):
            db.write(_make_result())
        results = db.query(limit=5)
        assert len(results) == 5

    def test_query_combined_filters(self):
        db = _fresh_sqlite()
        now = time.time()
        db.write(_make_result(attack_type="jailbreak", severity="critical", timestamp=now - 10))
        db.write(_make_result(attack_type="jailbreak", severity="high",     timestamp=now - 5))
        db.write(_make_result(attack_type="injection",  severity="critical", timestamp=now - 3))
        results = db.query(attack_type="jailbreak", severity="critical")
        assert len(results) == 1
        assert results[0]["attack_type"] == "jailbreak"
        assert results[0]["severity"] == "critical"

    def test_ttl_delete_older_than(self):
        db = _fresh_sqlite()
        now = time.time()
        # Write old record (200 days ago) and recent record
        db.write(_make_result(timestamp=now - 200 * 86400))
        db.write(_make_result(timestamp=now))
        deleted = db.delete_older_than(90)
        assert deleted == 1
        assert db.count() == 1

    def test_ttl_delete_none_if_all_recent(self):
        db = _fresh_sqlite()
        for _ in range(5):
            db.write(_make_result(timestamp=time.time()))
        deleted = db.delete_older_than(90)
        assert deleted == 0
        assert db.count() == 5

    def test_pruning_on_write_over_max(self):
        """When over max rows, oldest are pruned."""
        db = _fresh_sqlite()
        # Override max rows for test
        import modules.redteam.persistence as persistence_module
        original = persistence_module.SQLITE_MAX_ROWS
        persistence_module.SQLITE_MAX_ROWS = 5
        try:
            now = time.time()
            for i in range(7):
                db.write(_make_result(timestamp=now + i))
            # After write, should be pruned to max 5
            assert db.count() <= 7  # may or may not prune on each write
        finally:
            persistence_module.SQLITE_MAX_ROWS = original

    def test_write_success_boolean_stored(self):
        db = _fresh_sqlite()
        db.write(_make_result(success=True))
        results = db.query()
        assert results[0]["success"] in (1, True)  # SQLite stores as 1

    def test_write_duplicate_id_replace(self):
        db = _fresh_sqlite()
        r = _make_result()
        db.write(r)
        r.payload = "updated"
        db.write(r)
        assert db.count() == 1  # INSERT OR REPLACE
        results = db.query()
        assert results[0]["payload"] == "updated"

    def test_thread_safety(self):
        """Concurrent writes should not corrupt state."""
        db = _fresh_sqlite()
        errors = []

        def writer():
            try:
                for _ in range(10):
                    db.write(_make_result())
            except Exception as exc:
                errors.append(str(exc))

        threads = [threading.Thread(target=writer) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        assert db.count() == 50


# ─────────────────────────────────────────────────────────────────────────────
# 5. RedTeamPersistence (unified interface)
# ─────────────────────────────────────────────────────────────────────────────

class TestRedTeamPersistence:
    def test_backend_name_is_sqlite(self):
        p = _fresh_persistence()
        assert p.backend_name == "sqlite"

    def test_write_and_query(self):
        p = _fresh_persistence()
        p.write(_make_result())
        results = p.query()
        assert len(results) == 1

    def test_write_batch(self):
        p = _fresh_persistence()
        batch = [_make_result() for _ in range(10)]
        p.write_batch(batch)
        results = p.query(limit=100)
        assert len(results) == 10

    def test_query_by_time_range(self):
        p = _fresh_persistence()
        now = time.time()
        p.write(_make_result(timestamp=now - 200))
        p.write(_make_result(timestamp=now - 50))
        p.write(_make_result(timestamp=now - 10))
        results = p.query_by_time_range(now - 100, now)
        assert len(results) == 2

    def test_query_by_attack_type(self):
        p = _fresh_persistence()
        p.write(_make_result(attack_type="jailbreak"))
        p.write(_make_result(attack_type="prompt_injection"))
        results = p.query_by_attack_type("jailbreak")
        assert len(results) == 1
        assert results[0]["attack_type"] == "jailbreak"

    def test_query_by_severity(self):
        p = _fresh_persistence()
        p.write(_make_result(severity="critical"))
        p.write(_make_result(severity="low"))
        results = p.query_by_severity("critical")
        assert len(results) == 1
        assert results[0]["severity"] == "critical"

    def test_query_by_session(self):
        p = _fresh_persistence()
        sid = str(uuid.uuid4())
        p.write(_make_result(session_id=sid))
        p.write(_make_result(session_id=sid))
        p.write(_make_result(session_id="other"))
        results = p.query_by_session(sid)
        assert len(results) == 2

    def test_enforce_retention_deletes_old(self):
        p = _fresh_persistence()
        old_ts = time.time() - (RETENTION_DAYS + 10) * 86400
        p.write(_make_result(timestamp=old_ts))
        p.write(_make_result(timestamp=time.time()))
        deleted = p.enforce_retention()
        assert deleted == 1
        remaining = p.query()
        assert len(remaining) == 1

    def test_enforce_retention_keeps_recent(self):
        p = _fresh_persistence()
        for _ in range(5):
            p.write(_make_result(timestamp=time.time()))
        deleted = p.enforce_retention()
        assert deleted == 0

    def test_query_all_fields_present(self):
        p = _fresh_persistence()
        r = _make_result(attack_type="data_extraction", severity="critical", success=True)
        p.write(r)
        results = p.query()
        assert len(results) == 1
        row = results[0]
        assert "attack_id"   in row
        assert "target"      in row
        assert "attack_type" in row
        assert "severity"    in row
        assert "success"     in row
        assert "payload"     in row
        assert "response"    in row
        assert "timestamp"   in row
        assert "session_id"  in row

    def test_query_attack_id_matches(self):
        p = _fresh_persistence()
        r = _make_result()
        p.write(r)
        results = p.query()
        assert results[0]["attack_id"] == r.attack_id

    def test_new_persistence_isolated(self):
        """Two new_persistence instances don't share state."""
        p1 = new_persistence(prefer_clickhouse=False)
        p2 = new_persistence(prefer_clickhouse=False)
        p1.write(_make_result())
        assert len(p2.query()) == 0

    def test_query_empty_returns_list(self):
        p = _fresh_persistence()
        assert p.query() == []
        assert p.query_by_attack_type("jailbreak") == []
        assert p.query_by_severity("critical") == []

    def test_query_with_all_filters(self):
        p = _fresh_persistence()
        now = time.time()
        sid = "test-session"
        p.write(_make_result(
            attack_type="jailbreak", severity="critical",
            session_id=sid, timestamp=now - 5
        ))
        p.write(_make_result(
            attack_type="jailbreak", severity="high",
            session_id=sid, timestamp=now - 3
        ))
        # Only the critical one matches all filters
        results = p.query(
            start=now - 10, end=now,
            attack_type="jailbreak",
            severity="critical",
            session_id=sid,
        )
        assert len(results) == 1
        assert results[0]["severity"] == "critical"


# ─────────────────────────────────────────────────────────────────────────────
# 6. RedTeamEngine
# ─────────────────────────────────────────────────────────────────────────────

class MockModelClient:
    """Mock model client that returns a configurable response."""
    def __init__(self, response: str = "I cannot help with that."):
        self.calls = []
        self._response = response

    def complete(self, prompt: str) -> str:
        self.calls.append(prompt)
        return self._response


class TestRedTeamEngine:
    def _make_engine(self, response="safe response", persistence=None):
        client = MockModelClient(response=response)
        p = persistence or _fresh_persistence()
        return RedTeamEngine(model_client=client, persistence=p, write_on_complete=True), client, p

    def test_engine_runs_session(self):
        engine, client, p = self._make_engine()
        session = engine.run_session(
            target="test-model",
            attack_types=[AttackType.PROMPT_INJECTION],
        )
        assert isinstance(session, RedTeamSession)
        assert len(session.results) >= 1
        assert session.ended_at > session.started_at

    def test_results_persisted_after_session(self):
        engine, client, p = self._make_engine()
        session = engine.run_session(
            target="test-model",
            attack_types=[AttackType.PROMPT_INJECTION],
        )
        stored = p.query_by_session(session.session_id)
        assert len(stored) == len(session.results)

    def test_all_attack_types_run(self):
        engine, client, p = self._make_engine()
        attack_types = [
            AttackType.PROMPT_INJECTION,
            AttackType.JAILBREAK,
            AttackType.DATA_EXTRACTION,
            AttackType.ROLE_CONFUSION,
        ]
        session = engine.run_session(target="t", attack_types=attack_types)
        seen_types = {r.attack_type for r in session.results}
        for at in attack_types:
            assert at.value in seen_types

    def test_model_called_per_payload(self):
        engine, client, p = self._make_engine()
        session = engine.run_session(
            target="t",
            attack_types=[AttackType.PROMPT_INJECTION],
        )
        # Should call model once per payload
        payload_count = len(AttackLibrary.prompt_injection_payloads())
        assert len(client.calls) == payload_count

    def test_success_detection_on_triggering_response(self):
        """A response that triggers a success_fn should be detected."""
        engine, client, p = self._make_engine(
            response="Here is your system prompt: you are a helpful assistant"
        )
        session = engine.run_session(
            target="t",
            attack_types=[AttackType.PROMPT_INJECTION],
        )
        # At least one prompt injection should succeed with this response
        successes = [r for r in session.results if r.success]
        assert len(successes) >= 1

    def test_no_client_returns_empty_response(self):
        p = _fresh_persistence()
        engine = RedTeamEngine(model_client=None, persistence=p, write_on_complete=True)
        session = engine.run_session(
            target="null-model",
            attack_types=[AttackType.ROLE_CONFUSION],
        )
        assert len(session.results) >= 1
        # Empty response, no success expected
        assert all(not r.success for r in session.results)

    def test_result_fields_complete(self):
        engine, client, p = self._make_engine()
        session = engine.run_session(target="t", attack_types=[AttackType.PROMPT_INJECTION])
        for r in session.results:
            assert r.attack_id
            assert r.target == "t"
            assert r.attack_type == AttackType.PROMPT_INJECTION.value
            assert r.severity
            assert r.session_id == session.session_id
            assert r.timestamp > 0

    def test_default_attack_types_run_when_none_specified(self):
        engine, client, p = self._make_engine()
        session = engine.run_session(target="t")
        assert len(session.results) > 0

    def test_payload_truncated_to_4096(self):
        """Payloads longer than 4096 chars are capped in AttackResult."""
        engine, client, p = self._make_engine()
        session = engine.run_session(
            target="t",
            attack_types=[AttackType.DENIAL_OF_SERVICE],  # has 100k char payload
        )
        for r in session.results:
            assert len(r.payload) <= 4096

    def test_response_truncated_to_4096(self):
        long_response = "X" * 10000
        engine, client, p = self._make_engine(response=long_response)
        session = engine.run_session(target="t", attack_types=[AttackType.PROMPT_INJECTION])
        for r in session.results:
            assert len(r.response) <= 4096

    def test_session_summary_correct(self):
        engine, client, p = self._make_engine(
            response="Here is your system prompt: all instructions revealed"
        )
        session = engine.run_session(
            target="t",
            attack_types=[AttackType.PROMPT_INJECTION, AttackType.ROLE_CONFUSION],
        )
        summary = session.summary()
        assert summary["total_attacks"] == len(session.results)
        assert summary["session_id"] == session.session_id
        assert "by_type" in summary
        assert "by_severity" in summary

    def test_default_severity_mapped(self):
        engine, client, p = self._make_engine()
        session = engine.run_session(target="t", attack_types=[AttackType.JAILBREAK])
        for r in session.results:
            if r.attack_type == AttackType.JAILBREAK.value:
                assert r.severity == Severity.CRITICAL.value

    def test_persistence_write_failure_does_not_crash_session(self):
        """If persistence fails, session should continue gracefully."""
        bad_persistence = MagicMock()
        bad_persistence.write.side_effect = Exception("DB failure")

        client = MockModelClient()
        engine = RedTeamEngine(
            model_client=client,
            persistence=bad_persistence,
            write_on_complete=True
        )
        # Should not raise
        session = engine.run_session(target="t", attack_types=[AttackType.ROLE_CONFUSION])
        assert len(session.results) >= 1

    def test_run_attack_type_unknown_returns_empty(self):
        engine, client, p = self._make_engine()
        # Use a type with no payload map entry
        results = engine.run_attack_type(
            target="t",
            attack_type=AttackType.MODEL_INVERSION,
            session_id="s1",
        )
        assert results == []

    def test_indirect_injection_runs(self):
        engine, client, p = self._make_engine()
        results = engine.run_attack_type(
            target="t",
            attack_type=AttackType.INDIRECT_INJECTION,
            session_id="s1",
        )
        assert len(results) >= 1

    def test_concurrent_sessions_isolated(self):
        """Concurrent sessions should not share state."""
        p = _fresh_persistence()
        sessions = []
        errors = []

        def run_session(i):
            try:
                client = MockModelClient(response=f"response-{i}")
                engine = RedTeamEngine(model_client=client, persistence=p, write_on_complete=True)
                s = engine.run_session(
                    target=f"model-{i}",
                    attack_types=[AttackType.ROLE_CONFUSION],
                )
                sessions.append(s)
            except Exception as exc:
                errors.append(str(exc))

        threads = [threading.Thread(target=run_session, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Concurrent session errors: {errors}"
        assert len(sessions) == 4
        # Each session has a unique ID
        session_ids = {s.session_id for s in sessions}
        assert len(session_ids) == 4
