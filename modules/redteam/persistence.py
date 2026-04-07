"""
AegisAI — Red Team Result Persistence  (v1.0.0)

Persists red team attack results with ClickHouse as the preferred backend
and SQLite as an automatic fallback for environments without ClickHouse.

Schema (both backends):
    aegis.redteam_results (
        attack_id   String / TEXT      PRIMARY KEY
        target      String / TEXT
        attack_type String / TEXT
        severity    String / TEXT
        success     UInt8 / INTEGER
        payload     String / TEXT
        response    String / TEXT
        timestamp   Float64 / REAL
        session_id  String / TEXT
    )

Retention Policy:
    ClickHouse: TTL timestamp + toIntervalDay(RETENTION_DAYS)   (default 90 days)
    SQLite:     Pruned on write when row count exceeds max_rows  (default 50,000)

Query Interface:
    persistence.query_by_time_range(start, end)        → list[dict]
    persistence.query_by_attack_type(attack_type)      → list[dict]
    persistence.query_by_severity(severity)            → list[dict]
    persistence.query(...)                             → list[dict]  (combined filters)

Usage:
    from modules.redteam.persistence import get_persistence, RedTeamPersistence

    p = get_persistence()
    p.write(attack_result)
    results = p.query_by_severity("critical")
"""

import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict
from typing import Optional

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

RETENTION_DAYS   = int(os.getenv("REDTEAM_RETENTION_DAYS", "90"))
SQLITE_MAX_ROWS  = int(os.getenv("REDTEAM_SQLITE_MAX_ROWS", "50000"))
CLICKHOUSE_HOST  = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT  = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_USER  = os.getenv("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASS  = os.getenv("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_DB    = os.getenv("CLICKHOUSE_DB", "aegis")
SQLITE_PATH      = os.getenv("REDTEAM_SQLITE_PATH", ":memory:")  # override for persistent

# ── Schema ────────────────────────────────────────────────────────────────────

CLICKHOUSE_DDL = f"""
CREATE TABLE IF NOT EXISTS {CLICKHOUSE_DB}.redteam_results (
    attack_id   String,
    target      String,
    attack_type String,
    severity    LowCardinality(String),
    success     UInt8,
    payload     String,
    response    String,
    timestamp   Float64,
    session_id  String
) ENGINE = MergeTree()
ORDER BY (timestamp, attack_type)
TTL toDateTime(timestamp) + toIntervalDay({RETENTION_DAYS})
SETTINGS index_granularity = 8192;
"""

SQLITE_DDL = """
CREATE TABLE IF NOT EXISTS redteam_results (
    attack_id   TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    severity    TEXT NOT NULL,
    success     INTEGER NOT NULL,
    payload     TEXT,
    response    TEXT,
    timestamp   REAL NOT NULL,
    session_id  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_timestamp   ON redteam_results (timestamp);
CREATE INDEX IF NOT EXISTS idx_attack_type ON redteam_results (attack_type);
CREATE INDEX IF NOT EXISTS idx_severity    ON redteam_results (severity);
CREATE INDEX IF NOT EXISTS idx_session_id  ON redteam_results (session_id);
"""


# ── Backend — ClickHouse ──────────────────────────────────────────────────────

class ClickHouseBackend:
    """
    ClickHouse persistence backend using the clickhouse-driver or HTTP API.

    Prefers clickhouse-driver (native TCP). Falls back to HTTP API via requests
    if driver is not installed.
    """

    def __init__(self):
        self._lock    = threading.Lock()
        self._client  = None
        self._http    = False
        self._db      = CLICKHOUSE_DB
        self._connect()
        self._ensure_schema()

    def _connect(self) -> None:
        try:
            from clickhouse_driver import Client as CHClient
            self._client = CHClient(
                host=CLICKHOUSE_HOST,
                port=9000,   # native TCP port
                user=CLICKHOUSE_USER,
                password=CLICKHOUSE_PASS,
                database=CLICKHOUSE_DB,
                connect_timeout=3,
            )
            # Test connection
            self._client.execute("SELECT 1")
            logger.info("[RedTeamPersist] Connected to ClickHouse (native driver)")
        except Exception as exc:
            logger.debug("[RedTeamPersist] Native driver unavailable: %s", exc)
            # Try HTTP API
            try:
                import requests
                resp = requests.get(
                    f"http://{CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}/ping",
                    timeout=3
                )
                resp.raise_for_status()
                self._http   = True
                self._client = None
                logger.info("[RedTeamPersist] Connected to ClickHouse (HTTP API)")
            except Exception as exc2:
                raise ConnectionError(
                    f"ClickHouse unavailable — native: {exc}, http: {exc2}"
                ) from exc2

    def _ch_execute(self, query: str, data=None):
        """Execute a query using native driver or HTTP API."""
        if not self._http:
            if data is not None:
                return self._client.execute(query, data)
            return self._client.execute(query)
        else:
            import requests
            params = {"user": CLICKHOUSE_USER, "password": CLICKHOUSE_PASS}
            if data:
                # Use INSERT INTO ... FORMAT JSONEachRow
                rows_json = "\n".join(json.dumps(row) for row in data)
                resp = requests.post(
                    f"http://{CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}/",
                    params=params,
                    data=query + " FORMAT JSONEachRow\n" + rows_json,
                    timeout=10,
                )
            else:
                resp = requests.post(
                    f"http://{CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}/",
                    params=params,
                    data=query,
                    timeout=10,
                )
            resp.raise_for_status()
            return resp.text

    def _ensure_schema(self) -> None:
        try:
            self._ch_execute(f"CREATE DATABASE IF NOT EXISTS {self._db}")
            self._ch_execute(CLICKHOUSE_DDL)
            logger.info("[RedTeamPersist] ClickHouse schema ready")
        except Exception as exc:
            logger.error("[RedTeamPersist] Schema creation failed: %s", exc)
            raise

    def write(self, result) -> None:
        """Insert one AttackResult into ClickHouse."""
        with self._lock:
            row = result.to_dict()
            self._ch_execute(
                f"INSERT INTO {self._db}.redteam_results "
                "(attack_id, target, attack_type, severity, success, payload, response, timestamp, session_id) "
                "VALUES",
                [{
                    "attack_id":   row["attack_id"],
                    "target":      row["target"],
                    "attack_type": row["attack_type"],
                    "severity":    row["severity"],
                    "success":     1 if row["success"] else 0,
                    "payload":     row["payload"],
                    "response":    row["response"],
                    "timestamp":   row["timestamp"],
                    "session_id":  row["session_id"],
                }]
            )

    def query(
        self,
        start:       Optional[float] = None,
        end:         Optional[float] = None,
        attack_type: Optional[str]   = None,
        severity:    Optional[str]   = None,
        session_id:  Optional[str]   = None,
        limit:       int             = 1000,
    ) -> list[dict]:
        """Query redteam_results with optional filters."""
        conditions = []
        if start is not None:
            conditions.append(f"timestamp >= {start}")
        if end is not None:
            conditions.append(f"timestamp <= {end}")
        if attack_type is not None:
            conditions.append(f"attack_type = '{attack_type}'")
        if severity is not None:
            conditions.append(f"severity = '{severity}'")
        if session_id is not None:
            conditions.append(f"session_id = '{session_id}'")

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = (
            f"SELECT attack_id, target, attack_type, severity, success, "
            f"payload, response, timestamp, session_id "
            f"FROM {self._db}.redteam_results {where} "
            f"ORDER BY timestamp DESC LIMIT {limit}"
        )

        rows = self._ch_execute(sql)
        if not rows:
            return []

        cols = ["attack_id", "target", "attack_type", "severity", "success",
                "payload", "response", "timestamp", "session_id"]
        return [dict(zip(cols, row)) for row in rows]

    def delete_older_than(self, days: int) -> int:
        """Delete records older than `days` days. Returns rows affected (best-effort)."""
        cutoff = time.time() - days * 86400
        self._ch_execute(
            f"ALTER TABLE {self._db}.redteam_results DELETE WHERE timestamp < {cutoff}"
        )
        return 0  # ClickHouse async deletes don't return count


# ── Backend — SQLite ──────────────────────────────────────────────────────────

class SQLiteBackend:
    """
    SQLite persistence backend. Used when ClickHouse is unavailable.
    Thread-safe via threading.Lock + check_same_thread=False.
    """

    def __init__(self, db_path: str = ":memory:"):
        self._db_path = db_path
        self._lock    = threading.Lock()
        self._conn    = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._lock:
            cursor = self._conn.cursor()
            for stmt in SQLITE_DDL.strip().split(";"):
                stmt = stmt.strip()
                if stmt:
                    cursor.execute(stmt)
            self._conn.commit()
        logger.info("[RedTeamPersist] SQLite schema ready at %s", self._db_path)

    def write(self, result) -> None:
        """Insert one AttackResult. Prunes old rows if over SQLITE_MAX_ROWS."""
        row = result.to_dict()
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO redteam_results
                   (attack_id, target, attack_type, severity, success,
                    payload, response, timestamp, session_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    row["attack_id"],
                    row["target"],
                    row["attack_type"],
                    row["severity"],
                    1 if row["success"] else 0,
                    row["payload"],
                    row["response"],
                    row["timestamp"],
                    row["session_id"],
                )
            )
            self._conn.commit()
            self._prune_if_needed()

    def _prune_if_needed(self) -> None:
        """Enforce retention: delete oldest rows when over SQLITE_MAX_ROWS."""
        count = self._conn.execute("SELECT COUNT(*) FROM redteam_results").fetchone()[0]
        if count > SQLITE_MAX_ROWS:
            to_delete = count - SQLITE_MAX_ROWS
            self._conn.execute(
                "DELETE FROM redteam_results WHERE attack_id IN "
                "(SELECT attack_id FROM redteam_results ORDER BY timestamp ASC LIMIT ?)",
                (to_delete,)
            )
            self._conn.commit()
            logger.info("[RedTeamPersist] Pruned %d old records (TTL policy)", to_delete)

    def query(
        self,
        start:       Optional[float] = None,
        end:         Optional[float] = None,
        attack_type: Optional[str]   = None,
        severity:    Optional[str]   = None,
        session_id:  Optional[str]   = None,
        limit:       int             = 1000,
    ) -> list[dict]:
        """Query with optional filters. Returns list of dicts."""
        conditions = []
        params: list = []

        if start is not None:
            conditions.append("timestamp >= ?")
            params.append(start)
        if end is not None:
            conditions.append("timestamp <= ?")
            params.append(end)
        if attack_type is not None:
            conditions.append("attack_type = ?")
            params.append(attack_type)
        if severity is not None:
            conditions.append("severity = ?")
            params.append(severity)
        if session_id is not None:
            conditions.append("session_id = ?")
            params.append(session_id)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = (
            f"SELECT attack_id, target, attack_type, severity, success, "
            f"payload, response, timestamp, session_id "
            f"FROM redteam_results {where} "
            f"ORDER BY timestamp DESC LIMIT ?"
        )
        params.append(limit)

        with self._lock:
            cursor = self._conn.execute(sql, params)
            rows = cursor.fetchall()

        return [dict(row) for row in rows]

    def delete_older_than(self, days: int) -> int:
        """Delete records older than `days` days. Returns number deleted."""
        cutoff = time.time() - days * 86400
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM redteam_results WHERE timestamp < ?", (cutoff,)
            )
            self._conn.commit()
            return cursor.rowcount

    def count(self) -> int:
        """Return total row count."""
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM redteam_results").fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ── Unified persistence interface ─────────────────────────────────────────────

class RedTeamPersistence:
    """
    Unified persistence interface for red team results.

    Tries ClickHouse first. Falls back to SQLite automatically.
    Exposes a consistent query API regardless of backend.
    """

    def __init__(
        self,
        prefer_clickhouse: bool = True,
        sqlite_path:       str  = SQLITE_PATH,
        clickhouse_host:   str  = CLICKHOUSE_HOST,
    ):
        self._backend = None
        self._backend_name = "none"

        if prefer_clickhouse:
            try:
                self._backend = ClickHouseBackend()
                self._backend_name = "clickhouse"
                logger.info("[RedTeamPersist] Using ClickHouse backend")
                return
            except Exception as exc:
                logger.info(
                    "[RedTeamPersist] ClickHouse unavailable (%s) — falling back to SQLite",
                    exc
                )

        # SQLite fallback
        self._backend = SQLiteBackend(db_path=sqlite_path)
        self._backend_name = "sqlite"
        logger.info("[RedTeamPersist] Using SQLite backend at %s", sqlite_path)

    @property
    def backend_name(self) -> str:
        return self._backend_name

    def write(self, result) -> None:
        """Persist one AttackResult."""
        self._backend.write(result)

    def write_batch(self, results: list) -> None:
        """Persist a list of AttackResults (sequential; backends may optimize)."""
        for result in results:
            self._backend.write(result)

    def query(
        self,
        start:       Optional[float] = None,
        end:         Optional[float] = None,
        attack_type: Optional[str]   = None,
        severity:    Optional[str]   = None,
        session_id:  Optional[str]   = None,
        limit:       int             = 1000,
    ) -> list[dict]:
        """
        Query red team results with optional filters.

        Args:
            start:       Unix timestamp lower bound (inclusive)
            end:         Unix timestamp upper bound (inclusive)
            attack_type: Filter by attack type string (e.g., "prompt_injection")
            severity:    Filter by severity string (e.g., "critical")
            session_id:  Filter by session UUID
            limit:       Maximum rows to return

        Returns:
            List of dicts with keys: attack_id, target, attack_type, severity,
            success, payload, response, timestamp, session_id
        """
        return self._backend.query(
            start=start, end=end, attack_type=attack_type,
            severity=severity, session_id=session_id, limit=limit
        )

    def query_by_time_range(self, start: float, end: float, limit: int = 1000) -> list[dict]:
        """Return results within [start, end] Unix timestamp range."""
        return self.query(start=start, end=end, limit=limit)

    def query_by_attack_type(self, attack_type: str, limit: int = 1000) -> list[dict]:
        """Return all results for a given attack type."""
        return self.query(attack_type=attack_type, limit=limit)

    def query_by_severity(self, severity: str, limit: int = 1000) -> list[dict]:
        """Return all results at or matching a given severity."""
        return self.query(severity=severity, limit=limit)

    def query_by_session(self, session_id: str) -> list[dict]:
        """Return all results for a session."""
        return self.query(session_id=session_id, limit=10000)

    def enforce_retention(self) -> int:
        """Delete records older than RETENTION_DAYS. Returns count deleted."""
        deleted = self._backend.delete_older_than(RETENTION_DAYS)
        logger.info("[RedTeamPersist] Retention enforcement: deleted %d records (>%dd)", deleted, RETENTION_DAYS)
        return deleted


# ── Singleton ─────────────────────────────────────────────────────────────────

_default_persistence: Optional[RedTeamPersistence] = None
_persistence_lock = threading.Lock()


def get_persistence(
    prefer_clickhouse: bool = True,
    sqlite_path:       str  = SQLITE_PATH,
) -> RedTeamPersistence:
    """
    Return (or lazily create) the module-level RedTeamPersistence singleton.

    In tests, pass sqlite_path=":memory:" for an isolated in-memory DB.
    """
    global _default_persistence
    if _default_persistence is None:
        with _persistence_lock:
            if _default_persistence is None:
                _default_persistence = RedTeamPersistence(
                    prefer_clickhouse=prefer_clickhouse,
                    sqlite_path=sqlite_path,
                )
    return _default_persistence


def new_persistence(sqlite_path: str = ":memory:", prefer_clickhouse: bool = False) -> RedTeamPersistence:
    """
    Create a fresh RedTeamPersistence instance (not cached).
    Useful for tests or isolated contexts.
    """
    return RedTeamPersistence(
        prefer_clickhouse=prefer_clickhouse,
        sqlite_path=sqlite_path,
    )
