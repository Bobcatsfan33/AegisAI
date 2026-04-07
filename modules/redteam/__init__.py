"""
AegisAI — Red Team Module

Provides adversarial red team testing capabilities with persistent result
storage and query interface.
"""

from .engine import RedTeamEngine, RedTeamSession, AttackResult, AttackType, Severity
from .persistence import RedTeamPersistence, get_persistence

__all__ = [
    "RedTeamEngine",
    "RedTeamSession",
    "AttackResult",
    "AttackType",
    "Severity",
    "RedTeamPersistence",
    "get_persistence",
]
