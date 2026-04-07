"""
Identity Engine — AegisAI v3.1.0 / TokenDNA Integration Layer

Machine identity governance, behavioral DNA fingerprinting, and
Zero Trust Identity Exchange (ZTIX) for human and non-human identities.

This module is the AegisAI integration layer for TokenDNA capabilities:
  - Machine vs Human identity classification at the protocol layer
  - Behavioral DNA baseline capture and anomaly detection
  - Zero Trust Identity Exchange: machine identities never exposed to targets
  - AI Agent identity chaining: cryptographically linked delegation graph
  - Non-Human Identity (NHI) lifecycle management
  - Automatic token revocation on behavioral anomaly

Key insight: enterprise ratio is now 40:1 to 144:1 machine-to-human identities.
Traditional IAM was built for humans. This module fills the gap.

NIST 800-53: IA-2, IA-3, IA-4, IA-5, IA-8, AC-2, AC-6, AC-17, SC-8.
NIST AI RMF: GOVERN 1.1, MAP 1.5, MEASURE 2.5.
Zero Trust: NIST SP 800-207 (Device Identity, Enhanced Identity Governance).
"""

from .machine_identity import (
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

__all__ = [
    "IdentityEngine",
    "MachineIdentity",
    "HumanIdentity",
    "IdentityClass",
    "BehavioralDNA",
    "ZTIXToken",
    "DelegationLink",
    "AgentIdentityChain",
    "IdentityAnomaly",
    "NHIRiskTier",
    "get_engine",
]
