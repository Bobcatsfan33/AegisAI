"""
Aegis — Software Supply Chain Security  (v2.11.0)

Three pillars:
  1. Provenance    — commit-to-deploy graph linking artifacts to source commits
  2. Attestation   — cryptographic signing + verification of pipeline artifacts
  3. Behavioral    — anomaly detection in supply chain event streams

Usage:
    from modules.supply_chain import ProvenanceGraph, ArtifactAttestation, BehavioralScorer
"""

from .provenance import ProvenanceGraph, ProvenanceNode, DeploymentRecord
from .attestation import ArtifactAttestation, AttestationRecord, AttestationError
from .behavioral import BehavioralScorer, SupplyChainEvent, AnomalyResult

__all__ = [
    "ProvenanceGraph",
    "ProvenanceNode",
    "DeploymentRecord",
    "ArtifactAttestation",
    "AttestationRecord",
    "AttestationError",
    "BehavioralScorer",
    "SupplyChainEvent",
    "AnomalyResult",
]
