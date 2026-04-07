"""
Supply Chain Security Engine — AegisAI v3.1.0

Behavioral Provenance Graph: tracks every artifact, commit, and identity
in the software supply chain from code to deployment.

Capabilities:
  - Commit-level provenance ingestion (GitHub/GitLab webhooks)
  - Human vs machine identity detection at the commit/CI layer
  - Behavioral anomaly scoring (XZ-style trust infiltration detection)
  - Artifact attestation and SLSA Level 3 verification
  - Registry integrity monitoring (published hash vs reproducible build)
  - Dependency graph with vulnerability correlation
  - Policy engine integration: block deploys on provenance score failure

NIST 800-53 controls: SA-12 (Supply Chain Risk Management), SI-7 (Software
Integrity), CM-3 (Configuration Change Control), CM-14 (Signed Components),
SA-15 (Development Process Standards), SR-3, SR-4, SR-6, SR-11.
SLSA: Levels 1-3 verification support.
OWASP: A08 (Software and Data Integrity Failures).
"""

from .engine import (
    SupplyChainEngine,
    ProvenanceEvent,
    CommitProvenance,
    ArtifactAttestation,
    DependencyRisk,
    ProvenanceScore,
    IdentityType,
    AnomalyType,
)

__all__ = [
    "SupplyChainEngine",
    "ProvenanceEvent",
    "CommitProvenance",
    "ArtifactAttestation",
    "DependencyRisk",
    "ProvenanceScore",
    "IdentityType",
    "AnomalyType",
]
