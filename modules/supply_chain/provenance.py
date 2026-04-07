"""
Aegis — Supply Chain Provenance Graph  (v2.11.0)

Tracks the full commit-to-deploy lineage of software artifacts.
Each artifact is linked to:
  - The source commit (git SHA) that produced it
  - The build pipeline that built it (CI run ID, builder identity)
  - The deployment record (environment, timestamp, deployer)

Graph structure:
  ProvenanceNode → represents one artifact version
  ProvenanceGraph → DAG linking commits → builds → artifacts → deployments

SLSA (Supply chain Levels for Software Artifacts) alignment:
  - Level 1: Provenance exists (we generate it)
  - Level 2: Signed provenance (see attestation.py)
  - Level 3: Builder is hermetic + provenance tamper-proof (aspirational)

Storage:
  ProvenanceGraph persists to JSON (default) or can be backed by any
  key-value store by subclassing / dependency injection.
"""

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ProvenanceNode:
    """A single artifact version with full lineage metadata."""

    artifact_id:    str          # unique ID (e.g. image digest, package name+version)
    artifact_type:  str          # "container_image" | "python_package" | "binary" | etc.
    commit_sha:     str          # git commit SHA that produced this artifact
    repo_url:       str          # source repo URL
    branch:         str          # git branch
    build_id:       str          # CI pipeline run ID
    builder_id:     str          # builder identity (e.g. "github-actions/runner-id")
    build_timestamp: float       # epoch seconds when build completed
    digest:         str          # artifact content digest (sha256:...)
    dependencies:   List[str] = field(default_factory=list)   # upstream artifact_ids
    metadata:       Dict         = field(default_factory=dict) # arbitrary extra fields

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ProvenanceNode":
        return cls(**d)

    def short_id(self) -> str:
        return self.artifact_id[:16] if len(self.artifact_id) > 16 else self.artifact_id


@dataclass
class DeploymentRecord:
    """Records the deployment of an artifact to an environment."""

    artifact_id:    str
    environment:    str          # "production" | "staging" | "dev" | etc.
    deployer:       str          # identity of the entity that triggered deployment
    deploy_timestamp: float      # epoch seconds
    deploy_id:      str          # unique deployment ID / job ID
    config_sha:     str = ""     # SHA of deployment config (helm chart, k8s manifest, etc.)
    rollback_of:    str = ""     # artifact_id of the artifact being replaced
    metadata:       Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "DeploymentRecord":
        return cls(**d)


class ProvenanceGraph:
    """
    Directed acyclic graph tracking artifact provenance from commit to deploy.

    Graph topology:
      commit → ProvenanceNode (artifact) → [child ProvenanceNodes] → DeploymentRecord

    Persistence:
      Default JSON file at storage_path. Call save() / load() explicitly,
      or use the context manager:
        with ProvenanceGraph(path) as g:
            g.add_artifact(node)
    """

    def __init__(self, storage_path: str = ""):
        self._storage_path = storage_path
        self._nodes:       Dict[str, ProvenanceNode]   = {}   # artifact_id → node
        self._deployments: Dict[str, List[DeploymentRecord]] = {}  # artifact_id → deploys
        self._commit_index: Dict[str, List[str]] = {}   # commit_sha → [artifact_ids]

    # ── Artifact management ────────────────────────────────────────────────────

    def add_artifact(self, node: ProvenanceNode) -> None:
        """Register a new artifact version in the provenance graph."""
        if node.artifact_id in self._nodes:
            logger.warning("[Provenance] Overwriting existing node: %s", node.short_id())
        self._nodes[node.artifact_id] = node
        self._commit_index.setdefault(node.commit_sha, []).append(node.artifact_id)
        logger.info(
            "[Provenance] Artifact added: %s (commit=%s, build=%s)",
            node.short_id(), node.commit_sha[:8], node.build_id,
        )

    def get_artifact(self, artifact_id: str) -> Optional[ProvenanceNode]:
        """Return a ProvenanceNode by artifact_id, or None."""
        return self._nodes.get(artifact_id)

    def artifacts_for_commit(self, commit_sha: str) -> List[ProvenanceNode]:
        """Return all artifacts produced from a given commit SHA."""
        ids = self._commit_index.get(commit_sha, [])
        return [self._nodes[i] for i in ids if i in self._nodes]

    def lineage(self, artifact_id: str, depth: int = 0, max_depth: int = 20) -> List[ProvenanceNode]:
        """
        Recursively trace the full dependency lineage of an artifact.

        Returns a flattened list of all ancestor ProvenanceNodes in BFS order.
        """
        if depth > max_depth:
            return []
        node = self._nodes.get(artifact_id)
        if node is None:
            return []
        result = [node]
        for dep_id in node.dependencies:
            result.extend(self.lineage(dep_id, depth + 1, max_depth))
        return result

    def all_artifacts(self) -> List[ProvenanceNode]:
        """Return all registered artifacts."""
        return list(self._nodes.values())

    def artifact_count(self) -> int:
        return len(self._nodes)

    # ── Deployment management ──────────────────────────────────────────────────

    def record_deployment(self, record: DeploymentRecord) -> None:
        """Record a deployment event for an artifact."""
        if record.artifact_id not in self._nodes:
            logger.warning(
                "[Provenance] Deployment recorded for unknown artifact: %s",
                record.artifact_id,
            )
        self._deployments.setdefault(record.artifact_id, []).append(record)
        logger.info(
            "[Provenance] Deployment recorded: %s → %s (by %s)",
            record.artifact_id[:16], record.environment, record.deployer,
        )

    def deployments_for_artifact(self, artifact_id: str) -> List[DeploymentRecord]:
        """Return all deployment records for an artifact."""
        return self._deployments.get(artifact_id, [])

    def latest_deployment(self, artifact_id: str) -> Optional[DeploymentRecord]:
        """Return the most recent deployment record for an artifact."""
        records = self._deployments.get(artifact_id, [])
        if not records:
            return None
        return max(records, key=lambda r: r.deploy_timestamp)

    def deployments_to_environment(self, environment: str) -> List[DeploymentRecord]:
        """Return all deployments to a given environment, sorted by timestamp desc."""
        all_deploys = []
        for records in self._deployments.values():
            all_deploys.extend([r for r in records if r.environment == environment])
        return sorted(all_deploys, key=lambda r: r.deploy_timestamp, reverse=True)

    def deployment_count(self) -> int:
        return sum(len(v) for v in self._deployments.values())

    # ── Commit-to-deploy tracing ───────────────────────────────────────────────

    def trace_commit(self, commit_sha: str) -> dict:
        """
        Full trace: given a commit SHA, return all artifacts and deployments.

        Returns:
          {
            "commit_sha": str,
            "artifacts": [ProvenanceNode.to_dict(), ...],
            "deployments": {artifact_id: [DeploymentRecord.to_dict(), ...], ...}
          }
        """
        artifacts = self.artifacts_for_commit(commit_sha)
        deployments = {}
        for node in artifacts:
            deploys = self.deployments_for_artifact(node.artifact_id)
            if deploys:
                deployments[node.artifact_id] = [d.to_dict() for d in deploys]
        return {
            "commit_sha": commit_sha,
            "artifacts":  [n.to_dict() for n in artifacts],
            "deployments": deployments,
        }

    # ── Digest verification ────────────────────────────────────────────────────

    def verify_digest(self, artifact_id: str, expected_digest: str) -> bool:
        """Verify that a registered artifact's digest matches the expected value."""
        node = self._nodes.get(artifact_id)
        if node is None:
            logger.warning("[Provenance] Cannot verify digest: artifact not found: %s", artifact_id)
            return False
        match = node.digest == expected_digest
        if not match:
            logger.warning(
                "[Provenance] Digest mismatch for %s: expected=%s got=%s",
                artifact_id, expected_digest, node.digest,
            )
        return match

    # ── Serialization ──────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "nodes": {k: v.to_dict() for k, v in self._nodes.items()},
            "deployments": {
                k: [r.to_dict() for r in v]
                for k, v in self._deployments.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict, storage_path: str = "") -> "ProvenanceGraph":
        g = cls(storage_path=storage_path)
        for node_dict in data.get("nodes", {}).values():
            node = ProvenanceNode.from_dict(node_dict)
            g._nodes[node.artifact_id] = node
            g._commit_index.setdefault(node.commit_sha, []).append(node.artifact_id)
        for artifact_id, records in data.get("deployments", {}).items():
            g._deployments[artifact_id] = [DeploymentRecord.from_dict(r) for r in records]
        return g

    def save(self) -> None:
        """Persist the graph to JSON storage_path."""
        if not self._storage_path:
            raise ValueError("ProvenanceGraph: storage_path not set — cannot save")
        path = Path(self._storage_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info("[Provenance] Graph saved to %s (%d nodes, %d deployments)",
                    path, len(self._nodes), self.deployment_count())

    def load(self) -> None:
        """Load graph from JSON storage_path. Merges into existing state."""
        if not self._storage_path:
            raise ValueError("ProvenanceGraph: storage_path not set — cannot load")
        path = Path(self._storage_path)
        if not path.exists():
            logger.debug("[Provenance] No existing graph at %s", path)
            return
        with open(path) as f:
            data = json.load(f)
        loaded = ProvenanceGraph.from_dict(data)
        self._nodes.update(loaded._nodes)
        for k, v in loaded._deployments.items():
            self._deployments.setdefault(k, []).extend(v)
        for k, v in loaded._commit_index.items():
            self._commit_index.setdefault(k, []).extend(v)
        logger.info("[Provenance] Graph loaded from %s (%d nodes, %d deployments)",
                    path, len(self._nodes), self.deployment_count())

    # ── Context manager ────────────────────────────────────────────────────────

    def __enter__(self) -> "ProvenanceGraph":
        if self._storage_path:
            self.load()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._storage_path and exc_type is None:
            self.save()

    # ── Utility ────────────────────────────────────────────────────────────────

    @staticmethod
    def compute_digest(data: bytes) -> str:
        """Compute SHA-256 digest for arbitrary bytes. Returns 'sha256:<hex>'."""
        return "sha256:" + hashlib.sha256(data).hexdigest()
