"""
Tests for modules/supply_chain/provenance.py

Covers: ProvenanceNode, DeploymentRecord, ProvenanceGraph
"""

import json
import os
import tempfile
import time
import pytest

from modules.supply_chain.provenance import (
    ProvenanceGraph,
    ProvenanceNode,
    DeploymentRecord,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_node(
    artifact_id: str = "img:aegis:1.0.0",
    commit_sha: str = "abc123def456",
    branch: str = "main",
    build_id: str = "run-001",
    builder_id: str = "github-actions",
    digest: str = "sha256:aabbcc",
    artifact_type: str = "container_image",
    dependencies: list = None,
) -> ProvenanceNode:
    return ProvenanceNode(
        artifact_id=artifact_id,
        artifact_type=artifact_type,
        commit_sha=commit_sha,
        repo_url="https://github.com/org/aegis",
        branch=branch,
        build_id=build_id,
        builder_id=builder_id,
        build_timestamp=time.time(),
        digest=digest,
        dependencies=dependencies or [],
    )


def _make_deploy(
    artifact_id: str = "img:aegis:1.0.0",
    environment: str = "production",
    deployer: str = "ci-bot",
    deploy_id: str = "deploy-001",
) -> DeploymentRecord:
    return DeploymentRecord(
        artifact_id=artifact_id,
        environment=environment,
        deployer=deployer,
        deploy_timestamp=time.time(),
        deploy_id=deploy_id,
    )


# ── ProvenanceNode tests ───────────────────────────────────────────────────────

class TestProvenanceNode:
    def test_to_dict_round_trip(self):
        node = _make_node()
        d = node.to_dict()
        assert d["artifact_id"] == "img:aegis:1.0.0"
        assert d["commit_sha"] == "abc123def456"
        restored = ProvenanceNode.from_dict(d)
        assert restored.artifact_id == node.artifact_id
        assert restored.digest == node.digest

    def test_short_id_truncates_long_ids(self):
        node = _make_node(artifact_id="a" * 32)
        assert len(node.short_id()) == 16

    def test_short_id_keeps_short_ids(self):
        node = _make_node(artifact_id="abc")
        assert node.short_id() == "abc"

    def test_dependencies_default_empty(self):
        node = _make_node()
        assert node.dependencies == []

    def test_dependencies_stored(self):
        node = _make_node(dependencies=["base:1.0", "lib:2.0"])
        assert "base:1.0" in node.dependencies


# ── DeploymentRecord tests ─────────────────────────────────────────────────────

class TestDeploymentRecord:
    def test_to_dict_round_trip(self):
        record = _make_deploy()
        d = record.to_dict()
        assert d["artifact_id"] == "img:aegis:1.0.0"
        assert d["environment"] == "production"
        restored = DeploymentRecord.from_dict(d)
        assert restored.deploy_id == record.deploy_id


# ── ProvenanceGraph core tests ─────────────────────────────────────────────────

class TestProvenanceGraphBasics:
    def test_add_and_get_artifact(self):
        g = ProvenanceGraph()
        node = _make_node()
        g.add_artifact(node)
        assert g.get_artifact("img:aegis:1.0.0") is node

    def test_get_nonexistent_returns_none(self):
        g = ProvenanceGraph()
        assert g.get_artifact("nonexistent") is None

    def test_artifact_count(self):
        g = ProvenanceGraph()
        g.add_artifact(_make_node("a:1"))
        g.add_artifact(_make_node("b:2", commit_sha="xyz"))
        assert g.artifact_count() == 2

    def test_all_artifacts(self):
        g = ProvenanceGraph()
        g.add_artifact(_make_node("a:1"))
        g.add_artifact(_make_node("b:2", commit_sha="xyz"))
        all_nodes = g.all_artifacts()
        ids = {n.artifact_id for n in all_nodes}
        assert "a:1" in ids
        assert "b:2" in ids

    def test_overwrite_existing_node(self):
        g = ProvenanceGraph()
        node1 = _make_node(digest="sha256:old")
        node2 = _make_node(digest="sha256:new")
        g.add_artifact(node1)
        g.add_artifact(node2)
        assert g.get_artifact("img:aegis:1.0.0").digest == "sha256:new"


class TestProvenanceGraphCommitIndex:
    def test_artifacts_for_commit(self):
        g = ProvenanceGraph()
        g.add_artifact(_make_node("a:1", commit_sha="SHA1"))
        g.add_artifact(_make_node("a:2", commit_sha="SHA1"))
        g.add_artifact(_make_node("b:1", commit_sha="SHA2"))
        nodes = g.artifacts_for_commit("SHA1")
        ids = {n.artifact_id for n in nodes}
        assert "a:1" in ids
        assert "a:2" in ids
        assert "b:1" not in ids

    def test_artifacts_for_unknown_commit(self):
        g = ProvenanceGraph()
        assert g.artifacts_for_commit("NOPE") == []


class TestProvenanceGraphLineage:
    def test_lineage_single_node(self):
        g = ProvenanceGraph()
        g.add_artifact(_make_node("a:1"))
        lineage = g.lineage("a:1")
        assert len(lineage) == 1
        assert lineage[0].artifact_id == "a:1"

    def test_lineage_with_dependencies(self):
        g = ProvenanceGraph()
        g.add_artifact(_make_node("base:1.0", commit_sha="SHA0"))
        g.add_artifact(_make_node("lib:2.0", commit_sha="SHA1", dependencies=["base:1.0"]))
        g.add_artifact(_make_node("app:3.0", commit_sha="SHA2", dependencies=["lib:2.0"]))

        lineage = g.lineage("app:3.0")
        ids = [n.artifact_id for n in lineage]
        assert "app:3.0" in ids
        assert "lib:2.0" in ids
        assert "base:1.0" in ids

    def test_lineage_missing_dependency_skipped(self):
        g = ProvenanceGraph()
        g.add_artifact(_make_node("app:1.0", dependencies=["missing-dep:1.0"]))
        lineage = g.lineage("app:1.0")
        assert len(lineage) == 1  # just the app node, missing dep silently skipped

    def test_lineage_max_depth_respected(self):
        g = ProvenanceGraph()
        # Create a deep chain
        for i in range(30):
            deps = [f"node:{i-1}"] if i > 0 else []
            g.add_artifact(_make_node(f"node:{i}", commit_sha=f"sha{i}", dependencies=deps))
        lineage = g.lineage("node:29", max_depth=5)
        # Should be truncated at max_depth
        assert len(lineage) <= 7  # node:29 + up to 6 ancestors


class TestProvenanceGraphDeployments:
    def test_record_and_retrieve_deployment(self):
        g = ProvenanceGraph()
        g.add_artifact(_make_node())
        record = _make_deploy()
        g.record_deployment(record)
        deploys = g.deployments_for_artifact("img:aegis:1.0.0")
        assert len(deploys) == 1
        assert deploys[0].environment == "production"

    def test_multiple_deployments_same_artifact(self):
        g = ProvenanceGraph()
        g.add_artifact(_make_node())
        g.record_deployment(_make_deploy(environment="staging", deploy_id="d1"))
        g.record_deployment(_make_deploy(environment="production", deploy_id="d2"))
        deploys = g.deployments_for_artifact("img:aegis:1.0.0")
        assert len(deploys) == 2

    def test_latest_deployment(self):
        g = ProvenanceGraph()
        g.add_artifact(_make_node())
        old = DeploymentRecord(
            artifact_id="img:aegis:1.0.0", environment="staging",
            deployer="bot", deploy_timestamp=1000.0, deploy_id="old"
        )
        new = DeploymentRecord(
            artifact_id="img:aegis:1.0.0", environment="production",
            deployer="bot", deploy_timestamp=9000.0, deploy_id="new"
        )
        g.record_deployment(old)
        g.record_deployment(new)
        latest = g.latest_deployment("img:aegis:1.0.0")
        assert latest.deploy_id == "new"

    def test_latest_deployment_none_for_unknown(self):
        g = ProvenanceGraph()
        assert g.latest_deployment("nonexistent") is None

    def test_deployments_to_environment(self):
        g = ProvenanceGraph()
        g.add_artifact(_make_node("a:1"))
        g.add_artifact(_make_node("b:1", commit_sha="SHA2"))
        g.record_deployment(_make_deploy("a:1", environment="production"))
        g.record_deployment(_make_deploy("b:1", environment="staging"))
        g.record_deployment(_make_deploy("a:1", environment="staging"))

        prod_deploys = g.deployments_to_environment("production")
        assert len(prod_deploys) == 1
        assert prod_deploys[0].artifact_id == "a:1"

    def test_deployment_count(self):
        g = ProvenanceGraph()
        g.add_artifact(_make_node())
        g.record_deployment(_make_deploy(environment="staging", deploy_id="d1"))
        g.record_deployment(_make_deploy(environment="production", deploy_id="d2"))
        assert g.deployment_count() == 2

    def test_deployment_for_unknown_artifact_logged(self):
        """Deploying an unknown artifact should not crash — just logs warning."""
        g = ProvenanceGraph()
        record = _make_deploy(artifact_id="ghost-artifact")
        g.record_deployment(record)  # should not raise
        assert g.deployment_count() == 1


class TestProvenanceGraphTraceCommit:
    def test_trace_commit_full(self):
        g = ProvenanceGraph()
        g.add_artifact(_make_node("img:1.0", commit_sha="COMMIT1"))
        g.record_deployment(_make_deploy("img:1.0", environment="production"))

        trace = g.trace_commit("COMMIT1")
        assert trace["commit_sha"] == "COMMIT1"
        assert len(trace["artifacts"]) == 1
        assert "img:1.0" in trace["deployments"]

    def test_trace_commit_no_deployments(self):
        g = ProvenanceGraph()
        g.add_artifact(_make_node("img:2.0", commit_sha="COMMIT2"))
        trace = g.trace_commit("COMMIT2")
        assert len(trace["artifacts"]) == 1
        assert trace["deployments"] == {}

    def test_trace_unknown_commit(self):
        g = ProvenanceGraph()
        trace = g.trace_commit("UNKNOWN")
        assert trace["artifacts"] == []
        assert trace["deployments"] == {}


class TestProvenanceGraphDigestVerification:
    def test_verify_correct_digest(self):
        g = ProvenanceGraph()
        g.add_artifact(_make_node(digest="sha256:aabbcc"))
        assert g.verify_digest("img:aegis:1.0.0", "sha256:aabbcc") is True

    def test_verify_wrong_digest(self):
        g = ProvenanceGraph()
        g.add_artifact(_make_node(digest="sha256:aabbcc"))
        assert g.verify_digest("img:aegis:1.0.0", "sha256:000000") is False

    def test_verify_nonexistent_artifact(self):
        g = ProvenanceGraph()
        assert g.verify_digest("nonexistent", "sha256:aabbcc") is False


class TestProvenanceGraphSerialization:
    def test_to_dict_from_dict_round_trip(self):
        g = ProvenanceGraph()
        g.add_artifact(_make_node("img:1.0"))
        g.record_deployment(_make_deploy("img:1.0"))

        data = g.to_dict()
        g2 = ProvenanceGraph.from_dict(data)
        assert g2.artifact_count() == 1
        assert g2.deployment_count() == 1
        assert g2.get_artifact("img:1.0") is not None

    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "provenance.json")
            g = ProvenanceGraph(storage_path=path)
            g.add_artifact(_make_node("img:1.0"))
            g.record_deployment(_make_deploy("img:1.0"))
            g.save()

            g2 = ProvenanceGraph(storage_path=path)
            g2.load()
            assert g2.artifact_count() == 1
            assert g2.deployment_count() == 1

    def test_load_nonexistent_file_is_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "does_not_exist.json")
            g = ProvenanceGraph(storage_path=path)
            g.load()  # should not raise
            assert g.artifact_count() == 0

    def test_save_creates_parent_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "nested", "deep", "provenance.json")
            g = ProvenanceGraph(storage_path=path)
            g.add_artifact(_make_node())
            g.save()
            assert os.path.exists(path)

    def test_context_manager(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "prov.json")
            with ProvenanceGraph(storage_path=path) as g:
                g.add_artifact(_make_node("ctx:1.0"))
            # File should exist after exit
            assert os.path.exists(path)
            with ProvenanceGraph(storage_path=path) as g2:
                assert g2.artifact_count() == 1

    def test_save_without_path_raises(self):
        g = ProvenanceGraph()
        with pytest.raises(ValueError, match="storage_path"):
            g.save()

    def test_load_without_path_raises(self):
        g = ProvenanceGraph()
        with pytest.raises(ValueError, match="storage_path"):
            g.load()


class TestProvenanceGraphDigestUtil:
    def test_compute_digest_format(self):
        digest = ProvenanceGraph.compute_digest(b"hello world")
        assert digest.startswith("sha256:")
        assert len(digest) == 7 + 64  # "sha256:" + 64 hex chars

    def test_compute_digest_deterministic(self):
        data = b"aegis supply chain"
        assert ProvenanceGraph.compute_digest(data) == ProvenanceGraph.compute_digest(data)

    def test_compute_digest_different_inputs(self):
        assert ProvenanceGraph.compute_digest(b"a") != ProvenanceGraph.compute_digest(b"b")
