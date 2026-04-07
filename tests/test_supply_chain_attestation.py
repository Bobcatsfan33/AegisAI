"""
Tests for modules/supply_chain/attestation.py

Covers: AttestationRecord, ArtifactAttestation (RSA, HMAC, hash-only)
"""

import base64
import hashlib
import pytest
import time

from modules.supply_chain.attestation import (
    ArtifactAttestation,
    AttestationError,
    AttestationRecord,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_attestation_service(mode: str = "hash_only") -> ArtifactAttestation:
    if mode == "hmac":
        return ArtifactAttestation(signer_id="test-signer", hmac_secret=b"super-secret-key-32bytes-padding!")
    elif mode == "rsa":
        priv, pub = ArtifactAttestation.generate_rsa_keypair(key_size=2048)
        return ArtifactAttestation(
            signer_id="test-signer",
            private_key_pem=priv,
            public_key_pem=pub,
        )
    else:
        return ArtifactAttestation(signer_id="test-signer")


def _attest(service: ArtifactAttestation, artifact_id: str = "img:aegis:1.0") -> AttestationRecord:
    return service.attest(
        artifact_id=artifact_id,
        artifact_type="container_image",
        digest="sha256:aabbccdd",
        commit_sha="abc123",
        build_id="run-42",
        builder_id="github-actions/ubuntu-latest",
        metadata={"pipeline": "ci"},
    )


# ── AttestationRecord tests ────────────────────────────────────────────────────

class TestAttestationRecord:
    def test_to_dict_round_trip(self):
        svc = _make_attestation_service()
        record = _attest(svc)
        d = record.to_dict()
        assert d["artifact_id"] == "img:aegis:1.0"
        assert d["signer_id"] == "test-signer"
        restored = AttestationRecord.from_dict(d)
        assert restored.artifact_id == record.artifact_id
        assert restored.signature == record.signature
        assert restored.payload_hash == record.payload_hash

    def test_payload_dict_excludes_signature(self):
        svc = _make_attestation_service()
        record = _attest(svc)
        payload = record.payload_dict()
        assert "signature" not in payload
        assert "artifact_id" in payload
        assert "digest" in payload

    def test_canonical_payload_bytes_is_utf8_json(self):
        svc = _make_attestation_service()
        record = _attest(svc)
        payload_bytes = record.canonical_payload_bytes()
        assert isinstance(payload_bytes, bytes)
        import json
        data = json.loads(payload_bytes.decode("utf-8"))
        assert data["artifact_id"] == "img:aegis:1.0"

    def test_payload_hash_computed_correctly(self):
        payload_hash = AttestationRecord.compute_payload_hash(
            artifact_id="img:1.0",
            artifact_type="container_image",
            digest="sha256:aabb",
            commit_sha="abc",
            build_id="r1",
            builder_id="builder",
            signed_at=1000.0,
            signer_id="signer",
            metadata={},
        )
        assert len(payload_hash) == 64  # SHA-256 hex
        assert all(c in "0123456789abcdef" for c in payload_hash)

    def test_payload_hash_is_deterministic(self):
        h1 = AttestationRecord.compute_payload_hash(
            "a", "t", "d", "c", "b", "builder", 1000.0, "s", {}
        )
        h2 = AttestationRecord.compute_payload_hash(
            "a", "t", "d", "c", "b", "builder", 1000.0, "s", {}
        )
        assert h1 == h2

    def test_payload_hash_different_for_different_inputs(self):
        h1 = AttestationRecord.compute_payload_hash("a", "t", "d", "c", "b", "b1", 1.0, "s", {})
        h2 = AttestationRecord.compute_payload_hash("b", "t", "d", "c", "b", "b1", 1.0, "s", {})
        assert h1 != h2


# ── Hash-only attestation tests ────────────────────────────────────────────────

class TestHashOnlyAttestation:
    def setup_method(self):
        self.svc = _make_attestation_service("hash_only")

    def test_attest_creates_record(self):
        record = _attest(self.svc)
        assert record.artifact_id == "img:aegis:1.0"
        assert record.signer_id == "test-signer"
        assert record.digest == "sha256:aabbccdd"
        assert record.signature.startswith("hash-only:")

    def test_signed_at_is_recent(self):
        before = time.time() - 1
        record = _attest(self.svc)
        after = time.time() + 1
        assert before <= record.signed_at <= after

    def test_verify_valid_record(self):
        record = _attest(self.svc)
        assert self.svc.verify(record) is True

    def test_verify_tampered_digest_fails(self):
        record = _attest(self.svc)
        record.digest = "sha256:tampered"
        assert self.svc.verify(record) is False

    def test_verify_tampered_signature_fails(self):
        record = _attest(self.svc)
        record.signature = "hash-only:" + "0" * 64
        assert self.svc.verify(record) is False

    def test_verify_tampered_payload_hash_fails(self):
        record = _attest(self.svc)
        record.payload_hash = "a" * 64
        assert self.svc.verify(record) is False

    def test_metadata_included_in_payload(self):
        record = self.svc.attest(
            artifact_id="img:1.0",
            artifact_type="binary",
            digest="sha256:ff",
            commit_sha="sha",
            build_id="b1",
            builder_id="builder",
            metadata={"env": "prod", "region": "us-east-1"},
        )
        assert record.metadata["env"] == "prod"
        assert self.svc.verify(record) is True

    def test_multiple_attestations_different_artifacts(self):
        r1 = _attest(self.svc, "img:1.0")
        r2 = _attest(self.svc, "img:2.0")
        assert r1.payload_hash != r2.payload_hash
        assert self.svc.verify(r1) is True
        assert self.svc.verify(r2) is True


# ── HMAC attestation tests ────────────────────────────────────────────────────

class TestHmacAttestation:
    def setup_method(self):
        self.svc = _make_attestation_service("hmac")
        self.wrong_key_svc = ArtifactAttestation(
            signer_id="wrong", hmac_secret=b"wrong-key-different-secret-bytes"
        )

    def test_attest_produces_base64_signature(self):
        record = _attest(self.svc)
        assert not record.signature.startswith("hash-only:")
        # Should be valid base64
        decoded = base64.b64decode(record.signature)
        assert len(decoded) == 32  # HMAC-SHA256 = 32 bytes

    def test_verify_with_correct_key(self):
        record = _attest(self.svc)
        assert self.svc.verify(record) is True

    def test_verify_fails_with_wrong_key(self):
        record = _attest(self.svc)
        assert self.wrong_key_svc.verify(record) is False

    def test_verify_tampered_artifact_id_fails(self):
        record = _attest(self.svc)
        record.artifact_id = "img:tampered"
        assert self.svc.verify(record) is False

    def test_verify_tampered_commit_sha_fails(self):
        record = _attest(self.svc)
        record.commit_sha = "tampered123"
        assert self.svc.verify(record) is False

    def test_sign_verify_empty_metadata(self):
        record = self.svc.attest(
            artifact_id="lib:1.0", artifact_type="python_package",
            digest="sha256:cc", commit_sha="abc", build_id="b1",
            builder_id="builder", metadata={}
        )
        assert self.svc.verify(record) is True

    def test_sign_verify_no_signature_returns_false(self):
        """Verifying with no key at all when signature is HMAC should fail."""
        record = _attest(self.svc)
        no_key_svc = ArtifactAttestation(signer_id="no-key")
        assert no_key_svc.verify(record) is False


# ── RSA attestation tests ──────────────────────────────────────────────────────

class TestRSAAttestation:
    def setup_method(self):
        self.svc = _make_attestation_service("rsa")

    def test_attest_produces_base64_signature(self):
        record = _attest(self.svc)
        assert not record.signature.startswith("hash-only:")
        # Should be valid base64
        decoded = base64.b64decode(record.signature)
        assert len(decoded) > 0

    def test_verify_with_correct_public_key(self):
        record = _attest(self.svc)
        assert self.svc.verify(record) is True

    def test_verify_fails_with_different_key_pair(self):
        priv2, pub2 = ArtifactAttestation.generate_rsa_keypair(key_size=2048)
        svc2 = ArtifactAttestation(
            signer_id="signer2", private_key_pem=priv2, public_key_pem=pub2
        )
        # Sign with svc, verify with svc2's public key
        record = _attest(self.svc)
        verify_svc = ArtifactAttestation(
            signer_id="test-signer", public_key_pem=pub2
        )
        assert verify_svc.verify(record) is False

    def test_verify_tampered_digest_fails(self):
        record = _attest(self.svc)
        record.digest = "sha256:tampered"
        assert self.svc.verify(record) is False

    def test_verify_tampered_signature_fails(self):
        record = _attest(self.svc)
        record.signature = base64.b64encode(b"not a real signature").decode()
        assert self.svc.verify(record) is False

    def test_sign_verify_round_trip_with_metadata(self):
        record = self.svc.attest(
            artifact_id="app:5.0",
            artifact_type="binary",
            digest="sha256:deadbeef",
            commit_sha="deadcafe",
            build_id="gh-run-999",
            builder_id="github-actions",
            metadata={"sbom_id": "sbom-001", "environment": "production"},
        )
        assert self.svc.verify(record) is True
        assert record.metadata["sbom_id"] == "sbom-001"


class TestRSAKeyGeneration:
    def test_generates_valid_pem_keys(self):
        priv, pub = ArtifactAttestation.generate_rsa_keypair(key_size=2048)
        assert priv.startswith(b"-----BEGIN RSA PRIVATE KEY-----") or priv.startswith(b"-----BEGIN PRIVATE KEY-----")
        assert pub.startswith(b"-----BEGIN PUBLIC KEY-----")

    def test_generates_unique_keys_each_time(self):
        priv1, _ = ArtifactAttestation.generate_rsa_keypair(2048)
        priv2, _ = ArtifactAttestation.generate_rsa_keypair(2048)
        assert priv1 != priv2

    def test_larger_key_size(self):
        priv, pub = ArtifactAttestation.generate_rsa_keypair(key_size=4096)
        assert len(priv) > 0
        assert len(pub) > 0


# ── Cross-mode verification tests ─────────────────────────────────────────────

class TestCrossMode:
    def test_rsa_signed_cannot_be_verified_by_hmac_service(self):
        rsa_svc = _make_attestation_service("rsa")
        hmac_svc = _make_attestation_service("hmac")
        record = _attest(rsa_svc)
        # HMAC service should fail to verify RSA-signed record
        assert hmac_svc.verify(record) is False

    def test_hash_only_cannot_be_verified_by_service_with_wrong_hash(self):
        svc = _make_attestation_service("hash_only")
        record = _attest(svc)
        # Tamper with the signature
        record.signature = "hash-only:" + "f" * 64
        assert svc.verify(record) is False
