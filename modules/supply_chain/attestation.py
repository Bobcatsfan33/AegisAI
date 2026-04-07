"""
Aegis — Supply Chain Artifact Attestation  (v2.11.0)

Cryptographic signing and verification of supply chain artifacts.
Implements a subset of the in-toto / SLSA attestation model using Python's
stdlib `cryptography` library (RSA-PSS + SHA-256).

Key concepts:
  AttestationRecord — signed document binding an artifact digest to provenance
  ArtifactAttestation — service for signing and verifying attestations

Signing algorithm: RSA-PSS with SHA-256 (FIPS-compatible)
Key management: PEM-encoded RSA key pairs (2048/4096-bit)

For production use, keys should be stored in HSM or cloud KMS.
This implementation supports file-based and in-memory keys for CI/CD pipelines.

Attestation format (JSON-serializable):
  {
    "artifact_id":   str,
    "artifact_type": str,
    "digest":        str,        # sha256:<hex>
    "commit_sha":    str,
    "build_id":      str,
    "builder_id":    str,
    "signed_at":     float,      # epoch seconds
    "signer_id":     str,        # identity of the signer
    "payload_hash":  str,        # sha256 of canonical JSON payload
    "signature":     str,        # base64-encoded RSA-PSS signature
  }
"""

import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)


class AttestationError(Exception):
    """Raised when attestation signing or verification fails."""


@dataclass
class AttestationRecord:
    """Signed attestation document for a single artifact."""

    artifact_id:   str
    artifact_type: str
    digest:        str          # sha256:<hex>
    commit_sha:    str
    build_id:      str
    builder_id:    str
    signed_at:     float
    signer_id:     str
    payload_hash:  str          # sha256 of canonical JSON (pre-signature)
    signature:     str = ""     # base64-encoded signature (set after signing)
    metadata:      dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "AttestationRecord":
        return cls(**d)

    def payload_dict(self) -> dict:
        """Canonical payload (excludes signature) used for signing/verification."""
        return {
            "artifact_id":   self.artifact_id,
            "artifact_type": self.artifact_type,
            "digest":        self.digest,
            "commit_sha":    self.commit_sha,
            "build_id":      self.build_id,
            "builder_id":    self.builder_id,
            "signed_at":     self.signed_at,
            "signer_id":     self.signer_id,
            "payload_hash":  self.payload_hash,
            "metadata":      self.metadata,
        }

    def canonical_payload_bytes(self) -> bytes:
        """Return canonical UTF-8 JSON bytes for signing."""
        return json.dumps(self.payload_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def compute_payload_hash(artifact_id: str, artifact_type: str, digest: str,
                             commit_sha: str, build_id: str, builder_id: str,
                             signed_at: float, signer_id: str, metadata: dict) -> str:
        """Compute SHA-256 hash of the canonical pre-signature payload."""
        payload = {
            "artifact_id":   artifact_id,
            "artifact_type": artifact_type,
            "digest":        digest,
            "commit_sha":    commit_sha,
            "build_id":      build_id,
            "builder_id":    builder_id,
            "signed_at":     signed_at,
            "signer_id":     signer_id,
            "metadata":      metadata,
        }
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload_bytes).hexdigest()


class ArtifactAttestation:
    """
    Service for signing and verifying supply chain artifact attestations.

    Supports:
    - RSA-PSS signing with private key (PEM)
    - RSA-PSS verification with public key (PEM)
    - HMAC-SHA256 signing/verification for lightweight use cases (shared secret)
    - Hash-only attestation (no key) for environments without PKI

    Key material can be provided at construction time or loaded from PEM files.
    """

    def __init__(
        self,
        signer_id: str = "aegis-supply-chain",
        private_key_pem: bytes = b"",
        public_key_pem: bytes = b"",
        hmac_secret: bytes = b"",
    ):
        self._signer_id = signer_id
        self._private_key_pem = private_key_pem
        self._public_key_pem  = public_key_pem
        self._hmac_secret     = hmac_secret

    @classmethod
    def from_key_files(
        cls,
        signer_id: str,
        private_key_path: str = "",
        public_key_path: str = "",
    ) -> "ArtifactAttestation":
        """Load PEM keys from files."""
        priv = b""
        pub  = b""
        if private_key_path:
            with open(private_key_path, "rb") as f:
                priv = f.read()
        if public_key_path:
            with open(public_key_path, "rb") as f:
                pub = f.read()
        return cls(signer_id=signer_id, private_key_pem=priv, public_key_pem=pub)

    @staticmethod
    def generate_rsa_keypair(key_size: int = 2048) -> tuple:
        """
        Generate a new RSA key pair for attestation signing.

        Returns: (private_key_pem: bytes, public_key_pem: bytes)
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            raise AttestationError("cryptography package not installed. Run: pip install cryptography")

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem

    # ── Attestation creation ───────────────────────────────────────────────────

    def attest(
        self,
        artifact_id: str,
        artifact_type: str,
        digest: str,
        commit_sha: str,
        build_id: str,
        builder_id: str,
        metadata: dict = None,
    ) -> AttestationRecord:
        """
        Create and sign an attestation record for an artifact.

        Raises AttestationError if signing fails.
        """
        signed_at = time.time()
        metadata = metadata or {}

        payload_hash = AttestationRecord.compute_payload_hash(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            digest=digest,
            commit_sha=commit_sha,
            build_id=build_id,
            builder_id=builder_id,
            signed_at=signed_at,
            signer_id=self._signer_id,
            metadata=metadata,
        )

        record = AttestationRecord(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            digest=digest,
            commit_sha=commit_sha,
            build_id=build_id,
            builder_id=builder_id,
            signed_at=signed_at,
            signer_id=self._signer_id,
            payload_hash=payload_hash,
            metadata=metadata,
        )

        # Sign with whichever mechanism is available
        if self._private_key_pem:
            record.signature = self._sign_rsa(record.canonical_payload_bytes())
        elif self._hmac_secret:
            record.signature = self._sign_hmac(record.canonical_payload_bytes())
        else:
            # Hash-only (no signing key) — integrity but not authentication
            record.signature = "hash-only:" + payload_hash

        logger.info(
            "[Attestation] Signed artifact %s (digest=%s, commit=%s)",
            artifact_id[:32], digest[:24], commit_sha[:8],
        )
        return record

    # ── Verification ──────────────────────────────────────────────────────────

    def verify(self, record: AttestationRecord) -> bool:
        """
        Verify an attestation record's signature and payload integrity.

        Returns True if valid, False otherwise. Never raises on invalid signature
        (logs the failure reason).
        """
        try:
            # 1. Verify payload hash matches the canonical payload
            recomputed = AttestationRecord.compute_payload_hash(
                artifact_id=record.artifact_id,
                artifact_type=record.artifact_type,
                digest=record.digest,
                commit_sha=record.commit_sha,
                build_id=record.build_id,
                builder_id=record.builder_id,
                signed_at=record.signed_at,
                signer_id=record.signer_id,
                metadata=record.metadata,
            )
            if recomputed != record.payload_hash:
                logger.warning("[Attestation] Payload hash mismatch for %s", record.artifact_id)
                return False

            # 2. Verify signature
            if record.signature.startswith("hash-only:"):
                # Hash-only mode: just confirm the payload_hash matches
                expected = record.signature[len("hash-only:"):]
                if expected != record.payload_hash:
                    logger.warning("[Attestation] Hash-only signature mismatch")
                    return False
            elif self._public_key_pem:
                ok = self._verify_rsa(record.canonical_payload_bytes(), record.signature)
                if not ok:
                    logger.warning("[Attestation] RSA signature invalid for %s", record.artifact_id)
                    return False
            elif self._hmac_secret:
                ok = self._verify_hmac(record.canonical_payload_bytes(), record.signature)
                if not ok:
                    logger.warning("[Attestation] HMAC signature invalid for %s", record.artifact_id)
                    return False
            else:
                # No verification key — cannot verify RSA/HMAC signatures
                logger.warning("[Attestation] No key for verification — cannot verify %s", record.artifact_id)
                return False

            logger.debug("[Attestation] Verified: %s", record.artifact_id)
            return True

        except Exception as exc:
            logger.warning("[Attestation] Verification error for %s: %s", record.artifact_id, exc)
            return False

    # ── RSA-PSS signing / verification ────────────────────────────────────────

    def _sign_rsa(self, payload: bytes) -> str:
        """Sign payload bytes with RSA-PSS. Returns base64-encoded signature."""
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
        except ImportError:
            raise AttestationError("cryptography not installed")

        private_key = serialization.load_pem_private_key(self._private_key_pem, password=None)
        sig = private_key.sign(
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return base64.b64encode(sig).decode("ascii")

    def _verify_rsa(self, payload: bytes, signature_b64: str) -> bool:
        """Verify RSA-PSS signature. Returns True if valid."""
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.exceptions import InvalidSignature

            public_key = serialization.load_pem_public_key(self._public_key_pem)
            sig = base64.b64decode(signature_b64)
            public_key.verify(
                sig,
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    # ── HMAC-SHA256 signing / verification ────────────────────────────────────

    def _sign_hmac(self, payload: bytes) -> str:
        """Sign payload bytes with HMAC-SHA256. Returns base64-encoded MAC."""
        import hmac as _hmac
        import hashlib
        mac = _hmac.new(self._hmac_secret, payload, hashlib.sha256).digest()
        return base64.b64encode(mac).decode("ascii")

    def _verify_hmac(self, payload: bytes, signature_b64: str) -> bool:
        """Verify HMAC-SHA256 MAC. Returns True if valid."""
        import hmac as _hmac
        import hashlib
        expected = _hmac.new(self._hmac_secret, payload, hashlib.sha256).digest()
        try:
            received = base64.b64decode(signature_b64)
            return _hmac.compare_digest(expected, received)
        except Exception:
            return False
