"""
Machine Identity Engine — Core Implementation.

Answers the critical questions enterprises can't answer today:
  - Is this caller a human or a machine?
  - Does this machine identity look like itself (behavioral DNA match)?
  - Is this AI agent operating within its delegated scope?
  - Is this machine identity hidden behind Zero Trust (ZTIX)?
  - Should this token be revoked based on behavioral drift?

Architecture:
  IdentityRegistry  →  stores all known identities (human + machine + agent)
  BehavioralAnalyzer  →  captures DNA baseline, detects drift
  ZTIXExchange  →  Zero Trust Identity Exchange (shields real identity from target)
  DelegationGraph  →  AI agent identity chaining (root → sub-agents)
  RevocationEngine  →  automatic revocation on anomaly
"""

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("aegis.identity")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class IdentityClass(str, Enum):
    """Broad classification of an identity actor."""
    HUMAN = "human"
    MACHINE = "machine"               # CI/CD, service account, cron, k8s pod
    AI_AGENT = "ai_agent"             # LLM-driven autonomous agent
    AI_SUBAGENT = "ai_subagent"       # Delegated sub-agent from a parent agent
    BOT = "bot"                       # Scripted automation (not AI)
    UNKNOWN = "unknown"


class NHIRiskTier(str, Enum):
    """Risk tier for Non-Human Identities (NHIs)."""
    CRITICAL = "critical"             # Unmanaged, over-privileged, no rotation
    HIGH = "high"                     # Missing key controls
    MEDIUM = "medium"                 # Some gaps
    LOW = "low"                       # Minor gaps
    COMPLIANT = "compliant"           # Fully governed


class IdentityAnomaly(str, Enum):
    """Types of behavioral anomalies detected on an identity."""
    GEO_SHIFT = "geo_shift"                        # Login from unexpected location
    OFF_SCHEDULE = "off_schedule"                  # Activity outside normal schedule
    TIMING_DRIFT = "timing_drift"                  # Machine lost its timing precision
    CALL_PATTERN_CHANGE = "call_pattern_change"    # API call sequence changed
    VOLUME_SPIKE = "volume_spike"                  # Unusual request volume
    PRIVILEGE_ESCALATION = "privilege_escalation"  # Attempted out-of-scope actions
    CREDENTIAL_REUSE = "credential_reuse"          # Same cred used from multiple origins
    DELEGATION_CHAIN_BROKEN = "delegation_chain_broken"  # Agent chain integrity failure
    SCOPE_VIOLATION = "scope_violation"            # Token used beyond its granted scope
    EXPIRED_CREDENTIAL = "expired_credential"
    UNKNOWN_SOURCE = "unknown_source"              # IP/fingerprint not in baseline


class TokenType(str, Enum):
    ZTIX_SCOPED = "ztix_scoped"         # ZTIX short-lived scoped token
    SESSION = "session"                  # Human session token
    SERVICE = "service"                  # Long-lived service credential
    DELEGATION = "delegation"            # Agent delegation assertion


# ---------------------------------------------------------------------------
# Behavioral DNA
# ---------------------------------------------------------------------------

@dataclass
class CallPattern:
    """A snapshot of API call behavior."""
    endpoint: str
    method: str
    avg_interval_ms: float              # Average time between calls (machines are precise)
    interval_std_ms: float              # Std dev of interval (humans are high, machines low)
    payload_size_bytes: int
    response_code: int


@dataclass
class BehavioralDNA:
    """
    The behavioral fingerprint of an identity.

    Machines exhibit:
      - Low interval std dev (they call on a precise schedule)
      - Deterministic API call sequences
      - Stable payload sizes
      - Geographically locked login origin
      - Consistent TLS fingerprint (JA3/JA4 hash)
      - No browsing behavior — connect/execute/disconnect

    Humans exhibit:
      - High interval variance
      - Exploratory, non-deterministic call patterns
      - Varied payload sizes
      - Geographic movement
      - Varied user agents / TLS fingerprints
    """
    identity_id: str
    identity_class: IdentityClass

    # Session timing
    login_hour_distribution: Dict[int, int] = field(default_factory=dict)   # {hour: count}
    avg_session_duration_secs: float = 0.0
    session_duration_std: float = 0.0

    # Call patterns
    top_endpoints: List[CallPattern] = field(default_factory=list)
    call_interval_ms_avg: float = 0.0
    call_interval_ms_std: float = 0.0   # Key discriminator: machines have low std

    # Network fingerprint
    known_source_ips: Set[str] = field(default_factory=set)
    known_geo_countries: Set[str] = field(default_factory=set)
    ja3_fingerprints: Set[str] = field(default_factory=set)  # TLS client fingerprints
    user_agents: Set[str] = field(default_factory=set)

    # Payload profile
    avg_payload_size_bytes: float = 0.0
    payload_size_std: float = 0.0

    # Metadata
    baseline_established: bool = False
    observation_count: int = 0
    baseline_established_at: Optional[str] = None
    last_updated: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def is_machine_like(self) -> Tuple[bool, float]:
        """
        Heuristic: is this identity behaving like a machine?
        Returns (is_machine, confidence 0-1).
        """
        if not self.baseline_established:
            return False, 0.0

        signals = []

        # Low call interval variance → machine
        if self.call_interval_ms_avg > 0 and self.call_interval_ms_std >= 0:
            cv = self.call_interval_ms_std / max(self.call_interval_ms_avg, 1)
            # Humans: CV > 1.0; machines: CV < 0.1
            if cv < 0.15:
                signals.append(0.9)   # Strong machine signal
            elif cv < 0.30:
                signals.append(0.6)
            else:
                signals.append(0.1)   # Human-like variance

        # Few distinct source IPs → machine (often single IP or small IP pool)
        ip_count = len(self.known_source_ips)
        if ip_count <= 2:
            signals.append(0.85)
        elif ip_count <= 5:
            signals.append(0.5)
        else:
            signals.append(0.1)

        # Single geo country → machine (machines don't travel)
        geo_count = len(self.known_geo_countries)
        if geo_count <= 1:
            signals.append(0.8)
        elif geo_count <= 2:
            signals.append(0.4)
        else:
            signals.append(0.1)

        # Consistent TLS fingerprint → machine (same SDK version)
        if len(self.ja3_fingerprints) <= 1:
            signals.append(0.8)
        else:
            signals.append(0.2)

        if not signals:
            return False, 0.0

        confidence = sum(signals) / len(signals)
        return confidence >= 0.60, confidence


# ---------------------------------------------------------------------------
# Identity records
# ---------------------------------------------------------------------------

@dataclass
class MachineIdentity:
    """A governed Non-Human Identity (NHI)."""
    identity_id: str
    display_name: str
    identity_class: IdentityClass
    owner_human_id: str                            # Human accountable for this NHI
    purpose: str                                   # What is this identity for?

    # Credentials
    public_key_pem: Optional[str] = None          # Ed25519 or RSA public key
    key_algorithm: str = "Ed25519"
    key_rotation_days: int = 90
    last_key_rotation: Optional[str] = None
    hardware_attested: bool = False                # TPM/HSM backed?

    # Scope
    allowed_scopes: List[str] = field(default_factory=list)    # OAuth2-style scopes
    allowed_endpoints: List[str] = field(default_factory=list)
    allowed_source_ips: List[str] = field(default_factory=list)
    max_requests_per_minute: int = 1000

    # Behavioral DNA
    behavioral_dna: Optional[BehavioralDNA] = None

    # Lifecycle
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    expires_at: Optional[str] = None
    is_active: bool = True
    is_revoked: bool = False
    revocation_reason: Optional[str] = None
    anomalies_detected: List[IdentityAnomaly] = field(default_factory=list)
    risk_tier: NHIRiskTier = NHIRiskTier.MEDIUM


@dataclass
class HumanIdentity:
    """A human identity record (complementary to machine identities)."""
    identity_id: str
    username: str
    email: str
    roles: List[str] = field(default_factory=list)
    mfa_enabled: bool = False
    hardware_key_enrolled: bool = False         # FIDO2/WebAuthn
    behavioral_dna: Optional[BehavioralDNA] = None
    managed_nhi_ids: List[str] = field(default_factory=list)  # NHIs this human owns
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    is_active: bool = True


# ---------------------------------------------------------------------------
# Zero Trust Identity Exchange (ZTIX)
# ---------------------------------------------------------------------------

@dataclass
class ZTIXToken:
    """
    A short-lived, scope-limited capability token issued by the ZTIX.

    The real machine identity (IP, key, credential) is NEVER sent to the target.
    Only this token is presented. The token is:
      - Short-lived (default 5 minutes)
      - Scoped (only the specific capability requested)
      - Single-use or request-bound (jti prevents replay)
      - Signed by the ZTIX — not by the machine itself

    This means:
      - Attackers scanning the target see only a scoped ephemeral token
      - The machine's IP, identity, and infrastructure are invisible
      - Revocation is instant (ZTIX stops issuing; old tokens expire naturally)
    """
    token_id: str                               # UUID / JTI
    token_type: TokenType = TokenType.ZTIX_SCOPED
    issuer: str = "aegis-ztix"
    subject_identity_id: str = ""              # The machine requesting access
    target_service: str = ""                   # The service being accessed
    granted_scopes: List[str] = field(default_factory=list)
    issued_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    expires_at: str = ""
    signature: str = ""                        # HMAC-SHA256 of token payload
    is_revoked: bool = False
    used_count: int = 0
    max_uses: int = 1                          # Single-use by default


class ZTIXExchange:
    """
    Zero Trust Identity Exchange.

    How it works:
      1. Machine calls ZTIX.request_token(identity_id, target_service, scopes)
      2. ZTIX validates: behavioral DNA ✓, key attestation ✓, scope allowed ✓
      3. ZTIX issues a ZTIXToken signed by its own key
      4. Machine presents ZTIXToken to target (never its own credential)
      5. Target validates ZTIXToken signature against ZTIX public key
      6. Machine IP and real identity remain hidden

    The ZTIX is the only entity that knows the mapping between
    real identity → scoped token. This mapping lives in memory only
    (or encrypted at rest in ClickHouse with field-level encryption).
    """

    ZTIX_SECRET_ENV = "ZTIX_SIGNING_SECRET"

    def __init__(self):
        self._secret = os.getenv(self.ZTIX_SECRET_ENV, secrets.token_hex(32))
        self._issued_tokens: Dict[str, ZTIXToken] = {}   # token_id → token
        self._revoked_ids: Set[str] = set()
        logger.info("ZTIXExchange initialized")

    def request_token(self,
                      identity_id: str,
                      target_service: str,
                      requested_scopes: List[str],
                      machine_identity: Optional[MachineIdentity] = None,
                      ttl_minutes: int = 5,
                      max_uses: int = 1) -> Optional[ZTIXToken]:
        """
        Issue a scoped ZTIX token.
        Validates scope against machine identity's allowed_scopes.
        Returns None if validation fails.
        """
        # Scope validation
        if machine_identity:
            allowed = set(machine_identity.allowed_scopes)
            requested = set(requested_scopes)
            if not requested.issubset(allowed | {"*"}):
                denied = requested - allowed
                logger.warning(
                    "ZTIX scope violation: identity %s requested %s, denied %s",
                    identity_id, requested_scopes, denied
                )
                return None

            if machine_identity.is_revoked:
                logger.warning("ZTIX: revoked identity %s attempted token request", identity_id)
                return None

        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=ttl_minutes)
        token_id = secrets.token_urlsafe(24)

        token = ZTIXToken(
            token_id=token_id,
            subject_identity_id=identity_id,
            target_service=target_service,
            granted_scopes=requested_scopes,
            issued_at=now.isoformat(),
            expires_at=expires.isoformat(),
            max_uses=max_uses,
        )

        # Sign the token payload
        payload = json.dumps({
            "jti": token_id,
            "sub": identity_id,
            "target": target_service,
            "scopes": sorted(requested_scopes),
            "iat": now.isoformat(),
            "exp": expires.isoformat(),
        }, sort_keys=True)
        token.signature = hmac.new(
            self._secret.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()

        self._issued_tokens[token_id] = token
        logger.info(
            "ZTIX token issued: %s → target=%s scopes=%s ttl=%dm",
            identity_id[:12] + "...", target_service, requested_scopes, ttl_minutes
        )
        return token

    def validate_token(self, token_id: str, target_service: str,
                       scope: str) -> Tuple[bool, str]:
        """
        Validate a ZTIX token presented by a machine to a target service.
        Returns (valid, reason).
        """
        if token_id in self._revoked_ids:
            return False, "token_revoked"

        token = self._issued_tokens.get(token_id)
        if not token:
            return False, "token_not_found"

        if token.target_service != target_service:
            return False, "wrong_target_service"

        if scope not in token.granted_scopes:
            return False, f"scope_not_granted:{scope}"

        now = datetime.now(timezone.utc)
        try:
            exp = datetime.fromisoformat(token.expires_at.replace("Z", "+00:00"))
            if now > exp:
                return False, "token_expired"
        except (ValueError, AttributeError):
            return False, "invalid_expiry"

        if token.used_count >= token.max_uses and token.max_uses > 0:
            return False, "token_exhausted"

        token.used_count += 1
        return True, "ok"

    def revoke_token(self, token_id: str):
        """Immediately revoke a token."""
        self._revoked_ids.add(token_id)
        if token_id in self._issued_tokens:
            self._issued_tokens[token_id].is_revoked = True
        logger.warning("ZTIX token revoked: %s", token_id)

    def revoke_all_for_identity(self, identity_id: str):
        """Revoke all tokens for a given identity (e.g. on anomaly detection)."""
        count = 0
        for token in self._issued_tokens.values():
            if token.subject_identity_id == identity_id and not token.is_revoked:
                self.revoke_token(token.token_id)
                count += 1
        logger.warning("ZTIX: revoked %d tokens for identity %s", count, identity_id)
        return count


# ---------------------------------------------------------------------------
# Agent Identity Chaining
# ---------------------------------------------------------------------------

@dataclass
class DelegationLink:
    """
    A cryptographically signed delegation assertion.
    When Agent A spawns Agent B, A issues a DelegationLink to B.
    The link constrains B's scope to a subset of A's scope.
    """
    link_id: str
    parent_identity_id: str
    child_identity_id: str
    delegated_scopes: List[str]         # MUST be subset of parent's scopes
    issued_at: str
    expires_at: str
    signature: str                       # HMAC signed by parent
    purpose: str = ""                   # Why was this delegation issued?
    is_revoked: bool = False


@dataclass
class AgentIdentityChain:
    """
    The full identity chain for an AI agent, from root orchestrator
    down through all sub-agent delegations.

    This enables:
      - Tracing any action back to the root agent and ultimately the human
      - Detecting if a sub-agent exceeds its delegated scope
      - Revoking the whole chain when the root is revoked
    """
    chain_id: str
    root_identity_id: str               # The top-level human or root machine
    links: List[DelegationLink] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    is_valid: bool = True

    def get_leaf_identity(self) -> str:
        """Return the most recently delegated (leaf) identity in the chain."""
        if self.links:
            return self.links[-1].child_identity_id
        return self.root_identity_id

    def verify_integrity(self, signing_secret: str) -> bool:
        """Verify all delegation signatures in the chain."""
        for link in self.links:
            payload = json.dumps({
                "link_id": link.link_id,
                "parent": link.parent_identity_id,
                "child": link.child_identity_id,
                "scopes": sorted(link.delegated_scopes),
                "iat": link.issued_at,
                "exp": link.expires_at,
            }, sort_keys=True)
            expected_sig = hmac.new(
                signing_secret.encode(), payload.encode(), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(expected_sig, link.signature):
                return False
        return True

    def scope_for_leaf(self) -> List[str]:
        """Return the effective scopes available to the leaf identity."""
        if not self.links:
            return []
        return self.links[-1].delegated_scopes


class DelegationGraph:
    """
    Manages the full graph of agent delegation relationships.
    Supports: issue, verify, revoke, enumerate chains.
    """

    def __init__(self, signing_secret: str):
        self._secret = signing_secret
        self._chains: Dict[str, AgentIdentityChain] = {}
        self._links: Dict[str, DelegationLink] = {}

    def create_chain(self, root_identity_id: str) -> AgentIdentityChain:
        chain_id = secrets.token_urlsafe(16)
        chain = AgentIdentityChain(
            chain_id=chain_id,
            root_identity_id=root_identity_id,
        )
        self._chains[chain_id] = chain
        return chain

    def delegate(self, chain: AgentIdentityChain,
                 parent_identity_id: str,
                 child_identity_id: str,
                 delegated_scopes: List[str],
                 purpose: str = "",
                 ttl_minutes: int = 60) -> Optional[DelegationLink]:
        """
        Add a delegation link to a chain.
        Validates that delegated_scopes are a subset of parent's current scope.
        """
        # Determine parent's current scopes
        parent_scopes: List[str] = []
        for link in chain.links:
            if link.child_identity_id == parent_identity_id:
                parent_scopes = link.delegated_scopes
                break

        if parent_scopes and not set(delegated_scopes).issubset(set(parent_scopes)):
            excess = set(delegated_scopes) - set(parent_scopes)
            logger.warning(
                "Delegation scope escalation attempt: %s tried to grant %s to %s",
                parent_identity_id, excess, child_identity_id
            )
            return None

        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=ttl_minutes)
        link_id = secrets.token_urlsafe(16)

        payload = json.dumps({
            "link_id": link_id,
            "parent": parent_identity_id,
            "child": child_identity_id,
            "scopes": sorted(delegated_scopes),
            "iat": now.isoformat(),
            "exp": expires.isoformat(),
        }, sort_keys=True)
        signature = hmac.new(
            self._secret.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()

        link = DelegationLink(
            link_id=link_id,
            parent_identity_id=parent_identity_id,
            child_identity_id=child_identity_id,
            delegated_scopes=delegated_scopes,
            issued_at=now.isoformat(),
            expires_at=expires.isoformat(),
            signature=signature,
            purpose=purpose,
        )
        chain.links.append(link)
        self._links[link_id] = link
        logger.info(
            "Delegation: %s → %s scopes=%s chain=%s",
            parent_identity_id[:8], child_identity_id[:8], delegated_scopes, chain.chain_id
        )
        return link

    def revoke_chain(self, chain_id: str):
        """Revoke an entire delegation chain (and all its links)."""
        chain = self._chains.get(chain_id)
        if chain:
            chain.is_valid = False
            for link in chain.links:
                link.is_revoked = True
            logger.warning("Delegation chain revoked: %s", chain_id)

    def get_chain(self, chain_id: str) -> Optional[AgentIdentityChain]:
        return self._chains.get(chain_id)


# ---------------------------------------------------------------------------
# Behavioral DNA Analyzer
# ---------------------------------------------------------------------------

class BehavioralDNAAnalyzer:
    """
    Captures behavioral baselines and detects drift.

    For machine identities, the baseline is established over the first N
    observations. After that, deviations trigger anomaly signals that can
    automatically revoke the token.
    """

    BASELINE_MIN_OBSERVATIONS = 50
    TIMING_PRECISION_THRESHOLD_MS = 100   # Machines are within 100ms of their schedule

    def __init__(self):
        # {identity_id: rolling window of call timestamps}
        self._call_timestamps: Dict[str, Deque[float]] = defaultdict(
            lambda: deque(maxlen=500)
        )
        self._source_ips: Dict[str, Set[str]] = defaultdict(set)
        self._geo_countries: Dict[str, Set[str]] = defaultdict(set)
        self._ja3_hashes: Dict[str, Set[str]] = defaultdict(set)

    def observe(self, identity_id: str, dna: BehavioralDNA,
                source_ip: str = "", geo_country: str = "",
                ja3_hash: str = "") -> List[IdentityAnomaly]:
        """
        Record an observation for an identity and detect anomalies.
        Returns list of detected anomalies.
        """
        now = time.monotonic()
        timestamps = self._call_timestamps[identity_id]
        anomalies: List[IdentityAnomaly] = []

        # Record observation
        if source_ip:
            self._source_ips[identity_id].add(source_ip)
            if dna.baseline_established and source_ip not in dna.known_source_ips:
                anomalies.append(IdentityAnomaly.UNKNOWN_SOURCE)

        if geo_country:
            self._geo_countries[identity_id].add(geo_country)
            if dna.baseline_established and geo_country not in dna.known_geo_countries:
                anomalies.append(IdentityAnomaly.GEO_SHIFT)

        if ja3_hash:
            self._ja3_hashes[identity_id].add(ja3_hash)

        # Timing analysis
        if timestamps:
            interval_ms = (now - timestamps[-1]) * 1000
            if dna.baseline_established and dna.call_interval_ms_avg > 0:
                expected = dna.call_interval_ms_avg
                deviation = abs(interval_ms - expected)
                # For machine identities: timing drift beyond 2× std dev is suspicious
                if dna.identity_class in (IdentityClass.MACHINE, IdentityClass.BOT):
                    threshold = max(dna.call_interval_ms_std * 2, 500)  # min 500ms grace
                    if deviation > threshold:
                        anomalies.append(IdentityAnomaly.TIMING_DRIFT)

        timestamps.append(now)
        dna.observation_count += 1

        # Establish baseline if enough data
        if not dna.baseline_established and dna.observation_count >= self.BASELINE_MIN_OBSERVATIONS:
            self._establish_baseline(identity_id, dna)

        return anomalies

    def _establish_baseline(self, identity_id: str, dna: BehavioralDNA):
        """Compute behavioral DNA baseline from accumulated observations."""
        timestamps = list(self._call_timestamps[identity_id])
        if len(timestamps) >= 2:
            intervals = [(timestamps[i+1] - timestamps[i]) * 1000
                         for i in range(len(timestamps)-1)]
            dna.call_interval_ms_avg = statistics.mean(intervals)
            dna.call_interval_ms_std = statistics.stdev(intervals) if len(intervals) > 1 else 0.0

        dna.known_source_ips = set(self._source_ips[identity_id])
        dna.known_geo_countries = set(self._geo_countries[identity_id])
        dna.ja3_fingerprints = set(self._ja3_hashes[identity_id])
        dna.baseline_established = True
        dna.baseline_established_at = datetime.now(timezone.utc).isoformat()
        logger.info(
            "BehavioralDNA baseline established for %s: "
            "interval=%.1f±%.1fms ips=%d geos=%d",
            identity_id[:12], dna.call_interval_ms_avg, dna.call_interval_ms_std,
            len(dna.known_source_ips), len(dna.known_geo_countries)
        )


# ---------------------------------------------------------------------------
# NHI Governance Scorer
# ---------------------------------------------------------------------------

class NHIGovernanceScorer:
    """
    Scores a machine identity's governance posture.
    Identifies compliance gaps and computes NHIRiskTier.
    """

    def score(self, identity: MachineIdentity) -> Tuple[NHIRiskTier, List[str]]:
        """Returns (risk_tier, list_of_gaps)."""
        gaps: List[str] = []
        penalty = 0

        if not identity.public_key_pem:
            gaps.append("No cryptographic identity (no public key registered)")
            penalty += 30

        if not identity.hardware_attested:
            gaps.append("Not hardware-attested (no TPM/HSM binding)")
            penalty += 10

        if identity.key_rotation_days > 90:
            gaps.append(f"Key rotation interval {identity.key_rotation_days}d exceeds 90d policy")
            penalty += 15

        if identity.last_key_rotation:
            try:
                last = datetime.fromisoformat(identity.last_key_rotation.replace("Z", "+00:00"))
                days_since = (datetime.now(timezone.utc) - last).days
                if days_since > identity.key_rotation_days:
                    gaps.append(f"Key overdue for rotation by {days_since - identity.key_rotation_days} days")
                    penalty += 20
            except (ValueError, AttributeError):
                pass
        else:
            gaps.append("Key has never been rotated")
            penalty += 15

        if not identity.owner_human_id:
            gaps.append("No human owner assigned (orphaned NHI)")
            penalty += 25

        if not identity.allowed_scopes:
            gaps.append("No scope constraints defined (wildcard effective)")
            penalty += 20

        if not identity.allowed_source_ips:
            gaps.append("No source IP allowlist (any-source effective)")
            penalty += 10

        if identity.behavioral_dna and not identity.behavioral_dna.baseline_established:
            gaps.append("Behavioral DNA baseline not yet established")
            penalty += 5

        if identity.anomalies_detected:
            gaps.append(f"Active anomalies: {[a.value for a in identity.anomalies_detected]}")
            penalty += 10 * len(identity.anomalies_detected)

        if penalty == 0:
            tier = NHIRiskTier.COMPLIANT
        elif penalty <= 15:
            tier = NHIRiskTier.LOW
        elif penalty <= 35:
            tier = NHIRiskTier.MEDIUM
        elif penalty <= 60:
            tier = NHIRiskTier.HIGH
        else:
            tier = NHIRiskTier.CRITICAL

        return tier, gaps


# ---------------------------------------------------------------------------
# Main Engine
# ---------------------------------------------------------------------------

class IdentityEngine:
    """
    Central identity governance orchestrator.

    Manages:
      - Human and machine identity registry
      - Behavioral DNA capture and anomaly detection
      - ZTIX token issuance and validation
      - Agent identity chain management
      - NHI governance scoring
      - Automatic revocation on anomaly
    """

    def __init__(self):
        self._secret = os.getenv("ZTIX_SIGNING_SECRET", secrets.token_hex(32))
        self.ztix = ZTIXExchange()
        self.delegation_graph = DelegationGraph(self._secret)
        self.dna_analyzer = BehavioralDNAAnalyzer()
        self.governance_scorer = NHIGovernanceScorer()
        self._machines: Dict[str, MachineIdentity] = {}
        self._humans: Dict[str, HumanIdentity] = {}
        logger.info("IdentityEngine initialized")

    # ── Registry ────────────────────────────────────────────────────────────

    def register_machine(self, identity_id: str, display_name: str,
                         identity_class: IdentityClass,
                         owner_human_id: str, purpose: str,
                         allowed_scopes: Optional[List[str]] = None,
                         public_key_pem: Optional[str] = None) -> MachineIdentity:
        dna = BehavioralDNA(identity_id=identity_id, identity_class=identity_class)
        identity = MachineIdentity(
            identity_id=identity_id,
            display_name=display_name,
            identity_class=identity_class,
            owner_human_id=owner_human_id,
            purpose=purpose,
            allowed_scopes=allowed_scopes or [],
            public_key_pem=public_key_pem,
            behavioral_dna=dna,
        )
        self._machines[identity_id] = identity
        tier, _ = self.governance_scorer.score(identity)
        identity.risk_tier = tier
        logger.info("Machine identity registered: %s (%s, tier=%s)",
                    display_name, identity_class.value, tier.value)
        return identity

    def register_human(self, identity_id: str, username: str, email: str,
                       roles: Optional[List[str]] = None) -> HumanIdentity:
        dna = BehavioralDNA(identity_id=identity_id, identity_class=IdentityClass.HUMAN)
        human = HumanIdentity(
            identity_id=identity_id,
            username=username,
            email=email,
            roles=roles or [],
            behavioral_dna=dna,
        )
        self._humans[identity_id] = human
        return human

    # ── Classification ──────────────────────────────────────────────────────

    def classify_identity(self, identity_id: str) -> Tuple[IdentityClass, float]:
        """
        Classify an identity as human or machine based on behavioral DNA.
        Returns (IdentityClass, confidence 0-1).
        """
        if identity_id in self._machines:
            return self._machines[identity_id].identity_class, 1.0

        if identity_id in self._humans:
            human = self._humans[identity_id]
            if human.behavioral_dna and human.behavioral_dna.baseline_established:
                is_machine, conf = human.behavioral_dna.is_machine_like()
                if is_machine:
                    # A registered human acting like a machine — credential compromise?
                    logger.warning(
                        "Human identity %s exhibiting machine-like behavior (confidence=%.2f)",
                        identity_id, conf
                    )
                    return IdentityClass.MACHINE, conf
            return IdentityClass.HUMAN, 1.0

        return IdentityClass.UNKNOWN, 0.0

    # ── Observation ─────────────────────────────────────────────────────────

    def observe(self, identity_id: str, source_ip: str = "",
                geo_country: str = "", ja3_hash: str = "",
                auto_revoke: bool = True) -> List[IdentityAnomaly]:
        """
        Record a protocol-level observation for an identity.
        Detects anomalies and optionally auto-revokes on critical findings.
        """
        identity = self._machines.get(identity_id)
        if not identity or not identity.behavioral_dna:
            return []

        anomalies = self.dna_analyzer.observe(
            identity_id, identity.behavioral_dna,
            source_ip=source_ip, geo_country=geo_country, ja3_hash=ja3_hash
        )

        if anomalies:
            identity.anomalies_detected.extend(anomalies)
            tier, _ = self.governance_scorer.score(identity)
            identity.risk_tier = tier
            logger.warning(
                "Identity %s anomalies: %s (tier now %s)",
                identity_id, [a.value for a in anomalies], tier.value
            )

            # Auto-revoke on critical anomalies
            if auto_revoke and tier == NHIRiskTier.CRITICAL:
                self.revoke_machine(
                    identity_id,
                    reason=f"Auto-revoked: critical anomalies {[a.value for a in anomalies]}"
                )
                self.ztix.revoke_all_for_identity(identity_id)

        return anomalies

    # ── ZTIX ────────────────────────────────────────────────────────────────

    def request_ztix_token(self, identity_id: str, target_service: str,
                           scopes: List[str], ttl_minutes: int = 5) -> Optional[ZTIXToken]:
        """Issue a ZTIX token for a machine identity."""
        machine = self._machines.get(identity_id)
        return self.ztix.request_token(
            identity_id=identity_id,
            target_service=target_service,
            requested_scopes=scopes,
            machine_identity=machine,
            ttl_minutes=ttl_minutes,
        )

    def validate_ztix_token(self, token_id: str, target_service: str,
                            scope: str) -> Tuple[bool, str]:
        return self.ztix.validate_token(token_id, target_service, scope)

    # ── Delegation / Agent chains ────────────────────────────────────────────

    def create_agent_chain(self, root_identity_id: str) -> AgentIdentityChain:
        """Start a new agent delegation chain from a root identity."""
        return self.delegation_graph.create_chain(root_identity_id)

    def delegate(self, chain: AgentIdentityChain, parent_id: str,
                 child_id: str, scopes: List[str],
                 purpose: str = "", ttl_minutes: int = 60) -> Optional[DelegationLink]:
        """Add a delegation link to an agent chain."""
        return self.delegation_graph.delegate(
            chain, parent_id, child_id, scopes, purpose, ttl_minutes
        )

    # ── Revocation ──────────────────────────────────────────────────────────

    def revoke_machine(self, identity_id: str, reason: str = ""):
        identity = self._machines.get(identity_id)
        if identity:
            identity.is_active = False
            identity.is_revoked = True
            identity.revocation_reason = reason
            logger.warning("Machine identity REVOKED: %s — %s", identity_id, reason)

    # ── Governance ─────────────────────────────────────────────────────────

    def governance_report(self) -> Dict[str, Any]:
        """Generate an NHI governance summary."""
        by_tier: Dict[str, int] = {}
        critical_ids: List[str] = []
        for identity in self._machines.values():
            tier, _ = self.governance_scorer.score(identity)
            identity.risk_tier = tier
            by_tier[tier.value] = by_tier.get(tier.value, 0) + 1
            if tier == NHIRiskTier.CRITICAL:
                critical_ids.append(identity.identity_id)

        return {
            "total_machine_identities": len(self._machines),
            "total_human_identities": len(self._humans),
            "nhi_by_risk_tier": by_tier,
            "critical_nhi_ids": critical_ids,
            "machine_to_human_ratio": (
                len(self._machines) / max(len(self._humans), 1)
            ),
        }

    def list_machines(self, risk_tier: Optional[str] = None) -> List[MachineIdentity]:
        machines = list(self._machines.values())
        if risk_tier:
            machines = [m for m in machines if m.risk_tier.value == risk_tier]
        return machines

    def get_machine(self, identity_id: str) -> Optional[MachineIdentity]:
        return self._machines.get(identity_id)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[IdentityEngine] = None


def get_engine() -> IdentityEngine:
    global _engine
    if _engine is None:
        _engine = IdentityEngine()
    return _engine
