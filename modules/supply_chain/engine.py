"""
Supply Chain Security Engine — Core Implementation.

Behavioral Provenance Graph: the answer to what SBOMs cannot provide.
An SBOM tells you what packages exist. This engine tells you:
  - Who touched each component, from where, and when
  - Whether each actor is human or machine
  - Whether behavioral patterns match known attack vectors (XZ-style)
  - Whether published artifacts match their source code
  - What the risk posture is end-to-end from commit to deploy
"""

import hashlib
import json
import logging
import os
import re
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("aegis.supply_chain")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class IdentityType(str, Enum):
    """Classification of the actor behind a supply chain action."""
    HUMAN = "human"
    MACHINE = "machine"           # CI bot, GitHub Actions, Dependabot, etc.
    AI_AGENT = "ai_agent"         # LLM-driven automation
    UNKNOWN = "unknown"


class AnomalyType(str, Enum):
    """Known behavioral anomaly patterns in supply chains."""
    NEW_CONTRIBUTOR_FAST_TRUST = "new_contributor_fast_trust"   # XZ pattern
    OFF_HOURS_GEO_SHIFT = "off_hours_geo_shift"                 # solarwinds pattern
    CREDENTIAL_COMPROMISE = "credential_compromise"              # maintainer cred theft
    BUILD_ARTIFACT_MISMATCH = "build_artifact_mismatch"         # XZ artifact drift
    DEPENDENCY_CONFUSION = "dependency_confusion"               # package namespace attack
    TYPOSQUATTING = "typosquatting"                             # similar-name package
    PHANTOM_DEPENDENCY = "phantom_dependency"                   # dep not in lockfile
    UNSIGNED_ARTIFACT = "unsigned_artifact"                     # missing Sigstore sig
    SLSA_VIOLATION = "slsa_violation"                           # provenance gap
    BEHAVIORAL_DRIFT = "behavioral_drift"                       # contributor pattern change
    PRIVILEGE_ESCALATION = "privilege_escalation"               # repo perms suddenly changed
    RAPID_VERSION_CHURN = "rapid_version_churn"                 # Shai-Hulud pattern
    MAINTAINER_TAKEOVER = "maintainer_takeover"                 # ownership changed


class SLSALevel(int, Enum):
    """SLSA supply chain security framework levels."""
    NONE = 0
    L1_DOCUMENTED = 1   # Build is scripted
    L2_HOSTED = 2       # Build hosted, provenance available
    L3_HARDENED = 3     # Hardened build, non-forgeable provenance


class RiskTier(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    CLEAN = "clean"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class CommitProvenance:
    """Full provenance record for a single commit."""
    repo: str
    commit_sha: str
    author_email: str
    author_name: str
    committer_email: str
    committer_name: str
    timestamp: str                              # ISO-8601
    message: str
    files_changed: List[str] = field(default_factory=list)
    additions: int = 0
    deletions: int = 0

    # Identity enrichment
    identity_type: IdentityType = IdentityType.UNKNOWN
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    login_ip: Optional[str] = None
    session_verified: bool = False             # MFA/hardware key used?
    gpg_signed: bool = False
    sigstore_signed: bool = False
    verified_by: Optional[str] = None         # "gpg", "sigstore", "github"

    # Behavioral context
    is_first_commit: bool = False
    days_since_account_creation: Optional[int] = None
    contributor_commit_count: int = 0          # Historical count for this author
    commit_hour_utc: Optional[int] = None      # 0-23 — off-hours detection
    previous_geo: Optional[str] = None        # For geo-shift detection

    # Scoring
    anomalies: List[AnomalyType] = field(default_factory=list)
    provenance_score: float = 1.0             # 1.0 = clean, 0.0 = critical risk


@dataclass
class ArtifactAttestation:
    """Attestation record for a published artifact (package, container, binary)."""
    artifact_name: str
    artifact_version: str
    registry: str                              # pypi, npm, ghcr, dockerhub, etc.
    published_hash: str                        # SHA-256 of what's on the registry
    source_hash: Optional[str] = None         # SHA-256 of reproducible build
    slsa_level: SLSALevel = SLSALevel.NONE
    sigstore_bundle: Optional[str] = None     # base64 Sigstore bundle
    sbom_sha: Optional[str] = None            # SBOM document hash (supplemental)

    # Verification results
    hash_match: Optional[bool] = None          # published_hash == source_hash
    sigstore_valid: Optional[bool] = None
    build_reproducible: Optional[bool] = None

    # Metadata
    publisher_identity: IdentityType = IdentityType.UNKNOWN
    published_at: str = ""
    build_system: Optional[str] = None        # "github-actions", "jenkins", etc.

    anomalies: List[AnomalyType] = field(default_factory=list)
    risk_tier: RiskTier = RiskTier.CLEAN


@dataclass
class DependencyRisk:
    """Risk record for a single dependency in the dependency graph."""
    name: str
    version: str
    ecosystem: str                             # "pypi", "npm", "cargo", etc.
    registry_url: str = ""
    is_direct: bool = True
    depth: int = 0                             # 0 = direct, 1+ = transitive

    # Vulnerability data
    known_cves: List[str] = field(default_factory=list)
    max_cvss: float = 0.0
    actively_exploited: bool = False

    # Provenance data
    attestation: Optional[ArtifactAttestation] = None
    anomalies: List[AnomalyType] = field(default_factory=list)
    risk_tier: RiskTier = RiskTier.CLEAN

    # Typosquatting detection
    similar_to: Optional[str] = None          # If name is suspiciously similar
    edit_distance: Optional[int] = None


@dataclass
class ProvenanceEvent:
    """A single event in the provenance event log."""
    event_id: str
    event_type: str                            # "commit", "artifact_publish", "deploy", "ci_run"
    timestamp: str
    actor: str
    actor_identity_type: IdentityType
    repo: Optional[str] = None
    artifact: Optional[str] = None
    risk_tier: RiskTier = RiskTier.CLEAN
    anomalies: List[AnomalyType] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvenanceScore:
    """Aggregated provenance risk score for a repo or artifact."""
    subject: str                               # repo URL or artifact name
    overall_score: float                       # 0.0 (critical) – 1.0 (clean)
    risk_tier: RiskTier = RiskTier.CLEAN
    commit_score: float = 1.0
    artifact_score: float = 1.0
    dependency_score: float = 1.0
    anomalies: List[AnomalyType] = field(default_factory=list)
    blocked: bool = False                      # Deploy blocked by policy
    reasons: List[str] = field(default_factory=list)
    evaluated_at: str = ""


# ---------------------------------------------------------------------------
# Behavioral Analysis
# ---------------------------------------------------------------------------

class BehavioralAnalyzer:
    """
    Detects supply chain attack patterns by analyzing contributor behavior.

    Key patterns detected:
      - XZ-style: new account, builds trust over months, small commits first,
        then injects backdoor in a release artifact that doesn't match source.
      - Shai-Hulud: rapid version churn, compromised maintainer creds,
        500+ packages infected via self-replicating publish loop.
      - s1ngularity: credential theft, foreign-geo publish of malicious version.
      - Dependency confusion: private package names squatted on public registry.
    """

    # Heuristic thresholds
    NEW_CONTRIBUTOR_DAYS = 180            # Account <6mo is flagged for extra scrutiny
    FAST_TRUST_COMMIT_RATIO = 0.15       # If contributor jumps to >15% of commits fast
    OFF_HOURS_START = 0                   # UTC hours considered "off hours"
    OFF_HOURS_END = 5
    GEO_SHIFT_RISK_COUNTRIES = {          # Countries with high APT activity targeting OSS
        "KP", "CN", "RU", "IR", "BY"
    }
    RAPID_CHURN_WINDOW_HOURS = 24
    RAPID_CHURN_MIN_VERSIONS = 5         # 5+ versions in 24h = suspicious

    def score_commit(self, commit: CommitProvenance) -> Tuple[float, List[AnomalyType]]:
        """Return (0.0-1.0 score, detected anomalies). Lower score = higher risk."""
        score = 1.0
        anomalies = []

        # ── Identity verification ────────────────────────────────────────────
        if not commit.gpg_signed and not commit.sigstore_signed:
            score -= 0.15
            anomalies.append(AnomalyType.UNSIGNED_ARTIFACT)

        # ── New contributor fast trust (XZ pattern) ──────────────────────────
        if (commit.days_since_account_creation is not None
                and commit.days_since_account_creation < self.NEW_CONTRIBUTOR_DAYS):
            if commit.contributor_commit_count > 50:  # New account, many commits fast
                score -= 0.30
                anomalies.append(AnomalyType.NEW_CONTRIBUTOR_FAST_TRUST)
            else:
                score -= 0.10  # New contributor, minor penalty

        # ── Off-hours geo shift ──────────────────────────────────────────────
        if commit.commit_hour_utc is not None:
            if self.OFF_HOURS_START <= commit.commit_hour_utc <= self.OFF_HOURS_END:
                if (commit.geo_country in self.GEO_SHIFT_RISK_COUNTRIES
                        or commit.previous_geo != commit.geo_country):
                    score -= 0.25
                    anomalies.append(AnomalyType.OFF_HOURS_GEO_SHIFT)

        # ── Behavioral drift ─────────────────────────────────────────────────
        # Large deletion spike from historically small committer
        if commit.contributor_commit_count > 10 and commit.deletions > 500:
            score -= 0.15
            anomalies.append(AnomalyType.BEHAVIORAL_DRIFT)

        # ── Unverified session ───────────────────────────────────────────────
        if not commit.session_verified:
            score -= 0.10

        return max(0.0, score), anomalies

    def score_artifact(self, attestation: ArtifactAttestation) -> Tuple[float, List[AnomalyType]]:
        """Score a published artifact."""
        score = 1.0
        anomalies = []

        if attestation.hash_match is False:
            # Artifact doesn't match reproducible build — XZ-style drift
            score -= 0.50
            anomalies.append(AnomalyType.BUILD_ARTIFACT_MISMATCH)

        if attestation.slsa_level < SLSALevel.L2_HOSTED:
            score -= 0.20
            anomalies.append(AnomalyType.SLSA_VIOLATION)

        if not attestation.sigstore_valid:
            score -= 0.15
            anomalies.append(AnomalyType.UNSIGNED_ARTIFACT)

        if attestation.publisher_identity == IdentityType.UNKNOWN:
            score -= 0.10

        return max(0.0, score), anomalies

    def score_dependency(self, dep: DependencyRisk) -> Tuple[float, List[AnomalyType]]:
        """Score a dependency entry."""
        score = 1.0
        anomalies = []

        if dep.actively_exploited:
            score -= 0.60
        elif dep.max_cvss >= 9.0:
            score -= 0.40
        elif dep.max_cvss >= 7.0:
            score -= 0.20
        elif dep.max_cvss >= 4.0:
            score -= 0.10

        if dep.edit_distance is not None and dep.edit_distance <= 2:
            score -= 0.30
            anomalies.append(AnomalyType.TYPOSQUATTING)

        if dep.attestation and dep.attestation.anomalies:
            score -= 0.15 * len(dep.attestation.anomalies)
            anomalies.extend(dep.attestation.anomalies)

        return max(0.0, score), anomalies

    @staticmethod
    def tier_from_score(score: float) -> RiskTier:
        if score >= 0.85:
            return RiskTier.CLEAN
        if score >= 0.65:
            return RiskTier.LOW
        if score >= 0.45:
            return RiskTier.MEDIUM
        if score >= 0.25:
            return RiskTier.HIGH
        return RiskTier.CRITICAL


# ---------------------------------------------------------------------------
# Typosquatting detector
# ---------------------------------------------------------------------------

class TyposquattingDetector:
    """
    Detects dependency confusion and typosquatting attacks.
    Uses edit distance (Levenshtein) against a known-good package list.
    """

    # Top packages most commonly targeted by typosquatters (npm + PyPI)
    TOP_PACKAGES = {
        "pypi": [
            "requests", "numpy", "pandas", "scipy", "django", "flask",
            "fastapi", "pydantic", "boto3", "cryptography", "paramiko",
            "pillow", "sqlalchemy", "pytest", "setuptools", "pip", "wheel",
            "urllib3", "certifi", "charset-normalizer", "idna",
        ],
        "npm": [
            "react", "lodash", "axios", "express", "typescript", "webpack",
            "babel", "jest", "eslint", "prettier", "moment", "chalk",
            "commander", "yargs", "dotenv", "uuid", "semver", "glob",
            "rimraf", "cross-env", "concurrently",
        ],
    }

    def levenshtein(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self.levenshtein(s2, s1)
        if not s2:
            return len(s1)
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                                prev[j] + (c1 != c2)))
            prev = curr
        return prev[-1]

    def check(self, name: str, ecosystem: str) -> Optional[Tuple[str, int]]:
        """Return (closest_match, edit_distance) if suspicious, else None."""
        known = self.TOP_PACKAGES.get(ecosystem, [])
        best_match = None
        best_dist = 999
        for pkg in known:
            d = self.levenshtein(name.lower(), pkg.lower())
            if d < best_dist:
                best_dist = d
                best_match = pkg
        if best_match and best_dist <= 2 and name.lower() != best_match.lower():
            return best_match, best_dist
        return None


# ---------------------------------------------------------------------------
# Registry integrity monitor
# ---------------------------------------------------------------------------

class RegistryIntegrityMonitor:
    """
    Compares the published artifact hash on a package registry against
    the expected hash from a local lockfile or reproducible build.

    Supports: PyPI, npm (extensible to cargo, rubygems, maven).
    """

    def fetch_pypi_hash(self, package: str, version: str) -> Optional[str]:
        """Fetch SHA-256 of the sdist/wheel from PyPI JSON API."""
        try:
            url = f"https://pypi.org/pypi/{package}/{version}/json"
            req = urllib.request.Request(url, headers={"User-Agent": "AegisAI/3.1"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            # Prefer the wheel hash, fall back to sdist
            urls = data.get("urls", [])
            for u in urls:
                if u.get("packagetype") == "bdist_wheel":
                    for dig in u.get("digests", {}).values():
                        return dig
            for u in urls:
                for dig in u.get("digests", {}).values():
                    return dig
        except Exception as exc:
            logger.debug("PyPI hash fetch failed for %s==%s: %s", package, version, exc)
        return None

    def fetch_npm_hash(self, package: str, version: str) -> Optional[str]:
        """Fetch integrity hash from npm registry."""
        try:
            url = f"https://registry.npmjs.org/{urllib.parse.quote(package)}/{version}"
            req = urllib.request.Request(url, headers={"User-Agent": "AegisAI/3.1"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            return data.get("dist", {}).get("integrity")  # SRI hash
        except Exception as exc:
            logger.debug("npm hash fetch failed for %s@%s: %s", package, version, exc)
        return None

    def verify(self, dep: DependencyRisk,
               expected_hash: Optional[str] = None) -> ArtifactAttestation:
        """Fetch registry hash and compare against expected (lockfile) hash."""
        attestation = ArtifactAttestation(
            artifact_name=dep.name,
            artifact_version=dep.version,
            registry=dep.registry_url or dep.ecosystem,
            published_hash="",
        )

        # Fetch
        if dep.ecosystem == "pypi":
            attestation.published_hash = self.fetch_pypi_hash(dep.name, dep.version) or ""
        elif dep.ecosystem == "npm":
            attestation.published_hash = self.fetch_npm_hash(dep.name, dep.version) or ""

        # Compare
        if expected_hash and attestation.published_hash:
            attestation.hash_match = (attestation.published_hash == expected_hash)
            if not attestation.hash_match:
                attestation.anomalies.append(AnomalyType.BUILD_ARTIFACT_MISMATCH)
                attestation.risk_tier = RiskTier.CRITICAL

        return attestation


# ---------------------------------------------------------------------------
# Main Engine
# ---------------------------------------------------------------------------

class SupplyChainEngine:
    """
    Central supply chain security orchestrator.

    Ingests:
      - Commit webhooks (GitHub/GitLab)
      - Artifact attestation records
      - Dependency manifests (requirements.txt, package.json, etc.)

    Produces:
      - Per-commit ProvenanceScore
      - Per-artifact ArtifactAttestation with risk scoring
      - Per-dependency DependencyRisk records
      - Aggregate ProvenanceScore for a repo/deployment
      - Deploy gate decision (block/allow based on policy threshold)
    """

    def __init__(self, policy_threshold: float = 0.60):
        """
        Args:
            policy_threshold: Minimum provenance score to allow a deploy.
                              Below this, the deploy is blocked.
        """
        self.policy_threshold = policy_threshold
        self.analyzer = BehavioralAnalyzer()
        self.typosquatting = TyposquattingDetector()
        self.registry_monitor = RegistryIntegrityMonitor()
        self._event_log: List[ProvenanceEvent] = []
        logger.info("SupplyChainEngine initialized (threshold=%.2f)", policy_threshold)

    # ── Commit ingestion ────────────────────────────────────────────────────

    def ingest_commit(self, commit_data: Dict[str, Any]) -> CommitProvenance:
        """
        Ingest a raw commit payload (GitHub/GitLab webhook format) and
        return an enriched CommitProvenance with behavioral analysis applied.
        """
        commit = CommitProvenance(
            repo=commit_data.get("repository", {}).get("full_name", "unknown"),
            commit_sha=commit_data.get("after", commit_data.get("id", "")),
            author_email=commit_data.get("head_commit", {}).get("author", {}).get("email", ""),
            author_name=commit_data.get("head_commit", {}).get("author", {}).get("name", ""),
            committer_email=commit_data.get("head_commit", {}).get("committer", {}).get("email", ""),
            committer_name=commit_data.get("head_commit", {}).get("committer", {}).get("name", ""),
            timestamp=commit_data.get("head_commit", {}).get("timestamp", datetime.now(timezone.utc).isoformat()),
            message=commit_data.get("head_commit", {}).get("message", ""),
            files_changed=commit_data.get("head_commit", {}).get("modified", []),
            additions=commit_data.get("head_commit", {}).get("added", []),
        )

        # Detect machine identity
        commit.identity_type = self._detect_identity(commit.author_email, commit.author_name)

        # Extract commit hour for off-hours detection
        try:
            dt = datetime.fromisoformat(commit.timestamp.replace("Z", "+00:00"))
            commit.commit_hour_utc = dt.hour
        except (ValueError, AttributeError):
            pass

        # Run behavioral analysis
        score, anomalies = self.analyzer.score_commit(commit)
        commit.provenance_score = score
        commit.anomalies = anomalies

        # Log event
        self._log_event(ProvenanceEvent(
            event_id=hashlib.sha256(f"{commit.repo}:{commit.commit_sha}".encode()).hexdigest()[:16],
            event_type="commit",
            timestamp=commit.timestamp,
            actor=commit.author_email,
            actor_identity_type=commit.identity_type,
            repo=commit.repo,
            risk_tier=self.analyzer.tier_from_score(score),
            anomalies=anomalies,
            metadata={"sha": commit.commit_sha, "score": score},
        ))

        if score < self.policy_threshold:
            logger.warning(
                "Commit provenance below threshold: %s in %s (score=%.2f, anomalies=%s)",
                commit.commit_sha[:8], commit.repo, score,
                [a.value for a in anomalies]
            )

        return commit

    def _detect_identity(self, email: str, name: str) -> IdentityType:
        """Heuristic human vs machine identity detection from commit metadata."""
        machine_patterns = [
            r"bot@", r"bot\+", r"\[bot\]", r"github-actions",
            r"dependabot", r"renovate", r"actions@github", r"noreply",
            r"automated", r"ci@", r"cd@", r"deploy@", r"robot@",
            r"service-account", r"svc-", r"automation@",
        ]
        combined = f"{email} {name}".lower()
        for pat in machine_patterns:
            if re.search(pat, combined):
                return IdentityType.MACHINE
        return IdentityType.HUMAN

    # ── Dependency analysis ─────────────────────────────────────────────────

    def analyze_dependencies(self, dependencies: List[Dict[str, Any]]) -> List[DependencyRisk]:
        """
        Analyze a list of dependency dicts:
          [{"name": "requests", "version": "2.31.0", "ecosystem": "pypi", ...}]
        """
        results = []
        for dep_data in dependencies:
            dep = DependencyRisk(
                name=dep_data["name"],
                version=dep_data.get("version", "unknown"),
                ecosystem=dep_data.get("ecosystem", "unknown"),
                registry_url=dep_data.get("registry_url", ""),
                is_direct=dep_data.get("is_direct", True),
                depth=dep_data.get("depth", 0),
                known_cves=dep_data.get("cves", []),
                max_cvss=dep_data.get("max_cvss", 0.0),
                actively_exploited=dep_data.get("actively_exploited", False),
            )

            # Typosquatting check
            match = self.typosquatting.check(dep.name, dep.ecosystem)
            if match:
                dep.similar_to, dep.edit_distance = match
                dep.anomalies.append(AnomalyType.TYPOSQUATTING)

            # Dependency confusion check (private-sounding names on public registries)
            if self._looks_like_internal_name(dep.name):
                dep.anomalies.append(AnomalyType.DEPENDENCY_CONFUSION)

            # Behavioral scoring
            score, anomalies = self.analyzer.score_dependency(dep)
            dep.anomalies.extend([a for a in anomalies if a not in dep.anomalies])
            dep.risk_tier = self.analyzer.tier_from_score(score)
            results.append(dep)

        return results

    def _looks_like_internal_name(self, name: str) -> bool:
        """Flag names that look like internal/private packages (common confusion targets)."""
        internal_patterns = [
            r"^internal-", r"^private-", r"^corp-", r"-internal$",
            r"^company-", r"^org-", r"^enterprise-",
        ]
        for pat in internal_patterns:
            if re.search(pat, name.lower()):
                return True
        return False

    # ── Artifact attestation ────────────────────────────────────────────────

    def attest_artifact(self, name: str, version: str, ecosystem: str,
                        expected_hash: Optional[str] = None,
                        slsa_level: int = 0,
                        sigstore_bundle: Optional[str] = None) -> ArtifactAttestation:
        """
        Verify a published artifact against its source and return an attestation.
        """
        dep = DependencyRisk(name=name, version=version, ecosystem=ecosystem)
        attestation = self.registry_monitor.verify(dep, expected_hash)
        attestation.slsa_level = SLSALevel(min(slsa_level, 3))
        attestation.sigstore_bundle = sigstore_bundle
        attestation.sigstore_valid = sigstore_bundle is not None  # Stub: real impl validates bundle

        score, anomalies = self.analyzer.score_artifact(attestation)
        attestation.anomalies.extend(anomalies)
        attestation.risk_tier = self.analyzer.tier_from_score(score)
        return attestation

    # ── Aggregate scoring ───────────────────────────────────────────────────

    def score_deployment(self, repo: str,
                         commits: Optional[List[CommitProvenance]] = None,
                         dependencies: Optional[List[DependencyRisk]] = None,
                         artifacts: Optional[List[ArtifactAttestation]] = None) -> ProvenanceScore:
        """
        Compute an aggregate ProvenanceScore for a deployment.
        This is the deploy gate decision: if .blocked is True, the deploy fails.
        """
        reasons: List[str] = []
        all_anomalies: List[AnomalyType] = []

        # Commit score (average of all commits)
        commit_score = 1.0
        if commits:
            commit_score = sum(c.provenance_score for c in commits) / len(commits)
            for c in commits:
                all_anomalies.extend(c.anomalies)
                if c.provenance_score < self.policy_threshold:
                    reasons.append(f"Commit {c.commit_sha[:8]} by {c.author_email} "
                                   f"scored {c.provenance_score:.2f} "
                                   f"(anomalies: {[a.value for a in c.anomalies]})")

        # Artifact score
        artifact_score = 1.0
        if artifacts:
            scores = []
            for a in artifacts:
                s, anoms = self.analyzer.score_artifact(a)
                scores.append(s)
                all_anomalies.extend(anoms)
                if s < self.policy_threshold:
                    reasons.append(f"Artifact {a.artifact_name}=={a.artifact_version} "
                                   f"scored {s:.2f} (anomalies: {[x.value for x in anoms]})")
            artifact_score = sum(scores) / len(scores) if scores else 1.0

        # Dependency score
        dep_score = 1.0
        if dependencies:
            scores = []
            for d in dependencies:
                s, _ = self.analyzer.score_dependency(d)
                scores.append(s)
                all_anomalies.extend(d.anomalies)
                if s < self.policy_threshold:
                    reasons.append(f"Dependency {d.name}=={d.version} "
                                   f"scored {s:.2f} (anomalies: {[a.value for a in d.anomalies]})")
            dep_score = sum(scores) / len(scores) if scores else 1.0

        # Weighted aggregate: commits 40%, artifacts 35%, deps 25%
        overall = (commit_score * 0.40 + artifact_score * 0.35 + dep_score * 0.25)

        # De-duplicate anomalies
        unique_anomalies = list(dict.fromkeys(all_anomalies))

        result = ProvenanceScore(
            subject=repo,
            overall_score=overall,
            risk_tier=self.analyzer.tier_from_score(overall),
            commit_score=commit_score,
            artifact_score=artifact_score,
            dependency_score=dep_score,
            anomalies=unique_anomalies,
            blocked=overall < self.policy_threshold,
            reasons=reasons,
            evaluated_at=datetime.now(timezone.utc).isoformat(),
        )

        if result.blocked:
            logger.warning(
                "DEPLOY BLOCKED for %s — provenance score %.2f < threshold %.2f. Reasons: %s",
                repo, overall, self.policy_threshold, reasons
            )
        else:
            logger.info("Deploy approved for %s (score=%.2f)", repo, overall)

        return result

    # ── Event log ──────────────────────────────────────────────────────────

    def _log_event(self, event: ProvenanceEvent):
        self._event_log.append(event)
        # Keep last 10k events in memory; ClickHouse ingestion handled by telemetry engine
        if len(self._event_log) > 10_000:
            self._event_log = self._event_log[-5_000:]

    def get_events(self, limit: int = 100,
                   risk_tier: Optional[str] = None) -> List[ProvenanceEvent]:
        events = self._event_log
        if risk_tier:
            events = [e for e in events if e.risk_tier.value == risk_tier]
        return events[-limit:]

    def get_summary(self) -> Dict[str, Any]:
        total = len(self._event_log)
        by_tier: Dict[str, int] = {}
        for e in self._event_log:
            by_tier[e.risk_tier.value] = by_tier.get(e.risk_tier.value, 0) + 1
        return {
            "total_events": total,
            "by_risk_tier": by_tier,
            "policy_threshold": self.policy_threshold,
        }


# ---------------------------------------------------------------------------
# Module-level singleton (lazily initialized)
# ---------------------------------------------------------------------------

import urllib.parse  # noqa: E402  (needed above, imported here for stdlib cleanliness)

_engine: Optional[SupplyChainEngine] = None


def get_engine() -> SupplyChainEngine:
    global _engine
    if _engine is None:
        threshold = float(os.getenv("SUPPLY_CHAIN_THRESHOLD", "0.60"))
        _engine = SupplyChainEngine(policy_threshold=threshold)
    return _engine
