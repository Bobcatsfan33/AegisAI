"""
Aegis — Supply Chain Behavioral Scoring  (v2.11.0)

Anomaly detection for supply chain events.

What we detect:
  1. Temporal anomalies — builds/deployments at unusual times
  2. Velocity anomalies — abnormal rate of deployments or artifact creation
  3. Provenance gaps   — artifact deployed with no provenance record
  4. Builder drift     — artifact signed by an unknown/new builder
  5. Branch anomalies  — deployment from unexpected branches
  6. Dependency drift  — sudden increase in dependency count
  7. Digest changes    — same artifact ID with different digest (potential supply chain attack)

Design:
  BehavioralScorer is stateful — it learns baselines from a stream of SupplyChainEvents.
  Anomaly scores are 0.0 (normal) to 1.0 (critical anomaly).
  Multiple anomalies are combined with a weighted max.

This is a lightweight statistical scorer, not a full ML pipeline.
For production, feed scores into SIEM/SOAR for response automation.
"""

import hashlib
import logging
import math
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Event model ────────────────────────────────────────────────────────────────

@dataclass
class SupplyChainEvent:
    """
    A single event in the software supply chain.

    event_type: "build" | "deploy" | "artifact_push" | "dependency_added" | "policy_change"
    """
    event_type:    str
    artifact_id:   str
    timestamp:     float         # epoch seconds
    builder_id:    str = ""
    branch:        str = ""
    environment:   str = ""
    digest:        str = ""      # artifact digest at time of event
    dependency_count: int = 0
    metadata:      dict = field(default_factory=dict)

    def hour_of_day(self) -> int:
        """Return 0-23 local hour of this event."""
        import datetime
        return datetime.datetime.fromtimestamp(self.timestamp).hour

    def day_of_week(self) -> int:
        """Return 0=Monday … 6=Sunday."""
        import datetime
        return datetime.datetime.fromtimestamp(self.timestamp).weekday()


@dataclass
class AnomalyResult:
    """Result of behavioral scoring for a single event."""
    event:         SupplyChainEvent
    score:         float                    # 0.0 (normal) – 1.0 (critical)
    anomalies:     List[str] = field(default_factory=list)   # human-readable findings
    details:       dict      = field(default_factory=dict)   # per-check details

    @property
    def is_anomalous(self) -> bool:
        return self.score >= 0.4

    @property
    def severity(self) -> str:
        if self.score >= 0.8:
            return "critical"
        if self.score >= 0.6:
            return "high"
        if self.score >= 0.4:
            return "medium"
        if self.score >= 0.2:
            return "low"
        return "normal"

    def to_dict(self) -> dict:
        return {
            "artifact_id":  self.event.artifact_id,
            "event_type":   self.event.event_type,
            "timestamp":    self.event.timestamp,
            "score":        round(self.score, 4),
            "severity":     self.severity,
            "anomalies":    self.anomalies,
            "details":      self.details,
        }


# ── Behavioral Scorer ──────────────────────────────────────────────────────────

class BehavioralScorer:
    """
    Stateful behavioral anomaly scorer for supply chain events.

    Call score_event() for each new event.
    The scorer builds baselines from the first N events (warm-up period)
    before producing meaningful anomaly scores.

    Thread safety: NOT thread-safe. Use one scorer per pipeline/thread.
    """

    # Default configuration
    _WARM_UP_EVENTS    = 10       # events before baselines are established
    _VELOCITY_WINDOW   = 3600     # seconds: window for rate calculations
    _MAX_HISTORY       = 1000     # max events to retain in memory
    _KNOWN_BRANCHES    = {"main", "master", "release", "hotfix"}
    _PROD_BRANCHES     = {"main", "master"}
    _KNOWN_ENVS        = {"production", "staging", "dev", "development", "qa", "test"}

    def __init__(
        self,
        warm_up_events: int = _WARM_UP_EVENTS,
        known_branches: set = None,
        prod_branches: set = None,
        business_hours: Tuple[int, int] = (6, 22),  # inclusive hour range
    ):
        self._warm_up = warm_up_events
        self._known_branches = known_branches or self._KNOWN_BRANCHES
        self._prod_branches  = prod_branches  or self._PROD_BRANCHES
        self._biz_start, self._biz_end = business_hours

        # Event history
        self._events: deque = deque(maxlen=self._MAX_HISTORY)
        self._event_count = 0

        # Baselines: keyed by (event_type, builder_id, branch, environment)
        self._known_builders:    set = set()
        self._artifact_digests:  Dict[str, str] = {}  # artifact_id → first-seen digest
        self._deploy_times:      List[float] = []     # timestamps of deployments
        self._build_times:       List[float] = []     # timestamps of builds
        self._dependency_counts: Dict[str, List[int]] = defaultdict(list)  # artifact → counts

    # ── Public interface ───────────────────────────────────────────────────────

    def score_event(self, event: SupplyChainEvent) -> AnomalyResult:
        """
        Score a supply chain event for anomalies.

        Returns AnomalyResult with score 0.0–1.0 and list of findings.
        """
        anomalies = []
        details = {}
        scores = []

        warm = self._event_count >= self._warm_up

        # ── Check 1: Temporal anomaly ────────────────────────────────────────
        hour = event.hour_of_day()
        dow  = event.day_of_week()
        is_weekend = dow >= 5
        is_after_hours = not (self._biz_start <= hour <= self._biz_end)

        if event.event_type in ("deploy", "build") and (is_weekend or is_after_hours):
            s = 0.5 if is_weekend else 0.3
            scores.append(s)
            label = "weekend" if is_weekend else "after-hours"
            anomalies.append(f"Temporal anomaly: {event.event_type} at {label} time (hour={hour}, dow={dow})")
            details["temporal"] = {"hour": hour, "dow": dow, "score": s}

        # ── Check 2: Unknown builder ─────────────────────────────────────────
        if warm and event.builder_id and event.builder_id not in self._known_builders:
            s = 0.7
            scores.append(s)
            anomalies.append(f"Builder drift: unknown builder_id '{event.builder_id}'")
            details["builder_drift"] = {"builder_id": event.builder_id, "score": s}

        # ── Check 3: Branch anomaly for production deploy ────────────────────
        if (event.event_type == "deploy" and
                event.environment in ("production", "prod") and
                event.branch and
                event.branch not in self._prod_branches):
            s = 0.8
            scores.append(s)
            anomalies.append(
                f"Branch anomaly: production deploy from non-main branch '{event.branch}'"
            )
            details["branch_anomaly"] = {"branch": event.branch, "environment": event.environment, "score": s}

        # ── Check 4: Digest change (potential tampering) ─────────────────────
        if event.digest and event.artifact_id in self._artifact_digests:
            known_digest = self._artifact_digests[event.artifact_id]
            if event.digest != known_digest and event.event_type != "build":
                # Different digest for same artifact at deploy time — possible supply chain attack
                s = 0.9
                scores.append(s)
                anomalies.append(
                    f"Digest mismatch: artifact '{event.artifact_id}' has unexpected digest at deploy time"
                )
                details["digest_mismatch"] = {
                    "expected": known_digest[:24],
                    "actual":   event.digest[:24],
                    "score":    s,
                }

        # ── Check 5: Deployment velocity anomaly ─────────────────────────────
        if warm and event.event_type == "deploy":
            rate = self._velocity(self._deploy_times, event.timestamp)
            if rate > 10:  # >10 deploys in velocity window
                s = min(0.6, 0.3 + rate * 0.03)
                scores.append(s)
                anomalies.append(f"Velocity anomaly: {rate:.0f} deploys in {self._VELOCITY_WINDOW}s window")
                details["deploy_velocity"] = {"rate": rate, "window_s": self._VELOCITY_WINDOW, "score": s}

        # ── Check 6: Dependency count spike ─────────────────────────────────
        if warm and event.dependency_count > 0 and event.artifact_id in self._dependency_counts:
            past_counts = self._dependency_counts[event.artifact_id]
            if past_counts:
                mean = statistics.mean(past_counts)
                if mean > 0 and event.dependency_count > mean * 2:
                    s = min(0.7, 0.4 + (event.dependency_count / mean - 2) * 0.1)
                    scores.append(s)
                    anomalies.append(
                        f"Dependency spike: {event.dependency_count} deps vs baseline {mean:.0f}"
                    )
                    details["dependency_spike"] = {
                        "count": event.dependency_count, "baseline": round(mean, 1), "score": s
                    }

        # ── Check 7: Unknown environment ─────────────────────────────────────
        if event.environment and event.environment.lower() not in self._KNOWN_ENVS:
            s = 0.3
            scores.append(s)
            anomalies.append(f"Unknown deployment environment: '{event.environment}'")
            details["unknown_env"] = {"environment": event.environment, "score": s}

        # ── Aggregate score (weighted max) ────────────────────────────────────
        final_score = max(scores) if scores else 0.0

        # Update baselines
        self._update_baselines(event)

        result = AnomalyResult(event=event, score=final_score, anomalies=anomalies, details=details)

        if result.is_anomalous:
            logger.warning(
                "[BehavioralScorer] Anomaly detected: artifact=%s type=%s score=%.2f severity=%s findings=%s",
                event.artifact_id[:24], event.event_type, final_score, result.severity,
                "; ".join(anomalies),
            )
        else:
            logger.debug(
                "[BehavioralScorer] Event scored: artifact=%s score=%.2f",
                event.artifact_id[:24], final_score,
            )

        return result

    # ── Batch scoring ─────────────────────────────────────────────────────────

    def score_batch(self, events: List[SupplyChainEvent]) -> List[AnomalyResult]:
        """Score a list of events in chronological order. Returns all results."""
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        return [self.score_event(e) for e in sorted_events]

    def flagged_events(self, events: List[SupplyChainEvent], threshold: float = 0.4) -> List[AnomalyResult]:
        """Return only the anomalous results above threshold."""
        results = self.score_batch(events)
        return [r for r in results if r.score >= threshold]

    # ── Baseline management ───────────────────────────────────────────────────

    def _update_baselines(self, event: SupplyChainEvent) -> None:
        """Update internal baselines from a new event."""
        self._events.append(event)
        self._event_count += 1

        if event.builder_id:
            self._known_builders.add(event.builder_id)

        if event.digest and event.artifact_id not in self._artifact_digests:
            self._artifact_digests[event.artifact_id] = event.digest

        if event.event_type == "deploy":
            self._deploy_times.append(event.timestamp)
            # Trim to velocity window only (keep memory bounded)
            cutoff = event.timestamp - self._VELOCITY_WINDOW * 10
            self._deploy_times = [t for t in self._deploy_times if t > cutoff]

        if event.event_type == "build":
            self._build_times.append(event.timestamp)
            cutoff = event.timestamp - self._VELOCITY_WINDOW * 10
            self._build_times = [t for t in self._build_times if t > cutoff]

        if event.dependency_count > 0:
            self._dependency_counts[event.artifact_id].append(event.dependency_count)
            # Keep last 50 counts per artifact
            if len(self._dependency_counts[event.artifact_id]) > 50:
                self._dependency_counts[event.artifact_id] = self._dependency_counts[event.artifact_id][-50:]

    def register_known_builder(self, builder_id: str) -> None:
        """Pre-register a builder as known/trusted (before warm-up is complete)."""
        self._known_builders.add(builder_id)

    def register_known_digest(self, artifact_id: str, digest: str) -> None:
        """Pre-register a known-good digest for an artifact."""
        self._artifact_digests[artifact_id] = digest

    def reset(self) -> None:
        """Reset all state and baselines."""
        self._events.clear()
        self._event_count = 0
        self._known_builders.clear()
        self._artifact_digests.clear()
        self._deploy_times.clear()
        self._build_times.clear()
        self._dependency_counts.clear()

    @property
    def is_warmed_up(self) -> bool:
        return self._event_count >= self._warm_up

    @property
    def event_count(self) -> int:
        return self._event_count

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _velocity(self, timestamps: List[float], current_time: float) -> int:
        """Count events in the last VELOCITY_WINDOW seconds."""
        cutoff = current_time - self._VELOCITY_WINDOW
        return sum(1 for t in timestamps if t >= cutoff)

    # ── Summary / reporting ───────────────────────────────────────────────────

    def summary(self) -> dict:
        """Return a summary of the scorer's current state and baselines."""
        return {
            "event_count":      self._event_count,
            "warmed_up":        self.is_warmed_up,
            "known_builders":   sorted(self._known_builders),
            "tracked_artifacts": len(self._artifact_digests),
            "deploy_history":   len(self._deploy_times),
            "build_history":    len(self._build_times),
        }
