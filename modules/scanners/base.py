"""
Abstract base classes shared by all scanner implementations.

v2.3: Finding enriched with MITRE ATT&CK technique IDs, tactic, CWE, and
NIST 800-53 control references so every finding is automatically compliance-mapped.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


@dataclass
class Finding:
    """
    A single security issue detected during a scan.

    ATT&CK fields (v2.3):
      mitre_techniques  — list of technique IDs, e.g. ["T1530", "T1078.004"]
      mitre_tactic      — primary tactic, e.g. "collection", "initial-access"
      nist_controls     — NIST 800-53 Rev5 controls violated, e.g. ["SC-7", "AC-3"]
      cwe_id            — CWE number string, e.g. "CWE-732"
    """

    resource: str           # Identifier of the affected resource
    issue: str              # Short description of the problem
    severity: str           # "critical" | "high" | "medium" | "low" | "info"
    provider: str           # "aws" | "azure" | "gcp" | "network" | "k8s" | "iac"
    region: Optional[str] = None
    resource_type: Optional[str] = None
    details: dict = field(default_factory=dict)
    remediation_hint: Optional[str] = None
    # MITRE ATT&CK + compliance mapping
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactic: Optional[str] = None
    nist_controls: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "resource":          self.resource,
            "issue":             self.issue,
            "severity":          self.severity,
            "provider":          self.provider,
            "region":            self.region,
            "resource_type":     self.resource_type,
            "details":           self.details,
            "remediation_hint":  self.remediation_hint,
            "mitre_techniques":  self.mitre_techniques,
            "mitre_tactic":      self.mitre_tactic,
            "nist_controls":     self.nist_controls,
            "cwe_id":            self.cwe_id,
            "timestamp":         self.timestamp,
        }


class BaseScanner(ABC):
    """Abstract base class that all cloud/network scanners must implement."""

    provider: str = "unknown"

    @abstractmethod
    def scan(self) -> List[Finding]:
        """Run all checks and return a list of Findings."""
        ...

    def is_available(self) -> bool:
        """
        Return True if this scanner's dependencies and credentials are present.
        Called before scan() to decide whether to include this scanner in a run.
        """
        return True
