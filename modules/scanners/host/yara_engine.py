"""
Aegis — YARA Malware Detection Engine  (v2.11.0)
=================================================

Loads YARA rules from the bundled rules/ directory (and any user-supplied
rules directory) and scans files or byte strings for malware patterns.

Gracefully degrades when yara-python is not installed — returns an empty
match list with a logged warning so the rest of the host scanner still runs.

NIST 800-53 Rev5:  SI-3 (Malware Protection), SI-7 (Software Integrity)
MITRE ATT&CK:      Detection for techniques referenced in rule metadata
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False
    logger.warning(
        "yara-python not installed — YARA scanning disabled. "
        "pip install yara-python"
    )

# Default rules directory: <this_file's_dir>/rules/
_DEFAULT_RULES_DIR = Path(__file__).parent / "rules"


@dataclass
class YaraMatch:
    """A single YARA rule hit."""
    rule_name: str
    tags: List[str]
    meta: Dict[str, str]
    strings: List[str]                  # matched string identifiers
    severity: str = "medium"
    mitre_technique: Optional[str] = None
    nist_controls: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_name":       self.rule_name,
            "tags":            self.tags,
            "meta":            self.meta,
            "strings":         self.strings,
            "severity":        self.severity,
            "mitre_technique": self.mitre_technique,
            "nist_controls":   self.nist_controls,
        }


class YaraEngine:
    """
    Compiles YARA rules once at construction and exposes scan_file()
    and scan_bytes() methods.

    Parameters
    ----------
    rules_dirs : list of str | Path
        Additional directories containing .yar / .yara files.
        The bundled rules/ directory is always included.
    """

    def __init__(self, rules_dirs: Optional[List[str]] = None):
        self._compiled = None
        dirs = [str(_DEFAULT_RULES_DIR)]
        if rules_dirs:
            dirs.extend(str(d) for d in rules_dirs)
        self._rules_dirs = dirs
        self._load_rules()

    # ── Rule loading ──────────────────────────────────────────────────────────

    def _load_rules(self):
        if not YARA_AVAILABLE:
            return

        filepaths: Dict[str, str] = {}       # namespace → file path
        for rules_dir in self._rules_dirs:
            p = Path(rules_dir)
            if not p.is_dir():
                logger.debug(f"YARA rules dir not found: {p}")
                continue
            for rule_file in p.glob("**/*.yar"):
                namespace = rule_file.stem
                filepaths[namespace] = str(rule_file)
            for rule_file in p.glob("**/*.yara"):
                namespace = rule_file.stem
                filepaths[namespace] = str(rule_file)

        if not filepaths:
            logger.warning("No YARA rule files found — host scanner running without rules")
            return

        try:
            self._compiled = yara.compile(filepaths=filepaths)
            logger.info(f"YARA engine loaded {len(filepaths)} rule file(s): {list(filepaths.keys())}")
        except yara.SyntaxError as exc:
            logger.error(f"YARA rule compile error: {exc}")
        except Exception as exc:
            logger.error(f"YARA engine init error: {exc}")

    def is_available(self) -> bool:
        return YARA_AVAILABLE and self._compiled is not None

    # ── Scanning ──────────────────────────────────────────────────────────────

    def scan_file(self, file_path: str) -> List[YaraMatch]:
        """Scan a file on disk. Returns [] if YARA unavailable or no match."""
        if not self.is_available():
            return []
        if not os.path.isfile(file_path):
            logger.debug(f"YARA scan: file not found: {file_path}")
            return []
        try:
            raw_matches = self._compiled.match(file_path, timeout=30)
            return [self._convert(m) for m in raw_matches]
        except yara.TimeoutError:
            logger.warning(f"YARA scan timed out on: {file_path}")
            return []
        except Exception as exc:
            logger.error(f"YARA scan error on {file_path}: {exc}")
            return []

    def scan_bytes(self, data: bytes, context: str = "bytes") -> List[YaraMatch]:
        """Scan a byte string (e.g. an in-memory download buffer)."""
        if not self.is_available():
            return []
        try:
            raw_matches = self._compiled.match(data=data, timeout=30)
            return [self._convert(m) for m in raw_matches]
        except yara.TimeoutError:
            logger.warning(f"YARA scan timed out on: {context}")
            return []
        except Exception as exc:
            logger.error(f"YARA scan error on {context}: {exc}")
            return []

    # ── Conversion ────────────────────────────────────────────────────────────

    @staticmethod
    def _convert(raw) -> YaraMatch:
        meta = {k: str(v) for k, v in (raw.meta or {}).items()}
        severity = meta.get("severity", "medium")
        mitre = meta.get("mitre")
        nist_raw = meta.get("nist", "")
        nist = [c.strip() for c in nist_raw.split(",") if c.strip()]

        # Collect matched string identifiers (not values, to avoid data exposure)
        string_ids = list({s.identifier for s in (raw.strings or [])})

        return YaraMatch(
            rule_name=raw.rule,
            tags=list(raw.tags or []),
            meta=meta,
            strings=string_ids,
            severity=severity,
            mitre_technique=mitre,
            nist_controls=nist,
        )
