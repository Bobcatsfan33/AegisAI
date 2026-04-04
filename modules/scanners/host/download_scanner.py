"""
AegisAI — Download Directory Scanner & File Integrity Monitor  (v2.11.0)
========================================================================

Two complementary host-level defences:

1. DownloadScanner — on-demand or scheduled scan of directories (default:
   ~/Downloads, /tmp, /var/tmp) using the YARA engine and SHA-256 hashing.
   Emits Finding objects for any YARA hit.

2. DownloadWatcher — inotify-style filesystem watcher (via watchdog) that
   triggers a YARA scan automatically whenever a new file is created or
   modified in the watched directories. Falls back gracefully when watchdog
   is not installed.

3. FileIntegrityMonitor — maintains a SHA-256 baseline of watched files and
   emits Finding objects whenever a file's hash changes unexpectedly after
   it was first seen (SI-7 File Integrity Monitoring).

NIST 800-53 Rev5:
  SI-3  — Malware Protection
  SI-7  — Software, Firmware, and Information Integrity
  CM-3  — Configuration Change Control
  AU-2  — Event Logging
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from modules.scanners.base import BaseScanner, Finding
from modules.scanners.host.yara_engine import YaraEngine, YaraMatch

logger = logging.getLogger(__name__)

try:
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
    from watchdog.observers import Observer
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logger.warning(
        "watchdog not installed — real-time download watching disabled. "
        "On-demand scanning still works. pip install watchdog"
    )
    # Stub classes so the rest of the module parses cleanly
    class FileSystemEventHandler:
        pass
    class Observer:
        pass

# Default directories to watch / scan
_DEFAULT_WATCH_DIRS = [
    str(Path.home() / "Downloads"),
    "/tmp",
    "/var/tmp",
]

# Extensions to skip (binary media, archives are deferred to AV — YARA is
# better suited for text/script files; large binaries time out)
_SKIP_EXTENSIONS = {
    ".mp4", ".mkv", ".avi", ".mov", ".mp3", ".wav", ".jpg", ".jpeg",
    ".png", ".gif", ".bmp", ".iso",
}

# Maximum file size to scan in-memory (50 MB)
_MAX_SCAN_BYTES = 50 * 1024 * 1024


# ── File integrity ────────────────────────────────────────────────────────────

@dataclass
class FileRecord:
    path: str
    sha256: str
    size: int
    first_seen: str
    last_checked: str
    yara_clean: bool = True
    yara_matches: List[str] = field(default_factory=list)


def _sha256(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


# ── On-demand scanner ─────────────────────────────────────────────────────────

class DownloadScanner(BaseScanner):
    """
    Recursively scans one or more directories for malicious files using YARA.

    Suitable for:
    - Scheduled cron-style scans
    - Single-shot CI/container scan at startup
    - Manual scan trigger via the /host/scan API endpoint

    NIST 800-53:  SI-3, SI-7, AU-2
    """

    provider = "host"

    def __init__(
        self,
        scan_dirs: Optional[List[str]] = None,
        yara_engine: Optional[YaraEngine] = None,
        extra_rules_dirs: Optional[List[str]] = None,
    ):
        self.scan_dirs = scan_dirs or _DEFAULT_WATCH_DIRS
        self._yara = yara_engine or YaraEngine(rules_dirs=extra_rules_dirs)
        self._baseline: Dict[str, FileRecord] = {}
        self._lock = threading.Lock()

    def is_available(self) -> bool:
        return True                         # always available (YARA degrades gracefully)

    # ── BaseScanner.scan() ────────────────────────────────────────────────────

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        for scan_dir in self.scan_dirs:
            p = Path(scan_dir)
            if not p.exists():
                logger.debug(f"DownloadScanner: directory not found: {p}")
                continue
            logger.info(f"DownloadScanner: scanning {p}")
            for filepath in self._walk(p):
                findings.extend(self._scan_file(filepath))
        return findings

    def scan_file(self, filepath: str) -> List[Finding]:
        """Public single-file scan entrypoint."""
        return self._scan_file(filepath)

    # ── Internals ─────────────────────────────────────────────────────────────

    def _walk(self, root: Path):
        for dirpath, _, filenames in os.walk(root, followlinks=False):
            for fname in filenames:
                fp = os.path.join(dirpath, fname)
                ext = Path(fname).suffix.lower()
                if ext in _SKIP_EXTENSIONS:
                    continue
                try:
                    size = os.path.getsize(fp)
                except OSError:
                    continue
                if size > _MAX_SCAN_BYTES:
                    logger.debug(f"Skipping oversized file: {fp} ({size} bytes)")
                    continue
                yield fp

    def _scan_file(self, filepath: str) -> List[Finding]:
        findings: List[Finding] = []
        now = datetime.now(timezone.utc).isoformat()

        sha = _sha256(filepath)
        if sha is None:
            return findings

        # File integrity check — emit finding if hash changed since baseline
        with self._lock:
            existing = self._baseline.get(filepath)
            if existing is None:
                self._baseline[filepath] = FileRecord(
                    path=filepath,
                    sha256=sha,
                    size=os.path.getsize(filepath),
                    first_seen=now,
                    last_checked=now,
                )
            elif existing.sha256 != sha:
                logger.warning(f"File integrity violation: {filepath}")
                findings.append(Finding(
                    resource=filepath,
                    issue=f"File hash changed after baseline: {filepath}",
                    severity="high",
                    provider="host",
                    resource_type="file_integrity",
                    details={
                        "path":         filepath,
                        "old_sha256":   existing.sha256,
                        "new_sha256":   sha,
                        "first_seen":   existing.first_seen,
                        "changed_at":   now,
                    },
                    remediation_hint=(
                        "Verify whether this file modification was authorised. "
                        "If unexpected, quarantine the file and investigate."
                    ),
                    mitre_techniques=["T1565.001"],
                    mitre_tactic="impact",
                    nist_controls=["SI-7", "CM-3", "AU-2"],
                    cwe_id="CWE-345",
                ))
                # Update baseline to new hash (one alert per change)
                existing.sha256 = sha
                existing.last_checked = now

        # YARA scan
        matches: List[YaraMatch] = self._yara.scan_file(filepath)
        for match in matches:
            findings.append(Finding(
                resource=filepath,
                issue=f"YARA rule hit: {match.rule_name}",
                severity=match.severity,
                provider="host",
                resource_type="malware_detection",
                details={
                    "path":       filepath,
                    "sha256":     sha,
                    "rule":       match.rule_name,
                    "tags":       match.tags,
                    "meta":       match.meta,
                    "strings":    match.strings,
                    "description": match.meta.get("description", ""),
                },
                remediation_hint=(
                    f"YARA rule '{match.rule_name}' matched. "
                    "Quarantine the file immediately and investigate its origin. "
                    "Run: mv \"" + filepath + "\" /tmp/quarantine/"
                ),
                mitre_techniques=[match.mitre_technique] if match.mitre_technique else [],
                nist_controls=match.nist_controls or ["SI-3"],
                cwe_id="CWE-506",
            ))

        return findings

    def baseline_summary(self) -> dict:
        """Return a summary of the file integrity baseline."""
        with self._lock:
            return {
                "total_files":     len(self._baseline),
                "scan_dirs":       self.scan_dirs,
                "yara_available":  self._yara.is_available(),
            }


# ── Real-time watcher ─────────────────────────────────────────────────────────

class _AegisEventHandler(FileSystemEventHandler):
    """watchdog event handler — triggers YARA scan on new/modified files."""

    def __init__(self, scanner: DownloadScanner, pending: list, lock: threading.Lock):
        super().__init__()
        self._scanner = scanner
        self._pending = pending
        self._lock = lock

    def on_created(self, event):
        if not event.is_directory:
            self._handle(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._handle(event.src_path)

    def _handle(self, filepath: str):
        try:
            findings = self._scanner.scan_file(filepath)
            if findings:
                with self._lock:
                    self._pending.extend(findings)
                logger.warning(
                    f"DownloadWatcher: {len(findings)} threat(s) detected in {filepath}"
                )
        except Exception as exc:
            logger.error(f"DownloadWatcher event handler error: {exc}")


class DownloadWatcher:
    """
    Filesystem watcher that automatically scans new/modified files
    in the configured download directories.

    Requires `watchdog`. Falls back gracefully when unavailable.

    NIST 800-53:  SI-3, SI-7, AU-2, AU-12
    """

    def __init__(
        self,
        watch_dirs: Optional[List[str]] = None,
        scanner: Optional[DownloadScanner] = None,
    ):
        self._watch_dirs = watch_dirs or _DEFAULT_WATCH_DIRS
        self._scanner = scanner or DownloadScanner(scan_dirs=self._watch_dirs)
        self._pending_findings: List[Finding] = []
        self._lock = threading.Lock()
        self._observer = None

    def start(self) -> bool:
        if not WATCHDOG_AVAILABLE:
            logger.warning("DownloadWatcher: watchdog not installed — running in scan-only mode")
            return False

        self._observer = Observer()
        handler = _AegisEventHandler(self._scanner, self._pending_findings, self._lock)

        for watch_dir in self._watch_dirs:
            p = Path(watch_dir)
            if p.exists():
                self._observer.schedule(handler, str(p), recursive=True)
                logger.info(f"DownloadWatcher: watching {p}")
            else:
                logger.debug(f"DownloadWatcher: directory not found: {p}")

        self._observer.start()
        logger.info("DownloadWatcher started")
        return True

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
        logger.info("DownloadWatcher stopped")

    def findings_since_last_call(self) -> List[Finding]:
        """Drain and return all findings accumulated since last call."""
        with self._lock:
            out = list(self._pending_findings)
            self._pending_findings.clear()
        return out

    def run_full_scan(self) -> List[Finding]:
        """Trigger a full scan of all watched directories (synchronous)."""
        return self._scanner.scan()

    @property
    def is_running(self) -> bool:
        return self._observer is not None and self._observer.is_alive()
