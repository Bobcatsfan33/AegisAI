"""
modules.scanners.host
=====================

Host-level threat detection: YARA-based malware scanning, download directory
monitoring, and file integrity baseline checking.

  DownloadScanner     — on-demand directory scan (YARA + file integrity)
  DownloadWatcher     — real-time filesystem watcher (requires watchdog)
  YaraEngine          — YARA rule loader and scanner
  YaraMatch           — dataclass: one YARA rule hit
  FileRecord          — dataclass: file integrity baseline entry

NIST 800-53 Rev5 coverage: SI-3, SI-7, CM-3, AU-2, AU-12
"""

from modules.scanners.host.yara_engine import YaraEngine, YaraMatch
from modules.scanners.host.download_scanner import (
    DownloadScanner,
    DownloadWatcher,
    FileRecord,
)

__all__ = [
    "YaraEngine",
    "YaraMatch",
    "DownloadScanner",
    "DownloadWatcher",
    "FileRecord",
]
