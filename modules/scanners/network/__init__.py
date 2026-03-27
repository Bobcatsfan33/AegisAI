"""
modules.scanners.network
========================

Network scanning and live flow monitoring.

  NetworkScanner      — port / service enumeration (existing, v2.3+)
  NetworkFlowMonitor  — live connection monitoring with IOC enrichment (v2.11)
  NetworkFlow         — data class representing one captured flow
  NETWORK_FLOWS_MAPPING — Elasticsearch index mapping for flow events
"""

from modules.scanners.network.scanner import NetworkScanner
from modules.scanners.network.flow_monitor import (
    NetworkFlowMonitor,
    NetworkFlow,
    NETWORK_FLOWS_MAPPING,
)

__all__ = [
    "NetworkScanner",
    "NetworkFlowMonitor",
    "NetworkFlow",
    "NETWORK_FLOWS_MAPPING",
]
