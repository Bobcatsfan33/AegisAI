"""
ACAS / Nessus Scanner Integration — Aegis v2.5.0
=================================================
ACAS (Assured Compliance Assessment Solution) is the DISA-authorized vulnerability
management solution mandated for DoD IL2–IL6 environments. It is built on
Tenable.sc (SecurityCenter) + Tenable Nessus.

Three ingestion modes:
  1. Tenable.sc REST API  — enterprise mode (production ACAS deployments)
  2. Nessus REST API       — standalone Nessus (dev/test environments, ≤ port 8834)
  3. .nessus XML file      — offline/air-gapped parse from exported scan results

All three modes produce normalized Finding objects with:
  • CVSS v2 / v3 scores
  • CVE list
  • IAVM notice IDs (DoD IA Vulnerability Management)
  • VPR (Vulnerability Priority Rating, Tenable proprietary)
  • NIST 800-53 Rev5 control mappings
  • MITRE ATT&CK technique IDs

Required environment variables (set in .env):
  ACAS_MODE          = "tenablesc" | "nessus" | "xml"         (default: xml)

  # Tenable.sc mode:
  TENABLESC_URL      = https://acas.yourdomain.mil
  TENABLESC_USERNAME = service_account
  TENABLESC_PASSWORD = ***
  TENABLESC_SCAN_IDS = 42,43,44   (comma-separated; empty = all)

  # Nessus mode:
  NESSUS_URL         = https://localhost:8834
  NESSUS_ACCESS_KEY  = <api access key>
  NESSUS_SECRET_KEY  = <api secret key>
  NESSUS_SCAN_IDS    = 10,11      (comma-separated; empty = all)

  # XML mode:
  NESSUS_XML_PATH    = /var/acas/exports/*.nessus  (glob or single file)

NIST 800-53 Rev5 controls addressed:
  RA-5  (Vulnerability Monitoring and Scanning)
  SI-2  (Flaw Remediation)
  CM-6  (Configuration Settings)
  CM-7  (Least Functionality)
  SC-7  (Boundary Protection)
  SC-28 (Protection of Information at Rest)
  SC-8  (Transmission Confidentiality and Integrity)
  IA-5  (Authenticator Management)
  AC-3  (Access Enforcement)
  AC-6  (Least Privilege)
  SI-3  (Malicious Code Protection)
"""

from __future__ import annotations

import glob
import json
import logging
import os
import re
import ssl
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from modules.scanners.base import BaseScanner, Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Map Nessus plugin risk_factor → Aegis severity labels
_RISK_FACTOR_MAP: Dict[str, str] = {
    "Critical": "critical",
    "High":     "high",
    "Medium":   "medium",
    "Low":      "low",
    "None":     "info",
    "":         "info",
}

# CVSS v3 score → severity (NIST NVD thresholds)
def _cvss3_to_severity(score: float) -> str:
    if score >= 9.0:  return "critical"
    if score >= 7.0:  return "high"
    if score >= 4.0:  return "medium"
    if score > 0.0:   return "low"
    return "info"


def _cvss2_to_severity(score: float) -> str:
    if score >= 7.0:  return "critical"
    if score >= 4.0:  return "high"
    if score >= 1.0:  return "medium"
    return "low"


# ---------------------------------------------------------------------------
# NIST 800-53 Rev5 control mappings keyed by Nessus plugin family
# ---------------------------------------------------------------------------
_FAMILY_NIST: Dict[str, List[str]] = {
    "Windows":                         ["SI-2", "CM-6", "CM-7"],
    "Red Hat Local Security Checks":   ["SI-2", "CM-6", "CM-7"],
    "Ubuntu Local Security Checks":    ["SI-2", "CM-6", "CM-7"],
    "Debian Local Security Checks":    ["SI-2", "CM-6", "CM-7"],
    "SuSE Local Security Checks":      ["SI-2", "CM-6", "CM-7"],
    "Amazon Linux Local Security Checks": ["SI-2", "CM-6", "CM-7"],
    "CGI abuses":                      ["SC-7", "CM-7", "RA-5"],
    "Web Servers":                     ["SC-7", "SC-8", "CM-7"],
    "Databases":                       ["SC-28", "AC-3", "CM-7"],
    "Backdoors":                       ["SI-3", "IR-4", "RA-5"],
    "Denial of Service":               ["SC-5", "SC-7"],
    "Firewalls":                       ["SC-7", "CM-7"],
    "FTP":                             ["SC-8", "IA-5", "CM-7"],
    "General":                         ["RA-5", "SI-2"],
    "Default Unix Accounts":           ["IA-5", "AC-6", "CM-6"],
    "Default Accounts":                ["IA-5", "AC-6", "CM-6"],
    "Credentials":                     ["IA-5", "AC-6"],
    "Encryption":                      ["SC-8", "SC-28", "SC-13"],
    "Policy Compliance":               ["CM-6", "CM-7", "RA-5"],
    "IAVA":                            ["SI-2", "RA-5"],
    "IAVB":                            ["SI-2", "RA-5"],
    "IAVM":                            ["SI-2", "RA-5"],
    "Misc.":                           ["RA-5"],
    "Service detection":               ["CM-7", "SC-7"],
    "Settings":                        ["CM-6"],
    "Brute force attacks":             ["IA-5", "AC-7"],
    "DNS":                             ["SC-20", "SC-21"],
    "SMTP problems":                   ["SC-8", "CM-7"],
    "Peer-To-Peer File Sharing":       ["CM-7", "SC-7"],
    "RPC":                             ["SC-7", "CM-7"],
    "SNMP":                            ["CM-7", "IA-5"],
    "Virtualization":                  ["CM-6", "SC-7"],
    "Containers":                      ["CM-7", "SC-7", "SI-2"],
}

# ---------------------------------------------------------------------------
# MITRE ATT&CK mappings keyed by Nessus plugin family + risk_factor
# ---------------------------------------------------------------------------
_FAMILY_MITRE: Dict[str, Tuple[List[str], str]] = {
    # (techniques, tactic)
    "Windows":                        (["T1190", "T1068"], "initial-access"),
    "Red Hat Local Security Checks":  (["T1190", "T1068"], "initial-access"),
    "Ubuntu Local Security Checks":   (["T1190", "T1068"], "initial-access"),
    "Debian Local Security Checks":   (["T1190", "T1068"], "initial-access"),
    "SuSE Local Security Checks":     (["T1190", "T1068"], "initial-access"),
    "CGI abuses":                     (["T1190", "T1059.007"], "initial-access"),
    "Web Servers":                    (["T1190"], "initial-access"),
    "Databases":                      (["T1078", "T1552.001"], "credential-access"),
    "Backdoors":                      (["T1543", "T1134"], "persistence"),
    "Default Unix Accounts":          (["T1078.001"], "defense-evasion"),
    "Default Accounts":               (["T1078.001"], "defense-evasion"),
    "Brute force attacks":            (["T1110"], "credential-access"),
    "Encryption":                     (["T1557", "T1040"], "credential-access"),
    "RPC":                            (["T1021.006"], "lateral-movement"),
    "SNMP":                           (["T1602.001"], "collection"),
    "FTP":                            (["T1071.002", "T1552"], "exfiltration"),
    "Peer-To-Peer File Sharing":      (["T1048"], "exfiltration"),
    "Policy Compliance":              (["T1562.001"], "defense-evasion"),
    "IAVA":                           (["T1190", "T1068"], "initial-access"),
    "IAVB":                           (["T1190", "T1068"], "initial-access"),
    "IAVM":                           (["T1190", "T1068"], "initial-access"),
    "Containers":                     (["T1610", "T1611"], "execution"),
    "Virtualization":                 (["T1610"], "execution"),
}

# IAVM notice ID regex (DoD format: IAVA-YYYY-A-NNNN, IAVB-YYYY-B-NNNN, etc.)
_IAVM_RE = re.compile(r'\b(IAV[AB]\d{4}[A-Z]-\d{4}|\d{4}-[AB]-\d{4})\b', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Dataclasses for raw Nessus data before normalization
# ---------------------------------------------------------------------------

@dataclass
class RawPlugin:
    """One plugin result from a Nessus ReportItem or Tenable.sc vuln record."""
    plugin_id:     int
    plugin_name:   str
    family:        str
    severity_int:  int          # 0=None, 1=Low, 2=Medium, 3=High, 4=Critical
    risk_factor:   str          # "Critical" | "High" | "Medium" | "Low" | "None"
    cvss3_score:   float = 0.0
    cvss2_score:   float = 0.0
    vpr_score:     float = 0.0  # Tenable VPR (0–10), 0 if unavailable
    cves:          List[str] = field(default_factory=list)
    iavm_ids:      List[str] = field(default_factory=list)
    synopsis:      str = ""
    description:   str = ""
    solution:      str = ""
    hostname:      str = ""
    ip:            str = ""
    port:          int = 0
    protocol:      str = "tcp"
    plugin_output: str = ""
    scan_id:       str = ""
    scan_name:     str = ""


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only — no requests dependency)
# ---------------------------------------------------------------------------

def _make_ssl_ctx(verify: bool = True) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_get(url: str, headers: Dict[str, str], ssl_ctx: ssl.SSLContext,
              timeout: int = 30) -> dict:
    req = Request(url, headers=headers)
    with urlopen(req, context=ssl_ctx, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _http_post(url: str, headers: Dict[str, str], body: dict,
               ssl_ctx: ssl.SSLContext, timeout: int = 30) -> dict:
    data = json.dumps(body).encode()
    headers = {**headers, "Content-Type": "application/json"}
    req = Request(url, data=data, headers=headers, method="POST")
    with urlopen(req, context=ssl_ctx, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _http_delete(url: str, headers: Dict[str, str], ssl_ctx: ssl.SSLContext,
                 timeout: int = 30) -> None:
    req = Request(url, headers=headers, method="DELETE")
    try:
        with urlopen(req, context=ssl_ctx, timeout=timeout):
            pass
    except HTTPError:
        pass


# ---------------------------------------------------------------------------
# Tenable.sc (SecurityCenter) API client
# ---------------------------------------------------------------------------

class TenableSCClient:
    """
    Minimal Tenable.sc REST API client.

    Authentication: POST /rest/token  → session token (Bearer-style X-SecurityCenter-Token)
    Scan results:  GET  /rest/analysis?type=vuln&sourceType=cumulative&query=<id>
    """

    def __init__(self, base_url: str, username: str, password: str,
                 ssl_verify: bool = True, timeout: int = 60):
        self.base_url  = base_url.rstrip("/")
        self.username  = username
        self.password  = password
        self.ssl_ctx   = _make_ssl_ctx(ssl_verify)
        self.timeout   = timeout
        self._token: Optional[str] = None

    def login(self) -> None:
        url  = f"{self.base_url}/rest/token"
        body = {"username": self.username, "password": self.password}
        resp = _http_post(url, {}, body, self.ssl_ctx, self.timeout)
        token = resp.get("response", {}).get("token")
        if not token:
            raise RuntimeError(f"Tenable.sc login failed: {resp}")
        self._token = str(token)
        logger.info("Tenable.sc session token acquired")

    def logout(self) -> None:
        if not self._token:
            return
        url = f"{self.base_url}/rest/token"
        _http_delete(url, self._headers(), self.ssl_ctx, self.timeout)
        self._token = None

    def _headers(self) -> Dict[str, str]:
        h = {"Accept": "application/json"}
        if self._token:
            h["X-SecurityCenter-Token"] = self._token
        return h

    def get_scan_results(self, scan_ids: List[int]) -> List[RawPlugin]:
        """Pull cumulative vulnerability data for one or more scan IDs."""
        if not self._token:
            self.login()

        plugins: List[RawPlugin] = []

        for scan_id in scan_ids:
            logger.info(f"Fetching Tenable.sc results for scan {scan_id}")
            offset = 0
            page_size = 1000

            while True:
                url = (
                    f"{self.base_url}/rest/analysis"
                    f"?type=vuln&sourceType=cumulative"
                    f"&scan={scan_id}"
                    f"&fields=ip,dnsName,port,protocol,pluginID,pluginName,"
                    f"family,severity,riskFactor,cvssV3BaseScore,cvssBaseScore,"
                    f"vprScore,cve,iavmID,synopsis,description,solution,"
                    f"pluginOutput"
                    f"&startOffset={offset}&endOffset={offset + page_size}"
                )
                try:
                    resp = _http_get(url, self._headers(), self.ssl_ctx, self.timeout)
                except (HTTPError, URLError) as e:
                    logger.error(f"Tenable.sc analysis fetch error: {e}")
                    break

                vulns = resp.get("response", {}).get("results", [])
                if not vulns:
                    break

                for v in vulns:
                    plugins.append(self._parse_sc_vuln(v, str(scan_id)))

                total = resp.get("response", {}).get("totalRecords", 0)
                offset += page_size
                if offset >= total:
                    break

        return plugins

    @staticmethod
    def _parse_sc_vuln(v: dict, scan_id: str) -> RawPlugin:
        sev_map = {0: "None", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        sev_int = int(v.get("severity", {}).get("id", 0))

        raw_cves = v.get("cve", "") or ""
        cves = [c.strip() for c in raw_cves.split(",") if c.strip()]

        raw_iavm = v.get("iavmID", "") or ""
        iavms = [i.strip() for i in raw_iavm.split(",") if i.strip()]

        try:
            cvss3 = float(v.get("cvssV3BaseScore") or 0)
        except (ValueError, TypeError):
            cvss3 = 0.0
        try:
            cvss2 = float(v.get("cvssBaseScore") or 0)
        except (ValueError, TypeError):
            cvss2 = 0.0
        try:
            vpr = float(v.get("vprScore") or 0)
        except (ValueError, TypeError):
            vpr = 0.0

        return RawPlugin(
            plugin_id    = int(v.get("pluginID", 0)),
            plugin_name  = v.get("pluginName", ""),
            family       = v.get("family", {}).get("name", "") if isinstance(v.get("family"), dict) else str(v.get("family", "")),
            severity_int = sev_int,
            risk_factor  = sev_map.get(sev_int, "None"),
            cvss3_score  = cvss3,
            cvss2_score  = cvss2,
            vpr_score    = vpr,
            cves         = cves,
            iavm_ids     = iavms,
            synopsis     = v.get("synopsis", ""),
            description  = v.get("description", ""),
            solution     = v.get("solution", ""),
            hostname     = v.get("dnsName", ""),
            ip           = v.get("ip", ""),
            port         = int(v.get("port", 0)),
            protocol     = v.get("protocol", "tcp"),
            plugin_output= v.get("pluginOutput", ""),
            scan_id      = scan_id,
        )


# ---------------------------------------------------------------------------
# Nessus REST API client (port 8834)
# ---------------------------------------------------------------------------

class NessusClient:
    """
    Minimal Nessus REST API client for standalone Nessus Professional / Essentials.

    Authentication: POST /session  → token  (X-Cookie: token=<token>)
    Scans:          GET  /scans           → list
    Export:         POST /scans/{id}/export?format=nessus → file_id
                    GET  /scans/{id}/export/{file_id}/download → .nessus XML bytes
    """

    def __init__(self, base_url: str, access_key: str, secret_key: str,
                 ssl_verify: bool = True, timeout: int = 60):
        self.base_url   = base_url.rstrip("/")
        self.access_key = access_key
        self.secret_key = secret_key
        self.ssl_ctx    = _make_ssl_ctx(ssl_verify)
        self.timeout    = timeout

    def _headers(self) -> Dict[str, str]:
        return {
            "X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key}",
            "Accept":    "application/json",
        }

    def list_scans(self) -> List[dict]:
        url  = f"{self.base_url}/scans"
        resp = _http_get(url, self._headers(), self.ssl_ctx, self.timeout)
        return resp.get("scans") or []

    def export_scan_xml(self, scan_id: int) -> bytes:
        """Export scan as .nessus XML and return raw bytes."""
        # Request export
        export_url = f"{self.base_url}/scans/{scan_id}/export"
        req_body   = {"format": "nessus"}
        export_hdr = {**self._headers(), "Content-Type": "application/json"}
        req = Request(
            export_url,
            data=json.dumps(req_body).encode(),
            headers=export_hdr,
            method="POST",
        )
        with urlopen(req, context=self.ssl_ctx, timeout=self.timeout) as resp:
            file_id = json.loads(resp.read()).get("file")

        if not file_id:
            raise RuntimeError(f"Nessus export failed for scan {scan_id}")

        # Poll until ready
        status_url = f"{self.base_url}/scans/{scan_id}/export/{file_id}/status"
        for _ in range(60):
            status_resp = _http_get(status_url, self._headers(), self.ssl_ctx, self.timeout)
            if status_resp.get("status") == "ready":
                break
            time.sleep(2)
        else:
            raise TimeoutError(f"Nessus export timed out for scan {scan_id}")

        # Download
        dl_url = f"{self.base_url}/scans/{scan_id}/export/{file_id}/download"
        dl_req = Request(dl_url, headers=self._headers())
        with urlopen(dl_req, context=self.ssl_ctx, timeout=self.timeout) as resp:
            return resp.read()

    def get_scan_results(self, scan_ids: List[int]) -> List[RawPlugin]:
        """Export each scan and parse resulting XML."""
        plugins: List[RawPlugin] = []
        all_scans = {s["id"]: s for s in self.list_scans()}

        for sid in (scan_ids or list(all_scans.keys())):
            scan_info = all_scans.get(sid, {})
            logger.info(f"Exporting Nessus scan {sid} ({scan_info.get('name', '')})")
            try:
                xml_bytes = self.export_scan_xml(sid)
                batch = NessusXMLParser.parse_bytes(xml_bytes, str(sid),
                                                    scan_info.get("name", ""))
                plugins.extend(batch)
            except Exception as e:
                logger.error(f"Failed to export/parse Nessus scan {sid}: {e}")

        return plugins


# ---------------------------------------------------------------------------
# .nessus XML parser
# ---------------------------------------------------------------------------

class NessusXMLParser:
    """
    Parse Tenable .nessus XML files (NessusClientData_v2 schema).

    Structure:
      <NessusClientData_v2>
        <Policy> ... </Policy>
        <Report name="...">
          <ReportHost name="hostname">
            <HostProperties>
              <tag name="host-ip">...</tag>
              ...
            </HostProperties>
            <ReportItem port="22" svc_name="ssh" protocol="tcp"
                        severity="3" pluginID="70658" pluginName="...">
              <risk_factor>High</risk_factor>
              <cvss3_base_score>7.5</cvss3_base_score>
              <cvss_base_score>7.2</cvss_base_score>
              <vpr_score>7.1</vpr_score>
              <cve>CVE-2019-XXXX</cve>
              <iava>IAVA2019-A-0001</iava>
              <synopsis>...</synopsis>
              <description>...</description>
              <solution>...</solution>
              <plugin_output>...</plugin_output>
            </ReportItem>
          </ReportHost>
        </Report>
      </NessusClientData_v2>
    """

    @classmethod
    def parse_file(cls, path: str, scan_name: str = "") -> List[RawPlugin]:
        with open(path, "rb") as f:
            return cls.parse_bytes(f.read(), scan_id=path, scan_name=scan_name or path)

    @classmethod
    def parse_bytes(cls, data: bytes, scan_id: str = "",
                    scan_name: str = "") -> List[RawPlugin]:
        plugins: List[RawPlugin] = []
        try:
            root = ET.fromstring(data)
        except ET.ParseError as e:
            logger.error(f"Failed to parse .nessus XML: {e}")
            return plugins

        for report in root.iter("Report"):
            r_name = report.get("name", scan_name)

            for report_host in report.iter("ReportHost"):
                hostname = report_host.get("name", "")
                # Extract host IP from HostProperties tags
                ip = hostname
                for tag in report_host.iter("tag"):
                    if tag.get("name") == "host-ip":
                        ip = tag.text or ip
                    elif tag.get("name") == "host-fqdn" and not hostname:
                        hostname = tag.text or hostname

                for item in report_host.iter("ReportItem"):
                    rp = cls._parse_report_item(
                        item, hostname=hostname, ip=ip,
                        scan_id=scan_id, scan_name=r_name
                    )
                    if rp.severity_int > 0:  # skip info-only (severity=0)
                        plugins.append(rp)

        return plugins

    @classmethod
    def _parse_report_item(cls, item: ET.Element, hostname: str, ip: str,
                           scan_id: str, scan_name: str) -> RawPlugin:
        def _txt(tag: str) -> str:
            el = item.find(tag)
            return (el.text or "").strip() if el is not None else ""

        def _float(tag: str) -> float:
            v = _txt(tag)
            try:
                return float(v)
            except (ValueError, TypeError):
                return 0.0

        # CVEs — multiple <cve> elements possible
        cves = [el.text.strip() for el in item.findall("cve") if el.text]

        # IAVM IDs — <iava>, <iavb>, <iavm> elements or embedded in description
        iavm_ids: List[str] = []
        for tag in ("iava", "iavb", "iavm"):
            for el in item.findall(tag):
                if el.text:
                    iavm_ids.append(el.text.strip())
        # Also scan synopsis/description for IAVM IDs
        for text_field in (_txt("synopsis"), _txt("description"), _txt("plugin_output")):
            iavm_ids.extend(_IAVM_RE.findall(text_field))
        iavm_ids = list(dict.fromkeys(iavm_ids))  # deduplicate, preserve order

        sev_int = int(item.get("severity", "0"))
        risk_factor = _txt("risk_factor") or {
            4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "None"
        }.get(sev_int, "None")

        return RawPlugin(
            plugin_id    = int(item.get("pluginID", "0")),
            plugin_name  = item.get("pluginName", _txt("pluginName")),
            family       = item.get("pluginFamily", ""),
            severity_int = sev_int,
            risk_factor  = risk_factor,
            cvss3_score  = _float("cvss3_base_score"),
            cvss2_score  = _float("cvss_base_score"),
            vpr_score    = _float("vpr_score"),
            cves         = cves,
            iavm_ids     = iavm_ids,
            synopsis     = _txt("synopsis"),
            description  = _txt("description"),
            solution     = _txt("solution"),
            hostname     = hostname,
            ip           = ip,
            port         = int(item.get("port", "0")),
            protocol     = item.get("protocol", "tcp"),
            plugin_output= _txt("plugin_output"),
            scan_id      = scan_id,
            scan_name    = scan_name,
        )


# ---------------------------------------------------------------------------
# Normalizer: RawPlugin → Finding
# ---------------------------------------------------------------------------

def _normalize(rp: RawPlugin) -> Finding:
    """Convert a RawPlugin record to the Aegis Finding schema."""

    # Severity: prefer CVSS v3 > CVSS v2 > risk_factor string
    if rp.cvss3_score > 0:
        severity = _cvss3_to_severity(rp.cvss3_score)
    elif rp.cvss2_score > 0:
        severity = _cvss2_to_severity(rp.cvss2_score)
    else:
        severity = _RISK_FACTOR_MAP.get(rp.risk_factor, "info")

    # Resource label
    host_label = rp.hostname or rp.ip or "unknown-host"
    resource   = f"{host_label}:{rp.port}" if rp.port else host_label

    # NIST 800-53 controls
    nist = _FAMILY_NIST.get(rp.family, ["RA-5", "SI-2"])

    # MITRE ATT&CK
    mitre_entry   = _FAMILY_MITRE.get(rp.family)
    techniques    = mitre_entry[0] if mitre_entry else []
    tactic        = mitre_entry[1] if mitre_entry else "initial-access"

    # Build detail blob
    details: Dict = {
        "plugin_id":    rp.plugin_id,
        "plugin_name":  rp.plugin_name,
        "plugin_family":rp.family,
        "ip":           rp.ip,
        "hostname":     rp.hostname,
        "port":         rp.port,
        "protocol":     rp.protocol,
        "scan_id":      rp.scan_id,
        "scan_name":    rp.scan_name,
        "cvss3":        rp.cvss3_score,
        "cvss2":        rp.cvss2_score,
        "vpr":          rp.vpr_score,
        "cves":         rp.cves,
        "iavm_ids":     rp.iavm_ids,
        "synopsis":     rp.synopsis[:500],
        "plugin_output": rp.plugin_output[:500],
    }

    return Finding(
        resource         = resource,
        issue            = rp.plugin_name or rp.synopsis or f"Plugin {rp.plugin_id}",
        severity         = severity,
        provider         = "acas",
        region           = None,
        resource_type    = "vulnerability",
        details          = details,
        remediation_hint = rp.solution[:300] if rp.solution else None,
        mitre_techniques = techniques,
        mitre_tactic     = tactic,
        nist_controls    = nist,
        cwe_id           = None,  # Nessus doesn't natively surface CWE; extendable
    )


# ---------------------------------------------------------------------------
# ACAS Scanner (main class)
# ---------------------------------------------------------------------------

class ACASScanner(BaseScanner):
    """
    Unified ACAS / Nessus scanner for IL5 environments.

    Mode is driven by ACAS_MODE env var:
      "tenablesc" → Tenable.sc (SecurityCenter) REST API
      "nessus"    → Standalone Nessus REST API (port 8834)
      "xml"       → Parse local .nessus XML file(s) (default / air-gap mode)

    All modes return Finding objects normalized against the Aegis base schema.
    """

    provider = "acas"

    def __init__(self):
        self.mode = os.getenv("ACAS_MODE", "xml").lower()
        self._ssl_verify = os.getenv("ACAS_SSL_VERIFY", "true").lower() != "false"

    # ── availability check ─────────────────────────────────────────────────

    def is_available(self) -> bool:
        if self.mode == "tenablesc":
            return bool(
                os.getenv("TENABLESC_URL") and
                os.getenv("TENABLESC_USERNAME") and
                os.getenv("TENABLESC_PASSWORD")
            )
        if self.mode == "nessus":
            return bool(
                os.getenv("NESSUS_URL") and
                os.getenv("NESSUS_ACCESS_KEY") and
                os.getenv("NESSUS_SECRET_KEY")
            )
        if self.mode == "xml":
            xml_path = os.getenv("NESSUS_XML_PATH", "")
            return bool(xml_path and glob.glob(xml_path))
        return False

    # ── main scan entry point ──────────────────────────────────────────────

    def scan(self) -> List[Finding]:
        logger.info(f"[ACAS] Starting scan — mode={self.mode}")
        raw_plugins: List[RawPlugin] = []

        try:
            if self.mode == "tenablesc":
                raw_plugins = self._scan_tenablesc()
            elif self.mode == "nessus":
                raw_plugins = self._scan_nessus()
            else:
                raw_plugins = self._scan_xml()
        except Exception as e:
            logger.error(f"[ACAS] Scan failed: {e}")
            return []

        findings = [_normalize(rp) for rp in raw_plugins]

        # Deduplicate on (host, port, plugin_id)
        seen = set()
        deduped: List[Finding] = []
        for f in findings:
            key = (
                f.details.get("ip", ""),
                f.details.get("port", ""),
                f.details.get("plugin_id", ""),
            )
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        logger.info(
            f"[ACAS] Scan complete — raw={len(raw_plugins)}, "
            f"normalized={len(findings)}, after_dedup={len(deduped)}"
        )
        return deduped

    # ── Tenable.sc mode ────────────────────────────────────────────────────

    def _scan_tenablesc(self) -> List[RawPlugin]:
        base_url  = os.getenv("TENABLESC_URL", "")
        username  = os.getenv("TENABLESC_USERNAME", "")
        password  = os.getenv("TENABLESC_PASSWORD", "")
        scan_ids  = self._parse_id_list(os.getenv("TENABLESC_SCAN_IDS", ""))

        client = TenableSCClient(
            base_url, username, password,
            ssl_verify=self._ssl_verify
        )
        try:
            return client.get_scan_results(scan_ids)
        finally:
            client.logout()

    # ── Nessus REST mode ───────────────────────────────────────────────────

    def _scan_nessus(self) -> List[RawPlugin]:
        base_url   = os.getenv("NESSUS_URL", "https://localhost:8834")
        access_key = os.getenv("NESSUS_ACCESS_KEY", "")
        secret_key = os.getenv("NESSUS_SECRET_KEY", "")
        scan_ids   = self._parse_id_list(os.getenv("NESSUS_SCAN_IDS", ""))

        client = NessusClient(
            base_url, access_key, secret_key,
            ssl_verify=self._ssl_verify
        )
        return client.get_scan_results(scan_ids)

    # ── XML file mode ──────────────────────────────────────────────────────

    def _scan_xml(self) -> List[RawPlugin]:
        xml_path = os.getenv("NESSUS_XML_PATH", "")
        files    = sorted(glob.glob(xml_path))
        if not files:
            logger.warning(f"[ACAS] No .nessus XML files found at: {xml_path}")
            return []

        plugins: List[RawPlugin] = []
        for path in files:
            logger.info(f"[ACAS] Parsing {path}")
            try:
                batch = NessusXMLParser.parse_file(path)
                logger.info(f"[ACAS] {path}: {len(batch)} plugins parsed")
                plugins.extend(batch)
            except Exception as e:
                logger.error(f"[ACAS] Failed to parse {path}: {e}")
        return plugins

    # ── helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_id_list(raw: str) -> List[int]:
        """Parse comma-separated integer list; empty string returns []."""
        ids = []
        for part in raw.split(","):
            part = part.strip()
            if part:
                try:
                    ids.append(int(part))
                except ValueError:
                    pass
        return ids


# ---------------------------------------------------------------------------
# Summary helper (used by Aegis API /api/acas/summary endpoint)
# ---------------------------------------------------------------------------

@dataclass
class ACASSummary:
    """Rolled-up ACAS scan summary for API response and eMASS POA&M."""
    generated_at:      str
    mode:              str
    total_findings:    int
    critical:          int
    high:              int
    medium:            int
    low:               int
    info:              int
    unique_hosts:      int
    unique_cves:       int
    iavm_open:         int
    top_plugins:       List[dict]    # [{plugin_id, name, count, severity}]
    top_hosts:         List[dict]    # [{host, count}]
    poam_candidates:   List[dict]    # critical + high + IAVM findings for POA&M

    def to_dict(self) -> dict:
        return {
            "generated_at":    self.generated_at,
            "mode":            self.mode,
            "total_findings":  self.total_findings,
            "severity_counts": {
                "critical": self.critical,
                "high":     self.high,
                "medium":   self.medium,
                "low":      self.low,
                "info":     self.info,
            },
            "unique_hosts":    self.unique_hosts,
            "unique_cves":     self.unique_cves,
            "iavm_open":       self.iavm_open,
            "top_plugins":     self.top_plugins,
            "top_hosts":       self.top_hosts,
            "poam_candidates": self.poam_candidates,
        }


def build_summary(findings: List[Finding]) -> ACASSummary:
    """Aggregate a list of ACAS findings into a summary report."""
    from collections import Counter

    sev_counts: Dict[str, int] = Counter()
    plugin_counts: Counter     = Counter()
    host_counts: Counter       = Counter()
    all_cves:  set             = set()
    iavm_open: int             = 0
    poam: List[dict]           = []
    plugin_meta: Dict[int, dict] = {}

    for f in findings:
        sev_counts[f.severity] += 1
        pid   = f.details.get("plugin_id", 0)
        pname = f.details.get("plugin_name", str(pid))
        host  = f.details.get("hostname") or f.details.get("ip", "")

        plugin_counts[pid] += 1
        plugin_meta[pid] = {"name": pname, "severity": f.severity}
        host_counts[host] += 1
        all_cves.update(f.details.get("cves", []))

        if f.details.get("iavm_ids"):
            iavm_open += 1

        if f.severity in ("critical", "high") or f.details.get("iavm_ids"):
            poam.append({
                "resource":     f.resource,
                "issue":        f.issue,
                "severity":     f.severity,
                "plugin_id":    pid,
                "cves":         f.details.get("cves", []),
                "iavm_ids":     f.details.get("iavm_ids", []),
                "remediation":  f.remediation_hint or "",
                "nist_controls":f.nist_controls,
            })

    top_plugins = [
        {"plugin_id": pid, "name": plugin_meta[pid]["name"],
         "count": cnt, "severity": plugin_meta[pid]["severity"]}
        for pid, cnt in plugin_counts.most_common(10)
    ]
    top_hosts = [
        {"host": host, "count": cnt}
        for host, cnt in host_counts.most_common(10)
    ]

    return ACASSummary(
        generated_at   = datetime.now(timezone.utc).isoformat(),
        mode           = os.getenv("ACAS_MODE", "xml"),
        total_findings = len(findings),
        critical       = sev_counts["critical"],
        high           = sev_counts["high"],
        medium         = sev_counts["medium"],
        low            = sev_counts["low"],
        info           = sev_counts["info"],
        unique_hosts   = len(host_counts),
        unique_cves    = len(all_cves),
        iavm_open      = iavm_open,
        top_plugins    = top_plugins,
        top_hosts      = top_hosts,
        poam_candidates= poam[:50],  # cap at 50 for API response size
    )
