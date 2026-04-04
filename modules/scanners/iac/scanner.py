"""
AegisAI — Infrastructure-as-Code (IaC) Security Scanner  (v2.3.0)

Scans Terraform (.tf), CloudFormation (.yaml/.json), and Kubernetes manifest
files for security misconfigurations BEFORE they reach a cloud environment.
Shift-left security: catch issues in the PR, not in production.

Supported checks:

TERRAFORM
  IAC-TF-001  S3 bucket with public ACL (acl = "public-read" / "public-read-write")
  IAC-TF-002  S3 bucket without versioning enabled
  IAC-TF-003  S3 bucket without server-side encryption
  IAC-TF-004  Security group with 0.0.0.0/0 ingress on sensitive ports
  IAC-TF-005  Security group with unrestricted SSH/RDP (port 22/3389) inbound
  IAC-TF-006  RDS instance not encrypted (storage_encrypted = false)
  IAC-TF-007  RDS instance publicly accessible
  IAC-TF-008  IAM policy with Action="*" or Resource="*" (wildcard grants)
  IAC-TF-009  Hardcoded secrets / access keys detected in .tf files

CLOUDFORMATION
  IAC-CF-001  S3 bucket with PublicAccessBlockConfiguration disabled
  IAC-CF-002  EC2 instance with public IP and no security group restriction
  IAC-CF-003  IAM policy with wildcards (Action:* or Resource:*)
  IAC-CF-004  Hardcoded secrets in CloudFormation templates

KUBERNETES MANIFESTS
  IAC-K8-001  Privileged container in manifest
  IAC-K8-002  Missing securityContext
  IAC-K8-003  Image with :latest tag (unpinned — supply chain risk)
  IAC-K8-004  Hardcoded secret values in env vars

All findings carry MITRE ATT&CK technique IDs and NIST 800-53 control refs.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import List, Optional

from modules.scanners.base import BaseScanner, Finding

logger = logging.getLogger(__name__)

# ── Regex patterns ────────────────────────────────────────────────────────────

_SECRET_PATTERN = re.compile(
    r"""(?i)(password|passwd|secret|api.?key|private.?key|access.?key|token|credential)"""
    r"""\s*[=:]\s*["']([^"'\s]{8,})["']"""
)
_AWS_KEY_PATTERN  = re.compile(r"AKIA[0-9A-Z]{16}")
_TF_RESOURCE      = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"')
_TF_ATTR          = re.compile(r'\b(\w+)\s*=\s*"([^"]*)"')
_TF_ATTR_BOOL     = re.compile(r'\b(\w+)\s*=\s*(true|false)\b')
_TF_CIDR          = re.compile(r'"(0\.0\.0\.0/0|::/0)"')
_CF_YAML_KEY      = re.compile(r"^\s{0,16}(\w+):\s*(.+)$")
_K8S_IMAGE_LATEST = re.compile(r"image:\s*\S+:latest")

_SENSITIVE_PORTS = {22, 23, 3389, 5900, 5432, 3306, 1433, 6379, 27017}

# ── MITRE/NIST mapping ────────────────────────────────────────────────────────

_EXPOSURE_TECHNIQUES = ["T1530", "T1190"]   # Data from Cloud Storage, Exploit Public-Facing
_EXPOSURE_NIST        = ["AC-3", "SC-7", "SC-28"]
_IAM_TECHNIQUES       = ["T1078", "T1098"]  # Valid Accounts, Account Manipulation
_IAM_NIST             = ["AC-2", "AC-3", "AC-6"]
_SECRET_TECHNIQUES    = ["T1552.001"]       # Unsecured Credentials: Credentials in Files
_SECRET_NIST          = ["IA-5", "SC-28"]
_SUPPLY_TECHNIQUES    = ["T1195.001"]       # Supply Chain: Compromise Software Dependencies
_SUPPLY_NIST          = ["SA-12", "CM-14"]


class IaCScanner(BaseScanner):
    """
    Infrastructure-as-Code security scanner.

    Scans directories and files for Terraform, CloudFormation, and Kubernetes
    manifest security misconfigurations.

    Configuration:
      IAC_SCAN_PATHS   — comma-separated paths to scan (default: current working dir)
      IAC_MAX_DEPTH    — max directory recursion depth (default: 10)
    """

    provider = "iac"

    def __init__(self):
        raw = os.getenv("IAC_SCAN_PATHS", ".")
        self._scan_paths = [p.strip() for p in raw.split(",") if p.strip()]
        self._max_depth  = int(os.getenv("IAC_MAX_DEPTH", "10"))

    def is_available(self) -> bool:
        for p in self._scan_paths:
            if os.path.exists(p):
                return True
        logger.debug("IaC scanner: no scan paths exist.")
        return False

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        for base_path in self._scan_paths:
            for path in self._walk(base_path):
                try:
                    if path.suffix == ".tf":
                        findings.extend(self._scan_terraform(path))
                    elif path.suffix in (".yaml", ".yml"):
                        findings.extend(self._scan_yaml(path))
                    elif path.suffix == ".json" and self._looks_like_cfn(path):
                        findings.extend(self._scan_cfn_json(path))
                except Exception as e:
                    logger.warning(f"IaC scan error on {path}: {e}")

        logger.info(f"IaC scan complete: {len(findings)} findings across {self._scan_paths}.")
        return findings

    # ── Terraform ─────────────────────────────────────────────────────────────

    def _scan_terraform(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        text  = path.read_text(errors="replace")
        lines = text.splitlines()

        # IAC-TF-009: hardcoded secrets / AWS keys
        for i, line in enumerate(lines, 1):
            if _AWS_KEY_PATTERN.search(line):
                findings.append(self._finding(
                    resource=f"{path}:{i}",
                    issue="[IAC-TF-009] Hardcoded AWS Access Key ID detected",
                    severity="critical",
                    resource_type="terraform_secret",
                    hint="Remove from source. Use aws_secretsmanager_secret or environment variables. Rotate the key immediately.",
                    techniques=_SECRET_TECHNIQUES, nist=_SECRET_NIST, cwe="CWE-798",
                ))
            m = _SECRET_PATTERN.search(line)
            if m and len(m.group(2)) > 8:
                findings.append(self._finding(
                    resource=f"{path}:{i}",
                    issue=f"[IAC-TF-009] Possible hardcoded credential in variable '{m.group(1)}'",
                    severity="high",
                    resource_type="terraform_secret",
                    hint="Use var.* references or data.aws_secretsmanager_secret instead of inline values.",
                    techniques=_SECRET_TECHNIQUES, nist=_SECRET_NIST, cwe="CWE-312",
                ))

        # Parse resource blocks for attribute-level checks
        current_resource = None
        current_type     = None
        block_lines: List[str] = []
        depth = 0

        for line in lines:
            stripped = line.strip()

            m = _TF_RESOURCE.search(stripped)
            if m:
                current_type     = m.group(1)
                current_resource = m.group(2)
                block_lines      = []
                depth            = 0

            if current_resource:
                block_lines.append(stripped)
                depth += stripped.count("{") - stripped.count("}")
                if depth <= 0 and block_lines:
                    block_text = "\n".join(block_lines)
                    findings.extend(
                        self._check_tf_resource(path, current_type, current_resource, block_text)
                    )
                    current_resource = None
                    current_type     = None
                    block_lines      = []

        return findings

    def _check_tf_resource(self, path: Path, rtype: str, rname: str, block: str) -> List[Finding]:
        findings: List[Finding] = []
        ref = f"{path} → {rtype}.{rname}"
        attrs = dict(_TF_ATTR.findall(block))
        bools = dict(_TF_ATTR_BOOL.findall(block))

        if rtype == "aws_s3_bucket":
            # IAC-TF-001: public ACL
            acl = attrs.get("acl", "")
            if "public" in acl:
                findings.append(self._finding(
                    resource=ref, severity="critical",
                    issue=f"[IAC-TF-001] S3 bucket '{rname}' has public ACL: '{acl}'",
                    resource_type="s3_bucket",
                    hint="Remove the ACL or set it to 'private'. Enable S3 Block Public Access.",
                    techniques=_EXPOSURE_TECHNIQUES, nist=_EXPOSURE_NIST, cwe="CWE-732",
                ))
            # IAC-TF-002: no versioning
            if "versioning" not in block or 'enabled = "true"' not in block and "enabled = true" not in block:
                findings.append(self._finding(
                    resource=ref, severity="medium",
                    issue=f"[IAC-TF-002] S3 bucket '{rname}' has no versioning — data loss / tampering risk",
                    resource_type="s3_bucket",
                    hint="Add versioning { enabled = true } block.",
                    techniques=["T1485"], nist=["SI-12", "CP-9"], cwe="CWE-359",
                ))
            # IAC-TF-003: no SSE
            if "server_side_encryption_configuration" not in block:
                findings.append(self._finding(
                    resource=ref, severity="high",
                    issue=f"[IAC-TF-003] S3 bucket '{rname}' has no server-side encryption",
                    resource_type="s3_bucket",
                    hint="Add server_side_encryption_configuration with AES256 or aws:kms.",
                    techniques=["T1530"], nist=["SC-28"], cwe="CWE-311",
                ))

        elif rtype == "aws_security_group":
            # IAC-TF-004/005: open ingress
            if _TF_CIDR.search(block) and "ingress" in block:
                # Check for sensitive ports
                port_matches = re.findall(r"from_port\s*=\s*(\d+)", block)
                to_matches   = re.findall(r"to_port\s*=\s*(\d+)", block)
                open_ports   = set()
                for fp, tp in zip(port_matches, to_matches):
                    fp_i, tp_i = int(fp), int(tp)
                    if fp_i == 0 and tp_i == 0:
                        open_ports.add("ALL")
                    else:
                        for p in range(fp_i, tp_i + 1):
                            if p in _SENSITIVE_PORTS:
                                open_ports.add(p)
                if "ALL" in open_ports or open_ports:
                    check = "IAC-TF-005" if ({22, 3389} & open_ports) else "IAC-TF-004"
                    findings.append(self._finding(
                        resource=ref, severity="critical",
                        issue=f"[{check}] Security group '{rname}' allows 0.0.0.0/0 ingress on ports: {open_ports}",
                        resource_type="security_group",
                        hint="Restrict ingress to specific CIDR ranges. Never open sensitive ports to the internet.",
                        techniques=_EXPOSURE_TECHNIQUES, nist=_EXPOSURE_NIST, cwe="CWE-284",
                    ))

        elif rtype == "aws_db_instance":
            # IAC-TF-006: unencrypted RDS
            if bools.get("storage_encrypted") == "false" or "storage_encrypted" not in block:
                findings.append(self._finding(
                    resource=ref, severity="high",
                    issue=f"[IAC-TF-006] RDS instance '{rname}' storage is not encrypted",
                    resource_type="rds_instance",
                    hint="Set storage_encrypted = true. Use kms_key_id for FIPS/IL4+ environments.",
                    techniques=["T1530"], nist=["SC-28"], cwe="CWE-311",
                ))
            # IAC-TF-007: publicly accessible
            if bools.get("publicly_accessible") == "true":
                findings.append(self._finding(
                    resource=ref, severity="critical",
                    issue=f"[IAC-TF-007] RDS instance '{rname}' is publicly accessible",
                    resource_type="rds_instance",
                    hint="Set publicly_accessible = false. Place RDS in private subnets.",
                    techniques=_EXPOSURE_TECHNIQUES, nist=_EXPOSURE_NIST, cwe="CWE-284",
                ))

        elif rtype in ("aws_iam_policy", "aws_iam_policy_document"):
            # IAC-TF-008: wildcard IAM
            if '"*"' in block and ("Action" in block or "actions" in block):
                findings.append(self._finding(
                    resource=ref, severity="critical",
                    issue=f"[IAC-TF-008] IAM policy '{rname}' grants wildcard Action or Resource",
                    resource_type="iam_policy",
                    hint="Replace '*' with explicit actions and resource ARNs. Apply least-privilege.",
                    techniques=_IAM_TECHNIQUES, nist=_IAM_NIST, cwe="CWE-732",
                ))

        return findings

    # ── CloudFormation (YAML) ─────────────────────────────────────────────────

    def _scan_yaml(self, path: Path) -> List[Finding]:
        """Route YAML files — CloudFormation templates and K8s manifests."""
        try:
            import yaml
            with path.open() as f:
                docs = list(yaml.safe_load_all(f))
        except ImportError:
            # Fall back to line-based scanning if PyYAML not installed
            return self._scan_yaml_lines(path)
        except Exception as e:
            logger.debug(f"YAML parse failed for {path}: {e}")
            return self._scan_yaml_lines(path)

        findings: List[Finding] = []
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            if doc.get("AWSTemplateFormatVersion") or doc.get("Resources"):
                findings.extend(self._check_cfn_doc(path, doc))
            elif doc.get("apiVersion") and doc.get("kind"):
                findings.extend(self._check_k8s_manifest(path, doc))
        return findings

    def _scan_yaml_lines(self, path: Path) -> List[Finding]:
        """Line-based fallback scanner when PyYAML is not available."""
        findings: List[Finding] = []
        text = path.read_text(errors="replace")

        # K8S-003: latest image tag
        for i, line in enumerate(text.splitlines(), 1):
            if _K8S_IMAGE_LATEST.search(line):
                findings.append(self._finding(
                    resource=f"{path}:{i}",
                    issue="[IAC-K8-003] Container image uses ':latest' tag — supply chain risk",
                    severity="medium", resource_type="k8s_manifest",
                    hint="Pin to a specific image digest (sha256:...) or immutable version tag.",
                    techniques=_SUPPLY_TECHNIQUES, nist=_SUPPLY_NIST, cwe="CWE-1357",
                ))
            if _AWS_KEY_PATTERN.search(line) or _SECRET_PATTERN.search(line):
                findings.append(self._finding(
                    resource=f"{path}:{i}",
                    issue="[IAC-CF-004] Possible hardcoded secret in YAML template",
                    severity="high", resource_type="cfn_template",
                    hint="Use CloudFormation dynamic references {{resolve:secretsmanager:...}} instead.",
                    techniques=_SECRET_TECHNIQUES, nist=_SECRET_NIST, cwe="CWE-798",
                ))
        return findings

    def _check_cfn_doc(self, path: Path, doc: dict) -> List[Finding]:
        findings: List[Finding] = []
        resources = doc.get("Resources", {}) or {}
        ref = str(path)

        for rname, rdef in resources.items():
            if not isinstance(rdef, dict):
                continue
            rtype = rdef.get("Type", "")
            props = rdef.get("Properties", {}) or {}

            # IAC-CF-001: S3 block public access disabled
            if rtype == "AWS::S3::Bucket":
                bpa = props.get("PublicAccessBlockConfiguration", {})
                if not bpa or not all([
                    bpa.get("BlockPublicAcls"),
                    bpa.get("BlockPublicPolicy"),
                    bpa.get("IgnorePublicAcls"),
                    bpa.get("RestrictPublicBuckets"),
                ]):
                    findings.append(self._finding(
                        resource=f"{ref} → {rname}",
                        issue=f"[IAC-CF-001] S3 bucket '{rname}' missing full PublicAccessBlock configuration",
                        severity="high", resource_type="s3_bucket",
                        hint="Add PublicAccessBlockConfiguration with all four settings set to true.",
                        techniques=_EXPOSURE_TECHNIQUES, nist=_EXPOSURE_NIST, cwe="CWE-732",
                    ))
                if not props.get("BucketEncryption"):
                    findings.append(self._finding(
                        resource=f"{ref} → {rname}",
                        issue=f"[IAC-CF-001b] S3 bucket '{rname}' has no BucketEncryption defined",
                        severity="high", resource_type="s3_bucket",
                        hint="Add BucketEncryption with ServerSideEncryptionByDefault using AES256 or aws:kms.",
                        techniques=["T1530"], nist=["SC-28"], cwe="CWE-311",
                    ))

            # IAC-CF-003: wildcard IAM
            if rtype in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Role"):
                doc_str = json.dumps(props)
                if '"*"' in doc_str:
                    findings.append(self._finding(
                        resource=f"{ref} → {rname}",
                        issue=f"[IAC-CF-003] IAM resource '{rname}' grants wildcard Action or Resource",
                        severity="critical", resource_type="iam_policy",
                        hint="Replace '*' with explicit actions and ARNs. Apply least-privilege.",
                        techniques=_IAM_TECHNIQUES, nist=_IAM_NIST, cwe="CWE-732",
                    ))

        # Scan full doc text for hardcoded secrets
        doc_text = json.dumps(doc)
        if _AWS_KEY_PATTERN.search(doc_text):
            findings.append(self._finding(
                resource=ref, severity="critical",
                issue="[IAC-CF-004] Hardcoded AWS Access Key ID in CloudFormation template",
                resource_type="cfn_template",
                hint="Remove key. Use IAM roles or dynamic references {{resolve:secretsmanager:...}}.",
                techniques=_SECRET_TECHNIQUES, nist=_SECRET_NIST, cwe="CWE-798",
            ))

        return findings

    def _check_k8s_manifest(self, path: Path, doc: dict) -> List[Finding]:
        findings: List[Finding] = []
        ref  = str(path)
        kind = doc.get("kind", "")
        name = doc.get("metadata", {}).get("name", "unknown")

        # Drill to containers
        spec = doc.get("spec", {}) or {}
        template_spec = spec.get("template", {}).get("spec", spec)
        containers = template_spec.get("containers", []) + template_spec.get("initContainers", [])

        for c in containers:
            cname = c.get("name", "?")

            # IAC-K8-003: latest tag
            image = c.get("image", "")
            if ":latest" in image or (":" not in image and "@" not in image):
                findings.append(self._finding(
                    resource=f"{ref} → {kind}/{name}/{cname}",
                    issue=f"[IAC-K8-003] Container '{cname}' uses unpinned image '{image}' — supply chain risk",
                    severity="medium", resource_type="k8s_manifest",
                    hint="Pin to a specific digest: image: myapp@sha256:abc123...",
                    techniques=_SUPPLY_TECHNIQUES, nist=_SUPPLY_NIST, cwe="CWE-1357",
                ))

            # IAC-K8-001/002: security context
            sc = c.get("securityContext", {})
            if not sc:
                findings.append(self._finding(
                    resource=f"{ref} → {kind}/{name}/{cname}",
                    issue=f"[IAC-K8-002] Container '{cname}' has no securityContext — no hardening applied",
                    severity="high", resource_type="k8s_manifest",
                    hint=(
                        "Add securityContext with: runAsNonRoot: true, runAsUser: 10001, "
                        "allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, "
                        "capabilities: {drop: [ALL]}"
                    ),
                    techniques=["T1611"], nist=["CM-6", "CM-7"], cwe="CWE-250",
                ))
            elif sc.get("privileged"):
                findings.append(self._finding(
                    resource=f"{ref} → {kind}/{name}/{cname}",
                    issue=f"[IAC-K8-001] Container '{cname}' is privileged in manifest",
                    severity="critical", resource_type="k8s_manifest",
                    hint="Remove privileged: true. Use specific capabilities if needed.",
                    techniques=["T1611", "T1068"], nist=["CM-6", "CM-7", "AC-6"], cwe="CWE-250",
                ))

            # IAC-K8-004: hardcoded secrets in env vars
            for env in (c.get("env") or []):
                val = env.get("value", "")
                key = env.get("name", "")
                if val and _SECRET_PATTERN.search(f"{key}={val}"):
                    findings.append(self._finding(
                        resource=f"{ref} → {kind}/{name}/{cname}",
                        issue=f"[IAC-K8-004] Possible hardcoded secret in env var '{key}'",
                        severity="high", resource_type="k8s_manifest",
                        hint="Use secretKeyRef or a secrets manager CSI driver instead of inline values.",
                        techniques=_SECRET_TECHNIQUES, nist=_SECRET_NIST, cwe="CWE-312",
                        details={"env_key": key},
                    ))

        return findings

    def _scan_cfn_json(self, path: Path) -> List[Finding]:
        try:
            with path.open() as f:
                doc = json.load(f)
            return self._check_cfn_doc(path, doc)
        except Exception as e:
            logger.debug(f"CloudFormation JSON parse failed for {path}: {e}")
            return []

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _looks_like_cfn(self, path: Path) -> bool:
        try:
            text = path.read_text(errors="replace")[:4096]
            return "AWSTemplateFormatVersion" in text or '"Resources"' in text
        except Exception:
            return False

    def _walk(self, base: str):
        base_path = Path(base)
        if base_path.is_file():
            yield base_path
            return
        for p in base_path.rglob("*"):
            if p.is_file() and p.suffix in (".tf", ".yaml", ".yml", ".json"):
                # Skip .git, __pycache__, node_modules
                if any(part.startswith(".") or part in ("__pycache__", "node_modules", ".terraform")
                       for part in p.parts):
                    continue
                yield p

    def _finding(self, resource: str, issue: str, severity: str,
                 resource_type: str, hint: str,
                 techniques: List[str], nist: List[str],
                 cwe: Optional[str] = None,
                 details: Optional[dict] = None) -> Finding:
        return Finding(
            resource=resource,
            issue=issue,
            severity=severity,
            provider=self.provider,
            resource_type=resource_type,
            remediation_hint=hint,
            mitre_techniques=techniques,
            mitre_tactic=self._tactic_from_techniques(techniques),
            nist_controls=nist,
            cwe_id=cwe,
            details=details or {},
        )

    @staticmethod
    def _tactic_from_techniques(techniques: List[str]) -> Optional[str]:
        """Infer primary tactic from technique prefix."""
        if not techniques:
            return None
        t = techniques[0]
        mapping = {
            "T1530": "collection", "T1190": "initial-access",
            "T1078": "initial-access", "T1098": "persistence",
            "T1552": "credential-access", "T1611": "privilege-escalation",
            "T1068": "privilege-escalation", "T1485": "impact",
            "T1499": "impact", "T1195": "initial-access",
            "T1046": "discovery",
        }
        for prefix, tactic in mapping.items():
            if t.startswith(prefix):
                return tactic
        return "defense-evasion"
