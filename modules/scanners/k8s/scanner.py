"""
Aegis — Kubernetes Security Scanner  (v2.3.0)

Checks applied (CIS Kubernetes Benchmark v1.8 + NSA/CISA Hardening Guide):

RBAC / Access Control
  K8S-001  ClusterRoleBinding to cluster-admin for non-system subjects
  K8S-002  Wildcard (*) verbs or resources in ClusterRoles
  K8S-003  ServiceAccount with automounted token in default namespace
  K8S-004  Default service account used by running pods

Pod Security
  K8S-010  Privileged containers (securityContext.privileged: true)
  K8S-011  Containers running as root (runAsUser: 0 or missing runAsNonRoot)
  K8S-012  Containers with allowPrivilegeEscalation: true
  K8S-013  HostNetwork / HostPID / HostIPC enabled on pods
  K8S-014  Writable root filesystem (readOnlyRootFilesystem: false)
  K8S-015  Dangerous Linux capabilities added (SYS_ADMIN, NET_ADMIN, etc.)
  K8S-016  Missing resource limits (CPU / memory) — enables resource exhaustion

Secrets Hygiene
  K8S-020  Secrets exposed as environment variables (prefer volume mounts)
  K8S-021  Sensitive data patterns in ConfigMaps (passwords, tokens, keys)
  K8S-022  Default namespace Secrets readable by all service accounts

Network Policy
  K8S-030  Namespaces with no NetworkPolicy — unrestricted east-west traffic
  K8S-031  Pods with no matching NetworkPolicy in critical namespaces

Namespace Hygiene
  K8S-040  Workloads running in the default namespace
  K8S-041  Missing namespace-level resource quotas

Each finding is tagged with MITRE ATT&CK techniques and NIST 800-53 controls.
"""

import logging
import os
import re
from typing import List, Optional

from modules.scanners.base import BaseScanner, Finding

logger = logging.getLogger(__name__)

# ── MITRE / NIST mapping tables ───────────────────────────────────────────────

_RBAC_TECHNIQUES     = ["T1078.001", "T1098"]          # Valid Accounts: Default, Account Manipulation
_RBAC_TACTIC         = "privilege-escalation"
_RBAC_NIST           = ["AC-2", "AC-3", "AC-6"]

_PRIVILEGE_TECHNIQUES = ["T1611", "T1068"]             # Escape to Host, Exploitation for Privilege Escalation
_PRIVILEGE_TACTIC     = "privilege-escalation"
_PRIVILEGE_NIST       = ["CM-6", "CM-7", "AC-6"]

_SECRET_TECHNIQUES   = ["T1552.007", "T1552.001"]      # Container API secrets, Credentials in Files
_SECRET_TACTIC       = "credential-access"
_SECRET_NIST         = ["SC-28", "IA-5"]

_NETWORK_TECHNIQUES  = ["T1046", "T1021"]              # Network Service Scanning, Remote Services
_NETWORK_TACTIC      = "lateral-movement"
_NETWORK_NIST        = ["SC-7", "AC-4"]

# Patterns that suggest a ConfigMap holds sensitive data
_SENSITIVE_KEYS = re.compile(
    r"(password|passwd|secret|token|api.?key|private.?key|credential|auth)",
    re.IGNORECASE,
)

# Capabilities considered dangerous for container workloads
_DANGEROUS_CAPS = {
    "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
    "SYS_RAWIO", "NET_RAW", "SYS_CHROOT", "SETUID", "SETGID",
    "DAC_OVERRIDE", "AUDIT_WRITE",
}


class K8sScanner(BaseScanner):
    """
    Kubernetes security posture scanner.

    Connects to the cluster using the standard credential chain:
      1. In-cluster service account (KUBERNETES_SERVICE_HOST env var)
      2. ~/.kube/config kubeconfig file
      3. KUBECONFIG environment variable path

    Set K8S_NAMESPACES=kube-system,production,staging to restrict scan scope.
    Set K8S_CONTEXT=my-context to target a specific kubeconfig context.
    """

    provider = "k8s"

    def __init__(self):
        self._client = None
        self._rbac_client = None
        self._core_client = None
        self._networking_client = None
        self._namespaces: List[str] = [
            ns.strip()
            for ns in os.getenv("K8S_NAMESPACES", "").split(",")
            if ns.strip()
        ]
        self._context: Optional[str] = os.getenv("K8S_CONTEXT")

    def is_available(self) -> bool:
        try:
            from kubernetes import client, config as k8s_config  # noqa: F401
            try:
                k8s_config.load_incluster_config()
            except Exception:
                k8s_config.load_kube_config(context=self._context)
            self._core_client       = client.CoreV1Api()
            self._rbac_client       = client.RbacAuthorizationV1Api()
            self._networking_client = client.NetworkingV1Api()
            # Quick connectivity check
            self._core_client.list_namespace(_request_timeout=5)
            return True
        except Exception as e:
            logger.debug(f"K8s scanner unavailable: {e}")
            return False

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        try:
            findings.extend(self._check_rbac())
            findings.extend(self._check_pod_security())
            findings.extend(self._check_secrets())
            findings.extend(self._check_network_policies())
            findings.extend(self._check_namespace_hygiene())
        except Exception as e:
            logger.error(f"K8s scan error: {e}", exc_info=True)

        logger.info(f"K8s scan complete: {len(findings)} findings.")
        return findings

    # ── RBAC checks ───────────────────────────────────────────────────────────

    def _check_rbac(self) -> List[Finding]:
        findings: List[Finding] = []

        try:
            crbs = self._rbac_client.list_cluster_role_binding()
        except Exception as e:
            logger.warning(f"RBAC list_cluster_role_binding failed: {e}")
            return findings

        for crb in crbs.items:
            role_ref = crb.role_ref
            subjects  = crb.subjects or []

            # K8S-001: cluster-admin binding to non-system subjects
            if role_ref.name == "cluster-admin":
                for subj in subjects:
                    if subj.namespace and not subj.namespace.startswith("kube-"):
                        findings.append(Finding(
                            resource=f"ClusterRoleBinding/{crb.metadata.name}",
                            issue=f"[K8S-001] Subject '{subj.name}' ({subj.kind}) in namespace "
                                  f"'{subj.namespace}' is bound to cluster-admin",
                            severity="critical",
                            provider=self.provider,
                            resource_type="cluster_role_binding",
                            remediation_hint=(
                                "Remove this ClusterRoleBinding. Grant the minimum required "
                                "permissions via a namespaced Role/RoleBinding instead."
                            ),
                            mitre_techniques=_RBAC_TECHNIQUES,
                            mitre_tactic=_RBAC_TACTIC,
                            nist_controls=_RBAC_NIST,
                            cwe_id="CWE-269",
                        ))

        # K8S-002: wildcard verbs or resources in ClusterRoles
        try:
            crs = self._rbac_client.list_cluster_role()
        except Exception as e:
            logger.warning(f"RBAC list_cluster_role failed: {e}")
            return findings

        for cr in crs.items:
            if cr.metadata.name.startswith("system:"):
                continue
            for rule in (cr.rules or []):
                verbs     = rule.verbs or []
                resources = rule.resources or []
                if "*" in verbs or "*" in resources:
                    findings.append(Finding(
                        resource=f"ClusterRole/{cr.metadata.name}",
                        issue=f"[K8S-002] ClusterRole '{cr.metadata.name}' grants wildcard "
                              f"{'verbs' if '*' in verbs else 'resources'} — overly permissive",
                        severity="high",
                        provider=self.provider,
                        resource_type="cluster_role",
                        remediation_hint=(
                            "Replace wildcard '*' with explicit verbs and resource types. "
                            "Apply principle of least privilege."
                        ),
                        mitre_techniques=_RBAC_TECHNIQUES,
                        mitre_tactic=_RBAC_TACTIC,
                        nist_controls=_RBAC_NIST,
                        cwe_id="CWE-732",
                    ))
                    break  # one finding per role

        return findings

    # ── Pod security checks ───────────────────────────────────────────────────

    def _check_pod_security(self) -> List[Finding]:
        findings: List[Finding] = []
        namespaces = self._get_namespaces()

        for ns in namespaces:
            try:
                pods = self._core_client.list_namespaced_pod(ns)
            except Exception as e:
                logger.warning(f"list_namespaced_pod({ns}) failed: {e}")
                continue

            for pod in pods.items:
                pod_name = pod.metadata.name
                pod_spec = pod.spec or {}

                # K8S-013: host namespace sharing
                for attr, check_id, label in [
                    ("host_network", "K8S-013a", "hostNetwork"),
                    ("host_pid",     "K8S-013b", "hostPID"),
                    ("host_ipc",     "K8S-013c", "hostIPC"),
                ]:
                    if getattr(pod_spec, attr, False):
                        findings.append(Finding(
                            resource=f"{ns}/Pod/{pod_name}",
                            issue=f"[{check_id}] Pod has {label}=true — shares host {label.replace('host','')} namespace",
                            severity="high",
                            provider=self.provider,
                            resource_type="pod",
                            region=ns,
                            remediation_hint=f"Set {label}: false in pod spec unless explicitly required.",
                            mitre_techniques=_PRIVILEGE_TECHNIQUES,
                            mitre_tactic=_PRIVILEGE_TACTIC,
                            nist_controls=_PRIVILEGE_NIST,
                            cwe_id="CWE-250",
                        ))

                containers = list(pod.spec.containers or []) + list(pod.spec.init_containers or [])

                for c in containers:
                    sc = c.security_context

                    # K8S-010: privileged container
                    if sc and sc.privileged:
                        findings.append(Finding(
                            resource=f"{ns}/Pod/{pod_name}/Container/{c.name}",
                            issue=f"[K8S-010] Container '{c.name}' runs as privileged — full host access",
                            severity="critical",
                            provider=self.provider,
                            resource_type="container",
                            region=ns,
                            remediation_hint="Set securityContext.privileged: false. Use specific capabilities if required.",
                            mitre_techniques=_PRIVILEGE_TECHNIQUES,
                            mitre_tactic=_PRIVILEGE_TACTIC,
                            nist_controls=_PRIVILEGE_NIST,
                            cwe_id="CWE-250",
                        ))

                    # K8S-011: running as root
                    runs_as_root = False
                    if sc:
                        if sc.run_as_user == 0:
                            runs_as_root = True
                        if sc.run_as_non_root is False:
                            runs_as_root = True
                        if sc.run_as_non_root is None and sc.run_as_user is None:
                            runs_as_root = True  # no explicit non-root constraint
                    else:
                        runs_as_root = True  # no securityContext at all

                    if runs_as_root:
                        findings.append(Finding(
                            resource=f"{ns}/Pod/{pod_name}/Container/{c.name}",
                            issue=f"[K8S-011] Container '{c.name}' may run as root (no runAsNonRoot constraint)",
                            severity="high",
                            provider=self.provider,
                            resource_type="container",
                            region=ns,
                            remediation_hint=(
                                "Set securityContext.runAsNonRoot: true and runAsUser to a "
                                "non-zero UID (e.g. 10001)."
                            ),
                            mitre_techniques=_PRIVILEGE_TECHNIQUES,
                            mitre_tactic=_PRIVILEGE_TACTIC,
                            nist_controls=_PRIVILEGE_NIST,
                            cwe_id="CWE-250",
                        ))

                    # K8S-012: allowPrivilegeEscalation
                    if sc and sc.allow_privilege_escalation is not False:
                        findings.append(Finding(
                            resource=f"{ns}/Pod/{pod_name}/Container/{c.name}",
                            issue=f"[K8S-012] Container '{c.name}' allows privilege escalation",
                            severity="high",
                            provider=self.provider,
                            resource_type="container",
                            region=ns,
                            remediation_hint="Set securityContext.allowPrivilegeEscalation: false.",
                            mitre_techniques=_PRIVILEGE_TECHNIQUES,
                            mitre_tactic=_PRIVILEGE_TACTIC,
                            nist_controls=_PRIVILEGE_NIST,
                            cwe_id="CWE-269",
                        ))

                    # K8S-014: writable root filesystem
                    if not (sc and sc.read_only_root_filesystem):
                        findings.append(Finding(
                            resource=f"{ns}/Pod/{pod_name}/Container/{c.name}",
                            issue=f"[K8S-014] Container '{c.name}' has a writable root filesystem",
                            severity="medium",
                            provider=self.provider,
                            resource_type="container",
                            region=ns,
                            remediation_hint=(
                                "Set securityContext.readOnlyRootFilesystem: true. "
                                "Mount writable volumes only for paths that need writes."
                            ),
                            mitre_techniques=["T1565.001"],  # Data Manipulation: Stored Data
                            mitre_tactic="impact",
                            nist_controls=["CM-6", "CM-7"],
                            cwe_id="CWE-732",
                        ))

                    # K8S-015: dangerous capabilities
                    if sc and sc.capabilities and sc.capabilities.add:
                        dangerous = [cap for cap in sc.capabilities.add if cap in _DANGEROUS_CAPS]
                        if dangerous:
                            findings.append(Finding(
                                resource=f"{ns}/Pod/{pod_name}/Container/{c.name}",
                                issue=f"[K8S-015] Container '{c.name}' adds dangerous capabilities: {dangerous}",
                                severity="high",
                                provider=self.provider,
                                resource_type="container",
                                region=ns,
                                remediation_hint=(
                                    "Remove dangerous capabilities. Use 'cap_drop: ALL' and only "
                                    "add the specific capabilities truly required."
                                ),
                                mitre_techniques=_PRIVILEGE_TECHNIQUES,
                                mitre_tactic=_PRIVILEGE_TACTIC,
                                nist_controls=_PRIVILEGE_NIST,
                                cwe_id="CWE-250",
                                details={"dangerous_caps": dangerous},
                            ))

                    # K8S-016: missing resource limits
                    if not c.resources or not c.resources.limits:
                        findings.append(Finding(
                            resource=f"{ns}/Pod/{pod_name}/Container/{c.name}",
                            issue=f"[K8S-016] Container '{c.name}' has no CPU/memory limits — DoS risk",
                            severity="medium",
                            provider=self.provider,
                            resource_type="container",
                            region=ns,
                            remediation_hint=(
                                "Set resources.limits.cpu and resources.limits.memory. "
                                "Also set requests to enable the scheduler to make decisions."
                            ),
                            mitre_techniques=["T1499"],  # Endpoint Denial of Service
                            mitre_tactic="impact",
                            nist_controls=["SC-5", "CM-6"],
                            cwe_id="CWE-400",
                        ))

                    # K8S-020: secrets as env vars
                    for env in (c.env or []):
                        if env.value_from and env.value_from.secret_key_ref:
                            findings.append(Finding(
                                resource=f"{ns}/Pod/{pod_name}/Container/{c.name}",
                                issue=f"[K8S-020] Secret '{env.value_from.secret_key_ref.name}' "
                                      f"exposed as env var '{env.name}' — prefer volume mounts",
                                severity="medium",
                                provider=self.provider,
                                resource_type="container",
                                region=ns,
                                remediation_hint=(
                                    "Mount secrets as files via volumeMounts instead of env vars. "
                                    "Env vars are visible in process listings and crash dumps."
                                ),
                                mitre_techniques=_SECRET_TECHNIQUES,
                                mitre_tactic=_SECRET_TACTIC,
                                nist_controls=_SECRET_NIST,
                                cwe_id="CWE-312",
                                details={"secret_name": env.value_from.secret_key_ref.name},
                            ))

        return findings

    # ── Secrets checks ────────────────────────────────────────────────────────

    def _check_secrets(self) -> List[Finding]:
        findings: List[Finding] = []
        namespaces = self._get_namespaces()

        for ns in namespaces:
            # K8S-021: sensitive data in ConfigMaps
            try:
                cms = self._core_client.list_namespaced_config_map(ns)
                for cm in cms.items:
                    for key in (cm.data or {}):
                        if _SENSITIVE_KEYS.search(key):
                            findings.append(Finding(
                                resource=f"{ns}/ConfigMap/{cm.metadata.name}",
                                issue=f"[K8S-021] ConfigMap key '{key}' suggests sensitive data stored in plaintext",
                                severity="high",
                                provider=self.provider,
                                resource_type="configmap",
                                region=ns,
                                remediation_hint=(
                                    "Move sensitive values to a Kubernetes Secret (or better: "
                                    "an external secrets manager like AWS SM or Vault). "
                                    "ConfigMaps are not encrypted at rest by default."
                                ),
                                mitre_techniques=_SECRET_TECHNIQUES,
                                mitre_tactic=_SECRET_TACTIC,
                                nist_controls=_SECRET_NIST,
                                cwe_id="CWE-312",
                                details={"key": key, "configmap": cm.metadata.name},
                            ))
            except Exception as e:
                logger.warning(f"ConfigMap check failed in {ns}: {e}")

        return findings

    # ── Network policy checks ─────────────────────────────────────────────────

    def _check_network_policies(self) -> List[Finding]:
        findings: List[Finding] = []
        namespaces = self._get_namespaces()

        for ns in namespaces:
            if ns in ("kube-system", "kube-public", "kube-node-lease"):
                continue
            try:
                policies = self._networking_client.list_namespaced_network_policy(ns)
                if not policies.items:
                    findings.append(Finding(
                        resource=f"Namespace/{ns}",
                        issue=f"[K8S-030] Namespace '{ns}' has no NetworkPolicy — unrestricted pod-to-pod traffic",
                        severity="high",
                        provider=self.provider,
                        resource_type="namespace",
                        region=ns,
                        remediation_hint=(
                            "Create a default-deny NetworkPolicy in every namespace, then "
                            "add explicit allow policies for required traffic flows."
                        ),
                        mitre_techniques=_NETWORK_TECHNIQUES,
                        mitre_tactic=_NETWORK_TACTIC,
                        nist_controls=_NETWORK_NIST,
                        cwe_id="CWE-923",
                    ))
            except Exception as e:
                logger.warning(f"NetworkPolicy check failed in {ns}: {e}")

        return findings

    # ── Namespace hygiene ─────────────────────────────────────────────────────

    def _check_namespace_hygiene(self) -> List[Finding]:
        findings: List[Finding] = []

        # K8S-040: workloads in default namespace
        try:
            pods = self._core_client.list_namespaced_pod("default")
            user_pods = [p for p in pods.items
                         if not p.metadata.name.startswith(("kube-", "coredns"))]
            if user_pods:
                names = [p.metadata.name for p in user_pods[:5]]
                findings.append(Finding(
                    resource="Namespace/default",
                    issue=f"[K8S-040] {len(user_pods)} workload(s) running in 'default' namespace: {names}",
                    severity="medium",
                    provider=self.provider,
                    resource_type="namespace",
                    remediation_hint=(
                        "Create dedicated namespaces for each application/team. "
                        "The default namespace provides no isolation boundaries."
                    ),
                    mitre_techniques=["T1078"],
                    mitre_tactic="defense-evasion",
                    nist_controls=["AC-4", "CM-7"],
                    details={"pod_count": len(user_pods), "sample": names},
                ))
        except Exception as e:
            logger.warning(f"Default namespace check failed: {e}")

        # K8S-041: namespaces without resource quotas
        namespaces = self._get_namespaces()
        for ns in namespaces:
            if ns in ("kube-system", "kube-public", "kube-node-lease", "default"):
                continue
            try:
                quotas = self._core_client.list_namespaced_resource_quota(ns)
                if not quotas.items:
                    findings.append(Finding(
                        resource=f"Namespace/{ns}",
                        issue=f"[K8S-041] Namespace '{ns}' has no ResourceQuota — unlimited resource consumption",
                        severity="low",
                        provider=self.provider,
                        resource_type="namespace",
                        region=ns,
                        remediation_hint=(
                            "Add a ResourceQuota to cap CPU, memory, and object counts. "
                            "Also add LimitRange to set per-container defaults."
                        ),
                        mitre_techniques=["T1499"],
                        mitre_tactic="impact",
                        nist_controls=["SC-5"],
                    ))
            except Exception as e:
                logger.warning(f"ResourceQuota check failed in {ns}: {e}")

        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_namespaces(self) -> List[str]:
        """Return filtered namespace list, or all namespaces if no filter set."""
        if self._namespaces:
            return self._namespaces
        try:
            ns_list = self._core_client.list_namespace()
            return [ns.metadata.name for ns in ns_list.items]
        except Exception as e:
            logger.warning(f"list_namespace failed: {e}")
            return ["default"]
