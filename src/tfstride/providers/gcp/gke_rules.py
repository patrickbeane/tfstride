from __future__ import annotations

from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource
from tfstride.providers.gcp.resource_facts import GcpResourceFacts, gcp_facts
from tfstride.providers.gcp.resource_types import GCP_GKE_RESOURCE_TYPES
from tfstride.providers.kubernetes import is_broad_public_range, uncertainty_evidence

_GKE_BROAD_OAUTH_SCOPES = frozenset(
    {
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/compute",
        "https://www.googleapis.com/auth/devstorage.full_control",
    }
)
_GKE_SECURITY_LOGGING_COMPONENTS = frozenset({"APISERVER", "SCHEDULER", "CONTROLLER_MANAGER"})
_GKE_POSTURE_DISABLED = "disabled"
_GKE_POSTURE_UNKNOWN = "unknown"


class GcpGkeRuleDetectors:
    def detect_gke_public_control_plane(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type("google_container_cluster"):
            cluster_facts = gcp_facts(cluster)
            if not cluster.public_access_configured:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", cluster.address))
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{cluster.display_name} exposes a public GKE control-plane endpoint. "
                        "Public API server reachability increases dependence on IAM, Kubernetes RBAC, "
                        "and authorized network configuration to protect cluster administration."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "control_plane_endpoint",
                            [cluster_facts.gke_endpoint or "public endpoint configured"],
                        ),
                        evidence_item("public_access_reasons", cluster.public_access_reasons),
                        evidence_item("public_exposure_reasons", cluster.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gke_broad_authorized_networks(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type("google_container_cluster"):
            cluster_facts = gcp_facts(cluster)
            if not cluster.public_access_configured:
                continue
            broad_networks = _gke_broad_authorized_networks(cluster)
            if not broad_networks:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=2,
                blast_radius=1,
            )
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", cluster.address))
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{cluster.display_name} exposes the GKE control plane without narrow master "
                        "authorized networks. Internet-wide or unset CIDR controls leave the Kubernetes API "
                        "server reachable from untrusted client networks."
                    ),
                    evidence=collect_evidence(
                        evidence_item("authorized_networks", broad_networks),
                        evidence_item(
                            "configured_authorized_network_count",
                            [str(len(cluster_facts.gke_master_authorized_networks))],
                        ),
                        evidence_item("public_exposure_reasons", cluster.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gke_workload_identity_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type("google_container_cluster"):
            cluster_facts = gcp_facts(cluster)
            if cluster_facts.gke_workload_identity_enabled is True:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=cluster.public_exposure,
                privilege_breadth=1,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{cluster.display_name} does not enable GKE Workload Identity. Pods are more likely "
                        "to depend on node service-account credentials, which weakens workload-level identity "
                        "boundaries and can expand blast radius after pod compromise."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "workload_identity_posture",
                            [
                                (
                                    "workload_identity_enabled is "
                                    f"{_bool_status(cluster_facts.gke_workload_identity_enabled)}"
                                ),
                                f"workload_pool is {cluster_facts.gke_workload_identity_pool or 'unset'}",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gke_legacy_metadata_endpoints_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for resource in context.inventory.by_type(*GCP_GKE_RESOURCE_TYPES):
            resource_facts = gcp_facts(resource)
            if resource_facts.gke_legacy_metadata_endpoints_enabled is not True:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=1,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[resource.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{resource.display_name} allows legacy or broad node metadata exposure. Workloads "
                        "on the node may be able to reach metadata credentials outside the intended GKE "
                        "metadata server controls."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "node_metadata_posture",
                            [
                                "legacy metadata endpoints are enabled",
                                f"metadata mode is {resource_facts.gke_node_metadata_mode or 'unset'}",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gke_broad_node_service_account(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for resource in context.inventory.by_type(*GCP_GKE_RESOURCE_TYPES):
            resource_facts = gcp_facts(resource)
            risk_descriptions = _gke_node_identity_risks(resource)
            if not risk_descriptions:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=2,
                data_sensitivity=0,
                lateral_movement=2,
                blast_radius=2,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[resource.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{resource.display_name} uses broad GKE node identity settings. Default or broadly "
                        "scoped node service accounts can turn a node or pod compromise into wider GCP API "
                        "access."
                    ),
                    evidence=collect_evidence(
                        evidence_item("node_identity_risks", risk_descriptions),
                        evidence_item("node_service_account", [resource_facts.gke_node_service_account or "unset"]),
                        evidence_item("oauth_scopes", resource_facts.gke_node_oauth_scopes),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gke_control_plane_logging_incomplete(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type("google_container_cluster"):
            cluster_facts = gcp_facts(cluster)
            logging_issues = _gke_logging_issues(cluster_facts)
            if not logging_issues:
                continue
            explicit_gap = cluster_facts.gke_control_plane_logging_state in {"disabled", "not_configured"} or any(
                issue.startswith("missing security logging component") for issue in logging_issues
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=2 if explicit_gap else 0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{cluster.display_name} does not show deterministic GKE control-plane logging for key "
                        "security components. Missing API server, scheduler, or controller manager logs can limit "
                        "investigation of administrative and cluster-control activity."
                    ),
                    evidence=collect_evidence(
                        evidence_item("logging_posture", _gke_logging_evidence(cluster_facts, logging_issues)),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(
                                cluster_facts.gke_posture_uncertainties, ("logging_service", "logging_config")
                            ),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gke_network_policy_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type("google_container_cluster"):
            cluster_facts = gcp_facts(cluster)
            if cluster_facts.gke_network_policy_state == "enabled":
                continue
            explicit_gap = cluster_facts.gke_network_policy_state in {"disabled", "not_configured"}
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=2 if explicit_gap else 0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{cluster.display_name} does not deterministically enable GKE network policy. Without a "
                        "pod network policy provider, Kubernetes workloads have weaker pod-level traffic isolation "
                        "and lateral-movement controls."
                    ),
                    evidence=collect_evidence(
                        evidence_item("network_policy_posture", _gke_network_policy_evidence(cluster_facts)),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(cluster_facts.gke_posture_uncertainties, ("network_policy",)),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gke_secrets_encryption_not_configured(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type("google_container_cluster"):
            cluster_facts = gcp_facts(cluster)
            if cluster_facts.gke_secrets_encryption_state == "enabled":
                continue
            explicit_gap = cluster_facts.gke_secrets_encryption_state == "disabled"
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2 if explicit_gap else 1,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{cluster.display_name} does not show deterministic GKE application-layer secrets "
                        "encryption with a Cloud KMS key. Kubernetes secrets may not have customer-controlled "
                        "encryption key ownership represented in the Terraform plan."
                    ),
                    evidence=collect_evidence(
                        evidence_item("secret_encryption_posture", _gke_secrets_encryption_evidence(cluster_facts)),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(cluster_facts.gke_posture_uncertainties, ("database_encryption",)),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gke_legacy_abac_enabled_or_unknown(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type("google_container_cluster"):
            cluster_facts = gcp_facts(cluster)
            if cluster_facts.gke_legacy_abac_state == _GKE_POSTURE_DISABLED:
                continue
            unknown = cluster_facts.gke_legacy_abac_state == _GKE_POSTURE_UNKNOWN
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0 if unknown else 2,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{cluster.display_name} does not show legacy ABAC disabled. Legacy ABAC can bypass "
                        "stronger IAM and Kubernetes RBAC expectations, and an unknown Terraform value should "
                        "be reviewed before relying on RBAC-only authorization."
                    ),
                    evidence=collect_evidence(
                        evidence_item("legacy_abac_posture", _gke_legacy_abac_evidence(cluster_facts)),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(cluster_facts.gke_posture_uncertainties, ("enable_legacy_abac",)),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gke_client_certificate_auth_enabled_or_unknown(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type("google_container_cluster"):
            cluster_facts = gcp_facts(cluster)
            if not _gke_client_certificate_auth_represented(cluster_facts):
                continue
            if cluster_facts.gke_client_certificate_auth_state == _GKE_POSTURE_DISABLED:
                continue
            unknown = cluster_facts.gke_client_certificate_auth_state == _GKE_POSTURE_UNKNOWN
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0 if unknown else 1,
                data_sensitivity=0,
                lateral_movement=0 if unknown else 1,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{cluster.display_name} does not show client certificate authentication disabled. "
                        "Client certificate authentication can create an additional cluster-admin path outside "
                        "the intended centralized identity controls."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "client_certificate_auth_posture",
                            _gke_client_certificate_auth_evidence(cluster_facts),
                        ),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(
                                cluster_facts.gke_posture_uncertainties,
                                ("master_auth.client_certificate_config.issue_client_certificate",),
                            ),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gke_shielded_nodes_disabled_or_unknown(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type("google_container_cluster"):
            cluster_facts = gcp_facts(cluster)
            if cluster_facts.gke_shielded_nodes_state == "enabled":
                continue
            unknown = cluster_facts.gke_shielded_nodes_state == "unknown"
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0 if unknown else 2,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{cluster.display_name} does not show GKE Shielded Nodes enabled. Shielded Nodes add "
                        "node integrity protections that reduce the impact of boot-level tampering and host "
                        "compromise paths."
                    ),
                    evidence=collect_evidence(
                        evidence_item("shielded_nodes_posture", _gke_shielded_nodes_evidence(cluster_facts)),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(
                                cluster_facts.gke_posture_uncertainties,
                                ("enable_shielded_nodes", "shielded_nodes.enabled"),
                            ),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gke_binary_authorization_not_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type("google_container_cluster"):
            cluster_facts = gcp_facts(cluster)
            if not _gke_binary_authorization_represented(cluster_facts):
                continue
            if cluster_facts.gke_binary_authorization_state == "enabled":
                continue
            unknown = cluster_facts.gke_binary_authorization_state == "unknown"
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0 if unknown else 2,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{cluster.display_name} does not show GKE Binary Authorization enabled. Without an "
                        "admission policy for trusted container images, unauthorized or unreviewed workload "
                        "images are harder to prevent at deploy time."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "binary_authorization_posture",
                            _gke_binary_authorization_evidence(cluster_facts),
                        ),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(
                                cluster_facts.gke_posture_uncertainties, ("binary_authorization.evaluation_mode",)
                            ),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _bool_status(value: bool | None) -> str:
    if value is None:
        return "unset"
    return str(value).lower()


def _gke_broad_authorized_networks(cluster: NormalizedResource) -> list[str]:
    facts = gcp_facts(cluster)
    if not facts.gke_master_authorized_networks:
        return ["master authorized networks are not configured"]
    descriptions: list[str] = []
    for network in facts.gke_master_authorized_networks:
        cidr = str(network.get("cidr_block") or "").strip()
        if not is_broad_public_range(cidr):
            continue
        name = str(network.get("display_name") or network.get("name") or "unnamed").strip() or "unnamed"
        descriptions.append(f"{name} ({cidr})")
    return descriptions


def _gke_logging_issues(facts: GcpResourceFacts) -> list[str]:
    state = facts.gke_control_plane_logging_state
    if state == "unknown":
        return ["control-plane logging state is unknown"]
    if state in {"disabled", "not_configured"}:
        return [f"control-plane logging is {state}"]
    if not facts.gke_logging_components:
        return []
    configured_components = {component.strip().upper() for component in facts.gke_logging_components}
    missing_components = sorted(_GKE_SECURITY_LOGGING_COMPONENTS - configured_components)
    return [f"missing security logging component: {component}" for component in missing_components]


def _gke_logging_evidence(facts: GcpResourceFacts, issues: list[str]) -> list[str]:
    values = [f"control_plane_logging_state={facts.gke_control_plane_logging_state or 'unknown'}"]
    if facts.gke_logging_service:
        values.append(f"logging_service={facts.gke_logging_service}")
    else:
        values.append("logging_service is not represented in planned values")
    if facts.gke_logging_components:
        values.append(f"logging_components=[{', '.join(facts.gke_logging_components)}]")
    else:
        values.append("logging_components are not represented in planned values")
    values.extend(issues)
    return values


def _gke_network_policy_evidence(facts: GcpResourceFacts) -> list[str]:
    values = [f"network_policy_state={facts.gke_network_policy_state or 'unknown'}"]
    if facts.gke_network_policy_provider:
        values.append(f"network_policy_provider={facts.gke_network_policy_provider}")
    else:
        values.append("network_policy_provider is not represented in planned values")
    return values


def _gke_secrets_encryption_evidence(facts: GcpResourceFacts) -> list[str]:
    values = [f"secrets_encryption_state={facts.gke_secrets_encryption_state or 'unknown'}"]
    if facts.gke_database_encryption_state:
        values.append(f"database_encryption_state={facts.gke_database_encryption_state}")
    else:
        values.append("database_encryption_state is not represented in planned values")
    if facts.gke_database_encryption_key_name:
        values.append(f"database_encryption_key_name={facts.gke_database_encryption_key_name}")
    else:
        values.append("database_encryption_key_name is not represented in planned values")
    return values


def _gke_legacy_abac_evidence(facts: GcpResourceFacts) -> list[str]:
    values = [f"legacy_abac_state={facts.gke_legacy_abac_state or 'unknown'}"]
    if facts.gke_legacy_abac_enabled is None:
        values.append("enable_legacy_abac is not represented in planned values")
    else:
        values.append(f"enable_legacy_abac={str(facts.gke_legacy_abac_enabled).lower()}")
    return values


def _gke_client_certificate_auth_represented(facts: GcpResourceFacts) -> bool:
    return (
        facts.gke_client_certificate_auth_state in {"enabled", "disabled"}
        or bool(facts.gke_client_certificate_config)
        or bool(
            uncertainty_evidence(
                facts.gke_posture_uncertainties, ("master_auth.client_certificate_config.issue_client_certificate",)
            )
        )
    )


def _gke_client_certificate_auth_evidence(facts: GcpResourceFacts) -> list[str]:
    values = [f"client_certificate_auth_state={facts.gke_client_certificate_auth_state or 'unknown'}"]
    if facts.gke_client_certificate_auth_enabled is None:
        values.append(
            "master_auth.client_certificate_config.issue_client_certificate is not represented in planned values"
        )
    else:
        values.append(
            "master_auth.client_certificate_config.issue_client_certificate="
            f"{str(facts.gke_client_certificate_auth_enabled).lower()}"
        )
    return values


def _gke_shielded_nodes_evidence(facts: GcpResourceFacts) -> list[str]:
    values = [f"shielded_nodes_state={facts.gke_shielded_nodes_state or 'unknown'}"]
    if facts.gke_shielded_nodes_enabled is None:
        values.append("shielded nodes setting is not represented in planned values")
    else:
        values.append(f"shielded_nodes.enabled={str(facts.gke_shielded_nodes_enabled).lower()}")
    return values


def _gke_binary_authorization_represented(facts: GcpResourceFacts) -> bool:
    return (
        facts.gke_binary_authorization_state in {"enabled", "disabled"}
        or bool(facts.gke_binary_authorization)
        or bool(uncertainty_evidence(facts.gke_posture_uncertainties, ("binary_authorization.evaluation_mode",)))
    )


def _gke_binary_authorization_evidence(facts: GcpResourceFacts) -> list[str]:
    values = [f"binary_authorization_state={facts.gke_binary_authorization_state or 'unknown'}"]
    if facts.gke_binary_authorization_evaluation_mode:
        values.append(f"evaluation_mode={facts.gke_binary_authorization_evaluation_mode}")
    else:
        values.append("binary_authorization.evaluation_mode is not represented in planned values")
    return values


def _gke_node_identity_risks(resource: NormalizedResource) -> list[str]:
    facts = gcp_facts(resource)
    risks: list[str] = []
    service_account = str(facts.gke_node_service_account or "").strip()
    if not service_account and not facts.gke_node_oauth_scopes:
        if facts.gke_legacy_metadata_endpoints_enabled is None:
            return []
    if not service_account or service_account == "default":
        risks.append("node service account is unset or default")
    elif service_account.endswith("-compute@developer.gserviceaccount.com"):
        risks.append(f"node service account uses default Compute Engine identity `{service_account}`")
    broad_scopes = [scope for scope in facts.gke_node_oauth_scopes if _gke_scope_is_broad(scope)]
    if broad_scopes:
        risks.extend(f"node OAuth scope is broad: {scope}" for scope in broad_scopes)
    return risks


def _gke_scope_is_broad(scope: str) -> bool:
    normalized = str(scope).strip().lower()
    return normalized in _GKE_BROAD_OAUTH_SCOPES or normalized.endswith("/auth/cloud-platform")
