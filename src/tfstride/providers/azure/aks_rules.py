from __future__ import annotations

from dataclasses import dataclass

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.kubernetes import is_broad_public_range, uncertainty_evidence

_ENABLED = "enabled"
_DISABLED = "disabled"
_CONFIGURED = "configured"
_NOT_CONFIGURED = "not_configured"
_UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class _AuthorizedIpRestriction:
    state: str
    broad_ranges: tuple[str, ...] = ()

    @property
    def is_broad_or_missing_or_unknown(self) -> bool:
        return self.state in {"broad", _NOT_CONFIGURED, _UNKNOWN}


class AzureAksRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_api_server_unrestricted(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type(AzureResourceType.KUBERNETES_CLUSTER):
            facts = azure_facts(cluster)
            authorized_ips = _authorized_ip_restriction(facts)
            if facts.aks_private_cluster_state not in {_DISABLED, _UNKNOWN}:
                continue
            if not authorized_ips.is_broad_or_missing_or_unknown:
                continue

            explicit_public_unrestricted = facts.aks_private_cluster_state == _DISABLED and authorized_ips.state in {
                "broad",
                _NOT_CONFIGURED,
            }
            severity_reasoning = build_severity_reasoning(
                internet_exposure=explicit_public_unrestricted,
                privilege_breadth=1,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=2 if explicit_public_unrestricted else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=_public_api_rationale(cluster.display_name, explicit_public_unrestricted),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(cluster)),
                        evidence_item("control_plane_posture", _control_plane_evidence(facts, authorized_ips)),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(
                                facts.aks_posture_uncertainties,
                                (
                                    "private_cluster_enabled",
                                    "api_server_access_profile.authorized_ip_ranges",
                                ),
                            ),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_private_cluster_not_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type(AzureResourceType.KUBERNETES_CLUSTER):
            facts = azure_facts(cluster)
            if facts.aks_private_cluster_state != _DISABLED:
                continue
            authorized_ips = _authorized_ip_restriction(facts)
            if authorized_ips.is_broad_or_missing_or_unknown:
                continue

            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
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
                        f"{cluster.display_name} does not enable AKS private cluster mode, so the Kubernetes API "
                        "server may be reachable through a public Azure endpoint. Authorized IP ranges reduce "
                        "exposure, but private-only control-plane access is not in use."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(cluster)),
                        evidence_item("control_plane_posture", _control_plane_evidence(facts, authorized_ips)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_local_accounts_not_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type(AzureResourceType.KUBERNETES_CLUSTER):
            facts = azure_facts(cluster)
            if facts.aks_local_account_state == _DISABLED:
                continue

            explicit_enabled = facts.aks_local_account_state == _ENABLED
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=2 if explicit_enabled else 1,
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
                        f"{cluster.display_name} does not deterministically disable AKS local accounts. Local "
                        "cluster accounts can weaken centralized Microsoft Entra ID identity, auditing, and access "
                        "control if they remain enabled."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(cluster)),
                        evidence_item("authentication_posture", _local_account_evidence(facts)),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(facts.aks_posture_uncertainties, ("local_account_disabled",)),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_rbac_posture_weak(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type(AzureResourceType.KUBERNETES_CLUSTER):
            facts = azure_facts(cluster)
            issues = _rbac_issues(facts)
            if not issues:
                continue

            explicit_disabled = any("disabled" in issue for issue in issues)
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=2 if explicit_disabled else 1,
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
                        f"{cluster.display_name} has weak or non-deterministic AKS RBAC posture. Kubernetes RBAC "
                        "should be explicitly enabled, and Azure RBAC integration should not be disabled when the "
                        "Azure Active Directory RBAC block is represented in the Terraform plan."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(cluster)),
                        evidence_item("rbac_posture", _rbac_evidence(facts, issues)),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(
                                facts.aks_posture_uncertainties,
                                (
                                    "role_based_access_control_enabled",
                                    "azure_active_directory_role_based_access_control.azure_rbac_enabled",
                                ),
                            ),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_network_policy_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type(AzureResourceType.KUBERNETES_CLUSTER):
            facts = azure_facts(cluster)
            if not _network_policy_missing_or_unknown(facts):
                continue

            explicit_absent = facts.aks_network_policy_state == _NOT_CONFIGURED or _network_policy_is_none(
                facts.aks_network_policy
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=2 if explicit_absent else 1,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{cluster.display_name} does not have deterministic AKS network policy configured. "
                        "Without a pod network policy provider, Kubernetes workloads have weaker pod-level traffic "
                        "isolation and lateral-movement controls."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(cluster)),
                        evidence_item("network_policy_posture", _network_policy_evidence(facts)),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(facts.aks_posture_uncertainties, ("network_profile.network_policy",)),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_workload_identity_not_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type(AzureResourceType.KUBERNETES_CLUSTER):
            facts = azure_facts(cluster)
            if facts.aks_oidc_issuer_state == _ENABLED and facts.aks_workload_identity_state == _ENABLED:
                continue

            explicit_absent = _state_absent(facts.aks_oidc_issuer_state) or _state_absent(
                facts.aks_workload_identity_state
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=2 if explicit_absent else 1,
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
                        f"{cluster.display_name} does not deterministically enable AKS workload identity and its "
                        "OIDC issuer. Pods may need to rely on broader node credentials, static secrets, or less "
                        "auditable identity paths for Azure resource access."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(cluster)),
                        evidence_item("workload_identity_posture", _workload_identity_evidence(facts)),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(
                                facts.aks_posture_uncertainties, ("oidc_issuer_enabled", "workload_identity_enabled")
                            ),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_key_management_service_not_configured(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type(AzureResourceType.KUBERNETES_CLUSTER):
            facts = azure_facts(cluster)
            if facts.aks_kms_state == _CONFIGURED and facts.aks_kms_key_vault_key_id:
                continue

            explicit_absent = facts.aks_kms_state == _NOT_CONFIGURED
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2 if explicit_absent else 1,
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
                        f"{cluster.display_name} does not show deterministic AKS Key Management Service "
                        "configuration with a Key Vault key. Kubernetes secrets may not have customer-controlled "
                        "encryption key ownership represented in the Terraform plan."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(cluster)),
                        evidence_item("secret_encryption_posture", _kms_evidence(facts)),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(facts.aks_posture_uncertainties, ("key_management_service",)),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_monitoring_agent_not_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type(AzureResourceType.KUBERNETES_CLUSTER):
            facts = azure_facts(cluster)
            if facts.aks_oms_agent_state == _ENABLED and facts.aks_log_analytics_workspace_id:
                continue

            explicit_absent = facts.aks_oms_agent_state == _NOT_CONFIGURED
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=2 if explicit_absent else 0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{cluster.display_name} does not show deterministic AKS monitoring through the OMS agent "
                        "and Log Analytics. Missing cluster telemetry can limit detection and investigation of "
                        "control-plane and workload activity."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(cluster)),
                        evidence_item("monitoring_posture", _monitoring_evidence(facts)),
                        evidence_item(
                            "posture_uncertainty", uncertainty_evidence(facts.aks_posture_uncertainties, ("oms_agent",))
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_defender_not_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type(AzureResourceType.KUBERNETES_CLUSTER):
            facts = azure_facts(cluster)
            if facts.aks_defender_state == _ENABLED:
                continue

            explicit_absent = facts.aks_defender_state == _NOT_CONFIGURED
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=2 if explicit_absent else 0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{cluster.display_name} does not show deterministic Microsoft Defender for Containers "
                        "coverage. Missing Defender signals can reduce runtime threat detection and security "
                        "recommendations for AKS workloads."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(cluster)),
                        evidence_item("defender_posture", _defender_evidence(facts)),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(
                                facts.aks_posture_uncertainties, ("microsoft_defender", "security_profile")
                            ),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_azure_policy_not_enabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "azure":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type(AzureResourceType.KUBERNETES_CLUSTER):
            facts = azure_facts(cluster)
            if facts.aks_azure_policy_state == _ENABLED:
                continue

            explicit_disabled = facts.aks_azure_policy_state == _DISABLED
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=2 if explicit_disabled else 0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[cluster.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{cluster.display_name} does not deterministically enable the Azure Policy add-on. "
                        "Without the add-on, Kubernetes policy and governance controls may rely on external review "
                        "instead of in-cluster policy enforcement."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _target_resource_evidence(cluster)),
                        evidence_item("azure_policy_posture", _azure_policy_evidence(facts)),
                        evidence_item(
                            "posture_uncertainty",
                            uncertainty_evidence(facts.aks_posture_uncertainties, ("azure_policy_enabled",)),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _target_resource_evidence(cluster) -> list[str]:
    return [f"address={cluster.address}", f"type={cluster.resource_type}"]


def _public_api_rationale(display_name: str, explicit_public_unrestricted: bool) -> str:
    if explicit_public_unrestricted:
        return (
            f"{display_name} has AKS private cluster mode disabled and does not define narrow authorized IP "
            "ranges for the Kubernetes API server. The control plane is publicly reachable without a reviewed "
            "source range restriction."
        )
    return (
        f"{display_name} does not provide enough deterministic plan evidence to prove private cluster mode and "
        "narrow authorized IP ranges are configured. tfSTRIDE cannot prove the AKS control plane is restricted "
        "from the available Terraform values."
    )


def _control_plane_evidence(facts: AzureResourceFacts, authorized_ips: _AuthorizedIpRestriction) -> list[str]:
    values = [f"private_cluster_state={facts.aks_private_cluster_state or _UNKNOWN}"]
    if facts.aks_private_dns_zone_id:
        values.append(f"private_dns_zone_id={facts.aks_private_dns_zone_id}")
    if facts.aks_authorized_ip_ranges:
        values.append(f"authorized_ip_ranges=[{', '.join(facts.aks_authorized_ip_ranges)}]")
    else:
        values.append(f"authorized_ip_ranges_state={facts.aks_authorized_ip_ranges_state or _UNKNOWN}")
    if authorized_ips.broad_ranges:
        values.append(f"broad_authorized_ip_ranges=[{', '.join(authorized_ips.broad_ranges)}]")
    if facts.aks_api_server_vnet_integration_state:
        values.append(f"api_server_vnet_integration_state={facts.aks_api_server_vnet_integration_state}")
    if facts.aks_api_server_subnet_id:
        values.append(f"api_server_subnet_id={facts.aks_api_server_subnet_id}")
    return values


def _local_account_evidence(facts: AzureResourceFacts) -> list[str]:
    return [f"local_account_state={facts.aks_local_account_state or _UNKNOWN}"]


def _rbac_evidence(facts: AzureResourceFacts, issues: list[str]) -> list[str]:
    values = [
        f"kubernetes_rbac_state={facts.aks_rbac_state or _UNKNOWN}",
        f"aad_rbac_state={facts.aks_aad_rbac_state or _UNKNOWN}",
        f"aad_managed_state={facts.aks_aad_managed_state or _UNKNOWN}",
        f"aad_azure_rbac_state={facts.aks_aad_azure_rbac_state or _UNKNOWN}",
        *issues,
    ]
    if facts.aks_aad_admin_group_object_ids:
        values.append(f"aad_admin_group_object_ids=[{', '.join(facts.aks_aad_admin_group_object_ids)}]")
    if facts.aks_aad_tenant_id:
        values.append(f"aad_tenant_id={facts.aks_aad_tenant_id}")
    return values


def _network_policy_evidence(facts: AzureResourceFacts) -> list[str]:
    values = [f"network_policy_state={facts.aks_network_policy_state or _UNKNOWN}"]
    if facts.aks_network_policy:
        values.append(f"network_policy={facts.aks_network_policy}")
    else:
        values.append("network_policy is not represented in planned values")
    if facts.aks_network_plugin:
        values.append(f"network_plugin={facts.aks_network_plugin}")
    return values


def _workload_identity_evidence(facts: AzureResourceFacts) -> list[str]:
    return [
        f"oidc_issuer_state={facts.aks_oidc_issuer_state or _UNKNOWN}",
        f"workload_identity_state={facts.aks_workload_identity_state or _UNKNOWN}",
    ]


def _kms_evidence(facts: AzureResourceFacts) -> list[str]:
    values = [f"key_management_service_state={facts.aks_kms_state or _UNKNOWN}"]
    if facts.aks_kms_key_vault_key_id:
        values.append(f"key_vault_key_id={facts.aks_kms_key_vault_key_id}")
    else:
        values.append("key_vault_key_id is not represented in planned values")
    return values


def _monitoring_evidence(facts: AzureResourceFacts) -> list[str]:
    values = [f"oms_agent_state={facts.aks_oms_agent_state or _UNKNOWN}"]
    if facts.aks_log_analytics_workspace_id:
        values.append(f"log_analytics_workspace_id={facts.aks_log_analytics_workspace_id}")
    else:
        values.append("log_analytics_workspace_id is not represented in planned values")
    return values


def _defender_evidence(facts: AzureResourceFacts) -> list[str]:
    return [f"defender_state={facts.aks_defender_state or _UNKNOWN}"]


def _azure_policy_evidence(facts: AzureResourceFacts) -> list[str]:
    return [f"azure_policy_state={facts.aks_azure_policy_state or _UNKNOWN}"]


def _state_absent(state: str | None) -> bool:
    return state in {_DISABLED, _NOT_CONFIGURED}


def _authorized_ip_restriction(facts: AzureResourceFacts) -> _AuthorizedIpRestriction:
    if facts.aks_authorized_ip_ranges_state == _UNKNOWN:
        return _AuthorizedIpRestriction(_UNKNOWN)
    if not facts.aks_authorized_ip_ranges:
        return _AuthorizedIpRestriction(_NOT_CONFIGURED)
    broad_ranges = tuple(
        range_value for range_value in facts.aks_authorized_ip_ranges if is_broad_public_range(range_value)
    )
    if broad_ranges:
        return _AuthorizedIpRestriction("broad", broad_ranges)
    return _AuthorizedIpRestriction("narrow")


def _rbac_issues(facts: AzureResourceFacts) -> list[str]:
    issues: list[str] = []
    if facts.aks_rbac_state == _DISABLED:
        issues.append("kubernetes RBAC is disabled")
    elif facts.aks_rbac_state == _UNKNOWN:
        issues.append("kubernetes RBAC state is unknown")

    if facts.aks_aad_rbac_state == _UNKNOWN:
        issues.append("Azure AD RBAC block is unknown")
    elif facts.aks_aad_rbac_state == _CONFIGURED:
        if facts.aks_aad_azure_rbac_state == _DISABLED:
            issues.append("Azure RBAC integration is disabled")
        elif facts.aks_aad_azure_rbac_state == _UNKNOWN:
            issues.append("Azure RBAC integration state is unknown")
    return issues


def _network_policy_missing_or_unknown(facts: AzureResourceFacts) -> bool:
    if facts.aks_network_policy_state in {_NOT_CONFIGURED, _UNKNOWN}:
        return True
    return _network_policy_is_none(facts.aks_network_policy)


def _network_policy_is_none(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"none", "disabled", "false", "off"}
