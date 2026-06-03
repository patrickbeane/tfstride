from __future__ import annotations

from dataclasses import dataclass

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.gcp_custom_roles import (
    GcpCustomRoleIndex,
    build_gcp_custom_role_index,
    custom_role_permissions,
    custom_role_privilege_risk,
)
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource, ResourceInventory, SecurityGroupRule
from tfstride.resource_helpers import describe_security_group_rule

_SENSITIVE_GCP_RESOURCE_TYPES = frozenset({"google_kms_crypto_key", "google_secret_manager_secret"})
_CLOUD_RUN_RESOURCE_TYPES = frozenset({"google_cloud_run_service", "google_cloud_run_v2_service"})
_CLOUD_FUNCTION_RESOURCE_TYPES = frozenset(
    {"google_cloudfunctions_function", "google_cloudfunctions2_function"}
)
_GKE_RESOURCE_TYPES = frozenset({"google_container_cluster", "google_container_node_pool"})
_PROJECT_IAM_RESOURCE_TYPES = frozenset(
    {"google_project_iam_binding", "google_project_iam_member", "google_project_iam_policy"}
)
_ORG_FOLDER_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_organization_iam_binding",
        "google_organization_iam_member",
        "google_organization_iam_policy",
        "google_folder_iam_binding",
        "google_folder_iam_member",
        "google_folder_iam_policy",
    }
)
_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_service_account_iam_binding",
        "google_service_account_iam_member",
        "google_service_account_iam_policy",
    }
)
_CLOUD_RUN_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker"})
_CLOUD_FUNCTION_PUBLIC_INVOKER_ROLES = frozenset({"roles/cloudfunctions.invoker"})
_PUBLIC_GCP_IAM_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})
_GKE_BROAD_OAUTH_SCOPES = frozenset(
    {
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/compute",
        "https://www.googleapis.com/auth/devstorage.full_control",
    }
)
_SECRET_ACCESS_ROLES = frozenset(
    {
        "roles/editor",
        "roles/owner",
        "roles/secretmanager.admin",
        "roles/secretmanager.secretAccessor",
    }
)
_KMS_ACCESS_ROLES = frozenset(
    {
        "roles/cloudkms.admin",
        "roles/cloudkms.cryptoKeyDecrypter",
        "roles/cloudkms.cryptoKeyEncrypterDecrypter",
        "roles/editor",
        "roles/owner",
    }
)


@dataclass(frozen=True, slots=True)
class _GcpIamMemberAssessment:
    member: str
    scope_description: str
    is_public: bool = False
    is_broad: bool = False


_HIGH_RISK_SERVICE_ACCOUNT_ROLES: dict[str, str] = {
    "roles/iam.serviceAccountAdmin": "service account administration and IAM policy control",
    "roles/iam.serviceAccountTokenCreator": "service account token minting and impersonation",
    "roles/iam.serviceAccountUser": "service account attachment and workload impersonation",
}


_PRIVILEGED_GCP_PROJECT_ROLES: dict[str, str] = {
    "roles/owner": "full project administration",
    "roles/editor": "broad write access across most project services",
    "roles/iam.serviceAccountTokenCreator": "service account token minting and impersonation",
    "roles/iam.serviceAccountUser": "service account attachment and impersonation paths",
    "roles/iam.serviceAccountAdmin": "service account administration",
    "roles/iam.securityAdmin": "IAM policy and security-control administration",
    "roles/resourcemanager.projectIamAdmin": "project IAM policy administration",
}


_PRIVILEGED_GCP_ORG_FOLDER_ROLES: dict[str, str] = {
    **_PRIVILEGED_GCP_PROJECT_ROLES,
    "roles/accesscontextmanager.policyAdmin": "access policy administration across protected resources",
    "roles/billing.admin": "billing account administration and project billing linkage control",
    "roles/iam.organizationRoleAdmin": "custom role administration at organization scope",
    "roles/orgpolicy.policyAdmin": "organization policy administration",
    "roles/resourcemanager.folderAdmin": "folder hierarchy administration",
    "roles/resourcemanager.organizationAdmin": "organization-level resource administration",
    "roles/resourcemanager.projectCreator": "project creation under the organization or folder",
    "roles/resourcemanager.projectDeleter": "project deletion under the organization or folder",
}


class GcpRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_public_compute_broad_ingress(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        for instance in inventory.by_type("google_compute_instance"):
            risky_rules = _risky_public_firewall_rules(instance, inventory)
            if not risky_rules:
                continue

            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", instance.address)
            )
            affected_resources = _dedupe_addresses(
                [instance.address, *[firewall.address for firewall, _ in risky_rules]]
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=affected_resources,
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=_public_compute_broad_ingress_rationale(instance),
                    evidence=collect_evidence(
                        evidence_item(
                            "firewall_rules",
                            [
                                describe_security_group_rule(firewall, rule)
                                for firewall, rule in risky_rules
                            ],
                        ),
                        evidence_item("network_tags", analysis_facts(instance).network_tags),
                        evidence_item("internet_ingress_reasons", instance.internet_ingress_reasons),
                        evidence_item("public_exposure_reasons", instance.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_compute_os_login_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for instance in context.inventory.by_type("google_compute_instance"):
            instance_facts = analysis_facts(instance)
            if instance_facts.os_login_enabled is not False:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=instance.public_exposure,
                privilege_breadth=1,
                data_sensitivity=0,
                lateral_movement=1 if instance.public_exposure else 0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[instance.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{instance.display_name} explicitly disables OS Login. SSH access can therefore "
                        "fall back to instance or project metadata keys instead of centralized IAM-backed "
                        "login and audit controls."
                    ),
                    evidence=collect_evidence(
                        evidence_item("os_login_posture", ["metadata.enable-oslogin is false"]),
                        evidence_item("public_exposure_reasons", instance.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gke_public_control_plane(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for cluster in context.inventory.by_type("google_container_cluster"):
            cluster_facts = analysis_facts(cluster)
            if not cluster.public_access_configured:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=1,
            )
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", cluster.address)
            )
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
                        evidence_item("control_plane_endpoint", [cluster_facts.gke_endpoint or "public endpoint configured"]),
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
            cluster_facts = analysis_facts(cluster)
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
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", cluster.address)
            )
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
                        evidence_item("configured_authorized_network_count", [str(len(cluster_facts.gke_master_authorized_networks))]),
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
            cluster_facts = analysis_facts(cluster)
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
                                f"workload_identity_enabled is {_bool_status(cluster_facts.gke_workload_identity_enabled)}",
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
        for resource in context.inventory.by_type(*_GKE_RESOURCE_TYPES):
            resource_facts = analysis_facts(resource)
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
        for resource in context.inventory.by_type(*_GKE_RESOURCE_TYPES):
            resource_facts = analysis_facts(resource)
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

    def detect_cloud_run_public_invoker(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for service in context.inventory.by_type(*_CLOUD_RUN_RESOURCE_TYPES):
            public_invokers = _cloud_run_public_invoker_bindings(service)
            if not service.public_exposure or not public_invokers:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1,
            )
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", service.address)
            )
            affected_resources = _dedupe_addresses(
                [service.address, *[source for source, _, _ in public_invokers]]
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=affected_resources,
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{service.display_name} allows public ingress and grants Cloud Run invoke "
                        "permission to public GCP principals. Unauthenticated internet clients can reach "
                        "the service entry point without an organization-owned identity boundary."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "public_invoker_bindings",
                            [
                                f"source={source}; role={role}; member={member}"
                                for source, role, member in public_invokers
                            ],
                        ),
                        evidence_item("public_access_reasons", service.public_access_reasons),
                        evidence_item("public_exposure_reasons", service.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_cloud_function_public_invoker(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for function in context.inventory.by_type(*_CLOUD_FUNCTION_RESOURCE_TYPES):
            public_invokers = _cloud_function_public_invoker_bindings(function)
            if not function.public_exposure or not public_invokers:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=0,
                lateral_movement=0,
                blast_radius=1,
            )
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", function.address)
            )
            affected_resources = _dedupe_addresses(
                [function.address, *[source for source, _, _ in public_invokers]]
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=affected_resources,
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{function.display_name} allows public HTTP access and grants Cloud Functions "
                        "invoke permission to public GCP principals. Unauthenticated internet clients can "
                        "reach the function entry point without an organization-owned identity boundary."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "public_invoker_bindings",
                            [
                                f"source={source}; role={role}; member={member}"
                                for source, role, member in public_invokers
                            ],
                        ),
                        evidence_item("public_access_reasons", function.public_access_reasons),
                        evidence_item("public_exposure_reasons", function.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_sensitive_iam_external_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        for resource in context.inventory.by_type(*_SENSITIVE_GCP_RESOURCE_TYPES):
            resource_facts = analysis_facts(resource)
            for binding in resource_facts.iam_bindings:
                role = str(binding.get("role") or "unknown role")
                if not _is_sensitive_gcp_resource_role(resource, role):
                    continue
                source = str(binding.get("source") or "").strip()
                for member in _binding_members(binding):
                    assessment = _assess_gcp_sensitive_iam_member(member, resource_facts.project)
                    if assessment is None:
                        continue
                    finding_key = (resource.address, role, assessment.member)
                    if finding_key in seen:
                        continue
                    seen.add(finding_key)

                    severity_reasoning = build_severity_reasoning(
                        internet_exposure=assessment.is_public,
                        privilege_breadth=2 if assessment.is_public or assessment.is_broad else 1,
                        data_sensitivity=2,
                        lateral_movement=1,
                        blast_radius=2 if assessment.is_public or assessment.is_broad else 1,
                    )
                    affected_resources = _dedupe_addresses([resource.address, source])
                    findings.append(
                        self._finding_factory.build(
                            rule_id=rule_id,
                            severity=severity_reasoning.severity,
                            affected_resources=affected_resources,
                            trust_boundary_id=None,
                            rationale=(
                                f"{resource.display_name} grants `{role}` to `{assessment.member}` through "
                                "GCP IAM. Public, broad-domain, or foreign-project principals can access "
                                "sensitive secrets or cryptographic key operations outside the expected "
                                "project trust boundary."
                            ),
                            evidence=collect_evidence(
                                evidence_item(
                                    "iam_binding",
                                    [
                                        f"source={source}" if source else "source=unknown",
                                        f"role={role}",
                                        f"member={assessment.member}",
                                    ],
                                ),
                                evidence_item("trust_scope", [assessment.scope_description]),
                                evidence_item(
                                    "resource_policy_sources",
                                    resource_facts.resource_policy_source_addresses,
                                ),
                            ),
                            severity_reasoning=severity_reasoning,
                        )
                    )
        return findings

    def detect_service_account_iam_broad_principal(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        for binding in inventory.by_type(*_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES):
            target = _service_account_iam_target(binding, inventory)
            for role, member in _iam_resource_binding_members(binding):
                assessment = _assess_gcp_broad_iam_member(member)
                if assessment is None:
                    continue
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=assessment.is_public,
                    privilege_breadth=2,
                    data_sensitivity=0,
                    lateral_movement=1,
                    blast_radius=2 if assessment.is_public else 1,
                )
                affected_resources = _dedupe_addresses(
                    [target.address if target else "", binding.address]
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=affected_resources,
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants `{role}` on a GCP service account to "
                            f"`{member}`. Public or broad principals can cross the service-account "
                            "identity boundary and may gain workload impersonation paths."
                        ),
                        evidence=collect_evidence(
                            evidence_item(
                                "iam_binding",
                                [
                                    f"source={binding.address}",
                                    f"member={member}",
                                    f"role={role}",
                                ],
                            ),
                            evidence_item("trust_scope", [assessment.scope_description]),
                            evidence_item(
                                "service_account_reference",
                                [analysis_facts(binding).service_account_reference or ""],
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_service_account_iam_privileged_role(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        for binding in inventory.by_type(*_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES):
            target = _service_account_iam_target(binding, inventory)
            for role, member in _iam_resource_binding_members(binding):
                role_risk = _high_risk_service_account_role_risk(role)
                if role_risk is None:
                    continue
                broad_assessment = _assess_gcp_broad_iam_member(member)
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=bool(broad_assessment and broad_assessment.is_public),
                    privilege_breadth=2,
                    data_sensitivity=0,
                    lateral_movement=2,
                    blast_radius=2,
                )
                affected_resources = _dedupe_addresses(
                    [target.address if target else "", binding.address]
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=affected_resources,
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants the high-impact service account role `{role}` "
                            f"to `{member}`. That role enables {role_risk}, expanding privilege if the "
                            "principal is compromised or mis-scoped."
                        ),
                        evidence=collect_evidence(
                            evidence_item(
                                "iam_binding",
                                [
                                    f"source={binding.address}",
                                    f"member={member}",
                                    f"role={role}",
                                ],
                            ),
                            evidence_item("role_risk", [role_risk]),
                            evidence_item(
                                "service_account_reference",
                                [analysis_facts(binding).service_account_reference or ""],
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_project_iam_broad_principal(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for binding in context.inventory.by_type(*_PROJECT_IAM_RESOURCE_TYPES):
            for role, member in _project_iam_binding_members(binding):
                if member not in _PUBLIC_GCP_IAM_MEMBERS:
                    continue
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=True,
                    privilege_breadth=1,
                    data_sensitivity=0,
                    lateral_movement=1,
                    blast_radius=1,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=[binding.address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants `{role}` to `{member}` at project scope. Public "
                            "or broadly authenticated principals can cross into the control plane without an "
                            "organization-owned identity boundary."
                        ),
                        evidence=collect_evidence(
                            evidence_item("iam_binding", [f"member={member}", f"role={role}"]),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_project_iam_privileged_role(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        custom_roles = build_gcp_custom_role_index(context.inventory.resources)
        for binding in context.inventory.by_type(*_PROJECT_IAM_RESOURCE_TYPES):
            for role, member in _project_iam_binding_members(binding):
                role_risk = _privileged_project_role_risk(role, custom_roles)
                if role_risk is None:
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
                        affected_resources=[binding.address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants the high-impact GCP role `{role}` to `{member}` "
                            f"at project scope. That role enables {role_risk} and can materially expand "
                            "control-plane blast radius if the principal is compromised or mis-scoped."
                        ),
                        evidence=collect_evidence(
                            evidence_item("iam_binding", [f"member={member}", f"role={role}"]),
                            evidence_item("role_risk", [role_risk]),
                            evidence_item("custom_role_permissions", custom_role_permissions(role, custom_roles)),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_org_folder_iam_broad_principal(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for binding in context.inventory.by_type(*_ORG_FOLDER_IAM_RESOURCE_TYPES):
            scope = _org_folder_scope_description(binding)
            for role, member in _org_folder_iam_binding_members(binding):
                assessment = _assess_gcp_broad_iam_member(member)
                if assessment is None:
                    continue
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=assessment.is_public,
                    privilege_breadth=2,
                    data_sensitivity=0,
                    lateral_movement=2,
                    blast_radius=2,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=[binding.address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants `{role}` to `{member}` at {scope}. Public or "
                            "broad-domain principals at organization or folder scope can expand access across "
                            "many descendant projects and workloads."
                        ),
                        evidence=collect_evidence(
                            evidence_item("iam_binding", [f"member={member}", f"role={role}"]),
                            evidence_item("scope", [scope]),
                            evidence_item("trust_scope", [assessment.scope_description]),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_org_folder_iam_privileged_role(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        custom_roles = build_gcp_custom_role_index(context.inventory.resources)
        for binding in context.inventory.by_type(*_ORG_FOLDER_IAM_RESOURCE_TYPES):
            scope = _org_folder_scope_description(binding)
            for role, member in _org_folder_iam_binding_members(binding):
                role_risk = _privileged_org_folder_role_risk(role, custom_roles)
                if role_risk is None:
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
                        affected_resources=[binding.address],
                        trust_boundary_id=None,
                        rationale=(
                            f"{binding.display_name} grants the high-impact GCP role `{role}` to `{member}` "
                            f"at {scope}. That role enables {role_risk} across a high-level resource "
                            "boundary and can materially expand blast radius if the principal is compromised."
                        ),
                        evidence=collect_evidence(
                            evidence_item("iam_binding", [f"member={member}", f"role={role}"]),
                            evidence_item("scope", [scope]),
                            evidence_item("role_risk", [role_risk]),
                            evidence_item("custom_role_permissions", custom_role_permissions(role, custom_roles)),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_gcs_public_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for bucket in context.inventory.by_type("google_storage_bucket"):
            if not bucket.public_exposure:
                continue
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", bucket.address)
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[bucket.address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{bucket.display_name} is publicly reachable through GCS IAM grants. "
                        "Public bucket access is a common source of unintended object disclosure."
                    ),
                    evidence=collect_evidence(
                        evidence_item("public_exposure_reasons", bucket.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gcs_uniform_bucket_level_access_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for bucket in context.inventory.by_type("google_storage_bucket"):
            bucket_facts = analysis_facts(bucket)
            if bucket_facts.gcs_uniform_bucket_level_access is True:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=1,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[bucket.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{bucket.display_name} does not enforce GCS uniform bucket-level access. "
                        "Object ACLs can bypass the intended bucket-level IAM model and make access "
                        "harder to audit consistently."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "access_control_posture",
                            [
                                f"uniform_bucket_level_access is {_bool_status(bucket_facts.gcs_uniform_bucket_level_access)}",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gcs_public_access_prevention_not_enforced(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for bucket in context.inventory.by_type("google_storage_bucket"):
            bucket_facts = analysis_facts(bucket)
            if _gcs_public_access_prevention_enforced(bucket_facts.gcs_public_access_prevention):
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=bucket.public_exposure,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", bucket.address)
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[bucket.address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{bucket.display_name} does not enforce GCS Public Access Prevention. "
                        "Public principals can still be introduced through bucket IAM unless an "
                        "organization-level policy blocks them."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "access_control_posture",
                            [
                                f"public_access_prevention is {bucket_facts.gcs_public_access_prevention or 'unset'}",
                            ],
                        ),
                        evidence_item("public_exposure_reasons", bucket.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gcs_versioning_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for bucket in context.inventory.by_type("google_storage_bucket"):
            bucket_facts = analysis_facts(bucket)
            if bucket.data_sensitivity != "sensitive":
                continue
            if bucket_facts.gcs_versioning_enabled is True:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[bucket.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{bucket.display_name} stores sensitive GCS data without bucket versioning. "
                        "Accidental overwrites, deletes, or destructive changes have fewer object-level "
                        "recovery options."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "data_protection_posture",
                            [
                                f"versioning.enabled is {_bool_status(bucket_facts.gcs_versioning_enabled)}",
                                f"data_sensitivity is {bucket.data_sensitivity}",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gcs_customer_managed_encryption_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for bucket in context.inventory.by_type("google_storage_bucket"):
            bucket_facts = analysis_facts(bucket)
            if bucket.data_sensitivity != "sensitive":
                continue
            if bucket_facts.gcs_default_kms_key_name:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[bucket.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{bucket.display_name} relies on default GCS encryption rather than a "
                        "customer-managed KMS key. Sensitive buckets lose key ownership, rotation, and "
                        "separation-of-duties controls that a CMEK can provide."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "encryption_posture",
                            [
                                "default_kms_key_name is unset",
                                "customer_managed_encryption is false",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_cloud_sql_public_authorized_network(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type("google_sql_database_instance"):
            if not database.public_exposure:
                continue
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", database.address)
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=1,
            )
            public_networks = _cloud_sql_public_authorized_networks(database)
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{database.display_name} has a public Cloud SQL IPv4 endpoint and an authorized "
                        "network that allows internet-wide client sources. That weakens the database trust "
                        "boundary even when database authentication is still required."
                    ),
                    evidence=collect_evidence(
                        evidence_item("authorized_networks", public_networks),
                        evidence_item("public_exposure_reasons", database.public_exposure_reasons),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_cloud_sql_backup_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type("google_sql_database_instance"):
            database_facts = analysis_facts(database)
            if database_facts.cloud_sql_backup_enabled:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            pitr_enabled = database_facts.cloud_sql_point_in_time_recovery_enabled
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{database.display_name} does not have Cloud SQL automated backups enabled. "
                        "A destructive change, operator error, or data corruption event would have fewer "
                        "managed recovery points."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "backup_posture",
                            [
                                "backup_configuration.enabled is false",
                                f"point_in_time_recovery_enabled is {str(bool(pitr_enabled)).lower()}",
                                f"engine is {database_facts.database_engine or 'unknown'}",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_cloud_sql_public_ip_without_private_network(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type("google_sql_database_instance"):
            database_facts = analysis_facts(database)
            if not database_facts.cloud_sql_ipv4_enabled or database_facts.cloud_sql_private_network:
                continue
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", database.address)
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=0,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{database.display_name} has Cloud SQL public IPv4 enabled without a private "
                        "network attachment. That keeps database client access on a public endpoint instead "
                        "of an internal VPC path."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "network_posture",
                            [
                                "ipv4_enabled is true",
                                "private_network is unset",
                                f"authorized_networks configured: {len(database_facts.cloud_sql_authorized_networks)}",
                            ],
                        ),
                        evidence_item("public_access_reasons", _metadata_string_list(database, "public_access_reasons")),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_cloud_sql_ssl_not_required(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type("google_sql_database_instance"):
            database_facts = analysis_facts(database)
            if not database_facts.cloud_sql_ipv4_enabled or _cloud_sql_ssl_enforced(database_facts):
                continue
            boundary = context.boundary_index.get(
                (BoundaryType.INTERNET_TO_SERVICE, "internet", database.address)
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=True,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=1,
                blast_radius=0,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=boundary.identifier if boundary else None,
                    rationale=(
                        f"{database.display_name} allows Cloud SQL public IPv4 client access without "
                        "requiring encrypted client connections. Credentials and database traffic should "
                        "not depend on client-side optional TLS behavior."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "ssl_posture",
                            [
                                f"require_ssl is {str(bool(database_facts.cloud_sql_require_ssl)).lower()}",
                                f"ssl_mode is {database_facts.cloud_sql_ssl_mode or 'unset'}",
                                "ipv4_enabled is true",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_cloud_sql_point_in_time_recovery_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type("google_sql_database_instance"):
            database_facts = analysis_facts(database)
            if not database_facts.cloud_sql_backup_enabled:
                continue
            if database_facts.cloud_sql_point_in_time_recovery_enabled is not False:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{database.display_name} has automated backups enabled but point-in-time "
                        "recovery disabled. That narrows recovery options after accidental writes, "
                        "destructive migrations, or credential misuse."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "backup_posture",
                            [
                                "backup_configuration.enabled is true",
                                "point_in_time_recovery_enabled is false",
                                f"engine is {database_facts.database_engine or 'unknown'}",
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_cloud_sql_deletion_protection_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for database in context.inventory.by_type("google_sql_database_instance"):
            database_facts = analysis_facts(database)
            if database_facts.deletion_protection is not False:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[database.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{database.display_name} has Cloud SQL deletion protection disabled. Accidental "
                        "or unauthorized infrastructure changes could destroy the managed database instance "
                        "without this provider-level guardrail."
                    ),
                    evidence=collect_evidence(
                        evidence_item("lifecycle_posture", ["deletion_protection is false"]),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _bool_status(value: bool | None) -> str:
    if value is None:
        return "unset"
    return str(value).lower()


def _gcs_public_access_prevention_enforced(value: str | None) -> bool:
    return str(value or "").strip().lower() == "enforced"

def _gke_broad_authorized_networks(cluster: NormalizedResource) -> list[str]:
    facts = analysis_facts(cluster)
    if not facts.gke_master_authorized_networks:
        return ["master authorized networks are not configured"]
    descriptions: list[str] = []
    for network in facts.gke_master_authorized_networks:
        cidr = str(network.get("cidr_block") or "").strip()
        if cidr not in {"0.0.0.0/0", "::/0"}:
            continue
        name = str(network.get("display_name") or network.get("name") or "unnamed").strip() or "unnamed"
        descriptions.append(f"{name} ({cidr})")
    return descriptions


def _gke_node_identity_risks(resource: NormalizedResource) -> list[str]:
    facts = analysis_facts(resource)
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


def _is_sensitive_gcp_resource_role(resource: NormalizedResource, role: str) -> bool:
    normalized_role = str(role).strip()
    if resource.resource_type == "google_secret_manager_secret":
        return normalized_role in _SECRET_ACCESS_ROLES
    if resource.resource_type == "google_kms_crypto_key":
        return normalized_role in _KMS_ACCESS_ROLES
    return False


def _assess_gcp_sensitive_iam_member(
    member: str,
    resource_project: str | None,
) -> _GcpIamMemberAssessment | None:
    normalized_member = str(member).strip()
    if not normalized_member:
        return None
    if normalized_member in _PUBLIC_GCP_IAM_MEMBERS:
        return _GcpIamMemberAssessment(
            member=normalized_member,
            scope_description=f"member is public GCP principal `{normalized_member}`",
            is_public=True,
            is_broad=True,
        )
    if normalized_member.startswith("domain:"):
        return _GcpIamMemberAssessment(
            member=normalized_member,
            scope_description="member grants a whole Google Workspace domain",
            is_broad=True,
        )
    if normalized_member.startswith("serviceAccount:"):
        service_account_project = _service_account_project(normalized_member)
        if resource_project and service_account_project and service_account_project != resource_project:
            return _GcpIamMemberAssessment(
                member=normalized_member,
                scope_description=(
                    f"service account belongs to project `{service_account_project}`, "
                    f"outside resource project `{resource_project}`"
                ),
            )
    return None


def _service_account_project(member: str) -> str | None:
    email = member.split(":", 1)[1] if ":" in member else member
    suffix = ".iam.gserviceaccount.com"
    if not email.endswith(suffix) or "@" not in email:
        return None
    domain = email.split("@", 1)[1]
    return domain[: -len(suffix)] or None


def _public_compute_broad_ingress_rationale(instance: NormalizedResource) -> str:
    if instance.public_exposure:
        return (
            f"{instance.display_name} has an external access config and matching GCP firewall "
            "rules allow administrative access or all ports from the public internet. That broad "
            "ingress raises the chance of unauthenticated probing and credential attacks."
        )
    return (
        f"{instance.display_name} is targeted by GCP firewall rules that allow administrative access "
        "or all ports from internet-wide source ranges. Even when the plan does not show a direct "
        "internet boundary, broad SSH/RDP ingress increases exposure if an external address, peering path, "
        "or forwarding path is later attached."
    )


def _iam_resource_binding_members(resource: NormalizedResource) -> list[tuple[str, str]]:
    bindings = analysis_facts(resource).iam_bindings
    if not bindings:
        facts = analysis_facts(resource)
        role = facts.iam_role
        member = facts.iam_member
        if role and member:
            return [(role, member)]
        return []

    members: list[tuple[str, str]] = []
    for binding in bindings:
        role = str(binding.get("role") or "unknown role")
        for member in _binding_members(binding):
            members.append((role, member))
    return members


def _assess_gcp_broad_iam_member(member: str) -> _GcpIamMemberAssessment | None:
    normalized_member = str(member).strip()
    if not normalized_member:
        return None
    if normalized_member in _PUBLIC_GCP_IAM_MEMBERS:
        return _GcpIamMemberAssessment(
            member=normalized_member,
            scope_description=f"member is public GCP principal `{normalized_member}`",
            is_public=True,
            is_broad=True,
        )
    if normalized_member.startswith("domain:"):
        return _GcpIamMemberAssessment(
            member=normalized_member,
            scope_description="member grants a whole Google Workspace domain",
            is_broad=True,
        )
    return None


def _high_risk_service_account_role_risk(role: str | None) -> str | None:
    if not role:
        return None
    normalized_role = role.strip()
    return _HIGH_RISK_SERVICE_ACCOUNT_ROLES.get(normalized_role)


def _service_account_iam_target(
    iam_resource: NormalizedResource,
    inventory: ResourceInventory,
) -> NormalizedResource | None:
    target_reference = analysis_facts(iam_resource).service_account_reference
    if not target_reference:
        return None
    target_key = _gcp_reference_key(target_reference)
    for service_account in inventory.by_type("google_service_account"):
        if target_key in _service_account_reference_keys(service_account):
            return service_account
    return None


def _service_account_reference_keys(resource: NormalizedResource) -> set[str]:
    facts = analysis_facts(resource)
    values = [
        resource.address,
        f"{resource.address}.id",
        f"{resource.address}.name",
        f"{resource.address}.email",
        resource.identifier,
        facts.service_account_email,
        facts.service_account_member,
        facts.resource_name,
    ]
    keys: set[str] = set()
    for value in values:
        if value in (None, ""):
            continue
        text = str(value).strip()
        if not text:
            continue
        keys.add(_gcp_reference_key(text))
        if text.startswith("serviceAccount:"):
            keys.add(_gcp_reference_key(text.removeprefix("serviceAccount:")))
        else:
            keys.add(_gcp_reference_key(f"serviceAccount:{text}"))
    return keys


def _gcp_reference_key(value: str) -> str:
    text = str(value).strip()
    for suffix in (".id", ".name", ".email", ".member", ".self_link"):
        if text.endswith(suffix):
            return text[: -len(suffix)]
    return text


def _project_iam_binding_members(resource: NormalizedResource) -> list[tuple[str, str]]:
    return _iam_resource_binding_members(resource)


def _org_folder_iam_binding_members(resource: NormalizedResource) -> list[tuple[str, str]]:
    return _iam_resource_binding_members(resource)


def _org_folder_scope_description(resource: NormalizedResource) -> str:
    facts = analysis_facts(resource)
    if resource.resource_type.startswith("google_organization_iam_"):
        if facts.organization_id:
            return f"organization scope `{facts.organization_id}`"
        return "organization scope"
    if facts.folder_id:
        return f"folder scope `{facts.folder_id}`"
    return "folder scope"


def _cloud_run_public_invoker_bindings(resource: NormalizedResource) -> list[tuple[str, str, str]]:
    return _public_invoker_bindings(resource, _CLOUD_RUN_PUBLIC_INVOKER_ROLES)


def _cloud_function_public_invoker_bindings(resource: NormalizedResource) -> list[tuple[str, str, str]]:
    return _public_invoker_bindings(resource, _CLOUD_FUNCTION_PUBLIC_INVOKER_ROLES)


def _public_invoker_bindings(
    resource: NormalizedResource,
    invoker_roles: frozenset[str],
) -> list[tuple[str, str, str]]:
    bindings: list[tuple[str, str, str]] = []
    for binding in analysis_facts(resource).iam_bindings:
        role = str(binding.get("role") or "").strip()
        if role not in invoker_roles:
            continue
        source = str(binding.get("source") or "").strip()
        for member in _binding_members(binding):
            if member in _PUBLIC_GCP_IAM_MEMBERS:
                bindings.append((source, role, member))
    return bindings


def _binding_members(binding: dict[str, object]) -> list[str]:
    members = binding.get("members")
    if isinstance(members, list):
        return [str(member) for member in members if member not in (None, "")]
    if members in (None, ""):
        return []
    return [str(members)]


def _risky_public_firewall_rules(
    instance: NormalizedResource,
    inventory: ResourceInventory,
) -> list[tuple[NormalizedResource, SecurityGroupRule]]:
    firewall_addresses = analysis_facts(instance).internet_ingress_firewalls
    risky_rules: list[tuple[NormalizedResource, SecurityGroupRule]] = []
    for firewall_address in firewall_addresses:
        firewall = inventory.get_by_address(firewall_address)
        if firewall is None:
            continue
        for rule in firewall.network_rules:
            if (
                rule.direction == "ingress"
                and rule.allows_internet()
                and (rule.is_administrative_access() or rule.is_all_ports())
            ):
                risky_rules.append((firewall, rule))
    return risky_rules


def _metadata_string_list(resource: NormalizedResource, key: str) -> list[str]:
    value = resource.metadata.get(key)
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "")]
    if value in (None, ""):
        return []
    return [str(value)]


def _cloud_sql_ssl_enforced(database_facts: object) -> bool:
    if getattr(database_facts, "cloud_sql_require_ssl", None):
        return True
    ssl_mode = str(getattr(database_facts, "cloud_sql_ssl_mode", None) or "").strip().upper()
    return ssl_mode in {"ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}


def _cloud_sql_public_authorized_networks(database: NormalizedResource) -> list[str]:
    descriptions: list[str] = []
    for network in analysis_facts(database).cloud_sql_authorized_networks:
        value = str(network.get("value") or "").strip()
        if value not in {"0.0.0.0/0", "::/0"}:
            continue
        name = str(network.get("name") or "unnamed").strip() or "unnamed"
        descriptions.append(f"{name} ({value})")
    return descriptions


def _privileged_project_role_risk(
    role: str | None,
    custom_roles: GcpCustomRoleIndex | None = None,
) -> str | None:
    return _privileged_gcp_role_risk(
        role,
        predefined_roles=_PRIVILEGED_GCP_PROJECT_ROLES,
        admin_risk="admin-level control over a GCP service or project security surface",
        custom_roles=custom_roles,
    )


def _privileged_org_folder_role_risk(
    role: str | None,
    custom_roles: GcpCustomRoleIndex | None = None,
) -> str | None:
    return _privileged_gcp_role_risk(
        role,
        predefined_roles=_PRIVILEGED_GCP_ORG_FOLDER_ROLES,
        admin_risk="admin-level control over a GCP organization, folder, or descendant project surface",
        custom_roles=custom_roles,
    )


def _privileged_gcp_role_risk(
    role: str | None,
    *,
    predefined_roles: dict[str, str],
    admin_risk: str,
    custom_roles: GcpCustomRoleIndex | None = None,
) -> str | None:
    if not role:
        return None
    normalized_role = role.strip()
    if normalized_role in predefined_roles:
        return predefined_roles[normalized_role]
    role_name = normalized_role.rsplit("/", 1)[-1].lower()
    if normalized_role.startswith("roles/") and "admin" in role_name:
        return admin_risk
    if custom_roles is not None:
        return custom_role_privilege_risk(normalized_role, custom_roles)
    return None


def _dedupe_addresses(addresses: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for address in addresses:
        if not address or address in seen:
            continue
        deduped.append(address)
        seen.add(address)
    return deduped