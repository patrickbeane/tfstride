from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.gcp_iam_inheritance import (
    GCP_IAM_SCOPE_FOLDER,
    GCP_IAM_SCOPE_ORGANIZATION,
    GCP_IAM_SCOPE_PROJECT,
    GcpIamScopeKey,
)
from tfstride.analysis.gcp_custom_roles import (
    GcpCustomRoleIndex,
    build_gcp_custom_role_index,
    custom_role_allows_data_store_access,
    custom_role_permissions,
    custom_role_privilege_risk,
)
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource, ResourceInventory, SecurityGroupRule
from tfstride.providers.gcp.constants import (
    GCP_CLOUD_FUNCTION_RESOURCE_TYPES,
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_GKE_RESOURCE_TYPES,
    GCP_ORG_FOLDER_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES,
    PUBLIC_GCP_IAM_MEMBERS,
)
from tfstride.providers.gcp.resource_utils import binding_members, gcp_reference_key
from tfstride.resource_helpers import describe_security_group_rule

_SENSITIVE_GCP_RESOURCE_TYPES = frozenset({"google_kms_crypto_key", "google_secret_manager_secret"})
_INHERITED_GCP_IAM_SCOPE_TYPES = frozenset(
    {
        GCP_IAM_SCOPE_ORGANIZATION,
        GCP_IAM_SCOPE_FOLDER,
        GCP_IAM_SCOPE_PROJECT,
    }
)
_INHERITED_IAM_BLAST_RADIUS_MIN_DESCENDANTS = 2
_SERVICE_ACCOUNT_KEY_MAX_VALIDITY_DAYS = 180
_CLOUD_RUN_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker"})
_CLOUD_FUNCTION_PUBLIC_INVOKER_ROLES = frozenset({"roles/cloudfunctions.invoker"})
_PUBSUB_RESOURCE_TYPES = frozenset({"google_pubsub_topic", "google_pubsub_subscription"})
_BIGQUERY_RESOURCE_TYPES = frozenset({"google_bigquery_dataset", "google_bigquery_table"})
_PUBSUB_DATA_ACCESS_ROLES = frozenset(
    {
        "roles/editor",
        "roles/owner",
        "roles/pubsub.admin",
        "roles/pubsub.editor",
        "roles/pubsub.publisher",
        "roles/pubsub.subscriber",
    }
)
_BIGQUERY_DATA_ACCESS_ROLES = frozenset(
    {
        "roles/bigquery.admin",
        "roles/bigquery.dataEditor",
        "roles/bigquery.dataOwner",
        "roles/bigquery.dataViewer",
        "roles/editor",
        "roles/owner",
    }
)
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
_GCS_DATA_ACCESS_ROLES = frozenset(
    {
        "roles/editor",
        "roles/owner",
        "roles/storage.admin",
        "roles/storage.objectAdmin",
        "roles/storage.objectCreator",
        "roles/storage.objectUser",
        "roles/storage.objectViewer",
    }
)
_CLOUD_SQL_DATA_ACCESS_ROLES = frozenset(
    {
        "roles/cloudsql.admin",
        "roles/cloudsql.client",
        "roles/editor",
        "roles/owner",
    }
)
_HIGH_BREADTH_INHERITED_DATA_ROLES = frozenset(
    {
        "roles/owner",
        "roles/editor",
        "roles/secretmanager.admin",
        "roles/cloudkms.admin",
        "roles/storage.admin",
        "roles/storage.objectAdmin",
        "roles/cloudsql.admin",
        "roles/bigquery.admin",
        "roles/bigquery.dataOwner",
        "roles/pubsub.admin",
        "roles/pubsub.editor",
    }
)
_KEYED_SERVICE_ACCOUNT_DATA_RESOURCE_ACCESS = {
    "google_secret_manager_secret": (_SECRET_ACCESS_ROLES, "Secret Manager secret IAM", 2),
    "google_kms_crypto_key": (_KMS_ACCESS_ROLES, "Cloud KMS key IAM", 2),
    "google_storage_bucket": (_GCS_DATA_ACCESS_ROLES, "GCS bucket IAM", 2),
    "google_bigquery_dataset": (_BIGQUERY_DATA_ACCESS_ROLES, "BigQuery dataset IAM", 2),
    "google_bigquery_table": (_BIGQUERY_DATA_ACCESS_ROLES, "BigQuery table IAM", 2),
    "google_pubsub_topic": (_PUBSUB_DATA_ACCESS_ROLES, "Pub/Sub topic IAM", 1),
    "google_pubsub_subscription": (_PUBSUB_DATA_ACCESS_ROLES, "Pub/Sub subscription IAM", 1),
}
_PROJECT_LEVEL_DATA_ACCESS_ROLES: dict[str, tuple[str, int]] = {
    "roles/storage.objectAdmin": ("project-level GCS object administration", 2),
    "roles/storage.objectCreator": ("project-level GCS object creation", 1),
    "roles/storage.objectUser": ("project-level GCS object use", 2),
    "roles/storage.objectViewer": ("project-level GCS object read access", 2),
    "roles/secretmanager.secretAccessor": ("project-level Secret Manager secret access", 2),
    "roles/cloudkms.cryptoKeyDecrypter": ("project-level Cloud KMS decrypt access", 2),
    "roles/cloudkms.cryptoKeyEncrypterDecrypter": ("project-level Cloud KMS encrypt/decrypt access", 2),
    "roles/cloudsql.client": ("project-level Cloud SQL client access", 2),
    "roles/bigquery.dataEditor": ("project-level BigQuery data edit access", 2),
    "roles/bigquery.dataOwner": ("project-level BigQuery data ownership", 2),
    "roles/bigquery.dataViewer": ("project-level BigQuery data read access", 2),
    "roles/pubsub.publisher": ("project-level Pub/Sub publish access", 1),
    "roles/pubsub.subscriber": ("project-level Pub/Sub subscription consume access", 1),
}
_INHERITED_SENSITIVE_RESOURCE_ACCESS: dict[str, tuple[frozenset[str], str, int]] = {
    "google_secret_manager_secret": (_SECRET_ACCESS_ROLES, "Secret Manager secret access", 2),
    "google_kms_crypto_key": (_KMS_ACCESS_ROLES, "Cloud KMS cryptographic key access", 2),
    "google_storage_bucket": (_GCS_DATA_ACCESS_ROLES, "GCS object data access", 2),
    "google_sql_database_instance": (_CLOUD_SQL_DATA_ACCESS_ROLES, "Cloud SQL client/admin access", 2),
    "google_bigquery_dataset": (
        _BIGQUERY_DATA_ACCESS_ROLES,
        "BigQuery dataset data access",
        2,
    ),
    "google_bigquery_table": (
        _BIGQUERY_DATA_ACCESS_ROLES,
        "BigQuery table data access",
        2,
    ),
    "google_pubsub_topic": (_PUBSUB_DATA_ACCESS_ROLES, "Pub/Sub topic data access", 1),
    "google_pubsub_subscription": (
        _PUBSUB_DATA_ACCESS_ROLES,
        "Pub/Sub subscription data access",
        1,
    ),
}


@dataclass(frozen=True, slots=True)
class _GcpIamMemberAssessment:
    member: str
    scope_description: str
    is_public: bool = False
    is_broad: bool = False


@dataclass(frozen=True, slots=True)
class _KeyedServiceAccountGrant:
    resource_address: str
    source: str
    scope: str
    role: str
    member: str
    risk: str
    data_sensitivity: int


@dataclass(frozen=True, slots=True)
class _InheritedSensitiveResourceAccess:
    resource_address: str
    resource_type: str
    risk: str
    data_sensitivity: int



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
        for resource in context.inventory.by_type(*GCP_GKE_RESOURCE_TYPES):
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
        for resource in context.inventory.by_type(*GCP_GKE_RESOURCE_TYPES):
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
        for service in context.inventory.by_type(*GCP_CLOUD_RUN_RESOURCE_TYPES):
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
        for function in context.inventory.by_type(*GCP_CLOUD_FUNCTION_RESOURCE_TYPES):
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
                for member in binding_members(binding):
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

    def detect_pubsub_public_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for resource in context.inventory.by_type(*_PUBSUB_RESOURCE_TYPES):
            for source, role, member, assessment in _broad_resource_iam_bindings(
                resource, _PUBSUB_DATA_ACCESS_ROLES
            ):
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=assessment.is_public,
                    privilege_breadth=2 if assessment.is_public else 1,
                    data_sensitivity=1,
                    lateral_movement=1,
                    blast_radius=1,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=_dedupe_addresses([resource.address, source]),
                        trust_boundary_id=None,
                        rationale=(
                            f"{resource.display_name} grants `{role}` to `{member}` through Pub/Sub "
                            "IAM. Public or broad principals can publish, consume, or administer event "
                            "streams outside the expected service boundary."
                        ),
                        evidence=collect_evidence(
                            evidence_item(
                                "iam_binding",
                                [
                                    f"source={source}" if source else "source=unknown",
                                    f"role={role}",
                                    f"member={member}",
                                ],
                            ),
                            evidence_item("trust_scope", [assessment.scope_description]),
                            evidence_item(
                                "resource_policy_sources",
                                analysis_facts(resource).resource_policy_source_addresses,
                            ),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
        return findings

    def detect_bigquery_public_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for resource in context.inventory.by_type(*_BIGQUERY_RESOURCE_TYPES):
            for source, role, member, assessment in _broad_resource_iam_bindings(
                resource, _BIGQUERY_DATA_ACCESS_ROLES
            ):
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=assessment.is_public,
                    privilege_breadth=2 if assessment.is_public else 1,
                    data_sensitivity=2,
                    lateral_movement=1,
                    blast_radius=2 if assessment.is_public else 1,
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=_dedupe_addresses([resource.address, source]),
                        trust_boundary_id=None,
                        rationale=(
                            f"{resource.display_name} grants `{role}` to `{member}` through BigQuery "
                            "IAM. Public or broad principals can read or modify analytical data outside "
                            "the expected project trust boundary."
                        ),
                        evidence=collect_evidence(
                            evidence_item(
                                "iam_binding",
                                [
                                    f"source={source}" if source else "source=unknown",
                                    f"role={role}",
                                    f"member={member}",
                                ],
                            ),
                            evidence_item("trust_scope", [assessment.scope_description]),
                            evidence_item(
                                "resource_policy_sources",
                                analysis_facts(resource).resource_policy_source_addresses,
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
        for binding in inventory.by_type(*GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES):
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
        for binding in inventory.by_type(*GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES):
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
        for binding in context.inventory.by_type(*GCP_PROJECT_IAM_RESOURCE_TYPES):
            for role, member in _project_iam_binding_members(binding):
                if member not in PUBLIC_GCP_IAM_MEMBERS:
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
        for binding in context.inventory.by_type(*GCP_PROJECT_IAM_RESOURCE_TYPES):
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

    def detect_inherited_iam_sensitive_resource_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str, str, str]] = set()
        inheritance_index = context.analysis_indexes.gcp_iam_inheritance
        custom_roles = build_gcp_custom_role_index(context.inventory.resources)

        for scope, iam_resources in sorted(
            inheritance_index.iam_resources_by_scope.items(),
            key=lambda item: item[0].label,
        ):
            if scope.scope_type not in _INHERITED_GCP_IAM_SCOPE_TYPES:
                continue
            descendant_resources = tuple(
                sorted(
                    inheritance_index.descendant_resources_for_scope(scope),
                    key=lambda resource: resource.address,
                )
            )
            if not descendant_resources:
                continue

            for binding in sorted(iam_resources, key=lambda resource: resource.address):
                for role, member in _iam_resource_binding_members(binding):
                    access_grants = _inherited_sensitive_resource_accesses(
                        descendant_resources,
                        role,
                        custom_roles,
                    )
                    if not access_grants:
                        continue
                    finding_key = (binding.address, scope.label, role, member)
                    if finding_key in seen:
                        continue
                    seen.add(finding_key)

                    member_assessment = _assess_inherited_gcp_iam_member(member, descendant_resources)
                    severity_reasoning = build_severity_reasoning(
                        internet_exposure=bool(member_assessment and member_assessment.is_public),
                        privilege_breadth=_inherited_sensitive_resource_privilege_breadth(
                            role,
                            member_assessment,
                        ),
                        data_sensitivity=max(grant.data_sensitivity for grant in access_grants),
                        lateral_movement=1,
                        blast_radius=_inherited_sensitive_resource_blast_radius(
                            scope,
                            access_grants,
                            member_assessment,
                        ),
                    )
                    scope_description = _inherited_iam_scope_description(scope)
                    findings.append(
                        self._finding_factory.build(
                            rule_id=rule_id,
                            severity=severity_reasoning.severity,
                            affected_resources=_dedupe_addresses(
                                [binding.address, *[grant.resource_address for grant in access_grants]]
                            ),
                            trust_boundary_id=None,
                            rationale=(
                                f"{binding.display_name} grants `{role}` to `{member}` at "
                                f"{scope_description}, and that inherited grant reaches "
                                f"{len(access_grants)} sensitive GCP descendant resource(s). "
                                "Project, folder, and organization IAM applies below the grant scope, "
                                "so a single ancestor binding can expose data resources beyond their "
                                "local IAM boundary."
                            ),
                            evidence=collect_evidence(
                                evidence_item(
                                    "iam_binding",
                                    [
                                        f"source={binding.address}",
                                        f"scope={scope.label}",
                                        f"member={member}",
                                        f"role={role}",
                                    ],
                                ),
                                evidence_item(
                                    "sensitive_descendants",
                                    [
                                        _inherited_sensitive_resource_access_evidence(grant)
                                        for grant in access_grants
                                    ],
                                ),
                                evidence_item(
                                    "trust_scope",
                                    [member_assessment.scope_description if member_assessment else ""],
                                ),
                                evidence_item(
                                    "custom_role_permissions",
                                    custom_role_permissions(role, custom_roles),
                                ),
                            ),
                            severity_reasoning=severity_reasoning,
                        )
                    )
        return findings

    def detect_inherited_iam_blast_radius(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str, str, str]] = set()
        inheritance_index = context.analysis_indexes.gcp_iam_inheritance
        custom_roles = build_gcp_custom_role_index(context.inventory.resources)

        for scope, iam_resources in sorted(
            inheritance_index.iam_resources_by_scope.items(),
            key=lambda item: item[0].label,
        ):
            if scope.scope_type not in _INHERITED_GCP_IAM_SCOPE_TYPES:
                continue
            descendants = tuple(
                sorted(
                    inheritance_index.descendant_resources_for_scope(scope),
                    key=lambda resource: resource.address,
                )
            )
            if not _has_inherited_iam_blast_radius(scope, descendants):
                continue

            for binding in sorted(iam_resources, key=lambda resource: resource.address):
                for role, member in _iam_resource_binding_members(binding):
                    role_risk = _inherited_iam_role_risk(scope, role, custom_roles)
                    member_assessment = _assess_inherited_gcp_iam_member(member, descendants)
                    if role_risk is None and member_assessment is None:
                        continue
                    finding_key = (binding.address, scope.label, role, member)
                    if finding_key in seen:
                        continue
                    seen.add(finding_key)

                    severity_reasoning = build_severity_reasoning(
                        internet_exposure=bool(member_assessment and member_assessment.is_public),
                        privilege_breadth=_inherited_iam_blast_radius_privilege_breadth(
                            role_risk,
                            member_assessment,
                        ),
                        data_sensitivity=_inherited_iam_descendant_data_sensitivity(descendants, role_risk),
                        lateral_movement=2 if role_risk is not None else 1,
                        blast_radius=_inherited_iam_scope_blast_radius(scope, descendants, member_assessment),
                    )
                    scope_description = _inherited_iam_scope_description(scope)
                    findings.append(
                        self._finding_factory.build(
                            rule_id=rule_id,
                            severity=severity_reasoning.severity,
                            affected_resources=_dedupe_addresses(
                                [binding.address, *[resource.address for resource in descendants]]
                            ),
                            trust_boundary_id=None,
                            rationale=(
                                f"{binding.display_name} grants `{role}` to `{member}` at "
                                f"{scope_description}, and that inherited grant applies to "
                                f"{len(descendants)} concrete descendant resource(s). "
                                "A high-level IAM grant with broad, external, or high-impact access increases "
                                "control-plane blast radius because compromise or misuse can affect "
                                "resources below the inherited scope."
                            ),
                            evidence=collect_evidence(
                                evidence_item(
                                    "iam_binding",
                                    [
                                        f"source={binding.address}",
                                        f"scope={scope.label}",
                                        f"member={member}",
                                        f"role={role}",
                                    ],
                                ),
                                evidence_item("role_risk", [role_risk or ""]),
                                evidence_item(
                                    "trust_scope",
                                    [member_assessment.scope_description if member_assessment else ""],
                                ),
                                evidence_item(
                                    "descendant_scope",
                                    _inherited_iam_descendant_scope_evidence(scope, descendants),
                                ),
                                evidence_item(
                                    "descendant_resource_types",
                                    _inherited_iam_descendant_type_evidence(descendants),
                                ),
                                evidence_item(
                                    "descendant_resources",
                                    _inherited_iam_descendant_resource_evidence(descendants),
                                ),
                                evidence_item(
                                    "custom_role_permissions",
                                    custom_role_permissions(role, custom_roles),
                                ),
                            ),
                            severity_reasoning=severity_reasoning,
                        )
                    )
        return findings

    def detect_service_account_key_hygiene(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        for key in inventory.by_type("google_service_account_key"):
            metadata = key.metadata_snapshot()
            service_account_reference = analysis_facts(key).service_account_reference
            target = _service_account_iam_target(key, inventory)
            validity_days = _service_account_key_validity_days(key)
            keepers = metadata.get("keepers")
            keepers_configured = isinstance(keepers, dict) and bool(keepers)

            risks = ["Terraform manages a user-created service-account key"]
            if validity_days is not None and validity_days > _SERVICE_ACCOUNT_KEY_MAX_VALIDITY_DAYS:
                risks.append(
                    f"validity window is {validity_days} days and exceeds "
                    f"{_SERVICE_ACCOUNT_KEY_MAX_VALIDITY_DAYS}-day threshold"
                )
            if not keepers_configured:
                risks.append("no Terraform keepers rotation trigger observed")

            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=1,
                data_sensitivity=0,
                lateral_movement=1,
                blast_radius=2 if len(risks) > 1 else 1,
            )
            validity_evidence = _service_account_key_validity_evidence(metadata, validity_days)
            rotation_evidence = (
                [f"keepers configured: {', '.join(sorted(str(keeper_name) for keeper_name in keepers))}"]
                if keepers_configured
                else ["no Terraform keepers rotation trigger observed"]
            )
            target_label = (
                target.address if target is not None else service_account_reference or "unknown service account"
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=_dedupe_addresses([target.address if target else "", key.address]),
                    trust_boundary_id=None,
                    rationale=(
                        f"{key.display_name} creates a user-managed GCP service account key for "
                        f"`{target_label}`. User-managed service account keys are portable, long-lived "
                        "credentials that can be copied outside GCP control, so they need explicit rotation "
                        "controls or should be replaced with workload identity or impersonation flows."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "key_context",
                            [
                                f"source={key.address}",
                                f"service_account_reference={service_account_reference or ''}",
                                f"key_algorithm={metadata.get('service_account_key_algorithm') or ''}",
                                f"public_key_type={metadata.get('service_account_public_key_type') or ''}",
                            ],
                        ),
                        evidence_item("key_risk", risks),
                        evidence_item("validity_window", validity_evidence),
                        evidence_item("rotation_control", rotation_evidence),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_service_account_key_effective_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        inventory = context.inventory
        custom_roles = build_gcp_custom_role_index(inventory.resources)
        for key in inventory.by_type("google_service_account_key"):
            target = _service_account_iam_target(key, inventory)
            grants = _keyed_service_account_effective_access_grants(
                key, target, inventory, custom_roles
            )
            if not grants:
                continue

            identity_control_plane_access = any(
                grant.scope == "service account IAM"
                or grant.scope.startswith(("project", "organization", "folder"))
                for grant in grants
            )
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=2 if identity_control_plane_access else 1,
                data_sensitivity=max(grant.data_sensitivity for grant in grants),
                lateral_movement=2 if identity_control_plane_access else 1,
                blast_radius=2,
            )
            service_account_reference = analysis_facts(key).service_account_reference
            target_label = (
                target.address if target is not None else service_account_reference or "unknown service account"
            )
            principals = sorted(_service_account_key_principals(key, target))
            affected_resources = _dedupe_addresses(
                [
                    target.address if target else "",
                    key.address,
                    *[grant.resource_address for grant in grants],
                    *[grant.source for grant in grants],
                ]
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=affected_resources,
                    trust_boundary_id=None,
                    rationale=(
                        f"{key.display_name} creates portable credentials for `{target_label}`, and that "
                        "service account has sensitive data access or high-impact IAM grants. A copied key "
                        "can exercise those effective permissions outside the intended workload boundary."
                    ),
                    evidence=collect_evidence(
                        evidence_item(
                            "key_context",
                            [
                                f"source={key.address}",
                                f"service_account_reference={service_account_reference or ''}",
                                f"resolved_service_account={target.address if target else ''}",
                            ],
                        ),
                        evidence_item("service_account_principals", principals),
                        evidence_item(
                            "effective_access",
                            [
                                _keyed_service_account_grant_evidence(grant)
                                for grant in grants
                            ],
                        ),
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
        for binding in context.inventory.by_type(*GCP_ORG_FOLDER_IAM_RESOURCE_TYPES):
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
        for binding in context.inventory.by_type(*GCP_ORG_FOLDER_IAM_RESOURCE_TYPES):
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
    if normalized_member in PUBLIC_GCP_IAM_MEMBERS:
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


def _broad_resource_iam_bindings(
    resource: NormalizedResource,
    allowed_roles: frozenset[str],
) -> list[tuple[str, str, str, _GcpIamMemberAssessment]]:
    matches: list[tuple[str, str, str, _GcpIamMemberAssessment]] = []
    seen: set[tuple[str, str, str]] = set()
    for binding in analysis_facts(resource).iam_bindings:
        role = str(binding.get("role") or "unknown role").strip()
        if role not in allowed_roles:
            continue
        source = str(binding.get("source") or "").strip()
        for member in binding_members(binding):
            assessment = _assess_gcp_broad_iam_member(member)
            if assessment is None:
                continue
            key = (source, role, assessment.member)
            if key in seen:
                continue
            seen.add(key)
            matches.append((source, role, assessment.member, assessment))
    return matches


def _keyed_service_account_effective_access_grants(
    key: NormalizedResource,
    target: NormalizedResource | None,
    inventory: ResourceInventory,
    custom_roles: GcpCustomRoleIndex,
) -> list[_KeyedServiceAccountGrant]:
    principals = _service_account_key_principals(key, target)
    if not principals:
        return []

    grants: list[_KeyedServiceAccountGrant] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add_grant(grant: _KeyedServiceAccountGrant) -> None:
        dedupe_key = (grant.resource_address, grant.source, grant.role, grant.member)
        if dedupe_key in seen:
            return
        seen.add(dedupe_key)
        grants.append(grant)

    for binding in inventory.by_type(*GCP_PROJECT_IAM_RESOURCE_TYPES):
        for role, member in _project_iam_binding_members(binding):
            if not _member_matches_service_account_principal(member, principals):
                continue
            role_risk = _privileged_project_role_risk(role, custom_roles)
            data_role_risk = _project_level_data_role_risk(role)
            if role_risk is not None:
                add_grant(
                    _KeyedServiceAccountGrant(
                        resource_address=binding.address,
                        source=binding.address,
                        scope="project IAM",
                        role=role,
                        member=member,
                        risk=role_risk,
                        data_sensitivity=0,
                    )
                )
                continue
            if data_role_risk is not None:
                risk, data_sensitivity = data_role_risk
                add_grant(
                    _KeyedServiceAccountGrant(
                        resource_address=binding.address,
                        source=binding.address,
                        scope="project IAM data access",
                        role=role,
                        member=member,
                        risk=risk,
                        data_sensitivity=data_sensitivity,
                    )
                )

    for binding in inventory.by_type(*GCP_ORG_FOLDER_IAM_RESOURCE_TYPES):
        scope = _org_folder_scope_description(binding)
        for role, member in _org_folder_iam_binding_members(binding):
            if not _member_matches_service_account_principal(member, principals):
                continue
            role_risk = _privileged_org_folder_role_risk(role, custom_roles)
            if role_risk is None:
                continue
            add_grant(
                _KeyedServiceAccountGrant(
                    resource_address=binding.address,
                    source=binding.address,
                    scope=scope,
                    role=role,
                    member=member,
                    risk=role_risk,
                    data_sensitivity=0,
                )
            )

    for binding in inventory.by_type(*GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES):
        iam_target = _service_account_iam_target(binding, inventory)
        for role, member in _iam_resource_binding_members(binding):
            if not _member_matches_service_account_principal(member, principals):
                continue
            role_risk = _high_risk_service_account_role_risk(role)
            if role_risk is None:
                continue
            add_grant(
                _KeyedServiceAccountGrant(
                    resource_address=iam_target.address if iam_target else binding.address,
                    source=binding.address,
                    scope="service account IAM",
                    role=role,
                    member=member,
                    risk=role_risk,
                    data_sensitivity=0,
                )
            )

    for resource in inventory.by_type(*tuple(_KEYED_SERVICE_ACCOUNT_DATA_RESOURCE_ACCESS)):
        allowed_roles, scope, data_sensitivity = _KEYED_SERVICE_ACCOUNT_DATA_RESOURCE_ACCESS[
            resource.resource_type
        ]
        for source, role, member in _resource_iam_binding_members(resource):
            if not _member_matches_service_account_principal(member, principals):
                continue
            if role in allowed_roles:
                risk = f"{scope} grants {role}"
            elif custom_role_allows_data_store_access(resource, role, custom_roles):
                risk = f"{scope} grants custom data-store role {role}"
            else:
                continue
            add_grant(
                _KeyedServiceAccountGrant(
                    resource_address=resource.address,
                    source=source,
                    scope=scope,
                    role=role,
                    member=member,
                    risk=risk,
                    data_sensitivity=data_sensitivity,
                )
            )

    return sorted(
        grants,
        key=lambda grant: (grant.resource_address, grant.source, grant.role, grant.member),
    )


def _service_account_key_principals(
    key: NormalizedResource,
    target: NormalizedResource | None,
) -> set[str]:
    values: list[object] = []
    if target is not None:
        target_facts = analysis_facts(target)
        values.extend(
            [
                target_facts.service_account_email,
                target_facts.service_account_member,
                target_facts.resource_name,
            ]
        )
    key_facts = analysis_facts(key)
    metadata = key.metadata_snapshot()
    values.extend(
        [
            key_facts.service_account_reference,
            metadata.get("service_account_reference"),
            metadata.get("service_account_id"),
            metadata.get("resource_name"),
            metadata.get("name"),
        ]
    )

    principals: set[str] = set()
    for value in values:
        email = _service_account_email_from_reference(value)
        if email is None:
            continue
        principals.add(email)
        principals.add(f"serviceAccount:{email}")
    return principals


def _service_account_email_from_reference(value: object) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.startswith("serviceAccount:"):
        text = text.removeprefix("serviceAccount:")
    if "/serviceAccounts/" in text:
        text = text.split("/serviceAccounts/", 1)[1].split("/", 1)[0]
    if "@" not in text or not text.endswith(".gserviceaccount.com"):
        return None
    return text


def _member_matches_service_account_principal(member: str, principals: set[str]) -> bool:
    normalized_member = str(member).strip()
    if normalized_member in principals:
        return True
    email = _service_account_email_from_reference(normalized_member)
    return bool(email and (email in principals or f"serviceAccount:{email}" in principals))


def _resource_iam_binding_members(resource: NormalizedResource) -> list[tuple[str, str, str]]:
    members: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for binding in analysis_facts(resource).iam_bindings:
        role = str(binding.get("role") or "unknown role").strip()
        source = str(binding.get("source") or "").strip()
        for member in binding_members(binding):
            normalized_member = str(member).strip()
            if not normalized_member:
                continue
            key = (source, role, normalized_member)
            if key in seen:
                continue
            seen.add(key)
            members.append(key)
    return members


def _has_inherited_iam_blast_radius(
    scope: GcpIamScopeKey,
    descendants: tuple[NormalizedResource, ...],
) -> bool:
    return len(descendants) >= _INHERITED_IAM_BLAST_RADIUS_MIN_DESCENDANTS


def _inherited_iam_role_risk(
    scope: GcpIamScopeKey,
    role: str | None,
    custom_roles: GcpCustomRoleIndex,
) -> str | None:
    if scope.scope_type in {GCP_IAM_SCOPE_ORGANIZATION, GCP_IAM_SCOPE_FOLDER}:
        return _privileged_org_folder_role_risk(role, custom_roles)
    return _privileged_project_role_risk(role, custom_roles)


def _inherited_iam_blast_radius_privilege_breadth(
    role_risk: str | None,
    member_assessment: _GcpIamMemberAssessment | None,
) -> int:
    if role_risk is not None:
        return 2
    if member_assessment is not None and member_assessment.is_broad:
        return 2
    return 1


def _inherited_iam_descendant_data_sensitivity(
    descendants: tuple[NormalizedResource, ...],
    role_risk: str | None,
) -> int:
    if role_risk is None:
        return 0
    return 2 if any(resource.data_sensitivity == "sensitive" for resource in descendants) else 0


def _inherited_iam_scope_blast_radius(
    scope: GcpIamScopeKey,
    descendants: tuple[NormalizedResource, ...],
    member_assessment: _GcpIamMemberAssessment | None,
) -> int:
    if scope.scope_type in {GCP_IAM_SCOPE_ORGANIZATION, GCP_IAM_SCOPE_FOLDER}:
        return 2
    if member_assessment is not None and member_assessment.is_broad:
        return 2
    if len(descendants) >= 5 or len({resource.resource_type for resource in descendants}) >= 3:
        return 2
    return 1


def _inherited_iam_descendant_scope_evidence(
    scope: GcpIamScopeKey,
    descendants: tuple[NormalizedResource, ...],
) -> list[str]:
    projects = _descendant_scope_values(descendants, "project")
    folders = _descendant_scope_values(descendants, "folder")
    organizations = _descendant_scope_values(descendants, "organization")
    values = [
        f"scope={scope.label}",
        f"descendant_count={len(descendants)}",
        f"resource_type_count={len({resource.resource_type for resource in descendants})}",
    ]
    if projects:
        values.append(f"projects={', '.join(projects[:5])}")
    if folders:
        values.append(f"folders={', '.join(folders[:5])}")
    if organizations:
        values.append(f"organizations={', '.join(organizations[:5])}")
    return values


def _inherited_iam_descendant_type_evidence(descendants: tuple[NormalizedResource, ...]) -> list[str]:
    counts: dict[str, int] = {}
    for resource in descendants:
        counts[resource.resource_type] = counts.get(resource.resource_type, 0) + 1
    return [f"{resource_type}: {counts[resource_type]}" for resource_type in sorted(counts)]


def _inherited_iam_descendant_resource_evidence(
    descendants: tuple[NormalizedResource, ...],
    *,
    limit: int = 10,
) -> list[str]:
    addresses = [resource.address for resource in descendants]
    values = addresses[:limit]
    remaining = len(addresses) - len(values)
    if remaining > 0:
        values.append(f"and {remaining} more descendant resources")
    return values


def _descendant_scope_values(
    descendants: tuple[NormalizedResource, ...],
    scope_type: str,
) -> list[str]:
    values: set[str] = set()
    for resource in descendants:
        facts = analysis_facts(resource)
        if scope_type == "project" and facts.project:
            values.add(facts.project)
        elif scope_type == "folder" and facts.folder_id:
            values.add(facts.folder_id)
        elif scope_type == "organization" and facts.organization_id:
            values.add(facts.organization_id)
    return sorted(values)


def _inherited_sensitive_resource_accesses(
    descendants: tuple[NormalizedResource, ...],
    role: str,
    custom_roles: GcpCustomRoleIndex,
) -> list[_InheritedSensitiveResourceAccess]:
    grants: list[_InheritedSensitiveResourceAccess] = []
    for resource in descendants:
        access_risk = _inherited_sensitive_resource_access_risk(resource, role, custom_roles)
        if access_risk is None:
            continue
        risk, data_sensitivity = access_risk
        grants.append(
            _InheritedSensitiveResourceAccess(
                resource_address=resource.address,
                resource_type=resource.resource_type,
                risk=risk,
                data_sensitivity=data_sensitivity,
            )
        )
    return sorted(grants, key=lambda grant: grant.resource_address)


def _inherited_sensitive_resource_access_risk(
    resource: NormalizedResource,
    role: str | None,
    custom_roles: GcpCustomRoleIndex,
) -> tuple[str, int] | None:
    normalized_role = str(role or "").strip()
    if not normalized_role:
        return None
    access_profile = _INHERITED_SENSITIVE_RESOURCE_ACCESS.get(resource.resource_type)
    if access_profile is None:
        return None
    allowed_roles, risk_label, data_sensitivity = access_profile
    if normalized_role in allowed_roles:
        return (f"{risk_label} through {normalized_role}", data_sensitivity)
    if custom_role_allows_data_store_access(resource, normalized_role, custom_roles):
        return (f"{risk_label} through custom role {normalized_role}", data_sensitivity)
    return None


def _assess_inherited_gcp_iam_member(
    member: str,
    descendants: tuple[NormalizedResource, ...],
) -> _GcpIamMemberAssessment | None:
    broad_assessment = _assess_gcp_broad_iam_member(member)
    if broad_assessment is not None:
        return broad_assessment
    projects = sorted(
        {
            project
            for project in (analysis_facts(resource).project for resource in descendants)
            if project
        }
    )
    for project in projects:
        assessment = _assess_gcp_sensitive_iam_member(member, project)
        if assessment is not None:
            return assessment
    return None


def _inherited_sensitive_resource_privilege_breadth(
    role: str | None,
    member_assessment: _GcpIamMemberAssessment | None,
) -> int:
    if member_assessment is not None and member_assessment.is_broad:
        return 2
    normalized_role = str(role or "").strip()
    if normalized_role in _HIGH_BREADTH_INHERITED_DATA_ROLES:
        return 2
    role_name = normalized_role.rsplit("/", 1)[-1].lower()
    if normalized_role.startswith("roles/") and "admin" in role_name:
        return 2
    return 1


def _inherited_sensitive_resource_blast_radius(
    scope: GcpIamScopeKey,
    grants: list[_InheritedSensitiveResourceAccess],
    member_assessment: _GcpIamMemberAssessment | None,
) -> int:
    if scope.scope_type in {GCP_IAM_SCOPE_ORGANIZATION, GCP_IAM_SCOPE_FOLDER}:
        return 2
    if member_assessment is not None and member_assessment.is_broad:
        return 2
    if len({grant.resource_address for grant in grants}) > 1:
        return 2
    return 1


def _inherited_iam_scope_description(scope: GcpIamScopeKey) -> str:
    if scope.scope_type == GCP_IAM_SCOPE_PROJECT:
        return f"project scope `{scope.identifier}`"
    if scope.scope_type == GCP_IAM_SCOPE_FOLDER:
        return f"folder scope `{scope.identifier}`"
    if scope.scope_type == GCP_IAM_SCOPE_ORGANIZATION:
        return f"organization scope `{scope.identifier}`"
    return f"{scope.scope_type} scope `{scope.identifier}`"


def _inherited_sensitive_resource_access_evidence(
    grant: _InheritedSensitiveResourceAccess,
) -> str:
    return (
        f"resource={grant.resource_address}; type={grant.resource_type}; "
        f"risk={grant.risk}"
    )


def _project_level_data_role_risk(role: str | None) -> tuple[str, int] | None:
    if not role:
        return None
    return _PROJECT_LEVEL_DATA_ACCESS_ROLES.get(role.strip())


def _keyed_service_account_grant_evidence(grant: _KeyedServiceAccountGrant) -> str:
    source = grant.source if grant.source else "unknown"
    return (
        f"resource={grant.resource_address}; source={source}; scope={grant.scope}; "
        f"role={grant.role}; member={grant.member}; risk={grant.risk}"
    )


def _service_account_key_validity_days(resource: NormalizedResource) -> int | None:
    metadata = resource.metadata_snapshot()
    valid_after = _parse_rfc3339_timestamp(metadata.get("valid_after"))
    valid_before = _parse_rfc3339_timestamp(metadata.get("valid_before"))
    if valid_after is None or valid_before is None or valid_before <= valid_after:
        return None
    return int((valid_before - valid_after).total_seconds() // 86400)


def _service_account_key_validity_evidence(
    metadata: dict[str, object],
    validity_days: int | None,
) -> list[str]:
    values = [
        f"valid_after={metadata.get('valid_after') or ''}",
        f"valid_before={metadata.get('valid_before') or ''}",
    ]
    if validity_days is not None:
        values.append(f"validity_days={validity_days}")
    return values


def _parse_rfc3339_timestamp(value: object) -> datetime | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


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
        for member in binding_members(binding):
            members.append((role, member))
    return members


def _assess_gcp_broad_iam_member(member: str) -> _GcpIamMemberAssessment | None:
    normalized_member = str(member).strip()
    if not normalized_member:
        return None
    if normalized_member in PUBLIC_GCP_IAM_MEMBERS:
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
    target_key = gcp_reference_key(target_reference)
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
        keys.add(gcp_reference_key(text))
        if text.startswith("serviceAccount:"):
            keys.add(gcp_reference_key(text.removeprefix("serviceAccount:")))
        else:
            keys.add(gcp_reference_key(f"serviceAccount:{text}"))
    return keys



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
        for member in binding_members(binding):
            if member in PUBLIC_GCP_IAM_MEMBERS:
                bindings.append((source, role, member))
    return bindings




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