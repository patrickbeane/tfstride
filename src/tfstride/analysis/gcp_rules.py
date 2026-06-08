from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.gcp_iam_rule_detectors import (
    GCP_BIGQUERY_DATA_ACCESS_ROLES,
    GCP_PUBSUB_DATA_ACCESS_ROLES,
    GcpIamRuleDetectors,
    broad_resource_iam_bindings,
)
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource, ResourceInventory, SecurityGroupRule
from tfstride.providers.gcp.constants import (
    GCP_CLOUD_FUNCTION_RESOURCE_TYPES,
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_GKE_RESOURCE_TYPES,
    PUBLIC_GCP_IAM_MEMBERS,
)
from tfstride.providers.gcp.resource_utils import binding_members
from tfstride.resource_helpers import describe_security_group_rule

_CLOUD_RUN_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker"})
_CLOUD_FUNCTION_PUBLIC_INVOKER_ROLES = frozenset({"roles/cloudfunctions.invoker"})
_PUBSUB_RESOURCE_TYPES = frozenset({"google_pubsub_topic", "google_pubsub_subscription"})
_BIGQUERY_RESOURCE_TYPES = frozenset({"google_bigquery_dataset", "google_bigquery_table"})
_GKE_BROAD_OAUTH_SCOPES = frozenset(
    {
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/compute",
        "https://www.googleapis.com/auth/devstorage.full_control",
    }
)


class GcpRuleDetectors(GcpIamRuleDetectors):
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

    def detect_pubsub_public_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for resource in context.inventory.by_type(*_PUBSUB_RESOURCE_TYPES):
            for source, role, member, assessment in broad_resource_iam_bindings(
                resource, GCP_PUBSUB_DATA_ACCESS_ROLES
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
            for source, role, member, assessment in broad_resource_iam_bindings(
                resource, GCP_BIGQUERY_DATA_ACCESS_ROLES
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

def _dedupe_addresses(addresses: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for address in addresses:
        if not address or address in seen:
            continue
        deduped.append(address)
        seen.add(address)
    return deduped