from __future__ import annotations

from dataclasses import dataclass

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource, ResourceInventory, SecurityGroupRule
from tfstride.resource_helpers import describe_security_group_rule

_SENSITIVE_GCP_RESOURCE_TYPES = frozenset({"google_kms_crypto_key", "google_secret_manager_secret"})
_CLOUD_RUN_RESOURCE_TYPES = frozenset({"google_cloud_run_service", "google_cloud_run_v2_service"})
_CLOUD_RUN_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker"})
_PUBLIC_GCP_IAM_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})
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


_PRIVILEGED_GCP_PROJECT_ROLES: dict[str, str] = {
    "roles/owner": "full project administration",
    "roles/editor": "broad write access across most project services",
    "roles/iam.serviceAccountTokenCreator": "service account token minting and impersonation",
    "roles/iam.serviceAccountUser": "service account attachment and impersonation paths",
    "roles/iam.serviceAccountAdmin": "service account administration",
    "roles/iam.securityAdmin": "IAM policy and security-control administration",
    "roles/resourcemanager.projectIamAdmin": "project IAM policy administration",
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

    def detect_project_iam_broad_principal(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for binding in context.inventory.by_type("google_project_iam_member"):
            binding_facts = analysis_facts(binding)
            member = binding_facts.iam_member
            if member not in {"allUsers", "allAuthenticatedUsers"}:
                continue
            role = binding_facts.iam_role or "unknown role"
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
        for binding in context.inventory.by_type("google_project_iam_member"):
            binding_facts = analysis_facts(binding)
            role = binding_facts.iam_role
            role_risk = _privileged_project_role_risk(role)
            if role_risk is None:
                continue
            member = binding_facts.iam_member or "unknown member"
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


def _cloud_run_public_invoker_bindings(resource: NormalizedResource) -> list[tuple[str, str, str]]:
    bindings: list[tuple[str, str, str]] = []
    for binding in analysis_facts(resource).iam_bindings:
        role = str(binding.get("role") or "").strip()
        if role not in _CLOUD_RUN_PUBLIC_INVOKER_ROLES:
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


def _privileged_project_role_risk(role: str | None) -> str | None:
    if not role:
        return None
    normalized_role = role.strip()
    if normalized_role in _PRIVILEGED_GCP_PROJECT_ROLES:
        return _PRIVILEGED_GCP_PROJECT_ROLES[normalized_role]
    role_name = normalized_role.rsplit("/", 1)[-1].lower()
    if normalized_role.startswith("roles/") and "admin" in role_name:
        return "admin-level control over a GCP service or project security surface"
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