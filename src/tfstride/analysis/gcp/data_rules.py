from __future__ import annotations

from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.gcp.iam_access import (
    GCP_BIGQUERY_DATA_ACCESS_ROLES,
    GCP_PUBSUB_DATA_ACCESS_ROLES,
    broad_resource_iam_bindings,
    gcp_iam_condition_evidence_values,
    gcp_iam_condition_limited_score,
)
from tfstride.analysis.gcp.org_policy_evidence import organization_guardrail_evidence
from tfstride.analysis.gcp.org_policy_guardrails import (
    ORG_POLICY_ALLOWED_MEMBER_DOMAINS,
    ORG_POLICY_STORAGE_PUBLIC_ACCESS_PREVENTION,
)
from tfstride.analysis.gcp.org_policy_severity import guardrail_adjusted_severity_reasoning
from tfstride.analysis.resource_facts import AnalysisSqlFacts, analysis_facts
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource

_PUBSUB_RESOURCE_TYPES = frozenset({"google_pubsub_topic", "google_pubsub_subscription"})
_BIGQUERY_RESOURCE_TYPES = frozenset({"google_bigquery_dataset", "google_bigquery_table"})


class GcpDataRuleDetectors:
    def detect_pubsub_public_access(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for resource in context.inventory.by_type(*_PUBSUB_RESOURCE_TYPES):
            for source, role, member, assessment, condition in broad_resource_iam_bindings(
                resource, GCP_PUBSUB_DATA_ACCESS_ROLES
            ):
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=assessment.is_public,
                    privilege_breadth=gcp_iam_condition_limited_score(
                        2 if assessment.is_public else 1, condition, floor=1
                    ),
                    data_sensitivity=1,
                    lateral_movement=1,
                    blast_radius=gcp_iam_condition_limited_score(1, condition, floor=0),
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=dedupe_addresses([resource.address, source]),
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
                            evidence_item("iam_condition", gcp_iam_condition_evidence_values(condition)),
                            evidence_item(
                                "resource_policy_sources",
                                analysis_facts(resource).iam.resource_policy_source_addresses,
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
            for source, role, member, assessment, condition in broad_resource_iam_bindings(
                resource, GCP_BIGQUERY_DATA_ACCESS_ROLES
            ):
                severity_reasoning = build_severity_reasoning(
                    internet_exposure=assessment.is_public,
                    privilege_breadth=gcp_iam_condition_limited_score(
                        2 if assessment.is_public else 1, condition, floor=1
                    ),
                    data_sensitivity=2,
                    lateral_movement=1,
                    blast_radius=gcp_iam_condition_limited_score(2 if assessment.is_public else 1, condition, floor=0),
                )
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=dedupe_addresses([resource.address, source]),
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
                            evidence_item("iam_condition", gcp_iam_condition_evidence_values(condition)),
                            evidence_item(
                                "resource_policy_sources",
                                analysis_facts(resource).iam.resource_policy_source_addresses,
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
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", bucket.address))
            severity_reasoning = guardrail_adjusted_severity_reasoning(
                context.analysis_indexes.gcp_org_policy_guardrails,
                bucket,
                constraints=(ORG_POLICY_ALLOWED_MEMBER_DOMAINS, ORG_POLICY_STORAGE_PUBLIC_ACCESS_PREVENTION),
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
                        organization_guardrail_evidence(
                            context.analysis_indexes.gcp_org_policy_guardrails,
                            bucket,
                            ORG_POLICY_ALLOWED_MEMBER_DOMAINS,
                            ORG_POLICY_STORAGE_PUBLIC_ACCESS_PREVENTION,
                        ),
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
            if bucket_facts.storage.uniform_bucket_level_access is True:
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
                                (
                                    "uniform_bucket_level_access is "
                                    f"{_bool_status(bucket_facts.storage.uniform_bucket_level_access)}"
                                ),
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
            if _gcs_public_access_prevention_enforced(bucket_facts.storage.public_access_prevention):
                continue
            severity_reasoning = guardrail_adjusted_severity_reasoning(
                context.analysis_indexes.gcp_org_policy_guardrails,
                bucket,
                constraints=(ORG_POLICY_STORAGE_PUBLIC_ACCESS_PREVENTION,),
                internet_exposure=bucket.public_exposure,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", bucket.address))
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
                                f"public_access_prevention is {bucket_facts.storage.public_access_prevention or 'unset'}",
                            ],
                        ),
                        evidence_item("public_exposure_reasons", bucket.public_exposure_reasons),
                        organization_guardrail_evidence(
                            context.analysis_indexes.gcp_org_policy_guardrails,
                            bucket,
                            ORG_POLICY_STORAGE_PUBLIC_ACCESS_PREVENTION,
                        ),
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
            if bucket_facts.storage.versioning_enabled is True:
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
                                f"versioning.enabled is {_bool_status(bucket_facts.storage.versioning_enabled)}",
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
            if bucket_facts.storage.customer_managed_encryption:
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
                                (
                                    "customer_managed_encryption is "
                                    f"{_bool_status(bucket_facts.storage.customer_managed_encryption)}"
                                ),
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
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", database.address))
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
            if database_facts.sql.backup_enabled:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            pitr_enabled = database_facts.sql.point_in_time_recovery_enabled
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
                                f"engine is {database_facts.sql.engine or 'unknown'}",
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
            if not database_facts.sql.ipv4_enabled or database_facts.sql.private_network:
                continue
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", database.address))
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
                                f"authorized_networks configured: {len(database_facts.sql.authorized_networks)}",
                            ],
                        ),
                        evidence_item("public_access_reasons", database.public_access_reasons),
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
            if not database_facts.sql.ipv4_enabled or _cloud_sql_ssl_enforced(database_facts.sql):
                continue
            boundary = context.boundary_index.get((BoundaryType.INTERNET_TO_SERVICE, "internet", database.address))
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
                                f"require_ssl is {str(bool(database_facts.sql.require_ssl)).lower()}",
                                f"ssl_mode is {database_facts.sql.ssl_mode or 'unset'}",
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
            if not database_facts.sql.backup_enabled:
                continue
            if database_facts.sql.point_in_time_recovery_enabled is not False:
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
                                f"engine is {database_facts.sql.engine or 'unknown'}",
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
            if database_facts.sql.deletion_protection is not False:
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


def _cloud_sql_ssl_enforced(sql_facts: AnalysisSqlFacts) -> bool:
    if sql_facts.require_ssl:
        return True
    ssl_mode = str(sql_facts.ssl_mode or "").strip().upper()
    return ssl_mode in {"ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}


def _cloud_sql_public_authorized_networks(database: NormalizedResource) -> list[str]:
    descriptions: list[str] = []
    for network in analysis_facts(database).sql.authorized_networks:
        value = str(network.get("value") or "").strip()
        if value not in {"0.0.0.0/0", "::/0"}:
            continue
        name = str(network.get("name") or "unnamed").strip() or "unnamed"
        descriptions.append(f"{name} ({value})")
    return descriptions
