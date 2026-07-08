from __future__ import annotations

import re

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
from tfstride.analysis.gcp.indexes import gcp_org_policy_guardrail_index
from tfstride.analysis.gcp.org_policy_evidence import organization_guardrail_evidence
from tfstride.analysis.gcp.org_policy_guardrails import (
    ORG_POLICY_ALLOWED_MEMBER_DOMAINS,
    ORG_POLICY_STORAGE_PUBLIC_ACCESS_PREVENTION,
)
from tfstride.analysis.gcp.org_policy_severity import guardrail_adjusted_severity_reasoning
from tfstride.analysis.resource_facts import (
    AnalysisSqlFacts,
    AnalysisStorageFacts,
    analysis_facts,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding, NormalizedResource

_PUBSUB_RESOURCE_TYPES = frozenset({"google_pubsub_topic", "google_pubsub_subscription"})
_BIGQUERY_RESOURCE_TYPES = frozenset({"google_bigquery_dataset", "google_bigquery_table"})
_GCS_MIN_RETENTION_PERIOD_DAYS = 7
_GCS_MIN_RETENTION_PERIOD_SECONDS = _GCS_MIN_RETENTION_PERIOD_DAYS * 24 * 60 * 60
_SECRET_MANAGER_MIN_VERSION_DESTROY_TTL_DAYS = 7
_SECRET_MANAGER_MIN_VERSION_DESTROY_TTL_SECONDS = _SECRET_MANAGER_MIN_VERSION_DESTROY_TTL_DAYS * 24 * 60 * 60
_KMS_MAX_ROTATION_PERIOD_DAYS = 90
_KMS_MAX_ROTATION_PERIOD_SECONDS = _KMS_MAX_ROTATION_PERIOD_DAYS * 24 * 60 * 60
_KMS_MIN_DESTROY_SCHEDULED_DURATION_DAYS = 7
_KMS_MIN_DESTROY_SCHEDULED_DURATION_SECONDS = _KMS_MIN_DESTROY_SCHEDULED_DURATION_DAYS * 24 * 60 * 60
_GCP_DURATION_SECONDS = re.compile(r"^\s*(\d+(?:\.\d+)?)s\s*$")


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
                gcp_org_policy_guardrail_index(context.analysis_indexes),
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
                            gcp_org_policy_guardrail_index(context.analysis_indexes),
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
            bucket_facts = analysis_facts(bucket).storage
            if bucket_facts.uniform_bucket_level_access is True:
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
                                    f"{_bool_status(bucket_facts.uniform_bucket_level_access)}"
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
            bucket_facts = analysis_facts(bucket).storage
            if _gcs_public_access_prevention_enforced(bucket_facts.public_access_prevention):
                continue
            severity_reasoning = guardrail_adjusted_severity_reasoning(
                gcp_org_policy_guardrail_index(context.analysis_indexes),
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
                                f"public_access_prevention is {bucket_facts.public_access_prevention or 'unset'}",
                            ],
                        ),
                        evidence_item("public_exposure_reasons", bucket.public_exposure_reasons),
                        organization_guardrail_evidence(
                            gcp_org_policy_guardrail_index(context.analysis_indexes),
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
            bucket_facts = analysis_facts(bucket).storage
            if bucket.data_sensitivity != "sensitive":
                continue
            if bucket_facts.versioning_enabled is True:
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
                                f"versioning.enabled is {_bool_status(bucket_facts.versioning_enabled)}",
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
            bucket_facts = analysis_facts(bucket).storage
            if bucket.data_sensitivity != "sensitive":
                continue
            if bucket_facts.customer_managed_encryption:
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
                                    f"{_bool_status(bucket_facts.customer_managed_encryption)}"
                                ),
                            ],
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_gcs_retention_policy_insufficient(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for bucket in context.inventory.by_type("google_storage_bucket"):
            bucket_facts = analysis_facts(bucket).storage
            if bucket.data_sensitivity != "sensitive":
                continue
            retention_issues = _gcs_retention_policy_issues(bucket_facts)
            if not retention_issues:
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
                        f"{bucket.display_name} does not have deterministic GCS retention posture that "
                        "meets the minimum retention threshold and lock expectation. Retention policy and "
                        "retention lock reduce destructive deletion or overwrite risk, but are distinct from "
                        "soft-delete recovery controls."
                    ),
                    evidence=collect_evidence(
                        evidence_item("retention_policy_issues", retention_issues),
                        evidence_item("retention_policy_posture", _gcs_retention_policy_evidence(bucket_facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_secret_manager_customer_managed_encryption_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for secret in context.inventory.by_type("google_secret_manager_secret"):
            secret_facts = analysis_facts(secret).storage
            if secret.data_sensitivity != "sensitive":
                continue
            if secret_facts.customer_managed_encryption is not False:
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
                    affected_resources=[secret.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{secret.display_name} relies on Google-managed Secret Manager encryption rather "
                        "than a customer-managed Cloud KMS key. Google-managed encryption still applies; "
                        "this finding concerns customer key ownership, rotation, audit separation, and "
                        "compliance posture for sensitive secrets."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _secret_manager_target_evidence(secret)),
                        evidence_item(
                            "encryption_ownership",
                            _secret_manager_encryption_evidence(secret_facts),
                        ),
                        evidence_item(
                            "replication_posture",
                            _secret_manager_replication_evidence(secret_facts),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_secret_manager_lifecycle_posture_incomplete(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for secret in context.inventory.by_type("google_secret_manager_secret"):
            secret_facts = analysis_facts(secret).storage
            if secret.data_sensitivity != "sensitive":
                continue
            lifecycle_issues = _secret_manager_lifecycle_issues(secret_facts)
            if not lifecycle_issues:
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
                    affected_resources=[secret.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{secret.display_name} does not show deterministic Secret Manager lifecycle posture "
                        "for secret expiry or delayed version destruction. Expiry and version-destroy TTL controls "
                        "reduce the lifetime of stale or accidentally destroyed secret material, but do not replace "
                        "access review or rotation."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _secret_manager_target_evidence(secret)),
                        evidence_item("lifecycle_issues", lifecycle_issues),
                        evidence_item("lifecycle_posture", _secret_manager_lifecycle_evidence(secret_facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_kms_key_rotation_not_configured_or_too_long(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for key in context.inventory.by_type("google_kms_crypto_key"):
            key_facts = analysis_facts(key).storage
            if key.data_sensitivity != "sensitive":
                continue
            rotation_issues = _kms_rotation_issues(key_facts)
            if not rotation_issues:
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
                    affected_resources=[key.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{key.display_name} does not show deterministic Cloud KMS key rotation posture "
                        f"within the {_KMS_MAX_ROTATION_PERIOD_DAYS}-day baseline used by tfSTRIDE. "
                        "Weak key rotation governance can undermine the customer-managed encryption posture "
                        "of services that depend on this key."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _kms_target_evidence(key)),
                        evidence_item("rotation_issues", rotation_issues),
                        evidence_item("rotation_posture", _kms_rotation_evidence(key_facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_kms_key_destroy_scheduled_duration_too_short(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for key in context.inventory.by_type("google_kms_crypto_key"):
            key_facts = analysis_facts(key).storage
            if key.data_sensitivity != "sensitive":
                continue
            destruction_issues = _kms_destroy_scheduled_duration_issues(key_facts)
            if not destruction_issues:
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
                    affected_resources=[key.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{key.display_name} configures a short Cloud KMS key-version destruction "
                        "schedule. A short destruction lifecycle gives operators less time to cancel "
                        "accidental or malicious key version destruction. This finding concerns key "
                        "recovery governance; it does not claim data exposure or inspect IAM policy."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _kms_target_evidence(key)),
                        evidence_item("destruction_lifecycle_issues", destruction_issues),
                        evidence_item(
                            "destruction_lifecycle_posture",
                            _kms_destroy_scheduled_duration_evidence(key_facts),
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
            database_facts = analysis_facts(database).sql
            if database_facts.backup_enabled:
                continue
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=2,
                lateral_movement=0,
                blast_radius=1,
            )
            pitr_enabled = database_facts.point_in_time_recovery_enabled
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
                                f"engine is {database_facts.engine or 'unknown'}",
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
            database_facts = analysis_facts(database).sql
            if not database_facts.ipv4_enabled or database_facts.private_network:
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
                                f"authorized_networks configured: {len(database_facts.authorized_networks)}",
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
            database_facts = analysis_facts(database).sql
            if not database_facts.ipv4_enabled or _cloud_sql_ssl_enforced(database_facts):
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
                                f"require_ssl is {str(bool(database_facts.require_ssl)).lower()}",
                                f"ssl_mode is {database_facts.ssl_mode or 'unset'}",
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
            database_facts = analysis_facts(database).sql
            if not database_facts.backup_enabled:
                continue
            if database_facts.point_in_time_recovery_enabled is not False:
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
                                f"engine is {database_facts.engine or 'unknown'}",
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
            database_facts = analysis_facts(database).sql
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


def _gcs_retention_policy_issues(bucket_facts: AnalysisStorageFacts) -> list[str]:
    if bucket_facts.gcs_retention_policy_uncertainties:
        return []

    issues: list[str] = []
    retention_period_seconds = bucket_facts.gcs_retention_period_seconds
    if retention_period_seconds is None:
        issues.append("retention_policy is missing")
    elif retention_period_seconds < _GCS_MIN_RETENTION_PERIOD_SECONDS:
        issues.append(
            "retention_policy.retention_period is "
            f"{retention_period_seconds} seconds; minimum is {_GCS_MIN_RETENTION_PERIOD_SECONDS} seconds"
        )

    if bucket_facts.gcs_retention_policy_locked is False:
        issues.append("retention_policy.is_locked is false")

    return issues


def _gcs_retention_policy_evidence(bucket_facts: AnalysisStorageFacts) -> list[str]:
    retention_period_seconds = bucket_facts.gcs_retention_period_seconds
    if retention_period_seconds is None:
        retention_state = "missing"
    elif retention_period_seconds < _GCS_MIN_RETENTION_PERIOD_SECONDS:
        retention_state = "short"
    else:
        retention_state = "configured"

    evidence = [
        f"retention_policy.retention_period_state={retention_state}",
        f"minimum_retention_period_days={_GCS_MIN_RETENTION_PERIOD_DAYS}",
        f"minimum_retention_period_seconds={_GCS_MIN_RETENTION_PERIOD_SECONDS}",
        f"retention_policy.is_locked is {_bool_status(bucket_facts.gcs_retention_policy_locked)}",
    ]
    if retention_period_seconds is not None:
        evidence.insert(1, f"retention_policy.retention_period_seconds={retention_period_seconds}")
    return evidence


def _gcs_public_access_prevention_enforced(value: str | None) -> bool:
    return str(value or "").strip().lower() == "enforced"


def _secret_manager_lifecycle_issues(secret_facts: AnalysisStorageFacts) -> list[str]:
    if _secret_manager_lifecycle_uncertainties(secret_facts):
        return []

    issues: list[str] = []
    has_expiry = bool(secret_facts.secret_manager_ttl or secret_facts.secret_manager_expire_time)
    has_destroy_ttl = bool(secret_facts.secret_manager_version_destroy_ttl)
    if not has_expiry and not has_destroy_ttl:
        issues.append("secret has no ttl, expire_time, or version_destroy_ttl lifecycle guardrail")

    if not has_destroy_ttl:
        issues.append("version_destroy_ttl is missing")
        return issues

    destroy_ttl_seconds = _gcp_duration_seconds(secret_facts.secret_manager_version_destroy_ttl)
    if destroy_ttl_seconds is None:
        return issues
    if destroy_ttl_seconds < _SECRET_MANAGER_MIN_VERSION_DESTROY_TTL_SECONDS:
        issues.append(
            "version_destroy_ttl is "
            f"{destroy_ttl_seconds} seconds; minimum is {_SECRET_MANAGER_MIN_VERSION_DESTROY_TTL_SECONDS} seconds"
        )
    return issues


def _secret_manager_lifecycle_evidence(secret_facts: AnalysisStorageFacts) -> list[str]:
    evidence = [
        f"ttl={secret_facts.secret_manager_ttl or 'unset'}",
        f"expire_time={secret_facts.secret_manager_expire_time or 'unset'}",
        f"version_destroy_ttl={secret_facts.secret_manager_version_destroy_ttl or 'unset'}",
        f"minimum_version_destroy_ttl_days={_SECRET_MANAGER_MIN_VERSION_DESTROY_TTL_DAYS}",
        f"minimum_version_destroy_ttl_seconds={_SECRET_MANAGER_MIN_VERSION_DESTROY_TTL_SECONDS}",
    ]
    destroy_ttl_seconds = _gcp_duration_seconds(secret_facts.secret_manager_version_destroy_ttl)
    if destroy_ttl_seconds is not None:
        evidence.append(f"version_destroy_ttl_seconds={destroy_ttl_seconds}")
    return evidence


def _secret_manager_lifecycle_uncertainties(secret_facts: AnalysisStorageFacts) -> list[str]:
    return [
        uncertainty
        for uncertainty in secret_facts.secret_manager_posture_uncertainties
        if any(field in uncertainty for field in ("ttl", "expire_time", "version_destroy_ttl"))
    ]


def _gcp_duration_seconds(value: str | None) -> int | None:
    if not isinstance(value, str) or not value:
        return None
    match = _GCP_DURATION_SECONDS.match(value)
    if not match:
        return None
    seconds = float(match.group(1))
    return int(seconds) if seconds.is_integer() else int(seconds) + 1


def _kms_rotation_issues(key_facts: AnalysisStorageFacts) -> list[str]:
    if key_facts.kms_posture_uncertainties:
        return []
    if not _kms_rotation_supported_for_purpose(key_facts.kms_purpose):
        return []

    rotation_period = key_facts.kms_rotation_period
    if not rotation_period:
        return ["rotation_period is missing"]

    rotation_seconds = _gcp_duration_seconds(rotation_period)
    if rotation_seconds is None:
        return []
    if rotation_seconds > _KMS_MAX_ROTATION_PERIOD_SECONDS:
        return [f"rotation_period is {rotation_seconds} seconds; maximum is {_KMS_MAX_ROTATION_PERIOD_SECONDS} seconds"]
    return []


def _kms_rotation_evidence(key_facts: AnalysisStorageFacts) -> list[str]:
    rotation_period = key_facts.kms_rotation_period
    rotation_seconds = _gcp_duration_seconds(rotation_period)
    if not rotation_period:
        rotation_state = "missing"
    elif rotation_seconds is None:
        rotation_state = "unknown"
    elif rotation_seconds > _KMS_MAX_ROTATION_PERIOD_SECONDS:
        rotation_state = "too_long"
    else:
        rotation_state = "configured"

    evidence = [
        f"purpose={key_facts.kms_purpose or 'unknown'}",
        f"rotation_period={rotation_period or 'unset'}",
        f"rotation_period_state={rotation_state}",
        f"maximum_rotation_period_days={_KMS_MAX_ROTATION_PERIOD_DAYS}",
        f"maximum_rotation_period_seconds={_KMS_MAX_ROTATION_PERIOD_SECONDS}",
    ]
    if rotation_seconds is not None:
        evidence.append(f"rotation_period_seconds={rotation_seconds}")
    return evidence


def _kms_destroy_scheduled_duration_issues(key_facts: AnalysisStorageFacts) -> list[str]:
    if _kms_destroy_scheduled_duration_uncertainties(key_facts):
        return []

    destroy_scheduled_duration = key_facts.kms_destroy_scheduled_duration
    if not destroy_scheduled_duration:
        return []

    destroy_seconds = _gcp_duration_seconds(destroy_scheduled_duration)
    if destroy_seconds is None:
        return []
    if destroy_seconds < _KMS_MIN_DESTROY_SCHEDULED_DURATION_SECONDS:
        return [
            "destroy_scheduled_duration is "
            f"{destroy_seconds} seconds; minimum is {_KMS_MIN_DESTROY_SCHEDULED_DURATION_SECONDS} seconds"
        ]
    return []


def _kms_destroy_scheduled_duration_evidence(key_facts: AnalysisStorageFacts) -> list[str]:
    destroy_scheduled_duration = key_facts.kms_destroy_scheduled_duration
    destroy_seconds = _gcp_duration_seconds(destroy_scheduled_duration)
    if not destroy_scheduled_duration:
        destroy_state = "missing"
    elif destroy_seconds is None:
        destroy_state = "unknown"
    elif destroy_seconds < _KMS_MIN_DESTROY_SCHEDULED_DURATION_SECONDS:
        destroy_state = "too_short"
    else:
        destroy_state = "configured"

    evidence = [
        f"purpose={key_facts.kms_purpose or 'unknown'}",
        f"destroy_scheduled_duration={destroy_scheduled_duration or 'unset'}",
        f"destroy_scheduled_duration_state={destroy_state}",
        f"minimum_destroy_scheduled_duration_days={_KMS_MIN_DESTROY_SCHEDULED_DURATION_DAYS}",
        f"minimum_destroy_scheduled_duration_seconds={_KMS_MIN_DESTROY_SCHEDULED_DURATION_SECONDS}",
    ]
    if destroy_seconds is not None:
        evidence.append(f"destroy_scheduled_duration_seconds={destroy_seconds}")
    return evidence


def _kms_destroy_scheduled_duration_uncertainties(key_facts: AnalysisStorageFacts) -> list[str]:
    return [
        uncertainty
        for uncertainty in key_facts.kms_posture_uncertainties
        if "destroy_scheduled_duration" in uncertainty
    ]


def _kms_rotation_supported_for_purpose(purpose: str | None) -> bool:
    return str(purpose or "ENCRYPT_DECRYPT").strip().upper() == "ENCRYPT_DECRYPT"


def _kms_target_evidence(key: NormalizedResource) -> list[str]:
    evidence = [f"address={key.address}", f"type={key.resource_type}"]
    if key.identifier:
        evidence.append(f"identifier={key.identifier}")
    return evidence


def _secret_manager_target_evidence(secret: NormalizedResource) -> list[str]:
    evidence = [f"address={secret.address}", f"type={secret.resource_type}"]
    if secret.identifier:
        evidence.append(f"identifier={secret.identifier}")
    return evidence


def _secret_manager_encryption_evidence(secret_facts: AnalysisStorageFacts) -> list[str]:
    evidence = [
        "customer_managed_encryption is false",
        f"secret_manager_replication_mode={secret_facts.secret_manager_replication_mode or 'unknown'}",
    ]
    key_names = secret_facts.secret_manager_kms_key_names
    if key_names:
        evidence.append("secret_manager_kms_key_names=" + "; ".join(key_names))
    else:
        evidence.append("secret_manager_kms_key_names is empty")
    return evidence


def _secret_manager_replication_evidence(secret_facts: AnalysisStorageFacts) -> list[str]:
    replication = secret_facts.secret_manager_replication
    evidence = [
        f"replication.mode={replication.get('mode') or secret_facts.secret_manager_replication_mode or 'unknown'}"
    ]
    if secret_facts.secret_manager_kms_key_names:
        evidence.append("replication.kms_key_names=" + "; ".join(secret_facts.secret_manager_kms_key_names))
    replicas = replication.get("replicas")
    if isinstance(replicas, list):
        for index, replica in enumerate(replicas):
            if not isinstance(replica, dict):
                continue
            parts = [f"replica[{index}]"]
            location = replica.get("location")
            if location:
                parts.append(f"location={location}")
            kms_key_names = replica.get("kms_key_names")
            if isinstance(kms_key_names, list) and kms_key_names:
                parts.append("kms_key_names=" + "; ".join(str(item) for item in kms_key_names))
            unknown_fields = replica.get("unknown_fields")
            if isinstance(unknown_fields, list) and unknown_fields:
                parts.append("unknown_fields=" + "; ".join(str(item) for item in unknown_fields))
            evidence.append("; ".join(parts))
    return evidence


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
