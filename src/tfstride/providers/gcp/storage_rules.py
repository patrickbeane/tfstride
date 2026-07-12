from __future__ import annotations

from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import BoundaryType, Finding
from tfstride.providers.gcp.indexes import gcp_org_policy_guardrail_index
from tfstride.providers.gcp.org_policy_evidence import organization_guardrail_evidence
from tfstride.providers.gcp.org_policy_guardrails import (
    ORG_POLICY_ALLOWED_MEMBER_DOMAINS,
    ORG_POLICY_STORAGE_PUBLIC_ACCESS_PREVENTION,
)
from tfstride.providers.gcp.org_policy_severity import guardrail_adjusted_severity_reasoning
from tfstride.providers.gcp.resource_facts import GcpResourceFacts, gcp_facts

_GCS_MIN_RETENTION_PERIOD_DAYS = 7
_GCS_MIN_RETENTION_PERIOD_SECONDS = _GCS_MIN_RETENTION_PERIOD_DAYS * 24 * 60 * 60


class GcpStorageRuleDetectors:
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
            bucket_facts = gcp_facts(bucket)
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
            bucket_facts = gcp_facts(bucket)
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
            bucket_facts = gcp_facts(bucket)
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
            bucket_facts = gcp_facts(bucket)
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
            bucket_facts = gcp_facts(bucket)
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


def _bool_status(value: bool | None) -> str:
    if value is None:
        return "unset"
    return str(value).lower()


def _gcs_retention_policy_issues(bucket_facts: GcpResourceFacts) -> list[str]:
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


def _gcs_retention_policy_evidence(bucket_facts: GcpResourceFacts) -> list[str]:
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
