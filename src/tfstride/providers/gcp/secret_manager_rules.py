from __future__ import annotations

from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.gcp.data_rule_utils import gcp_duration_seconds as _gcp_duration_seconds
from tfstride.providers.gcp.resource_facts import GcpResourceFacts, gcp_facts

_SECRET_MANAGER_MIN_VERSION_DESTROY_TTL_DAYS = 7
_SECRET_MANAGER_MIN_VERSION_DESTROY_TTL_SECONDS = _SECRET_MANAGER_MIN_VERSION_DESTROY_TTL_DAYS * 24 * 60 * 60


class GcpSecretManagerRuleDetectors:
    def detect_secret_manager_customer_managed_encryption_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "gcp":
            return []

        findings: list[Finding] = []
        for secret in context.inventory.by_type("google_secret_manager_secret"):
            secret_facts = gcp_facts(secret)
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
            secret_facts = gcp_facts(secret)
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


def _secret_manager_lifecycle_issues(secret_facts: GcpResourceFacts) -> list[str]:
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


def _secret_manager_lifecycle_evidence(secret_facts: GcpResourceFacts) -> list[str]:
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


def _secret_manager_lifecycle_uncertainties(secret_facts: GcpResourceFacts) -> list[str]:
    return [
        uncertainty
        for uncertainty in secret_facts.secret_manager_posture_uncertainties
        if any(field in uncertainty for field in ("ttl", "expire_time", "version_destroy_ttl"))
    ]


def _secret_manager_target_evidence(secret: NormalizedResource) -> list[str]:
    evidence = [f"address={secret.address}", f"type={secret.resource_type}"]
    if secret.identifier:
        evidence.append(f"identifier={secret.identifier}")
    return evidence


def _secret_manager_encryption_evidence(secret_facts: GcpResourceFacts) -> list[str]:
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


def _secret_manager_replication_evidence(secret_facts: GcpResourceFacts) -> list[str]:
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
