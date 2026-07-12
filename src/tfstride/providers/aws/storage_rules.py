from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts
from tfstride.providers.coercion import STATE_CONFIGURED, STATE_DISABLED, STATE_UNKNOWN, as_optional_int

_AWS_S3_BUCKET = "aws_s3_bucket"
_KMS_ENCRYPTION_ALGORITHMS = frozenset({"aws:kms", "aws:kms:dsse"})
_STATE_NOT_MODELED = "not_modeled"
_STATE_PROVIDER_MANAGED_SSE_S3 = "provider_managed_sse_s3"
_STATE_SSE_KMS_WITHOUT_CUSTOMER_KEY = "sse_kms_without_customer_key"
_STATE_NON_KMS_ALGORITHM = "non_kms_algorithm"
_STATE_DEFAULT_RETENTION_MISSING = "default_retention_missing"
_STATE_SHORT_RETENTION = "short_retention"
_MIN_S3_RECOVERY_RETENTION_DAYS = 7


class AwsS3PostureRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_customer_managed_encryption_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for bucket in context.inventory.by_type(_AWS_S3_BUCKET):
            facts = aws_facts(bucket)
            state = _s3_customer_managed_encryption_state(facts)
            if state in {STATE_CONFIGURED, _STATE_NOT_MODELED}:
                continue
            unknown = state == STATE_UNKNOWN
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1 if unknown else 2,
                lateral_movement=0,
                blast_radius=0 if unknown else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[bucket.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{bucket.display_name} does not show deterministic customer-managed SSE-KMS "
                        "encryption in the Terraform plan. S3 provider-managed encryption may still apply; "
                        "this finding concerns customer key ownership, rotation, and separation-of-duties controls."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _s3_target_evidence(bucket)),
                        evidence_item("encryption_ownership", _s3_encryption_evidence(facts, state)),
                        evidence_item(
                            "posture_uncertainty",
                            _s3_uncertainty_evidence(facts, "rule.apply_server_side_encryption_by_default"),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_versioning_disabled_or_unknown(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for bucket in context.inventory.by_type(_AWS_S3_BUCKET):
            facts = aws_facts(bucket)
            state = _s3_versioning_state(facts)
            if state in {STATE_CONFIGURED, _STATE_NOT_MODELED}:
                continue
            unknown = state == STATE_UNKNOWN
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1 if unknown else 2,
                lateral_movement=0,
                blast_radius=0 if unknown else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[bucket.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{bucket.display_name} does not have deterministic S3 bucket versioning enabled. "
                        "Reduced object version history limits recovery options after overwrite, deletion, "
                        "or destructive change."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _s3_target_evidence(bucket)),
                        evidence_item("versioning_posture", _s3_versioning_evidence(facts, state)),
                        evidence_item(
                            "posture_uncertainty",
                            _s3_uncertainty_evidence(facts, "versioning_configuration.status"),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_object_lock_retention_missing_or_short(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for bucket in context.inventory.by_type(_AWS_S3_BUCKET):
            facts = aws_facts(bucket)
            state = _s3_object_lock_retention_state(facts)
            if state in {STATE_CONFIGURED, _STATE_NOT_MODELED}:
                continue
            unknown = state == STATE_UNKNOWN
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1 if unknown else 2,
                lateral_movement=0,
                blast_radius=0 if unknown else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[bucket.address],
                    trust_boundary_id=None,
                    rationale=_s3_object_lock_rationale(bucket.display_name, state),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _s3_target_evidence(bucket)),
                        evidence_item("object_lock_posture", _s3_object_lock_evidence(facts, state)),
                        evidence_item("posture_uncertainty", _s3_object_lock_uncertainty_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_lifecycle_noncurrent_retention_insufficient(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for bucket in context.inventory.by_type(_AWS_S3_BUCKET):
            facts = aws_facts(bucket)
            state, rule = _s3_lifecycle_noncurrent_retention_state(facts)
            if state in {STATE_CONFIGURED, _STATE_NOT_MODELED}:
                continue
            unknown = state == STATE_UNKNOWN
            severity_reasoning = build_severity_reasoning(
                internet_exposure=False,
                privilege_breadth=0,
                data_sensitivity=1 if unknown else 2,
                lateral_movement=0,
                blast_radius=0 if unknown else 1,
            )
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[bucket.address],
                    trust_boundary_id=None,
                    rationale=_s3_lifecycle_rationale(bucket.display_name, state, rule),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _s3_target_evidence(bucket)),
                        evidence_item("lifecycle_recovery_posture", _s3_lifecycle_evidence(facts, state, rule)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _s3_customer_managed_encryption_state(facts: AwsResourceFacts) -> str:
    algorithm = facts.s3_encryption_algorithm
    if algorithm in _KMS_ENCRYPTION_ALGORITHMS and facts.s3_kms_master_key_id:
        return STATE_CONFIGURED
    if _s3_encryption_unknown(facts):
        return STATE_UNKNOWN
    if not facts.s3_encryption_source_address and not algorithm:
        return _STATE_NOT_MODELED
    if algorithm in _KMS_ENCRYPTION_ALGORITHMS:
        return _STATE_SSE_KMS_WITHOUT_CUSTOMER_KEY
    if algorithm == "AES256":
        return _STATE_PROVIDER_MANAGED_SSE_S3
    return _STATE_NON_KMS_ALGORITHM


def _s3_versioning_state(facts: AwsResourceFacts) -> str:
    if facts.s3_versioning_enabled is True:
        return STATE_CONFIGURED
    if facts.s3_versioning_enabled is False:
        return STATE_DISABLED
    if facts.s3_versioning_source_address or _s3_uncertainty_evidence(facts, "versioning_configuration"):
        return STATE_UNKNOWN
    return _STATE_NOT_MODELED


def _s3_object_lock_retention_state(facts: AwsResourceFacts) -> str:
    if not facts.s3_object_lock_source_address and not _s3_object_lock_uncertainty_evidence(facts):
        return _STATE_NOT_MODELED
    if _s3_object_lock_unknown(facts):
        return STATE_UNKNOWN
    if facts.s3_object_lock_enabled is False:
        return STATE_DISABLED
    if facts.s3_object_lock_enabled is not True:
        return STATE_UNKNOWN
    if not facts.s3_object_lock_default_retention_mode:
        return _STATE_DEFAULT_RETENTION_MISSING
    if facts.s3_object_lock_default_retention_years is not None:
        return STATE_CONFIGURED if facts.s3_object_lock_default_retention_years > 0 else _STATE_SHORT_RETENTION
    if facts.s3_object_lock_default_retention_days is None:
        return _STATE_DEFAULT_RETENTION_MISSING
    if facts.s3_object_lock_default_retention_days < _MIN_S3_RECOVERY_RETENTION_DAYS:
        return _STATE_SHORT_RETENTION
    return STATE_CONFIGURED


def _s3_lifecycle_noncurrent_retention_state(facts: AwsResourceFacts) -> tuple[str, Mapping[str, Any] | None]:
    if not facts.s3_lifecycle_source_address:
        return _STATE_NOT_MODELED, None

    configured_rule: Mapping[str, Any] | None = None
    unknown_rule: Mapping[str, Any] | None = None
    for rule in facts.s3_lifecycle_rules:
        if not _s3_lifecycle_rule_enabled(rule):
            continue
        unknown_fields = _string_list(rule.get("unknown_fields"))
        if "noncurrent_version_expiration" in unknown_fields:
            unknown_rule = rule
            continue
        for expiration in _mapping_list(rule.get("noncurrent_version_expiration")):
            days = as_optional_int(expiration.get("noncurrent_days"))
            if days is None:
                continue
            if days < _MIN_S3_RECOVERY_RETENTION_DAYS:
                return _STATE_SHORT_RETENTION, rule
            configured_rule = rule

    if unknown_rule is not None:
        return STATE_UNKNOWN, unknown_rule
    if configured_rule is not None:
        return STATE_CONFIGURED, configured_rule
    return _STATE_NOT_MODELED, None


def _s3_encryption_unknown(facts: AwsResourceFacts) -> bool:
    if _s3_uncertainty_evidence(facts, "rule.apply_server_side_encryption_by_default"):
        return True
    return bool(facts.s3_encryption_source_address and not facts.s3_encryption_algorithm)


def _s3_object_lock_unknown(facts: AwsResourceFacts) -> bool:
    uncertainty = _s3_object_lock_uncertainty_evidence(facts)
    if uncertainty:
        return True
    return bool(facts.s3_object_lock_source_address and facts.s3_object_lock_enabled_state is None)


def _s3_lifecycle_rule_enabled(rule: Mapping[str, Any]) -> bool:
    status = rule.get("status")
    return not isinstance(status, str) or status.strip().lower() == "enabled"


def _mapping_list(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _s3_target_evidence(bucket) -> list[str]:
    return [f"address={bucket.address}", f"type={bucket.resource_type}"]


def _s3_encryption_evidence(facts: AwsResourceFacts, state: str) -> list[str]:
    values = [f"s3_encryption_state={state}"]
    if facts.s3_encryption_algorithm:
        values.append(f"sse_algorithm={facts.s3_encryption_algorithm}")
    else:
        values.append("sse_algorithm is unknown")
    if facts.s3_kms_master_key_id:
        values.append(f"kms_master_key_id={facts.s3_kms_master_key_id}")
    else:
        values.append("kms_master_key_id is unset")
    if facts.s3_bucket_key_enabled_state:
        values.append(f"bucket_key_enabled_state={facts.s3_bucket_key_enabled_state}")
    if facts.s3_encryption_source_address:
        values.append(f"source={facts.s3_encryption_source_address}")
    values.append("S3 provider-managed encryption may still apply; this finding concerns customer key control")
    return values


def _s3_versioning_evidence(facts: AwsResourceFacts, state: str) -> list[str]:
    values = [f"s3_versioning_state={state}"]
    if facts.s3_versioning_status:
        values.append(f"versioning_configuration.status={facts.s3_versioning_status}")
    else:
        values.append("versioning_configuration.status is unknown")
    if facts.s3_versioning_source_address:
        values.append(f"source={facts.s3_versioning_source_address}")
    return values


def _s3_object_lock_evidence(facts: AwsResourceFacts, state: str) -> list[str]:
    values = [
        f"s3_object_lock_state={state}",
        f"minimum_retention_days={_MIN_S3_RECOVERY_RETENTION_DAYS}",
    ]
    if facts.s3_object_lock_enabled_state:
        values.append(f"object_lock_enabled_state={facts.s3_object_lock_enabled_state}")
    else:
        values.append("object_lock_enabled_state is unknown")
    if facts.s3_object_lock_default_retention_mode:
        values.append(f"default_retention.mode={facts.s3_object_lock_default_retention_mode}")
    else:
        values.append("default_retention.mode is unset")
    if facts.s3_object_lock_default_retention_days is not None:
        values.append(f"default_retention.days={facts.s3_object_lock_default_retention_days}")
    if facts.s3_object_lock_default_retention_years is not None:
        values.append(f"default_retention.years={facts.s3_object_lock_default_retention_years}")
    if facts.s3_object_lock_source_address:
        values.append(f"source={facts.s3_object_lock_source_address}")
    return values


def _s3_lifecycle_evidence(
    facts: AwsResourceFacts,
    state: str,
    rule: Mapping[str, Any] | None,
) -> list[str]:
    values = [
        f"s3_lifecycle_noncurrent_version_retention_state={state}",
        f"minimum_retention_days={_MIN_S3_RECOVERY_RETENTION_DAYS}",
    ]
    if facts.s3_lifecycle_source_address:
        values.append(f"source={facts.s3_lifecycle_source_address}")
    if rule is not None:
        rule_id = rule.get("id")
        if isinstance(rule_id, str) and rule_id:
            values.append(f"rule.id={rule_id}")
        status = rule.get("status")
        if isinstance(status, str) and status:
            values.append(f"rule.status={status}")
        days = _s3_lifecycle_noncurrent_days(rule)
        if days is not None:
            values.append(f"noncurrent_version_expiration.noncurrent_days={days}")
        unknown_fields = _string_list(rule.get("unknown_fields"))
        if unknown_fields:
            values.append("unknown_fields=" + ",".join(unknown_fields))
    return values


def _s3_lifecycle_noncurrent_days(rule: Mapping[str, Any] | None) -> int | None:
    if rule is None:
        return None
    for expiration in _mapping_list(rule.get("noncurrent_version_expiration")):
        days = as_optional_int(expiration.get("noncurrent_days"))
        if days is not None:
            return days
    return None


def _s3_object_lock_rationale(display_name: str, state: str) -> str:
    if state == STATE_DISABLED:
        return (
            f"{display_name} has an S3 Object Lock configuration with object lock disabled. "
            "Buckets that require immutability protection should enable Object Lock and default retention."
        )
    if state == _STATE_SHORT_RETENTION:
        return (
            f"{display_name} has S3 Object Lock default retention below the "
            f"{_MIN_S3_RECOVERY_RETENTION_DAYS}-day tfSTRIDE recovery baseline. Short retention can weaken "
            "immutability protection after delayed detection of destructive changes."
        )
    if state == STATE_UNKNOWN:
        return (
            f"{display_name} has S3 Object Lock posture that remains unresolved after Terraform planning. "
            "tfSTRIDE cannot confirm whether immutable default retention is enabled."
        )
    return (
        f"{display_name} enables S3 Object Lock but does not show deterministic default retention mode and duration. "
        "Object Lock without default retention may leave newly written objects without the expected immutability guardrail."
    )


def _s3_lifecycle_rationale(display_name: str, state: str, rule: Mapping[str, Any] | None) -> str:
    if state == STATE_UNKNOWN:
        return (
            f"{display_name} has lifecycle noncurrent-version retention that remains unresolved after Terraform "
            "planning. tfSTRIDE cannot confirm whether recoverable object versions meet the recovery baseline."
        )
    days = _s3_lifecycle_noncurrent_days(rule)
    return (
        f"{display_name} expires noncurrent S3 object versions after {days} days, below the "
        f"{_MIN_S3_RECOVERY_RETENTION_DAYS}-day tfSTRIDE recovery baseline. Short noncurrent-version retention can "
        "limit recovery after overwrite, deletion, or destructive change."
    )


def _s3_object_lock_uncertainty_evidence(facts: AwsResourceFacts) -> list[str]:
    field_paths = ("object_lock_enabled", "rule.default_retention")
    return [
        uncertainty
        for uncertainty in facts.s3_posture_uncertainties
        if any(field_path in uncertainty for field_path in field_paths)
    ]


def _s3_uncertainty_evidence(facts: AwsResourceFacts, field_path: str) -> list[str]:
    return [uncertainty for uncertainty in facts.s3_posture_uncertainties if field_path in uncertainty]
