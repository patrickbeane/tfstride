from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts

_AWS_S3_BUCKET = "aws_s3_bucket"
_KMS_ENCRYPTION_ALGORITHMS = frozenset({"aws:kms", "aws:kms:dsse"})
_STATE_CONFIGURED = "configured"
_STATE_NOT_MODELED = "not_modeled"
_STATE_UNKNOWN = "unknown"
_STATE_PROVIDER_MANAGED_SSE_S3 = "provider_managed_sse_s3"
_STATE_SSE_KMS_WITHOUT_CUSTOMER_KEY = "sse_kms_without_customer_key"
_STATE_NON_KMS_ALGORITHM = "non_kms_algorithm"
_STATE_DISABLED = "disabled"


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
            if state in {_STATE_CONFIGURED, _STATE_NOT_MODELED}:
                continue
            unknown = state == _STATE_UNKNOWN
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
            if state in {_STATE_CONFIGURED, _STATE_NOT_MODELED}:
                continue
            unknown = state == _STATE_UNKNOWN
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


def _s3_customer_managed_encryption_state(facts: AwsResourceFacts) -> str:
    algorithm = facts.s3_encryption_algorithm
    if algorithm in _KMS_ENCRYPTION_ALGORITHMS and facts.s3_kms_master_key_id:
        return _STATE_CONFIGURED
    if _s3_encryption_unknown(facts):
        return _STATE_UNKNOWN
    if not facts.s3_encryption_source_address and not algorithm:
        return _STATE_NOT_MODELED
    if algorithm in _KMS_ENCRYPTION_ALGORITHMS:
        return _STATE_SSE_KMS_WITHOUT_CUSTOMER_KEY
    if algorithm == "AES256":
        return _STATE_PROVIDER_MANAGED_SSE_S3
    return _STATE_NON_KMS_ALGORITHM


def _s3_versioning_state(facts: AwsResourceFacts) -> str:
    if facts.s3_versioning_enabled is True:
        return _STATE_CONFIGURED
    if facts.s3_versioning_enabled is False:
        return _STATE_DISABLED
    if facts.s3_versioning_source_address or _s3_uncertainty_evidence(facts, "versioning_configuration"):
        return _STATE_UNKNOWN
    return _STATE_NOT_MODELED


def _s3_encryption_unknown(facts: AwsResourceFacts) -> bool:
    if _s3_uncertainty_evidence(facts, "rule.apply_server_side_encryption_by_default"):
        return True
    return bool(facts.s3_encryption_source_address and not facts.s3_encryption_algorithm)


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


def _s3_uncertainty_evidence(facts: AwsResourceFacts, field_path: str) -> list[str]:
    return [uncertainty for uncertainty in facts.s3_posture_uncertainties if field_path in uncertainty]
