from __future__ import annotations

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts

_AWS_KMS_KEY = "aws_kms_key"
_KMS_STATE_ENABLED = "enabled"
_KMS_STATE_DISABLED = "disabled"
_KMS_STATE_UNKNOWN = "unknown"
_SYMMETRIC_KEY_SPECS = frozenset({"SYMMETRIC_DEFAULT"})


class AwsKmsRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_key_rotation_disabled_or_unknown(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for key in context.inventory.by_type(_AWS_KMS_KEY):
            facts = aws_facts(key)
            if not _kms_rotation_applicable(facts):
                continue
            state = facts.kms_enable_key_rotation_state or _KMS_STATE_DISABLED
            if state == _KMS_STATE_ENABLED:
                continue

            unknown = state == _KMS_STATE_UNKNOWN
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
                    affected_resources=[key.address],
                    trust_boundary_id=None,
                    rationale=_kms_rotation_rationale(key.display_name, state),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _kms_target_evidence(key)),
                        evidence_item("key_posture", _kms_key_posture_evidence(facts)),
                        evidence_item("rotation_posture", _kms_rotation_evidence(facts, state)),
                        evidence_item("posture_uncertainty", _kms_uncertainty_evidence(facts, "enable_key_rotation")),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _kms_rotation_applicable(facts: AwsResourceFacts) -> bool:
    if _kms_uncertainty_evidence(facts, "key_usage") or _kms_uncertainty_evidence(facts, "key_spec"):
        return False
    if _kms_uncertainty_evidence(facts, "customer_master_key_spec"):
        return False

    key_usage = _normalized_upper(facts.kms_key_usage) or "ENCRYPT_DECRYPT"
    if key_usage != "ENCRYPT_DECRYPT":
        return False

    for spec in (facts.kms_key_spec, facts.kms_customer_master_key_spec):
        normalized = _normalized_upper(spec)
        if normalized is not None and normalized not in _SYMMETRIC_KEY_SPECS:
            return False
    return True


def _normalized_upper(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip().upper()
    return text or None


def _kms_target_evidence(key: NormalizedResource) -> list[str]:
    values = [f"address={key.address}", f"type={key.resource_type}"]
    if key.identifier:
        values.append(f"identifier={key.identifier}")
    if key.arn:
        values.append(f"arn={key.arn}")
    return values


def _kms_key_posture_evidence(facts: AwsResourceFacts) -> list[str]:
    return [
        f"key_usage={facts.kms_key_usage or 'ENCRYPT_DECRYPT'}",
        f"key_spec={facts.kms_key_spec or 'unset'}",
        f"customer_master_key_spec={facts.kms_customer_master_key_spec or 'unset'}",
    ]


def _kms_rotation_evidence(facts: AwsResourceFacts, state: str) -> list[str]:
    values = [f"enable_key_rotation_state={state}"]
    if facts.kms_enable_key_rotation is True:
        values.append("enable_key_rotation is true")
    elif facts.kms_enable_key_rotation is False:
        values.append("enable_key_rotation is false")
    else:
        values.append("enable_key_rotation is unknown")
    values.append("automatic annual rotation is evaluated for customer-managed symmetric KMS keys")
    return values


def _kms_uncertainty_evidence(facts: AwsResourceFacts, field_path: str) -> list[str]:
    return [uncertainty for uncertainty in facts.kms_posture_uncertainties if field_path in uncertainty]


def _kms_rotation_rationale(display_name: str, state: str) -> str:
    if state == _KMS_STATE_UNKNOWN:
        return (
            f"{display_name} does not show deterministic AWS KMS key rotation posture in the Terraform plan. "
            "Review the final plan or deployed key to confirm automatic annual rotation is enabled for this "
            "customer-managed symmetric key."
        )
    return (
        f"{display_name} has automatic KMS key rotation disabled. Customer-managed symmetric KMS keys can "
        "protect secrets, storage, databases, and Kubernetes secrets; disabling rotation weakens key lifecycle "
        "governance for dependent encrypted data."
    )
