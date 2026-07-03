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

_AWS_SECRETS_MANAGER_SECRET = "aws_secretsmanager_secret"
_MIN_SECRET_RECOVERY_WINDOW_DAYS = 7
_STATE_CONFIGURED = "configured"
_STATE_NOT_CONFIGURED = "not_configured"
_STATE_UNKNOWN = "unknown"


class AwsSecretsManagerPostureRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_customer_managed_kms_key_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for secret in context.inventory.by_type(_AWS_SECRETS_MANAGER_SECRET):
            facts = aws_facts(secret)
            state = _secret_customer_managed_kms_state(facts)
            if state == _STATE_CONFIGURED:
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
                    affected_resources=[secret.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{secret.display_name} does not show a deterministic customer-managed KMS key in "
                        "the Terraform plan. Secrets Manager AWS-managed encryption may still apply; this "
                        "finding concerns customer key ownership, rotation, audit separation, and compliance "
                        "posture."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _secret_target_evidence(secret)),
                        evidence_item("encryption_ownership", _secret_encryption_evidence(facts, state)),
                        evidence_item(
                            "posture_uncertainty",
                            _secret_uncertainty_evidence(facts, "kms_key_id"),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_recovery_window_too_short(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for secret in context.inventory.by_type(_AWS_SECRETS_MANAGER_SECRET):
            facts = aws_facts(secret)
            recovery_days = facts.secrets_manager_recovery_window_in_days
            if recovery_days is None or recovery_days >= _MIN_SECRET_RECOVERY_WINDOW_DAYS:
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
                    rationale=_recovery_window_rationale(secret.display_name, recovery_days),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _secret_target_evidence(secret)),
                        evidence_item("recovery_posture", _secret_recovery_evidence(recovery_days)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _secret_customer_managed_kms_state(facts: AwsResourceFacts) -> str:
    if facts.secrets_manager_kms_key_id:
        return _STATE_CONFIGURED
    if _secret_uncertainty_evidence(facts, "kms_key_id"):
        return _STATE_UNKNOWN
    return _STATE_NOT_CONFIGURED


def _secret_target_evidence(secret) -> list[str]:
    values = [f"address={secret.address}", f"type={secret.resource_type}"]
    if secret.identifier:
        values.append(f"identifier={secret.identifier}")
    if secret.arn:
        values.append(f"arn={secret.arn}")
    return values


def _secret_encryption_evidence(facts: AwsResourceFacts, state: str) -> list[str]:
    values = [f"customer_managed_kms_state={state}"]
    if facts.secrets_manager_kms_key_id:
        values.append(f"kms_key_id={facts.secrets_manager_kms_key_id}")
    else:
        values.append("kms_key_id is unset")
    values.append("AWS-managed encryption may still apply; this finding concerns customer key control")
    return values


def _secret_recovery_evidence(recovery_days: int) -> list[str]:
    state = "immediate_delete" if recovery_days <= 0 else "short_recovery_window"
    return [
        f"recovery_window_state={state}",
        f"recovery_window_in_days={recovery_days}",
        f"minimum_recovery_window_days={_MIN_SECRET_RECOVERY_WINDOW_DAYS}",
    ]


def _secret_uncertainty_evidence(facts: AwsResourceFacts, field_path: str) -> list[str]:
    return [uncertainty for uncertainty in facts.secrets_manager_posture_uncertainties if field_path in uncertainty]


def _recovery_window_rationale(display_name: str, recovery_days: int) -> str:
    if recovery_days <= 0:
        return (
            f"{display_name} has a Secrets Manager recovery window of {recovery_days} days, which allows "
            "immediate secret deletion without a meaningful recovery period after accidental or malicious removal."
        )
    return (
        f"{display_name} has a Secrets Manager recovery window of {recovery_days} days, below the "
        f"{_MIN_SECRET_RECOVERY_WINDOW_DAYS}-day baseline used by tfSTRIDE. Short recovery windows can "
        "limit restoration options after delayed detection of destructive changes."
    )
