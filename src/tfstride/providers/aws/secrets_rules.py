from __future__ import annotations

import re

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
_MAX_SECRET_ROTATION_INTERVAL_DAYS = 90
_RATE_EXPRESSION = re.compile(r"^rate\(\s*(\d+)\s+([a-z]+)s?\s*\)$", re.IGNORECASE)
_STATE_CONFIGURED = "configured"
_STATE_NOT_CONFIGURED = "not_configured"
_STATE_UNKNOWN = "unknown"
_STATE_TOO_LONG = "too_long"


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

    def detect_rotation_not_configured_or_too_long(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for secret in context.inventory.by_type(_AWS_SECRETS_MANAGER_SECRET):
            facts = aws_facts(secret)
            state, interval_days = _secret_rotation_state(facts)
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
                    rationale=_rotation_rationale(secret.display_name, state, interval_days),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _secret_target_evidence(secret)),
                        evidence_item("rotation_posture", _secret_rotation_evidence(facts, state, interval_days)),
                        evidence_item(
                            "posture_uncertainty",
                            _secret_uncertainty_evidence(facts, "rotation"),
                        ),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings


def _secret_rotation_state(facts: AwsResourceFacts) -> tuple[str, int | None]:
    if not facts.secrets_manager_rotation_source_address:
        return _STATE_NOT_CONFIGURED, None
    interval_days = _rotation_interval_days(facts)
    if interval_days is None:
        return _STATE_UNKNOWN, None
    if interval_days > _MAX_SECRET_ROTATION_INTERVAL_DAYS:
        return _STATE_TOO_LONG, interval_days
    return _STATE_CONFIGURED, interval_days


def _rotation_interval_days(facts: AwsResourceFacts) -> int | None:
    if facts.secrets_manager_rotation_automatically_after_days is not None:
        return facts.secrets_manager_rotation_automatically_after_days
    schedule_expression = facts.secrets_manager_rotation_schedule_expression
    if not schedule_expression:
        return None
    match = _RATE_EXPRESSION.match(schedule_expression.strip())
    if not match:
        return None
    amount = int(match.group(1))
    unit = match.group(2).lower().removesuffix("s")
    if unit == "day":
        return amount
    if unit == "week":
        return amount * 7
    if unit == "hour":
        return max(1, (amount + 23) // 24)
    return None


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


def _secret_rotation_evidence(facts: AwsResourceFacts, state: str, interval_days: int | None) -> list[str]:
    values = [
        f"rotation_state={state}",
        f"maximum_rotation_interval_days={_MAX_SECRET_ROTATION_INTERVAL_DAYS}",
    ]
    if facts.secrets_manager_rotation_source_address:
        values.append(f"rotation_source={facts.secrets_manager_rotation_source_address}")
    else:
        values.append("aws_secretsmanager_secret_rotation resource was not resolved for this secret")
    if facts.secrets_manager_rotation_lambda_arn:
        values.append(f"rotation_lambda_arn={facts.secrets_manager_rotation_lambda_arn}")
    if facts.secrets_manager_rotation_automatically_after_days is not None:
        values.append(f"automatically_after_days={facts.secrets_manager_rotation_automatically_after_days}")
    if facts.secrets_manager_rotation_schedule_expression:
        values.append(f"schedule_expression={facts.secrets_manager_rotation_schedule_expression}")
    if facts.secrets_manager_rotation_duration:
        values.append(f"duration={facts.secrets_manager_rotation_duration}")
    if interval_days is not None:
        values.append(f"effective_rotation_interval_days={interval_days}")
    elif facts.secrets_manager_rotation_source_address:
        values.append("effective_rotation_interval_days=unknown")
    return values


def _secret_uncertainty_evidence(facts: AwsResourceFacts, field_path: str) -> list[str]:
    return [uncertainty for uncertainty in facts.secrets_manager_posture_uncertainties if field_path in uncertainty]


def _rotation_rationale(display_name: str, state: str, interval_days: int | None) -> str:
    if state == _STATE_NOT_CONFIGURED:
        return (
            f"{display_name} does not show a deterministic Secrets Manager rotation resource in the Terraform "
            "plan. Static or manually rotated secrets can remain valid longer after disclosure, service compromise, "
            "or operator error."
        )
    if state == _STATE_TOO_LONG:
        return (
            f"{display_name} rotates every {interval_days} days, above the "
            f"{_MAX_SECRET_ROTATION_INTERVAL_DAYS}-day baseline used by tfSTRIDE. Long rotation intervals increase "
            "the usable lifetime of a disclosed secret."
        )
    return (
        f"{display_name} has a Secrets Manager rotation resource, but tfSTRIDE could not determine a concrete "
        "rotation interval from the Terraform plan. Review the rotation schedule to confirm it meets the expected "
        "secret lifecycle policy."
    )


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
