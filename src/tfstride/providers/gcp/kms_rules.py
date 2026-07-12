from __future__ import annotations

from tfstride.analysis.finding_helpers import build_severity_reasoning, collect_evidence, evidence_item
from tfstride.analysis.resource_facts import analysis_facts
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.gcp.data_rule_utils import gcp_duration_seconds as _gcp_duration_seconds
from tfstride.providers.resource_facts.contracts import ProviderStorageFacts

_KMS_MAX_ROTATION_PERIOD_DAYS = 90
_KMS_MAX_ROTATION_PERIOD_SECONDS = _KMS_MAX_ROTATION_PERIOD_DAYS * 24 * 60 * 60
_KMS_MIN_DESTROY_SCHEDULED_DURATION_DAYS = 7
_KMS_MIN_DESTROY_SCHEDULED_DURATION_SECONDS = _KMS_MIN_DESTROY_SCHEDULED_DURATION_DAYS * 24 * 60 * 60


class GcpKmsRuleDetectors:
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


def _kms_rotation_issues(key_facts: ProviderStorageFacts) -> list[str]:
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


def _kms_rotation_evidence(key_facts: ProviderStorageFacts) -> list[str]:
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


def _kms_destroy_scheduled_duration_issues(key_facts: ProviderStorageFacts) -> list[str]:
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


def _kms_destroy_scheduled_duration_evidence(key_facts: ProviderStorageFacts) -> list[str]:
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


def _kms_destroy_scheduled_duration_uncertainties(key_facts: ProviderStorageFacts) -> list[str]:
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
