from __future__ import annotations

from collections.abc import Iterable

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.finding_helpers import (
    build_severity_reasoning,
    collect_evidence,
    dedupe_addresses,
    evidence_item,
)
from tfstride.analysis.rule_definitions import RuleEvaluationContext
from tfstride.models import Finding, NormalizedResource
from tfstride.providers.aws.resource_facts import AwsResourceFacts, aws_facts

_AWS_CLOUDTRAIL = "aws_cloudtrail"
_AWS_GUARDDUTY_DETECTOR = "aws_guardduty_detector"
_AWS_SECURITYHUB_ACCOUNT = "aws_securityhub_account"
_AWS_CONFIG_CONFIGURATION_RECORDER = "aws_config_configuration_recorder"
_AWS_ACCOUNT_AUDIT_RESOURCE_TYPES = (
    _AWS_CLOUDTRAIL,
    _AWS_GUARDDUTY_DETECTOR,
    _AWS_SECURITYHUB_ACCOUNT,
    _AWS_CONFIG_CONFIGURATION_RECORDER,
)


class AwsAccountAuditRuleDetectors:
    def __init__(self, finding_factory: FindingFactory) -> None:
        self._finding_factory = finding_factory

    def detect_cloudtrail_multi_region_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for trail in context.inventory.by_type(_AWS_CLOUDTRAIL):
            facts = aws_facts(trail)
            if facts.cloudtrail_multi_region is not False:
                continue
            severity_reasoning = _audit_detection_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[trail.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{trail.display_name} is not configured as a multi-region CloudTrail. Account activity "
                        "outside the trail region may therefore lack the same deterministic audit coverage in this "
                        "Terraform plan."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _account_resource_evidence(trail, facts)),
                        evidence_item("cloudtrail_scope", _cloudtrail_scope_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_cloudtrail_log_file_validation_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for trail in context.inventory.by_type(_AWS_CLOUDTRAIL):
            facts = aws_facts(trail)
            if facts.cloudtrail_log_file_validation_enabled is not False:
                continue
            severity_reasoning = _audit_detection_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[trail.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{trail.display_name} has CloudTrail log file validation disabled. That weakens the "
                        "ability to verify log integrity after incident response, legal hold, or forensic review."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _account_resource_evidence(trail, facts)),
                        evidence_item("log_integrity", _cloudtrail_log_validation_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_guardduty_detector_disabled_or_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        guardduty_detectors = context.inventory.by_type(_AWS_GUARDDUTY_DETECTOR)
        findings: list[Finding] = []
        for detector in guardduty_detectors:
            facts = aws_facts(detector)
            if facts.guardduty_enabled is not False:
                continue
            severity_reasoning = _audit_detection_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[detector.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{detector.display_name} has GuardDuty disabled. Threat-detection findings for the "
                        "modeled account or region may not be produced until the detector is enabled."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _account_resource_evidence(detector, facts)),
                        evidence_item("guardduty_posture", _guardduty_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )

        if guardduty_detectors:
            return findings

        modeled_controls = _modeled_account_audit_resources(context.inventory.resources)
        if not modeled_controls:
            return findings

        severity_reasoning = _audit_detection_severity()
        findings.append(
            self._finding_factory.build(
                rule_id=rule_id,
                severity=severity_reasoning.severity,
                affected_resources=_resource_addresses(modeled_controls),
                trust_boundary_id=None,
                rationale=(
                    "The Terraform plan models AWS account audit or detection controls, but no "
                    "aws_guardduty_detector resource is present. tfSTRIDE cannot confirm GuardDuty is enabled for "
                    "the modeled account controls from this plan."
                ),
                evidence=collect_evidence(
                    evidence_item("missing_control", ["aws_guardduty_detector is not modeled"]),
                    evidence_item("modeled_account_controls", _modeled_control_evidence(modeled_controls)),
                ),
                severity_reasoning=severity_reasoning,
            )
        )
        return findings

    def detect_securityhub_account_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []
        if context.inventory.by_type(_AWS_SECURITYHUB_ACCOUNT):
            return []

        modeled_controls = _modeled_account_audit_resources(context.inventory.resources)
        if not modeled_controls:
            return []

        severity_reasoning = _audit_detection_severity()
        return [
            self._finding_factory.build(
                rule_id=rule_id,
                severity=severity_reasoning.severity,
                affected_resources=_resource_addresses(modeled_controls),
                trust_boundary_id=None,
                rationale=(
                    "The Terraform plan models AWS account audit or detection controls, but no "
                    "aws_securityhub_account resource is present. tfSTRIDE cannot confirm Security Hub is enabled "
                    "for the modeled account controls from this plan."
                ),
                evidence=collect_evidence(
                    evidence_item("missing_control", ["aws_securityhub_account is not modeled"]),
                    evidence_item("modeled_account_controls", _modeled_control_evidence(modeled_controls)),
                ),
                severity_reasoning=severity_reasoning,
            )
        ]


def _audit_detection_severity():
    return build_severity_reasoning(
        internet_exposure=False,
        privilege_breadth=0,
        data_sensitivity=0,
        lateral_movement=1,
        blast_radius=2,
    )


def _modeled_account_audit_resources(resources: Iterable[NormalizedResource]) -> list[NormalizedResource]:
    return [resource for resource in resources if resource.resource_type in _AWS_ACCOUNT_AUDIT_RESOURCE_TYPES]


def _resource_addresses(resources: Iterable[NormalizedResource]) -> list[str]:
    return dedupe_addresses([resource.address for resource in resources])


def _account_resource_evidence(resource: NormalizedResource, facts: AwsResourceFacts) -> list[str]:
    values = [f"address={resource.address}", f"type={resource.resource_type}"]
    name = facts.resource_name or resource.identifier or resource.name
    if name:
        values.append(f"name={name}")
    if resource.arn:
        values.append(f"arn={resource.arn}")
    return values


def _cloudtrail_scope_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [f"multi_region_state={facts.cloudtrail_multi_region_state or 'unknown'}"]
    if facts.cloudtrail_multi_region is False:
        values.append("is_multi_region_trail is false")
    elif facts.cloudtrail_multi_region is True:
        values.append("is_multi_region_trail is true")
    else:
        values.append("is_multi_region_trail is unknown")
    if facts.cloudtrail_global_service_events_state:
        values.append(f"include_global_service_events_state={facts.cloudtrail_global_service_events_state}")
    if facts.cloudtrail_organization_trail_state:
        values.append(f"organization_trail_state={facts.cloudtrail_organization_trail_state}")
    return values


def _cloudtrail_log_validation_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [f"log_file_validation_state={facts.cloudtrail_log_file_validation_state or 'unknown'}"]
    if facts.cloudtrail_log_file_validation_enabled is False:
        values.append("enable_log_file_validation is false")
    elif facts.cloudtrail_log_file_validation_enabled is True:
        values.append("enable_log_file_validation is true")
    else:
        values.append("enable_log_file_validation is unknown")
    return values


def _guardduty_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [f"enable_state={facts.guardduty_enable_state or 'unknown'}"]
    if facts.guardduty_enabled is False:
        values.append("guardduty is disabled")
    elif facts.guardduty_enabled is True:
        values.append("guardduty is enabled")
    else:
        values.append("guardduty enablement is unknown")
    if facts.guardduty_finding_publishing_frequency:
        values.append(f"finding_publishing_frequency={facts.guardduty_finding_publishing_frequency}")
    return values


def _modeled_control_evidence(resources: Iterable[NormalizedResource]) -> list[str]:
    return [f"{resource.resource_type}:{resource.address}" for resource in resources]
