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
_AWS_CONFIG_CONFIGURATION_RECORDER_STATUS = "aws_config_configuration_recorder_status"
_AWS_CONFIG_DELIVERY_CHANNEL = "aws_config_delivery_channel"
_AWS_ACCESSANALYZER_ANALYZER = "aws_accessanalyzer_analyzer"
_AWS_MACIE2_ACCOUNT = "aws_macie2_account"
_AWS_S3_BUCKET = "aws_s3_bucket"
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

    def detect_cloudtrail_management_events_disabled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for trail in context.inventory.by_type(_AWS_CLOUDTRAIL):
            facts = aws_facts(trail)
            if _event_selectors_unknown(facts) or not _management_events_explicitly_disabled(
                facts.cloudtrail_event_selectors
            ):
                continue
            severity_reasoning = _audit_detection_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[trail.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{trail.display_name} has modeled CloudTrail event selectors that explicitly disable "
                        "management events. Control-plane API activity may not have the expected audit coverage "
                        "from this trail."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _account_resource_evidence(trail, facts)),
                        evidence_item("event_selectors", _cloudtrail_event_selector_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_cloudtrail_data_events_not_modeled(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for trail in context.inventory.by_type(_AWS_CLOUDTRAIL):
            facts = aws_facts(trail)
            event_selectors = facts.cloudtrail_event_selectors
            if _event_selectors_unknown(facts) or not event_selectors or _has_data_event_selector(event_selectors):
                continue
            severity_reasoning = _audit_detection_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[trail.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{trail.display_name} models CloudTrail event selectors, but none include data event "
                        "resources. Data-plane operations for resources such as S3 objects or Lambda functions may "
                        "not have retained CloudTrail data event coverage from this trail."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _account_resource_evidence(trail, facts)),
                        evidence_item("data_event_coverage", _cloudtrail_data_event_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        return findings

    def detect_cloudtrail_insight_selectors_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        findings: list[Finding] = []
        for trail in context.inventory.by_type(_AWS_CLOUDTRAIL):
            facts = aws_facts(trail)
            if facts.cloudtrail_insight_selectors or _insight_selectors_unknown(facts):
                continue
            severity_reasoning = _audit_detection_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[trail.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{trail.display_name} does not model CloudTrail Insights selectors. Control-plane anomaly "
                        "detection for unusual API call rates or error rates may be outside this trail coverage."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _account_resource_evidence(trail, facts)),
                        evidence_item("insight_selectors", _cloudtrail_insight_selector_evidence(facts)),
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

    def detect_config_recorder_disabled_or_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        recorders = list(context.inventory.by_type(_AWS_CONFIG_CONFIGURATION_RECORDER))
        recorder_statuses = list(context.inventory.by_type(_AWS_CONFIG_CONFIGURATION_RECORDER_STATUS))
        findings: list[Finding] = []
        for status in recorder_statuses:
            facts = aws_facts(status)
            if facts.config_recorder_status_is_enabled is not False:
                continue
            severity_reasoning = _audit_detection_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[status.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{status.display_name} reports the AWS Config recorder is disabled. Configuration "
                        "changes for the modeled account resources may not be captured by AWS Config until "
                        "recording is enabled."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _account_resource_evidence(status, facts)),
                        evidence_item("config_recorder_posture", _config_recorder_status_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        if recorders:
            if not recorder_statuses:
                severity_reasoning = _audit_detection_severity()
                findings.append(
                    self._finding_factory.build(
                        rule_id=rule_id,
                        severity=severity_reasoning.severity,
                        affected_resources=_resource_addresses(recorders),
                        trust_boundary_id=None,
                        rationale=(
                            "The Terraform plan models aws_config_configuration_recorder, but no "
                            "aws_config_configuration_recorder_status resource is present. tfSTRIDE cannot "
                            "confirm the recorder is enabled and actively recording resource configurations "
                            "from this plan."
                        ),
                        evidence=collect_evidence(
                            evidence_item(
                                "missing_control",
                                ["aws_config_configuration_recorder_status is not modeled"],
                            ),
                            evidence_item("target_recorders", _modeled_control_evidence(recorders)),
                        ),
                        severity_reasoning=severity_reasoning,
                    )
                )
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
                    "aws_config_configuration_recorder resource is present. tfSTRIDE cannot confirm AWS Config is "
                    "recording resource configurations for the modeled account from this plan."
                ),
                evidence=collect_evidence(
                    evidence_item("missing_control", ["aws_config_configuration_recorder is not modeled"]),
                    evidence_item("modeled_account_controls", _modeled_control_evidence(modeled_controls)),
                ),
                severity_reasoning=severity_reasoning,
            )
        )
        return findings

    def detect_config_delivery_channel_missing(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []
        if context.inventory.by_type(_AWS_CONFIG_DELIVERY_CHANNEL):
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
                    "aws_config_delivery_channel resource is present. tfSTRIDE cannot confirm AWS Config "
                    "configuration history is exported to a durable destination from this plan."
                ),
                evidence=collect_evidence(
                    evidence_item("missing_control", ["aws_config_delivery_channel is not modeled"]),
                    evidence_item("modeled_account_controls", _modeled_control_evidence(modeled_controls)),
                ),
                severity_reasoning=severity_reasoning,
            )
        ]

    def detect_access_analyzer_not_configured(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []
        if context.inventory.by_type(_AWS_ACCESSANALYZER_ANALYZER):
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
                    "aws_accessanalyzer_analyzer resource is present. tfSTRIDE cannot confirm IAM Access "
                    "Analyzer is reviewing external or unused access for the modeled account from this plan."
                ),
                evidence=collect_evidence(
                    evidence_item("missing_control", ["aws_accessanalyzer_analyzer is not modeled"]),
                    evidence_item("modeled_account_controls", _modeled_control_evidence(modeled_controls)),
                ),
                severity_reasoning=severity_reasoning,
            )
        ]

    def detect_macie_not_enabled_for_sensitive_storage(
        self,
        context: RuleEvaluationContext,
        rule_id: str,
    ) -> list[Finding]:
        if context.inventory.provider != "aws":
            return []

        sensitive_storage = list(context.inventory.by_type(_AWS_S3_BUCKET))
        if not sensitive_storage:
            return []

        macie_accounts = list(context.inventory.by_type(_AWS_MACIE2_ACCOUNT))
        findings: list[Finding] = []
        for macie in macie_accounts:
            facts = aws_facts(macie)
            if facts.macie_account_enabled is not False:
                continue
            severity_reasoning = _audit_detection_severity()
            findings.append(
                self._finding_factory.build(
                    rule_id=rule_id,
                    severity=severity_reasoning.severity,
                    affected_resources=[macie.address],
                    trust_boundary_id=None,
                    rationale=(
                        f"{macie.display_name} has Amazon Macie disabled. Sensitive objects in the modeled "
                        "Amazon S3 storage may not be discovered or classified until Macie is enabled."
                    ),
                    evidence=collect_evidence(
                        evidence_item("target_resource", _account_resource_evidence(macie, facts)),
                        evidence_item("macie_posture", _macie_evidence(facts)),
                    ),
                    severity_reasoning=severity_reasoning,
                )
            )
        if macie_accounts:
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
                    "The Terraform plan models sensitive Amazon S3 storage and AWS account audit or detection "
                    "controls, but no aws_macie2_account resource is present. tfSTRIDE cannot confirm Amazon Macie "
                    "is enabled to discover and classify sensitive data in the modeled S3 storage from this plan."
                ),
                evidence=collect_evidence(
                    evidence_item("missing_control", ["aws_macie2_account is not modeled"]),
                    evidence_item("sensitive_storage", _macie_sensitive_storage_evidence(sensitive_storage)),
                    evidence_item("modeled_account_controls", _modeled_control_evidence(modeled_controls)),
                ),
                severity_reasoning=severity_reasoning,
            )
        )
        return findings


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


def _event_selectors_unknown(facts: AwsResourceFacts) -> bool:
    return bool(_matching_uncertainties(facts.audit_detection_posture_uncertainties, ("event_selector",)))


def _insight_selectors_unknown(facts: AwsResourceFacts) -> bool:
    return bool(_matching_uncertainties(facts.audit_detection_posture_uncertainties, ("insight_selector",)))


def _management_events_explicitly_disabled(selectors: list[dict]) -> bool:
    include_values = [_known_boolish(selector.get("include_management_events")) for selector in selectors]
    return bool(include_values) and all(value is False for value in include_values)


def _has_data_event_selector(selectors: list[dict]) -> bool:
    return any(bool(_data_resource_records(selector)) for selector in selectors)


def _known_boolish(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
    return None


def _data_resource_records(selector: dict) -> list[dict]:
    records = selector.get("data_resource")
    if not isinstance(records, list):
        return []
    return [record for record in records if isinstance(record, dict)]


def _cloudtrail_event_selector_evidence(facts: AwsResourceFacts) -> list[str]:
    selectors = facts.cloudtrail_event_selectors
    if not selectors:
        values = ["event_selectors=not_modeled"]
    else:
        values = [f"event_selector_count={len(selectors)}"]
        for index, selector in enumerate(selectors):
            prefix = f"event_selector[{index}]"
            values.append(f"{prefix}.read_write_type={selector.get('read_write_type', 'unknown')}")
            values.append(f"{prefix}.include_management_events={selector.get('include_management_events', 'unknown')}")
            data_resources = _data_resource_records(selector)
            values.append(f"{prefix}.data_resource_count={len(data_resources)}")
            for resource_index, data_resource in enumerate(data_resources):
                resource_prefix = f"{prefix}.data_resource[{resource_index}]"
                values.append(f"{resource_prefix}.type={data_resource.get('type', 'unknown')}")
                values.append(f"{resource_prefix}.value_count={len(_selector_values(data_resource))}")
    values.extend(_uncertainty_evidence(facts, ("event_selector",)))
    return values


def _cloudtrail_data_event_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [
        f"event_selector_count={len(facts.cloudtrail_event_selectors)}",
        f"data_resource_selectors={_data_resource_selector_count(facts.cloudtrail_event_selectors)}",
    ]
    values.extend(_cloudtrail_event_selector_evidence(facts))
    return values


def _cloudtrail_insight_selector_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [f"insight_selector={selector}" for selector in facts.cloudtrail_insight_selectors]
    if not values:
        values.append("insight_selectors=not_configured")
    values.extend(_uncertainty_evidence(facts, ("insight_selector",)))
    return values


def _data_resource_selector_count(selectors: list[dict]) -> int:
    return sum(len(_data_resource_records(selector)) for selector in selectors)


def _selector_values(data_resource: dict) -> list[object]:
    values = data_resource.get("values")
    return values if isinstance(values, list) else []


def _uncertainty_evidence(facts: AwsResourceFacts, fields: tuple[str, ...]) -> list[str]:
    return [
        f"uncertainty={uncertainty}"
        for uncertainty in _matching_uncertainties(facts.audit_detection_posture_uncertainties, fields)
    ]


def _matching_uncertainties(uncertainties: Iterable[str], fields: tuple[str, ...]) -> list[str]:
    return [uncertainty for uncertainty in uncertainties if any(field in uncertainty for field in fields)]


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


def _config_recorder_status_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [f"recorder_status_is_enabled_state={facts.config_recorder_status_is_enabled_state or 'unknown'}"]
    if facts.config_recorder_status_is_enabled is False:
        values.append("recorder is disabled")
    elif facts.config_recorder_status_is_enabled is True:
        values.append("recorder is enabled")
    else:
        values.append("recorder enablement is unknown")
    return values


def _macie_evidence(facts: AwsResourceFacts) -> list[str]:
    values = [f"account_status_state={facts.macie_account_status_state or 'unknown'}"]
    if facts.macie_account_enabled is False:
        values.append("macie is disabled")
    elif facts.macie_account_enabled is True:
        values.append("macie is enabled")
    else:
        values.append("macie enablement is unknown")
    if facts.macie_finding_publishing_frequency:
        values.append(f"finding_publishing_frequency={facts.macie_finding_publishing_frequency}")
    return values


def _macie_sensitive_storage_evidence(resources: Iterable[NormalizedResource]) -> list[str]:
    return sorted({f"{resource.resource_type}:{resource.address}" for resource in resources})
