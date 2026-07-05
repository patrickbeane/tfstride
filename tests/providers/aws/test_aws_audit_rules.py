from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer

_CLOUDTRAIL_MULTI_REGION_RULE = "aws-cloudtrail-multi-region-disabled"
_CLOUDTRAIL_LOG_VALIDATION_RULE = "aws-cloudtrail-log-file-validation-disabled"
_CLOUDTRAIL_MANAGEMENT_EVENTS_RULE = "aws-cloudtrail-management-events-disabled"
_CLOUDTRAIL_DATA_EVENTS_RULE = "aws-cloudtrail-data-events-not-modeled"
_CLOUDTRAIL_INSIGHT_SELECTORS_RULE = "aws-cloudtrail-insight-selectors-missing"
_GUARDDUTY_RULE = "aws-guardduty-detector-disabled-or-missing"
_SECURITYHUB_RULE = "aws-securityhub-account-missing"
_AUDIT_RULE_IDS = (
    _CLOUDTRAIL_MULTI_REGION_RULE,
    _CLOUDTRAIL_LOG_VALIDATION_RULE,
    _CLOUDTRAIL_MANAGEMENT_EVENTS_RULE,
    _CLOUDTRAIL_DATA_EVENTS_RULE,
    _CLOUDTRAIL_INSIGHT_SELECTORS_RULE,
    _GUARDDUTY_RULE,
    _SECURITYHUB_RULE,
)
_MISSING = object()
_SAFE_EVENT_SELECTORS = [
    {
        "read_write_type": "All",
        "include_management_events": True,
        "data_resource": [{"type": "AWS::S3::Object", "values": ["arn:aws:s3:::audit/*"]}],
    }
]
_SAFE_INSIGHT_SELECTORS = [{"insight_type": "ApiCallRateInsight"}]


def _resource(
    resource_type: str,
    values: dict[str, Any],
    *,
    name: str = "main",
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _cloudtrail(
    *,
    name: str = "audit",
    multi_region: object = True,
    log_file_validation: object = True,
    event_selectors: object = _MISSING,
    insight_selectors: object = _MISSING,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": name,
        "name": name,
        "arn": f"arn:aws:cloudtrail:us-east-1:111122223333:trail/{name}",
        "enable_logging": True,
        "include_global_service_events": True,
        "is_organization_trail": False,
    }
    if multi_region is not _MISSING:
        values["is_multi_region_trail"] = multi_region
    if log_file_validation is not _MISSING:
        values["enable_log_file_validation"] = log_file_validation
    if event_selectors is _MISSING:
        values["event_selector"] = _SAFE_EVENT_SELECTORS
    elif event_selectors is not None:
        values["event_selector"] = event_selectors
    if insight_selectors is _MISSING:
        values["insight_selector"] = _SAFE_INSIGHT_SELECTORS
    elif insight_selectors is not None:
        values["insight_selector"] = insight_selectors
    return _resource("aws_cloudtrail", values, name=name, unknown_values=unknown_values)


def _guardduty(*, name: str = "main", enabled: object = True, unknown_values: dict[str, Any] | None = None):
    values: dict[str, Any] = {
        "id": f"guardduty-{name}",
        "finding_publishing_frequency": "FIFTEEN_MINUTES",
    }
    if enabled is not _MISSING:
        values["enable"] = enabled
    return _resource("aws_guardduty_detector", values, name=name, unknown_values=unknown_values)


def _securityhub(*, name: str = "main") -> TerraformResource:
    return _resource(
        "aws_securityhub_account",
        {
            "id": "111122223333",
            "enable_default_standards": True,
            "auto_enable_controls": True,
            "control_finding_generator": "SECURITY_CONTROL",
        },
        name=name,
    )


def _config_recorder(*, name: str = "default") -> TerraformResource:
    return _resource(
        "aws_config_configuration_recorder",
        {
            "id": name,
            "name": name,
            "role_arn": "arn:aws:iam::111122223333:role/config",
            "recording_group": [{"all_supported": True, "include_global_resource_types": True}],
        },
        name=name,
    )


def _s3_bucket(*, name: str = "logs") -> TerraformResource:
    return _resource("aws_s3_bucket", {"id": name, "bucket": name}, name=name)


def _findings(resources: list[TerraformResource], *rule_ids: str):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsAccountAuditRuleTests(unittest.TestCase):
    def test_cloudtrail_multi_region_and_log_validation_findings_are_detected(self) -> None:
        findings = _findings(
            [
                _cloudtrail(name="regional", multi_region=False, log_file_validation=False),
                _guardduty(),
                _securityhub(),
            ],
            _CLOUDTRAIL_MULTI_REGION_RULE,
            _CLOUDTRAIL_LOG_VALIDATION_RULE,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [_CLOUDTRAIL_MULTI_REGION_RULE, _CLOUDTRAIL_LOG_VALIDATION_RULE],
        )
        self.assertTrue(all(finding.severity.value == "medium" for finding in findings))
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        scope_evidence = _evidence_by_key(findings_by_rule[_CLOUDTRAIL_MULTI_REGION_RULE])
        self.assertEqual(
            scope_evidence["cloudtrail_scope"],
            [
                "multi_region_state=disabled",
                "is_multi_region_trail is false",
                "include_global_service_events_state=enabled",
                "organization_trail_state=disabled",
            ],
        )
        validation_evidence = _evidence_by_key(findings_by_rule[_CLOUDTRAIL_LOG_VALIDATION_RULE])
        self.assertEqual(
            validation_evidence["log_integrity"],
            ["log_file_validation_state=disabled", "enable_log_file_validation is false"],
        )

    def test_guardduty_disabled_is_detected_without_missing_securityhub_noise(self) -> None:
        findings = _findings(
            [_guardduty(enabled=False), _securityhub()],
            _GUARDDUTY_RULE,
            _SECURITYHUB_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_GUARDDUTY_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["guardduty_posture"],
            [
                "enable_state=disabled",
                "guardduty is disabled",
                "finding_publishing_frequency=FIFTEEN_MINUTES",
            ],
        )

    def test_cloudtrail_event_coverage_findings_are_detected(self) -> None:
        findings = _findings(
            [
                _cloudtrail(
                    name="limited",
                    event_selectors=[{"read_write_type": "All", "include_management_events": False}],
                    insight_selectors=[],
                )
            ],
            _CLOUDTRAIL_MANAGEMENT_EVENTS_RULE,
            _CLOUDTRAIL_DATA_EVENTS_RULE,
            _CLOUDTRAIL_INSIGHT_SELECTORS_RULE,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                _CLOUDTRAIL_MANAGEMENT_EVENTS_RULE,
                _CLOUDTRAIL_DATA_EVENTS_RULE,
                _CLOUDTRAIL_INSIGHT_SELECTORS_RULE,
            ],
        )
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        management_evidence = _evidence_by_key(findings_by_rule[_CLOUDTRAIL_MANAGEMENT_EVENTS_RULE])
        data_evidence = _evidence_by_key(findings_by_rule[_CLOUDTRAIL_DATA_EVENTS_RULE])
        insights_evidence = _evidence_by_key(findings_by_rule[_CLOUDTRAIL_INSIGHT_SELECTORS_RULE])
        self.assertIn(
            "event_selector[0].include_management_events=False",
            management_evidence["event_selectors"],
        )
        self.assertIn("data_resource_selectors=0", data_evidence["data_event_coverage"])
        self.assertEqual(insights_evidence["insight_selectors"], ["insight_selectors=not_configured"])

    def test_cloudtrail_event_coverage_safe_selectors_are_quiet(self) -> None:
        findings = _findings(
            [_cloudtrail()],
            _CLOUDTRAIL_MANAGEMENT_EVENTS_RULE,
            _CLOUDTRAIL_DATA_EVENTS_RULE,
            _CLOUDTRAIL_INSIGHT_SELECTORS_RULE,
        )

        self.assertEqual(findings, [])

    def test_absent_event_selectors_do_not_overclaim_management_or_data_event_coverage(self) -> None:
        findings = _findings(
            [_cloudtrail(event_selectors=None)],
            _CLOUDTRAIL_MANAGEMENT_EVENTS_RULE,
            _CLOUDTRAIL_DATA_EVENTS_RULE,
        )

        self.assertEqual(findings, [])

    def test_missing_guardduty_and_securityhub_are_detected_when_account_controls_are_modeled(self) -> None:
        findings = _findings([_cloudtrail(), _config_recorder()], _GUARDDUTY_RULE, _SECURITYHUB_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_GUARDDUTY_RULE, _SECURITYHUB_RULE])
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        guardduty_evidence = _evidence_by_key(findings_by_rule[_GUARDDUTY_RULE])
        self.assertEqual(guardduty_evidence["missing_control"], ["aws_guardduty_detector is not modeled"])
        self.assertEqual(
            guardduty_evidence["modeled_account_controls"],
            [
                "aws_cloudtrail:aws_cloudtrail.audit",
                "aws_config_configuration_recorder:aws_config_configuration_recorder.default",
            ],
        )
        securityhub_evidence = _evidence_by_key(findings_by_rule[_SECURITYHUB_RULE])
        self.assertEqual(securityhub_evidence["missing_control"], ["aws_securityhub_account is not modeled"])

    def test_complete_account_audit_detection_posture_is_quiet(self) -> None:
        findings = _findings(
            [_cloudtrail(), _guardduty(), _securityhub(), _config_recorder()],
            *_AUDIT_RULE_IDS,
        )

        self.assertEqual(findings, [])

    def test_unknown_values_are_not_overclaimed(self) -> None:
        findings = _findings(
            [
                _cloudtrail(
                    multi_region=False,
                    log_file_validation=False,
                    event_selectors=[{"read_write_type": "All", "include_management_events": False}],
                    insight_selectors=[],
                    unknown_values={
                        "is_multi_region_trail": True,
                        "enable_log_file_validation": True,
                        "event_selector": True,
                        "insight_selector": True,
                    },
                ),
                _guardduty(enabled=False, unknown_values={"enable": True}),
                _securityhub(),
            ],
            *_AUDIT_RULE_IDS,
        )

        self.assertEqual(findings, [])

    def test_missing_detection_services_are_not_inferred_without_account_audit_resources(self) -> None:
        findings = _findings([_s3_bucket()], _GUARDDUTY_RULE, _SECURITYHUB_RULE)

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
