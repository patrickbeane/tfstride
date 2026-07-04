from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.aws.audit_normalizers import (
    normalize_cloudtrail,
    normalize_config_configuration_recorder,
    normalize_guardduty_detector,
    normalize_securityhub_account,
)
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES, AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts


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


class AwsAuditDetectionNormalizerTests(unittest.TestCase):
    def test_cloudtrail_normalizes_audit_delivery_and_scope_posture(self) -> None:
        normalized = normalize_cloudtrail(
            _resource(
                "aws_cloudtrail",
                {
                    "id": "org-trail",
                    "name": "org-trail",
                    "arn": "arn:aws:cloudtrail:us-east-1:111122223333:trail/org-trail",
                    "s3_bucket_name": "audit-logs",
                    "s3_key_prefix": "cloudtrail",
                    "kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/audit",
                    "cloud_watch_logs_group_arn": "arn:aws:logs:us-east-1:111122223333:log-group:/aws/cloudtrail",
                    "cloud_watch_logs_role_arn": "arn:aws:iam::111122223333:role/cloudtrail-logs",
                    "enable_logging": True,
                    "enable_log_file_validation": True,
                    "is_multi_region_trail": True,
                    "include_global_service_events": True,
                    "is_organization_trail": False,
                    "event_selector": [
                        {
                            "read_write_type": "All",
                            "include_management_events": True,
                            "data_resource": [{"type": "AWS::S3::Object", "values": ["arn:aws:s3:::audit/*"]}],
                        }
                    ],
                    "insight_selector": [{"insight_type": "ApiCallRateInsight"}],
                },
                name="org",
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.identifier, "org-trail")
        self.assertEqual(normalized.arn, "arn:aws:cloudtrail:us-east-1:111122223333:trail/org-trail")
        self.assertEqual(facts.resource_name, "org-trail")
        self.assertEqual(facts.cloudtrail_s3_bucket_name, "audit-logs")
        self.assertEqual(facts.cloudtrail_s3_key_prefix, "cloudtrail")
        self.assertEqual(facts.cloudtrail_kms_key_id, "arn:aws:kms:us-east-1:111122223333:key/audit")
        self.assertEqual(
            facts.cloudtrail_cloudwatch_logs_group_arn,
            "arn:aws:logs:us-east-1:111122223333:log-group:/aws/cloudtrail",
        )
        self.assertEqual(facts.cloudtrail_cloudwatch_logs_role_arn, "arn:aws:iam::111122223333:role/cloudtrail-logs")
        self.assertEqual(facts.cloudtrail_enable_logging_state, "enabled")
        self.assertTrue(facts.cloudtrail_enable_logging)
        self.assertEqual(facts.cloudtrail_log_file_validation_state, "enabled")
        self.assertTrue(facts.cloudtrail_log_file_validation_enabled)
        self.assertEqual(facts.cloudtrail_multi_region_state, "enabled")
        self.assertTrue(facts.cloudtrail_multi_region)
        self.assertEqual(facts.cloudtrail_global_service_events_state, "enabled")
        self.assertTrue(facts.cloudtrail_global_service_events)
        self.assertEqual(facts.cloudtrail_organization_trail_state, "disabled")
        self.assertFalse(facts.cloudtrail_organization_trail)
        self.assertEqual(facts.cloudtrail_insight_selectors, ["ApiCallRateInsight"])
        self.assertEqual(facts.cloudtrail_event_selectors[0]["read_write_type"], "All")
        self.assertEqual(facts.audit_detection_posture_uncertainties, [])

    def test_detection_services_normalize_provider_local_posture(self) -> None:
        guardduty = normalize_guardduty_detector(
            _resource(
                "aws_guardduty_detector",
                {
                    "id": "12abc",
                    "enable": True,
                    "finding_publishing_frequency": "FIFTEEN_MINUTES",
                    "datasources": [{"s3_logs": [{"enable": True}]}],
                    "features": [{"name": "EKS_AUDIT_LOGS", "status": "ENABLED"}],
                },
            )
        )
        securityhub = normalize_securityhub_account(
            _resource(
                "aws_securityhub_account",
                {
                    "id": "111122223333",
                    "enable_default_standards": False,
                    "auto_enable_controls": True,
                    "control_finding_generator": "SECURITY_CONTROL",
                },
            )
        )
        recorder = normalize_config_configuration_recorder(
            _resource(
                "aws_config_configuration_recorder",
                {
                    "id": "default",
                    "name": "default",
                    "role_arn": "arn:aws:iam::111122223333:role/config",
                    "recording_group": [
                        {
                            "all_supported": True,
                            "include_global_resource_types": True,
                            "resource_types": ["AWS::S3::Bucket", "AWS::IAM::Role"],
                        }
                    ],
                    "recording_strategy": [{"use_only": "ALL_SUPPORTED_RESOURCE_TYPES"}],
                },
            )
        )

        guardduty_facts = aws_facts(guardduty)
        self.assertEqual(guardduty.identifier, "12abc")
        self.assertEqual(guardduty_facts.guardduty_enable_state, "enabled")
        self.assertTrue(guardduty_facts.guardduty_enabled)
        self.assertEqual(guardduty_facts.guardduty_finding_publishing_frequency, "FIFTEEN_MINUTES")
        self.assertEqual(guardduty_facts.guardduty_datasources, {"s3_logs": [{"enable": True}]})
        self.assertEqual(guardduty_facts.guardduty_features, [{"name": "EKS_AUDIT_LOGS", "status": "ENABLED"}])

        securityhub_facts = aws_facts(securityhub)
        self.assertEqual(securityhub.identifier, "111122223333")
        self.assertEqual(securityhub_facts.securityhub_enable_default_standards_state, "disabled")
        self.assertFalse(securityhub_facts.securityhub_enable_default_standards)
        self.assertEqual(securityhub_facts.securityhub_auto_enable_controls_state, "enabled")
        self.assertTrue(securityhub_facts.securityhub_auto_enable_controls)
        self.assertEqual(securityhub_facts.securityhub_control_finding_generator, "SECURITY_CONTROL")

        recorder_facts = aws_facts(recorder)
        self.assertEqual(recorder.identifier, "default")
        self.assertEqual(recorder_facts.config_recorder_name, "default")
        self.assertEqual(recorder_facts.config_recorder_role_arn, "arn:aws:iam::111122223333:role/config")
        self.assertEqual(recorder_facts.config_recorder_all_supported_state, "enabled")
        self.assertTrue(recorder_facts.config_recorder_all_supported)
        self.assertEqual(recorder_facts.config_recorder_include_global_resource_types_state, "enabled")
        self.assertTrue(recorder_facts.config_recorder_include_global_resource_types)
        self.assertEqual(recorder_facts.config_recorder_resource_types, ["AWS::S3::Bucket", "AWS::IAM::Role"])
        self.assertEqual(recorder_facts.config_recorder_recording_strategy_use_only, "ALL_SUPPORTED_RESOURCE_TYPES")
        self.assertEqual(recorder_facts.config_recorder_recording_group["all_supported"], True)
        self.assertEqual(
            recorder_facts.config_recorder_recording_strategy, {"use_only": "ALL_SUPPORTED_RESOURCE_TYPES"}
        )

    def test_unknown_audit_detection_values_are_explicit(self) -> None:
        cloudtrail = normalize_cloudtrail(
            _resource(
                "aws_cloudtrail",
                {"name": "audit", "enable_logging": True},
                unknown_values={"enable_logging": True, "event_selector": True},
            )
        )
        guardduty = normalize_guardduty_detector(
            _resource(
                "aws_guardduty_detector",
                {"enable": True},
                unknown_values={"enable": True, "datasources": True},
            )
        )
        recorder = normalize_config_configuration_recorder(
            _resource(
                "aws_config_configuration_recorder",
                {
                    "recording_group": [{"all_supported": True, "resource_types": ["AWS::S3::Bucket"]}],
                    "recording_strategy": [{"use_only": "ALL_SUPPORTED_RESOURCE_TYPES"}],
                },
                unknown_values={
                    "recording_group": [{"all_supported": True, "resource_types": True}],
                    "recording_strategy": [{"use_only": True}],
                },
            )
        )

        cloudtrail_facts = aws_facts(cloudtrail)
        self.assertEqual(cloudtrail_facts.cloudtrail_enable_logging_state, "unknown")
        self.assertEqual(cloudtrail_facts.cloudtrail_event_selectors, [])
        self.assertEqual(
            cloudtrail_facts.audit_detection_posture_uncertainties,
            ["enable_logging is unknown after planning", "event_selector is unknown after planning"],
        )

        guardduty_facts = aws_facts(guardduty)
        self.assertEqual(guardduty_facts.guardduty_enable_state, "unknown")
        self.assertIsNone(guardduty_facts.guardduty_enabled)
        self.assertEqual(guardduty_facts.guardduty_datasources, {})
        self.assertEqual(
            guardduty_facts.audit_detection_posture_uncertainties,
            ["enable is unknown after planning", "datasources is unknown after planning"],
        )

        recorder_facts = aws_facts(recorder)
        self.assertEqual(recorder_facts.config_recorder_all_supported_state, "unknown")
        self.assertEqual(recorder_facts.config_recorder_resource_types, [])
        self.assertIsNone(recorder_facts.config_recorder_recording_strategy_use_only)
        self.assertEqual(
            recorder_facts.audit_detection_posture_uncertainties,
            [
                "recording_group.all_supported is unknown after planning",
                "recording_group.resource_types is unknown after planning",
                "recording_strategy.use_only is unknown after planning",
            ],
        )

    def test_audit_detection_resource_types_are_supported_without_findings(self) -> None:
        for resource_type in (
            "aws_cloudtrail",
            "aws_guardduty_detector",
            "aws_securityhub_account",
            "aws_config_configuration_recorder",
        ):
            with self.subTest(resource_type=resource_type):
                self.assertIn(resource_type, SUPPORTED_AWS_TYPES)

        inventory = AwsNormalizer().normalize(
            [
                _resource("aws_cloudtrail", {"name": "audit"}),
                _resource("aws_guardduty_detector", {"enable": True}),
                _resource("aws_securityhub_account", {"enable_default_standards": True}),
                _resource("aws_config_configuration_recorder", {"name": "default"}),
            ]
        )

        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual(len(inventory.resources), 4)


if __name__ == "__main__":
    unittest.main()
