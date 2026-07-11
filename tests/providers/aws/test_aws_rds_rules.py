from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer

_RDS_PUBLIC_ENDPOINT_RULE = "aws-rds-public-endpoint-enabled"
_RDS_BACKUP_RULE = "aws-rds-backup-retention-insufficient"
_RDS_DELETION_PROTECTION_RULE = "aws-rds-deletion-protection-disabled"
_RDS_CMK_RULE = "aws-rds-customer-managed-kms-key-missing"
_RDS_MULTI_AZ_RULE = "aws-rds-multi-az-disabled"
_RDS_PERFORMANCE_INSIGHTS_RULE = "aws-rds-performance-insights-disabled"
_RDS_CLOUDWATCH_LOG_EXPORTS_RULE = "aws-rds-cloudwatch-log-exports-missing"
_RDS_IAM_AUTH_RULE = "aws-rds-iam-auth-disabled"
_RDS_RULE_IDS = (
    _RDS_PUBLIC_ENDPOINT_RULE,
    _RDS_BACKUP_RULE,
    _RDS_DELETION_PROTECTION_RULE,
    _RDS_CMK_RULE,
)
_RDS_NEW_RULE_IDS = (
    _RDS_MULTI_AZ_RULE,
    _RDS_PERFORMANCE_INSIGHTS_RULE,
    _RDS_CLOUDWATCH_LOG_EXPORTS_RULE,
    _RDS_IAM_AUTH_RULE,
)
_MISSING = object()


def _db_instance(
    *,
    name: str = "customer",
    engine: str = "postgres",
    publicly_accessible: object = _MISSING,
    backup_retention_period: object = _MISSING,
    deletion_protection: object = _MISSING,
    storage_encrypted: object = _MISSING,
    kms_key_id: object = _MISSING,
    multi_az: object = _MISSING,
    performance_insights_enabled: object = _MISSING,
    enabled_cloudwatch_logs_exports: object = _MISSING,
    iam_database_authentication_enabled: object = _MISSING,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": f"db-{name}",
        "identifier": name,
        "arn": f"arn:aws:rds:us-east-1:111122223333:db:{name}",
        "engine": engine,
        "vpc_security_group_ids": ["sg-db"],
    }
    if publicly_accessible is not _MISSING:
        values["publicly_accessible"] = publicly_accessible
    if backup_retention_period is not _MISSING:
        values["backup_retention_period"] = backup_retention_period
    if deletion_protection is not _MISSING:
        values["deletion_protection"] = deletion_protection
    if storage_encrypted is not _MISSING:
        values["storage_encrypted"] = storage_encrypted
    if kms_key_id is not _MISSING:
        values["kms_key_id"] = kms_key_id
    if multi_az is not _MISSING:
        values["multi_az"] = multi_az
    if performance_insights_enabled is not _MISSING:
        values["performance_insights_enabled"] = performance_insights_enabled
    if enabled_cloudwatch_logs_exports is not _MISSING:
        values["enabled_cloudwatch_logs_exports"] = enabled_cloudwatch_logs_exports
    if iam_database_authentication_enabled is not _MISSING:
        values["iam_database_authentication_enabled"] = iam_database_authentication_enabled
    return TerraformResource(
        address=f"aws_db_instance.{name}",
        mode="managed",
        resource_type="aws_db_instance",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _safe_db_instance(*, name: str = "safe", **overrides: object) -> TerraformResource:
    defaults: dict[str, object] = {
        "name": name,
        "publicly_accessible": False,
        "backup_retention_period": 14,
        "deletion_protection": True,
        "storage_encrypted": True,
        "kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/rds",
    }
    defaults.update(overrides)
    return _db_instance(**defaults)


def _findings(resources: list[TerraformResource], *rule_ids: str):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsRdsPostureRuleTests(unittest.TestCase):
    def test_public_endpoint_disabled_backups_deletion_protection_and_missing_cmk_are_detected(self) -> None:
        findings = _findings(
            [
                _db_instance(
                    name="unsafe",
                    publicly_accessible=True,
                    backup_retention_period=0,
                    deletion_protection=False,
                    storage_encrypted=True,
                )
            ],
            *_RDS_RULE_IDS,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                _RDS_PUBLIC_ENDPOINT_RULE,
                _RDS_BACKUP_RULE,
                _RDS_DELETION_PROTECTION_RULE,
                _RDS_CMK_RULE,
            ],
        )
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual(findings_by_rule[_RDS_PUBLIC_ENDPOINT_RULE].severity.value, "medium")
        self.assertEqual(findings_by_rule[_RDS_BACKUP_RULE].severity.value, "medium")
        self.assertEqual(findings_by_rule[_RDS_DELETION_PROTECTION_RULE].severity.value, "medium")
        self.assertEqual(findings_by_rule[_RDS_CMK_RULE].severity.value, "low")

        endpoint_evidence = _evidence_by_key(findings_by_rule[_RDS_PUBLIC_ENDPOINT_RULE])
        self.assertEqual(
            endpoint_evidence["endpoint_posture"],
            ["publicly_accessible_state=enabled", "publicly_accessible is true"],
        )
        backup_evidence = _evidence_by_key(findings_by_rule[_RDS_BACKUP_RULE])
        self.assertEqual(
            backup_evidence["backup_posture"],
            [
                "backup_retention_state=disabled",
                "backup_retention_period=0",
                "minimum_backup_retention_days=7",
            ],
        )
        deletion_evidence = _evidence_by_key(findings_by_rule[_RDS_DELETION_PROTECTION_RULE])
        self.assertEqual(
            deletion_evidence["deletion_protection"],
            ["deletion_protection_state=disabled", "deletion_protection is false"],
        )
        cmk_finding = findings_by_rule[_RDS_CMK_RULE]
        self.assertNotIn("unencrypted", cmk_finding.rationale.lower())
        cmk_evidence = _evidence_by_key(cmk_finding)
        self.assertEqual(
            cmk_evidence["encryption_ownership"],
            [
                "storage_encrypted is true",
                "kms_key_id is unset",
                "AWS-managed encryption may still apply; this finding concerns customer key control",
            ],
        )

    def test_safe_private_database_has_no_rds_posture_findings(self) -> None:
        findings = _findings([_safe_db_instance()], *_RDS_RULE_IDS)

        self.assertEqual(findings, [])

    def test_short_backup_retention_is_reported_with_threshold_evidence(self) -> None:
        findings = _findings(
            [_safe_db_instance(backup_retention_period=3)],
            _RDS_BACKUP_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RDS_BACKUP_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["backup_posture"],
            [
                "backup_retention_state=short_retention",
                "backup_retention_period=3",
                "minimum_backup_retention_days=7",
            ],
        )

    def test_unencrypted_database_does_not_emit_duplicate_customer_managed_key_finding(self) -> None:
        findings = _findings(
            [_safe_db_instance(storage_encrypted=False, kms_key_id=_MISSING)],
            _RDS_CMK_RULE,
        )

        self.assertEqual(findings, [])

    def test_missing_or_unknown_posture_values_are_not_overclaimed(self) -> None:
        findings = _findings(
            [
                _db_instance(
                    name="unknown",
                    unknown_values={
                        "publicly_accessible": True,
                        "backup_retention_period": True,
                        "deletion_protection": True,
                        "kms_key_id": True,
                    },
                )
            ],
            *_RDS_RULE_IDS,
        )

        self.assertEqual(findings, [])

    def test_multi_az_disabled_is_detected(self) -> None:
        findings = _findings([_safe_db_instance(multi_az=False)], _RDS_MULTI_AZ_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_RDS_MULTI_AZ_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["multi_az_posture"], ["multi_az_state=disabled", "multi_az is false"])

    def test_multi_az_missing_or_unknown_is_not_overclaimed(self) -> None:
        findings = _findings(
            [
                _safe_db_instance(),
                _db_instance(name="unknown", unknown_values={"multi_az": True}),
            ],
            _RDS_MULTI_AZ_RULE,
        )

        self.assertEqual(findings, [])

    def test_performance_insights_disabled_is_detected(self) -> None:
        findings = _findings([_safe_db_instance(performance_insights_enabled=False)], _RDS_PERFORMANCE_INSIGHTS_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_RDS_PERFORMANCE_INSIGHTS_RULE])
        self.assertEqual(findings[0].severity.value, "low")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["performance_insights_posture"],
            ["performance_insights_state=disabled", "performance_insights_enabled is false"],
        )

    def test_performance_insights_missing_or_unknown_is_not_overclaimed(self) -> None:
        findings = _findings(
            [
                _safe_db_instance(),
                _db_instance(name="unknown", unknown_values={"performance_insights_enabled": True}),
            ],
            _RDS_PERFORMANCE_INSIGHTS_RULE,
        )

        self.assertEqual(findings, [])

    def test_iam_database_authentication_disabled_is_detected(self) -> None:
        findings = _findings(
            [_safe_db_instance(iam_database_authentication_enabled=False)],
            _RDS_IAM_AUTH_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RDS_IAM_AUTH_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["iam_database_authentication_posture"],
            ["iam_database_authentication_state=disabled", "iam_database_authentication_enabled is false"],
        )

    def test_iam_database_authentication_missing_or_unknown_is_not_overclaimed(self) -> None:
        findings = _findings(
            [
                _safe_db_instance(),
                _db_instance(name="unknown", unknown_values={"iam_database_authentication_enabled": True}),
            ],
            _RDS_IAM_AUTH_RULE,
        )

        self.assertEqual(findings, [])

    def test_cloudwatch_log_exports_missing_is_detected_for_known_engine(self) -> None:
        findings = _findings([_safe_db_instance()], _RDS_CLOUDWATCH_LOG_EXPORTS_RULE)

        self.assertEqual([finding.rule_id for finding in findings], [_RDS_CLOUDWATCH_LOG_EXPORTS_RULE])
        self.assertEqual(findings[0].severity.value, "low")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["log_export_posture"],
            [
                "enabled_cloudwatch_logs_exports=[]",
                "expected_log_exports=['postgresql']",
                "engine-family baseline log exports are absent",
            ],
        )

    def test_cloudwatch_log_exports_present_is_not_flagged(self) -> None:
        findings = _findings(
            [_safe_db_instance(enabled_cloudwatch_logs_exports=["postgresql"])],
            _RDS_CLOUDWATCH_LOG_EXPORTS_RULE,
        )

        self.assertEqual(findings, [])

    def test_cloudwatch_log_exports_unknown_is_not_treated_as_missing(self) -> None:
        findings = _findings(
            [
                _db_instance(
                    name="unknown",
                    unknown_values={"enabled_cloudwatch_logs_exports": True},
                )
            ],
            _RDS_CLOUDWATCH_LOG_EXPORTS_RULE,
        )

        self.assertEqual(findings, [])

    def test_cloudwatch_log_exports_unrecognized_engine_is_not_flagged(self) -> None:
        findings = _findings([_db_instance(name="docdb", engine="docdb")], _RDS_CLOUDWATCH_LOG_EXPORTS_RULE)

        self.assertEqual(findings, [])

    def test_multi_az_performance_insights_log_exports_and_iam_auth_are_detected_together(self) -> None:
        findings = _findings(
            [
                _safe_db_instance(
                    multi_az=False,
                    performance_insights_enabled=False,
                    iam_database_authentication_enabled=False,
                )
            ],
            *_RDS_NEW_RULE_IDS,
        )

        self.assertEqual(
            sorted(finding.rule_id for finding in findings),
            sorted(_RDS_NEW_RULE_IDS),
        )
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual(findings_by_rule[_RDS_MULTI_AZ_RULE].severity.value, "medium")
        self.assertEqual(findings_by_rule[_RDS_PERFORMANCE_INSIGHTS_RULE].severity.value, "low")
        self.assertEqual(findings_by_rule[_RDS_CLOUDWATCH_LOG_EXPORTS_RULE].severity.value, "low")
        self.assertEqual(findings_by_rule[_RDS_IAM_AUTH_RULE].severity.value, "medium")
        self.assertIn("engine `postgres`", findings_by_rule[_RDS_CLOUDWATCH_LOG_EXPORTS_RULE].rationale)

    def test_iam_database_authentication_supported_engine_is_flagged_when_disabled(self) -> None:
        findings = _findings(
            [_db_instance(name="mariadb", engine="mariadb", iam_database_authentication_enabled=False)],
            _RDS_IAM_AUTH_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RDS_IAM_AUTH_RULE])
        self.assertEqual(findings[0].severity.value, "medium")

    def test_iam_database_authentication_unsupported_engine_is_not_flagged(self) -> None:
        findings = _findings(
            [
                _db_instance(
                    name="sqlserver",
                    engine="sqlserver-express",
                    iam_database_authentication_enabled=False,
                )
            ],
            _RDS_IAM_AUTH_RULE,
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
