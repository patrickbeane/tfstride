from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.aws.data_normalizers import (
    normalize_db_instance,
    normalize_kms_key,
    normalize_s3_bucket_server_side_encryption_configuration,
    normalize_s3_bucket_versioning,
    normalize_secretsmanager_secret,
    normalize_secretsmanager_secret_rotation,
)
from tfstride.providers.aws.resource_facts import aws_facts


def _terraform_resource(
    resource_type: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.logs",
        mode="managed",
        resource_type=resource_type,
        name="logs",
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


class AwsDataNormalizerTests(unittest.TestCase):
    def test_db_instance_normalizes_recovery_endpoint_and_key_posture(self) -> None:
        resource = _terraform_resource(
            "aws_db_instance",
            {
                "id": "db-1",
                "identifier": "customer",
                "arn": "arn:aws:rds:us-east-1:111122223333:db:customer",
                "engine": "postgres",
                "publicly_accessible": True,
                "backup_retention_period": 14,
                "deletion_protection": True,
                "multi_az": False,
                "kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/rds",
                "storage_encrypted": True,
                "vpc_security_group_ids": ["sg-db"],
            },
        )

        normalized = normalize_db_instance(resource)
        facts = aws_facts(normalized)

        self.assertEqual(normalized.identifier, "db-1")
        self.assertEqual(normalized.arn, "arn:aws:rds:us-east-1:111122223333:db:customer")
        self.assertTrue(normalized.public_access_configured)
        self.assertTrue(normalized.publicly_accessible)
        self.assertTrue(normalized.storage_encrypted)
        self.assertEqual(normalized.security_group_ids, ("sg-db",))
        self.assertEqual(facts.engine, "postgres")
        self.assertEqual(facts.rds_publicly_accessible_state, "enabled")
        self.assertTrue(facts.rds_publicly_accessible)
        self.assertEqual(facts.rds_backup_retention_period, 14)
        self.assertEqual(facts.rds_deletion_protection_state, "enabled")
        self.assertTrue(facts.rds_deletion_protection)
        self.assertEqual(facts.rds_multi_az_state, "disabled")
        self.assertFalse(facts.rds_multi_az)
        self.assertEqual(facts.rds_kms_key_id, "arn:aws:kms:us-east-1:111122223333:key/rds")
        self.assertEqual(facts.rds_posture_uncertainties, [])

    def test_db_instance_missing_posture_fields_are_explicitly_unknown(self) -> None:
        facts = aws_facts(normalize_db_instance(_terraform_resource("aws_db_instance", {"identifier": "customer"})))

        self.assertEqual(facts.rds_publicly_accessible_state, "unknown")
        self.assertIsNone(facts.rds_publicly_accessible)
        self.assertIsNone(facts.rds_backup_retention_period)
        self.assertEqual(facts.rds_deletion_protection_state, "unknown")
        self.assertIsNone(facts.rds_deletion_protection)
        self.assertEqual(facts.rds_multi_az_state, "unknown")
        self.assertIsNone(facts.rds_multi_az)
        self.assertIsNone(facts.rds_kms_key_id)
        self.assertEqual(facts.rds_posture_uncertainties, [])

    def test_db_instance_preserves_unknown_posture_values(self) -> None:
        resource = _terraform_resource(
            "aws_db_instance",
            {"identifier": "customer"},
            unknown_values={
                "publicly_accessible": True,
                "backup_retention_period": True,
                "deletion_protection": True,
                "multi_az": True,
                "kms_key_id": True,
            },
        )

        facts = aws_facts(normalize_db_instance(resource))

        self.assertEqual(facts.rds_publicly_accessible_state, "unknown")
        self.assertIsNone(facts.rds_backup_retention_period)
        self.assertEqual(facts.rds_deletion_protection_state, "unknown")
        self.assertEqual(facts.rds_multi_az_state, "unknown")
        self.assertIsNone(facts.rds_kms_key_id)
        self.assertEqual(
            facts.rds_posture_uncertainties,
            [
                "publicly_accessible is unknown after planning",
                "deletion_protection is unknown after planning",
                "multi_az is unknown after planning",
                "backup_retention_period is unknown after planning",
                "kms_key_id is unknown after planning",
            ],
        )

    def test_kms_key_normalizes_rotation_usage_and_spec_posture(self) -> None:
        resource = _terraform_resource(
            "aws_kms_key",
            {
                "id": "key/customer",
                "key_id": "customer",
                "arn": "arn:aws:kms:us-east-1:111122223333:key/customer",
                "key_usage": "ENCRYPT_DECRYPT",
                "key_spec": "SYMMETRIC_DEFAULT",
                "customer_master_key_spec": "SYMMETRIC_DEFAULT",
                "enable_key_rotation": True,
            },
        )

        normalized = normalize_kms_key(resource)
        facts = aws_facts(normalized)

        self.assertEqual(normalized.identifier, "customer")
        self.assertEqual(normalized.arn, "arn:aws:kms:us-east-1:111122223333:key/customer")
        self.assertEqual(facts.kms_key_usage, "ENCRYPT_DECRYPT")
        self.assertEqual(facts.kms_key_spec, "SYMMETRIC_DEFAULT")
        self.assertEqual(facts.kms_customer_master_key_spec, "SYMMETRIC_DEFAULT")
        self.assertEqual(facts.kms_enable_key_rotation_state, "enabled")
        self.assertTrue(facts.kms_enable_key_rotation)
        self.assertEqual(facts.kms_posture_uncertainties, [])

    def test_kms_key_missing_rotation_defaults_to_disabled(self) -> None:
        facts = aws_facts(normalize_kms_key(_terraform_resource("aws_kms_key", {"key_id": "customer"})))

        self.assertIsNone(facts.kms_key_usage)
        self.assertIsNone(facts.kms_key_spec)
        self.assertIsNone(facts.kms_customer_master_key_spec)
        self.assertEqual(facts.kms_enable_key_rotation_state, "disabled")
        self.assertFalse(facts.kms_enable_key_rotation)
        self.assertEqual(facts.kms_posture_uncertainties, [])

    def test_kms_key_preserves_unknown_rotation_and_spec_values(self) -> None:
        resource = _terraform_resource(
            "aws_kms_key",
            {"key_id": "customer"},
            unknown_values={
                "key_usage": True,
                "key_spec": True,
                "customer_master_key_spec": True,
                "enable_key_rotation": True,
            },
        )

        facts = aws_facts(normalize_kms_key(resource))

        self.assertIsNone(facts.kms_key_usage)
        self.assertIsNone(facts.kms_key_spec)
        self.assertIsNone(facts.kms_customer_master_key_spec)
        self.assertEqual(facts.kms_enable_key_rotation_state, "unknown")
        self.assertIsNone(facts.kms_enable_key_rotation)
        self.assertEqual(
            facts.kms_posture_uncertainties,
            [
                "key_usage is unknown after planning",
                "key_spec is unknown after planning",
                "customer_master_key_spec is unknown after planning",
                "enable_key_rotation is unknown after planning",
            ],
        )

    def test_secretsmanager_secret_normalizes_key_recovery_and_replication_posture(self) -> None:
        resource = _terraform_resource(
            "aws_secretsmanager_secret",
            {
                "id": "app",
                "name": "app",
                "arn": "arn:aws:secretsmanager:us-east-1:111122223333:secret:app",
                "kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/secrets",
                "recovery_window_in_days": 14,
                "replica": [
                    {
                        "region": "us-west-2",
                        "kms_key_id": "arn:aws:kms:us-west-2:111122223333:key/secrets-replica",
                        "status": "InSync",
                    }
                ],
            },
        )

        normalized = normalize_secretsmanager_secret(resource)
        facts = aws_facts(normalized)

        self.assertEqual(normalized.identifier, "app")
        self.assertEqual(normalized.arn, "arn:aws:secretsmanager:us-east-1:111122223333:secret:app")
        self.assertEqual(facts.name, "app")
        self.assertEqual(facts.secrets_manager_kms_key_id, "arn:aws:kms:us-east-1:111122223333:key/secrets")
        self.assertEqual(facts.secrets_manager_recovery_window_in_days, 14)
        self.assertEqual(
            facts.secrets_manager_replication,
            [
                {
                    "region": "us-west-2",
                    "kms_key_id": "arn:aws:kms:us-west-2:111122223333:key/secrets-replica",
                    "status": "InSync",
                }
            ],
        )
        self.assertEqual(facts.secrets_manager_posture_uncertainties, [])

    def test_secretsmanager_secret_missing_posture_fields_are_explicitly_absent(self) -> None:
        facts = aws_facts(normalize_secretsmanager_secret(_terraform_resource("aws_secretsmanager_secret", {})))

        self.assertIsNone(facts.secrets_manager_kms_key_id)
        self.assertIsNone(facts.secrets_manager_recovery_window_in_days)
        self.assertEqual(facts.secrets_manager_replication, [])
        self.assertEqual(facts.secrets_manager_posture_uncertainties, [])

    def test_secretsmanager_secret_preserves_unknown_posture_values(self) -> None:
        resource = _terraform_resource(
            "aws_secretsmanager_secret",
            {
                "name": "app",
                "replica": [{"region": "us-west-2"}],
            },
            unknown_values={
                "kms_key_id": True,
                "recovery_window_in_days": True,
                "replica": [{"kms_key_id": True}],
            },
        )

        facts = aws_facts(normalize_secretsmanager_secret(resource))

        self.assertIsNone(facts.secrets_manager_kms_key_id)
        self.assertIsNone(facts.secrets_manager_recovery_window_in_days)
        self.assertEqual(
            facts.secrets_manager_replication,
            [{"region": "us-west-2", "unknown_fields": ["kms_key_id"]}],
        )
        self.assertEqual(
            facts.secrets_manager_posture_uncertainties,
            [
                "kms_key_id is unknown after planning",
                "recovery_window_in_days is unknown after planning",
                "replica[0].kms_key_id is unknown after planning",
            ],
        )

    def test_secretsmanager_secret_rotation_normalizes_schedule_posture(self) -> None:
        resource = _terraform_resource(
            "aws_secretsmanager_secret_rotation",
            {
                "id": "app-rotation",
                "secret_id": "aws_secretsmanager_secret.app.id",
                "rotation_lambda_arn": "arn:aws:lambda:us-east-1:111122223333:function:rotate-secret",
                "rotation_rules": [
                    {
                        "automatically_after_days": 30,
                        "duration": "2h",
                        "schedule_expression": "rate(30 days)",
                    }
                ],
            },
        )

        normalized = normalize_secretsmanager_secret_rotation(resource)
        facts = aws_facts(normalized)

        self.assertEqual(normalized.identifier, "app-rotation")
        self.assertEqual(facts.secrets_manager_rotation_secret_id, "aws_secretsmanager_secret.app.id")
        self.assertEqual(
            facts.secrets_manager_rotation_lambda_arn,
            "arn:aws:lambda:us-east-1:111122223333:function:rotate-secret",
        )
        self.assertEqual(facts.secrets_manager_rotation_automatically_after_days, 30)
        self.assertEqual(facts.secrets_manager_rotation_duration, "2h")
        self.assertEqual(facts.secrets_manager_rotation_schedule_expression, "rate(30 days)")
        self.assertEqual(
            facts.secrets_manager_rotation_rules,
            {
                "automatically_after_days": 30,
                "duration": "2h",
                "schedule_expression": "rate(30 days)",
            },
        )
        self.assertEqual(facts.secrets_manager_posture_uncertainties, [])

    def test_secretsmanager_secret_rotation_preserves_unknown_schedule_fields(self) -> None:
        resource = _terraform_resource(
            "aws_secretsmanager_secret_rotation",
            {
                "secret_id": "aws_secretsmanager_secret.app.id",
                "rotation_rules": [{}],
            },
            unknown_values={
                "rotation_lambda_arn": True,
                "rotation_rules": [
                    {
                        "automatically_after_days": True,
                        "duration": True,
                        "schedule_expression": True,
                    }
                ],
            },
        )

        facts = aws_facts(normalize_secretsmanager_secret_rotation(resource))

        self.assertEqual(facts.secrets_manager_rotation_secret_id, "aws_secretsmanager_secret.app.id")
        self.assertIsNone(facts.secrets_manager_rotation_lambda_arn)
        self.assertIsNone(facts.secrets_manager_rotation_automatically_after_days)
        self.assertIsNone(facts.secrets_manager_rotation_duration)
        self.assertIsNone(facts.secrets_manager_rotation_schedule_expression)
        self.assertEqual(facts.secrets_manager_rotation_rules, {})
        self.assertEqual(
            facts.secrets_manager_posture_uncertainties,
            [
                "rotation_lambda_arn is unknown after planning",
                "rotation_rules.automatically_after_days is unknown after planning",
                "rotation_rules.duration is unknown after planning",
                "rotation_rules.schedule_expression is unknown after planning",
            ],
        )

    def test_secretsmanager_secret_rotation_preserves_unknown_rotation_rules_block(self) -> None:
        resource = _terraform_resource(
            "aws_secretsmanager_secret_rotation",
            {"secret_id": "aws_secretsmanager_secret.app.id"},
            unknown_values={"rotation_rules": True},
        )

        facts = aws_facts(normalize_secretsmanager_secret_rotation(resource))

        self.assertEqual(facts.secrets_manager_rotation_secret_id, "aws_secretsmanager_secret.app.id")
        self.assertEqual(facts.secrets_manager_rotation_rules, {})
        self.assertEqual(
            facts.secrets_manager_posture_uncertainties,
            ["rotation_rules is unknown after planning"],
        )

    def test_s3_bucket_versioning_normalizes_enabled_status(self) -> None:
        resource = _terraform_resource(
            "aws_s3_bucket_versioning",
            {
                "id": "logs",
                "bucket": "logs",
                "versioning_configuration": [{"status": "Enabled"}],
            },
        )

        normalized = normalize_s3_bucket_versioning(resource)
        facts = aws_facts(normalized)

        self.assertEqual(normalized.identifier, "logs")
        self.assertEqual(facts.bucket_name, "logs")
        self.assertEqual(facts.s3_versioning_status, "Enabled")
        self.assertTrue(facts.s3_versioning_enabled)
        self.assertEqual(facts.s3_versioning_configuration, {"status": "Enabled"})
        self.assertEqual(facts.s3_posture_uncertainties, [])

    def test_s3_bucket_versioning_normalizes_suspended_status(self) -> None:
        resource = _terraform_resource(
            "aws_s3_bucket_versioning",
            {
                "bucket": "logs",
                "versioning_configuration": [{"status": "Suspended"}],
            },
        )

        facts = aws_facts(normalize_s3_bucket_versioning(resource))

        self.assertEqual(facts.s3_versioning_status, "Suspended")
        self.assertFalse(facts.s3_versioning_enabled)

    def test_s3_bucket_versioning_preserves_unknown_status(self) -> None:
        resource = _terraform_resource(
            "aws_s3_bucket_versioning",
            {"bucket": "logs", "versioning_configuration": [{}]},
            unknown_values={"versioning_configuration": [{"status": True}]},
        )

        facts = aws_facts(normalize_s3_bucket_versioning(resource))

        self.assertIsNone(facts.s3_versioning_status)
        self.assertIsNone(facts.s3_versioning_enabled)
        self.assertEqual(facts.s3_versioning_configuration, {})
        self.assertEqual(
            facts.s3_posture_uncertainties,
            ["versioning_configuration.status is unknown after planning"],
        )

    def test_s3_bucket_encryption_normalizes_sse_s3(self) -> None:
        resource = _terraform_resource(
            "aws_s3_bucket_server_side_encryption_configuration",
            {
                "id": "logs",
                "bucket": "logs",
                "rule": [
                    {
                        "apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}],
                        "bucket_key_enabled": False,
                    }
                ],
            },
        )

        normalized = normalize_s3_bucket_server_side_encryption_configuration(resource)
        facts = aws_facts(normalized)

        self.assertEqual(normalized.identifier, "logs")
        self.assertEqual(facts.bucket_name, "logs")
        self.assertEqual(facts.s3_encryption_algorithm, "AES256")
        self.assertIsNone(facts.s3_kms_master_key_id)
        self.assertEqual(facts.s3_bucket_key_enabled_state, "disabled")
        self.assertFalse(facts.s3_bucket_key_enabled)
        self.assertEqual(facts.s3_posture_uncertainties, [])

    def test_s3_bucket_encryption_normalizes_kms_key(self) -> None:
        kms_key_id = "arn:aws:kms:us-east-1:111122223333:key/storage"
        resource = _terraform_resource(
            "aws_s3_bucket_server_side_encryption_configuration",
            {
                "bucket": "logs",
                "rule": [
                    {
                        "apply_server_side_encryption_by_default": [
                            {
                                "sse_algorithm": "aws:kms",
                                "kms_master_key_id": kms_key_id,
                            }
                        ],
                        "bucket_key_enabled": True,
                    }
                ],
            },
        )

        facts = aws_facts(normalize_s3_bucket_server_side_encryption_configuration(resource))

        self.assertEqual(facts.s3_encryption_algorithm, "aws:kms")
        self.assertEqual(facts.s3_kms_master_key_id, kms_key_id)
        self.assertEqual(facts.s3_bucket_key_enabled_state, "enabled")
        self.assertTrue(facts.s3_bucket_key_enabled)
        self.assertEqual(
            facts.s3_server_side_encryption_configuration,
            {
                "rule": [
                    {
                        "apply_server_side_encryption_by_default": [
                            {
                                "sse_algorithm": "aws:kms",
                                "kms_master_key_id": kms_key_id,
                            }
                        ],
                        "bucket_key_enabled": True,
                    }
                ]
            },
        )

    def test_s3_bucket_encryption_preserves_unknown_fields(self) -> None:
        resource = _terraform_resource(
            "aws_s3_bucket_server_side_encryption_configuration",
            {
                "bucket": "logs",
                "rule": [{"apply_server_side_encryption_by_default": [{}]}],
            },
            unknown_values={
                "rule": [
                    {
                        "apply_server_side_encryption_by_default": [{"sse_algorithm": True, "kms_master_key_id": True}],
                        "bucket_key_enabled": True,
                    }
                ]
            },
        )

        facts = aws_facts(normalize_s3_bucket_server_side_encryption_configuration(resource))

        self.assertIsNone(facts.s3_encryption_algorithm)
        self.assertIsNone(facts.s3_kms_master_key_id)
        self.assertIsNone(facts.s3_bucket_key_enabled_state)
        self.assertIsNone(facts.s3_bucket_key_enabled)
        self.assertEqual(
            facts.s3_posture_uncertainties,
            [
                "rule.apply_server_side_encryption_by_default.sse_algorithm is unknown after planning",
                "rule.apply_server_side_encryption_by_default.kms_master_key_id is unknown after planning",
                "rule.bucket_key_enabled is unknown after planning",
            ],
        )


if __name__ == "__main__":
    unittest.main()
