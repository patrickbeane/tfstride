from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.aws.data_normalizers import (
    normalize_s3_bucket_server_side_encryption_configuration,
    normalize_s3_bucket_versioning,
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
