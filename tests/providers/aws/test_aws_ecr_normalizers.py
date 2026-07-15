from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.aws.ecr_normalizers import (
    normalize_ecr_registry_scanning_configuration,
    normalize_ecr_repository,
)
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES, AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts


def _repository(
    values: dict[str, Any],
    *,
    name: str = "images",
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"aws_ecr_repository.{name}",
        mode="managed",
        resource_type="aws_ecr_repository",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _registry_scanning_configuration(
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="aws_ecr_registry_scanning_configuration.account",
        mode="managed",
        resource_type="aws_ecr_registry_scanning_configuration",
        name="account",
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


class AwsEcrNormalizerTests(unittest.TestCase):
    def test_repository_normalizes_customer_managed_encryption_tag_mutability_and_scanning(self) -> None:
        normalized = normalize_ecr_repository(
            _repository(
                {
                    "id": "images",
                    "name": "images",
                    "arn": "arn:aws:ecr:us-east-1:111122223333:repository/images",
                    "encryption_configuration": [
                        {
                            "encryption_type": "KMS",
                            "kms_key": "arn:aws:kms:us-east-1:111122223333:key/customer-key",
                        }
                    ],
                    "image_tag_mutability": "IMMUTABLE_WITH_EXCLUSION",
                    "image_tag_mutability_exclusion_filter": [{"filter": "latest*", "filter_type": "WILDCARD"}],
                    "image_scanning_configuration": [{"scan_on_push": True}],
                }
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.DATA)
        self.assertEqual(normalized.identifier, "images")
        self.assertEqual(normalized.arn, "arn:aws:ecr:us-east-1:111122223333:repository/images")
        self.assertEqual(facts.resource_name, "images")
        self.assertEqual(facts.ecr_encryption_type, "KMS")
        self.assertEqual(facts.ecr_kms_key, "arn:aws:kms:us-east-1:111122223333:key/customer-key")
        self.assertEqual(facts.ecr_encryption_ownership_state, "customer_managed")
        self.assertEqual(facts.ecr_image_tag_mutability, "IMMUTABLE_WITH_EXCLUSION")
        self.assertEqual(
            facts.ecr_image_tag_mutability_exclusion_filters,
            [{"filter": "latest*", "filter_type": "WILDCARD"}],
        )
        self.assertEqual(facts.ecr_repository_scan_on_push_state, "enabled")
        self.assertTrue(facts.ecr_repository_scan_on_push)
        self.assertEqual(facts.ecr_posture_uncertainties, [])

    def test_repository_preserves_omitted_configuration_as_not_configured(self) -> None:
        facts = aws_facts(normalize_ecr_repository(_repository({"name": "defaults"}, name="defaults")))

        self.assertIsNone(facts.ecr_encryption_type)
        self.assertIsNone(facts.ecr_kms_key)
        self.assertEqual(facts.ecr_encryption_ownership_state, "not_configured")
        self.assertIsNone(facts.ecr_image_tag_mutability)
        self.assertEqual(facts.ecr_image_tag_mutability_exclusion_filters, [])
        self.assertEqual(facts.ecr_repository_scan_on_push_state, "not_configured")
        self.assertIsNone(facts.ecr_repository_scan_on_push)
        self.assertEqual(facts.ecr_posture_uncertainties, [])

    def test_repository_preserves_unresolved_values_as_unknown_posture(self) -> None:
        facts = aws_facts(
            normalize_ecr_repository(
                _repository(
                    {"name": "unresolved"},
                    name="unresolved",
                    unknown_values={
                        "encryption_configuration": True,
                        "image_tag_mutability": True,
                        "image_tag_mutability_exclusion_filter": True,
                        "image_scanning_configuration": True,
                    },
                )
            )
        )

        self.assertEqual(facts.ecr_encryption_ownership_state, "unknown")
        self.assertIsNone(facts.ecr_image_tag_mutability)
        self.assertEqual(facts.ecr_image_tag_mutability_exclusion_filters, [])
        self.assertEqual(facts.ecr_repository_scan_on_push_state, "unknown")
        self.assertIn("encryption_configuration is unknown after planning", facts.ecr_posture_uncertainties)
        self.assertIn("image_tag_mutability is unknown after planning", facts.ecr_posture_uncertainties)
        self.assertIn(
            "image_tag_mutability_exclusion_filter is unknown after planning",
            facts.ecr_posture_uncertainties,
        )
        self.assertIn("image_scanning_configuration is unknown after planning", facts.ecr_posture_uncertainties)

    def test_registry_scanning_configuration_normalizes_coverage_rules(self) -> None:
        normalized = normalize_ecr_registry_scanning_configuration(
            _registry_scanning_configuration(
                {
                    "id": "registry-scanning",
                    "scan_type": "ENHANCED",
                    "rule": [
                        {
                            "scan_frequency": "CONTINUOUS_SCAN",
                            "repository_filter": [{"filter": "*", "filter_type": "WILDCARD"}],
                        },
                        {
                            "scan_frequency": "SCAN_ON_PUSH",
                            "repository_filter": [{"filter": "service-*", "filter_type": "WILDCARD"}],
                        },
                    ],
                }
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.DATA)
        self.assertEqual(facts.ecr_registry_scan_type, "ENHANCED")
        self.assertEqual(facts.ecr_registry_scanning_coverage_state, "all_repositories")
        self.assertEqual(
            facts.ecr_registry_scanning_rules,
            [
                {
                    "scan_frequency": "CONTINUOUS_SCAN",
                    "repository_filters": [{"filter": "*", "filter_type": "WILDCARD"}],
                },
                {
                    "scan_frequency": "SCAN_ON_PUSH",
                    "repository_filters": [{"filter": "service-*", "filter_type": "WILDCARD"}],
                },
            ],
        )
        self.assertEqual(facts.ecr_posture_uncertainties, [])

    def test_registry_scanning_configuration_preserves_unresolved_rules(self) -> None:
        facts = aws_facts(
            normalize_ecr_registry_scanning_configuration(
                _registry_scanning_configuration(
                    {},
                    unknown_values={"scan_type": True, "rule": True},
                )
            )
        )

        self.assertIsNone(facts.ecr_registry_scan_type)
        self.assertEqual(facts.ecr_registry_scanning_coverage_state, "unknown")
        self.assertEqual(facts.ecr_registry_scanning_rules, [])
        self.assertEqual(
            facts.ecr_posture_uncertainties,
            ["rule is unknown after planning", "scan_type is unknown after planning"],
        )

    def test_ecr_resources_are_supported(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _repository({"name": "images"}),
                _registry_scanning_configuration({"scan_type": "BASIC", "rule": []}),
            ]
        )

        self.assertIn("aws_ecr_repository", SUPPORTED_AWS_TYPES)
        self.assertIn("aws_ecr_registry_scanning_configuration", SUPPORTED_AWS_TYPES)
        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual(
            [resource.address for resource in inventory.resources],
            ["aws_ecr_repository.images", "aws_ecr_registry_scanning_configuration.account"],
        )
        self.assertEqual(inventory.metadata["supported_resource_types"], sorted(SUPPORTED_AWS_TYPES))


if __name__ == "__main__":
    unittest.main()
