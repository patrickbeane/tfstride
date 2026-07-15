from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_MUTABLE_TAG_RULE = "aws-ecr-image-tag-mutability-enabled"
_ENCRYPTION_RULE = "aws-ecr-customer-managed-encryption-missing"
_SCANNING_RULE = "aws-ecr-repository-scanning-disabled"
_ECR_RULE_IDS = (_MUTABLE_TAG_RULE, _ENCRYPTION_RULE, _SCANNING_RULE)
_KMS_KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/ecr"
_MISSING = object()


def _repository(
    *,
    name: str = "images",
    encryption_configuration: object = _MISSING,
    image_tag_mutability: object = _MISSING,
    image_tag_mutability_exclusion_filter: object = _MISSING,
    scan_on_push: object = _MISSING,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": name,
        "name": name,
        "arn": f"arn:aws:ecr:us-east-1:111122223333:repository/{name}",
    }
    if encryption_configuration is not _MISSING:
        values["encryption_configuration"] = encryption_configuration
    if image_tag_mutability is not _MISSING:
        values["image_tag_mutability"] = image_tag_mutability
    if image_tag_mutability_exclusion_filter is not _MISSING:
        values["image_tag_mutability_exclusion_filter"] = image_tag_mutability_exclusion_filter
    if scan_on_push is not _MISSING:
        values["image_scanning_configuration"] = [{"scan_on_push": scan_on_push}]
    return TerraformResource(
        address=f"aws_ecr_repository.{name}",
        mode="managed",
        resource_type="aws_ecr_repository",
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _registry_scanning_configuration() -> TerraformResource:
    return TerraformResource(
        address="aws_ecr_registry_scanning_configuration.account",
        mode="managed",
        resource_type="aws_ecr_registry_scanning_configuration",
        name="account",
        provider_name="registry.terraform.io/hashicorp/aws",
        values={
            "scan_type": "ENHANCED",
            "rule": [
                {
                    "scan_frequency": "CONTINUOUS_SCAN",
                    "repository_filter": [{"filter": "*", "filter_type": "WILDCARD"}],
                }
            ],
        },
    )


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or _ECR_RULE_IDS)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsEcrRuleTests(unittest.TestCase):
    def test_ecr_rules_are_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}
        self.assertTrue(set(_ECR_RULE_IDS).issubset(registered))

    def test_mutable_tags_are_detected_for_all_mutable_policy(self) -> None:
        findings = _evaluate(
            [_repository(image_tag_mutability="MUTABLE")],
            _MUTABLE_TAG_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_MUTABLE_TAG_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["tag_mutability"],
            ["image_tag_mutability=MUTABLE", "mutable_tag_scope=all repository tags"],
        )
        self.assertIn("mutable ECR image tags", findings[0].rationale)

    def test_mutable_tags_with_exclusions_are_detected_with_scope_evidence(self) -> None:
        findings = _evaluate(
            [
                _repository(
                    image_tag_mutability="MUTABLE_WITH_EXCLUSION",
                    image_tag_mutability_exclusion_filter=[
                        {"filter": "release-*", "filter_type": "WILDCARD"},
                    ],
                )
            ],
            _MUTABLE_TAG_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_MUTABLE_TAG_RULE])
        self.assertEqual(
            _evidence_by_key(findings[0])["tag_mutability"],
            [
                "image_tag_mutability=MUTABLE_WITH_EXCLUSION",
                "mutable_tag_exclusion_filters=[filter=release-*, filter_type=WILDCARD]",
                "mutable_tag_scope=tags outside the exclusion filters",
            ],
        )

    def test_immutable_tags_are_quiet(self) -> None:
        findings = _evaluate(
            [
                _repository(
                    image_tag_mutability="IMMUTABLE",
                    image_tag_mutability_exclusion_filter=[],
                )
            ],
            _MUTABLE_TAG_RULE,
        )

        self.assertEqual(findings, [])

    def test_provider_managed_encryption_is_reported_as_key_ownership_posture(self) -> None:
        findings = _evaluate(
            [
                _repository(
                    encryption_configuration=[{"encryption_type": "AES256"}],
                )
            ],
            _ENCRYPTION_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_ENCRYPTION_RULE])
        self.assertIn("does not claim that the repository is unencrypted", findings[0].rationale)
        self.assertEqual(
            _evidence_by_key(findings[0])["encryption_ownership"],
            [
                "encryption_ownership_state=service_managed",
                "encryption_type=AES256",
                "kms_key=unset",
                "finding_scope=customer-managed key ownership and control posture",
            ],
        )

    def test_customer_managed_encryption_is_quiet(self) -> None:
        findings = _evaluate(
            [
                _repository(
                    encryption_configuration=[
                        {"encryption_type": "KMS", "kms_key": _KMS_KEY_ARN},
                    ]
                )
            ],
            _ENCRYPTION_RULE,
        )

        self.assertEqual(findings, [])

    def test_unknown_encryption_does_not_claim_missing_customer_key(self) -> None:
        findings = _evaluate(
            [
                _repository(
                    unknown_values={"encryption_configuration": True},
                )
            ],
            _ENCRYPTION_RULE,
        )

        self.assertEqual(findings, [])

    def test_explicitly_disabled_repository_scanning_is_detected(self) -> None:
        findings = _evaluate(
            [_repository(scan_on_push=False)],
            _SCANNING_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_SCANNING_RULE])
        self.assertEqual(
            _evidence_by_key(findings[0])["repository_scanning"],
            [
                "repository_scan_on_push_state=disabled",
                "scanning_scope=repository scan-on-push configuration",
                "registry_level_scanning_absence=not_inferred",
            ],
        )
        self.assertIn("registry-level scanning is absent", findings[0].rationale)

    def test_enabled_or_unknown_repository_scanning_is_quiet(self) -> None:
        self.assertEqual(_evaluate([_repository(scan_on_push=True)], _SCANNING_RULE), [])
        self.assertEqual(
            _evaluate(
                [_repository(unknown_values={"image_scanning_configuration": True})],
                _SCANNING_RULE,
            ),
            [],
        )
        self.assertEqual(_evaluate([_repository()], _SCANNING_RULE), [])

    def test_registry_scanning_configuration_does_not_create_repository_absence_finding(self) -> None:
        findings = _evaluate([_registry_scanning_configuration()], *_ECR_RULE_IDS)

        self.assertEqual(findings, [])

    def test_all_explicitly_unsafe_repository_postures_are_reported(self) -> None:
        findings = _evaluate(
            [
                _repository(
                    encryption_configuration=[{"encryption_type": "KMS"}],
                    image_tag_mutability="MUTABLE",
                    scan_on_push=False,
                )
            ],
            *_ECR_RULE_IDS,
        )

        self.assertEqual({finding.rule_id for finding in findings}, set(_ECR_RULE_IDS))


if __name__ == "__main__":
    unittest.main()
