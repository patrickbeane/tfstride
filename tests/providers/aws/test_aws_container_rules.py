from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_IMAGE_PIN_RULE = "aws-workload-image-not-digest-pinned"
_MUTABLE_ECR_RULE = "aws-workload-ecr-mutable-tag"
_CONTAINER_RULE_IDS = (_IMAGE_PIN_RULE, _MUTABLE_ECR_RULE)
_ECR_URL = "111122223333.dkr.ecr.us-east-1.amazonaws.com/orders"


def _resource(
    address: str,
    resource_type: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _ecs_task_definition(
    image: str | None,
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {"family": "orders", "revision": 4}
    if image is not None:
        values["container_definitions"] = json.dumps([{"name": "orders", "image": image}])
    return _resource(
        "aws_ecs_task_definition.orders",
        "aws_ecs_task_definition",
        values,
        unknown_values=unknown_values,
    )


def _lambda_function(
    image: str | None,
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {"function_name": "orders", "package_type": "Image"}
    if image is not None:
        values["image_uri"] = image
    return _resource(
        "aws_lambda_function.orders",
        "aws_lambda_function",
        values,
        unknown_values=unknown_values,
    )


def _ecr_repository(
    *,
    repository_url: str = _ECR_URL,
    mutability: str | None = "MUTABLE",
    filters: list[dict[str, str]] | None = None,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": "orders",
        "name": "orders",
        "repository_url": repository_url,
    }
    if mutability is not None:
        values["image_tag_mutability"] = mutability
    if filters is not None:
        values["image_tag_mutability_exclusion_filter"] = filters
    return _resource(
        "aws_ecr_repository.orders",
        "aws_ecr_repository",
        values,
        unknown_values=unknown_values,
    )


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or _CONTAINER_RULE_IDS)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsContainerDeploymentRuleTests(unittest.TestCase):
    def test_container_integrity_rule_ids_are_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}

        self.assertTrue(set(_CONTAINER_RULE_IDS).issubset(registered))

    def test_unpinned_workload_image_is_reported_as_low_reproducibility_posture(self) -> None:
        findings = _evaluate(
            [_ecs_task_definition("111122223333.dkr.ecr.us-east-1.amazonaws.com/orders:stable")], _IMAGE_PIN_RULE
        )

        self.assertEqual([finding.rule_id for finding in findings], [_IMAGE_PIN_RULE])
        self.assertEqual(findings[0].severity.value, "low")
        self.assertEqual(findings[0].affected_resources, ["aws_ecs_task_definition.orders"])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["image_reference"],
            [
                "source=aws_ecs_task_definition",
                "path=container_definitions[0].image",
                "raw=111122223333.dkr.ecr.us-east-1.amazonaws.com/orders:stable",
                "registry_host=111122223333.dkr.ecr.us-east-1.amazonaws.com",
                "repository=orders",
                "tag=stable",
                "digest=unset",
                "digest_pinned=False",
            ],
        )
        self.assertIn("without a digest pin", findings[0].rationale)

    def test_digest_pinned_ecs_and_lambda_images_are_quiet(self) -> None:
        digest = "sha256:" + "b" * 64

        findings = _evaluate(
            [
                _ecs_task_definition(f"{_ECR_URL}@{digest}"),
                _lambda_function(f"{_ECR_URL}@{digest}"),
            ],
            *_CONTAINER_RULE_IDS,
        )

        self.assertEqual(findings, [])

    def test_mutable_ecr_tag_is_reported_only_for_exact_repository_match(self) -> None:
        findings = _evaluate(
            [
                _ecs_task_definition(f"{_ECR_URL}:stable"),
                _ecr_repository(),
            ],
            _MUTABLE_ECR_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_MUTABLE_ECR_RULE])
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertEqual(
            findings[0].affected_resources,
            ["aws_ecs_task_definition.orders", "aws_ecr_repository.orders"],
        )
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["ecr_repository"],
            [
                "address=aws_ecr_repository.orders",
                f"repository_url={_ECR_URL}",
                "image_tag_mutability=MUTABLE",
                "exclusion_filters=[]",
            ],
        )
        self.assertIn("exact repository policy permits this tag to be mutable", findings[0].rationale)

        self.assertEqual(
            _evaluate(
                [
                    _ecs_task_definition(f"{_ECR_URL}:stable"),
                    _ecr_repository(repository_url=f"{_ECR_URL}-other"),
                ],
                _MUTABLE_ECR_RULE,
            ),
            [],
        )

    def test_immutable_ecr_repository_is_quiet_for_mutable_tag_rule(self) -> None:
        findings = _evaluate(
            [_ecs_task_definition(f"{_ECR_URL}:stable"), _ecr_repository(mutability="IMMUTABLE")],
            _MUTABLE_ECR_RULE,
        )

        self.assertEqual(findings, [])

    def test_ecr_exclusion_filters_are_applied_deterministically(self) -> None:
        release_image = f"{_ECR_URL}:release-2026"
        development_image = f"{_ECR_URL}:development"
        repository = _ecr_repository(
            mutability="MUTABLE_WITH_EXCLUSION",
            filters=[{"filter": "release-*", "filter_type": "WILDCARD"}],
        )

        self.assertEqual(_evaluate([_ecs_task_definition(release_image), repository], _MUTABLE_ECR_RULE), [])
        findings = _evaluate([_ecs_task_definition(development_image), repository], _MUTABLE_ECR_RULE)
        self.assertEqual([finding.rule_id for finding in findings], [_MUTABLE_ECR_RULE])

    def test_unknown_or_unresolved_images_do_not_create_integrity_claims(self) -> None:
        unknown_repository = _ecr_repository(
            mutability="MUTABLE_WITH_EXCLUSION",
            unknown_values={"image_tag_mutability_exclusion_filter": True},
        )
        self.assertEqual(
            _evaluate(
                [_ecs_task_definition(f"{_ECR_URL}:stable"), unknown_repository],
                _MUTABLE_ECR_RULE,
            ),
            [],
        )

        findings = _evaluate(
            [
                _ecs_task_definition(None, unknown_values={"container_definitions": True}),
                _lambda_function(None, unknown_values={"image_uri": True}),
            ],
            *_CONTAINER_RULE_IDS,
        )

        self.assertEqual(findings, [])

    def test_mutable_ecr_tag_also_keeps_general_unpinned_posture_distinct(self) -> None:
        findings = _evaluate(
            [_ecs_task_definition(f"{_ECR_URL}:stable"), _ecr_repository()],
            *_CONTAINER_RULE_IDS,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [_IMAGE_PIN_RULE, _MUTABLE_ECR_RULE],
        )


if __name__ == "__main__":
    unittest.main()
