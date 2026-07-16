from __future__ import annotations

import unittest
from collections import Counter
from typing import Any

from tests.providers.aws.test_aws_ecr_write_paths import (
    _EXECUTION_ROLE_ARN,
    _LAMBDA_ROLE_ARN,
    _REPOSITORY_ARN,
    _REPOSITORY_URL,
    _TASK_ROLE_ARN,
    _allow,
    _deny,
    _lambda_function,
    _role,
    _role_policy_attachment,
    _task_definition,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_RULE_ID = "aws-workload-can-modify-image-repository"
_IMAGE_PIN_RULE = "aws-workload-image-not-digest-pinned"
_MUTABLE_TAG_RULE = "aws-workload-ecr-mutable-tag"
_DIGEST = "sha256:" + "a" * 64


def _repository(
    *,
    mutability: object = "MUTABLE",
    filters: list[dict[str, str]] | None = None,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": "orders",
        "name": "orders",
        "arn": _REPOSITORY_ARN,
        "repository_url": _REPOSITORY_URL,
        "image_tag_mutability": mutability,
    }
    if filters is not None:
        values["image_tag_mutability_exclusion_filter"] = filters
    return TerraformResource(
        address="aws_ecr_repository.orders",
        mode="managed",
        resource_type="aws_ecr_repository",
        name="orders",
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids or {_RULE_ID})),
    )


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsEcrSelfModificationRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

    def test_ecs_runtime_task_role_with_put_image_access_is_detected(self) -> None:
        findings = _evaluate(
            [
                _repository(),
                _role("task", _TASK_ROLE_ARN, [_allow("ecr:PutImage", _REPOSITORY_ARN)]),
                _task_definition(execution_role_arn=None),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(
            finding.affected_resources,
            [
                "aws_ecs_task_definition.orders",
                "aws_ecr_repository.orders",
                "aws_iam_role.task",
            ],
        )
        self.assertIn("self-modification and persistence path", finding.rationale)
        evidence = _evidence(finding)
        self.assertIn("role_kind=ecs_task_role", evidence["runtime_identity"])
        self.assertIn("credential_context=workload_runtime", evidence["runtime_identity"])
        self.assertIn("runtime_credentials_available=True", evidence["runtime_identity"])
        self.assertIn("role_policy_complete=True", evidence["runtime_identity"])
        self.assertIn("can_put_image=True", evidence["ecr_write_path"])
        self.assertIn("resource_scope=exact_repository", evidence["ecr_write_path"])
        self.assertIn("image_tag_mutability=MUTABLE", evidence["ecr_repository"])

    def test_lambda_runtime_execution_role_with_put_image_access_is_detected(self) -> None:
        findings = _evaluate(
            [
                _repository(),
                _role("lambda", _LAMBDA_ROLE_ARN, [_allow("ecr:PutImage", _REPOSITORY_ARN)]),
                _lambda_function(),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence(findings[0])
        self.assertIn("role_kind=lambda_execution_role", evidence["runtime_identity"])
        self.assertIn("role_address=aws_iam_role.lambda", evidence["runtime_identity"])

    def test_ecs_image_pull_execution_role_does_not_become_runtime_self_modification(self) -> None:
        findings = _evaluate(
            [
                _repository(),
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [_allow("ecr:PutImage", _REPOSITORY_ARN)],
                ),
                _task_definition(task_role_arn=None),
            ]
        )

        self.assertEqual(findings, [])

    def test_digest_pinned_image_is_quiet(self) -> None:
        findings = _evaluate(
            [
                _repository(),
                _role("task", _TASK_ROLE_ARN, [_allow("ecr:PutImage", _REPOSITORY_ARN)]),
                _task_definition(image=f"{_REPOSITORY_URL}@{_DIGEST}", execution_role_arn=None),
            ]
        )

        self.assertEqual(findings, [])

    def test_immutable_repository_and_immutable_exclusion_are_quiet(self) -> None:
        role = _role("task", _TASK_ROLE_ARN, [_allow("ecr:PutImage", _REPOSITORY_ARN)])
        immutable = _evaluate(
            [
                _repository(mutability="IMMUTABLE"),
                role,
                _task_definition(execution_role_arn=None),
            ]
        )
        excluded_tag = _evaluate(
            [
                _repository(
                    mutability="MUTABLE_WITH_EXCLUSION",
                    filters=[{"filter": "release-*", "filter_type": "WILDCARD"}],
                ),
                _role("task", _TASK_ROLE_ARN, [_allow("ecr:PutImage", _REPOSITORY_ARN)]),
                _task_definition(image=f"{_REPOSITORY_URL}:release-2026", execution_role_arn=None),
            ]
        )

        self.assertEqual(immutable, [])
        self.assertEqual(excluded_tag, [])

    def test_mutable_exclusion_policy_only_reports_tags_that_remain_mutable(self) -> None:
        findings = _evaluate(
            [
                _repository(
                    mutability="MUTABLE_WITH_EXCLUSION",
                    filters=[{"filter": "release-*", "filter_type": "WILDCARD"}],
                ),
                _role("task", _TASK_ROLE_ARN, [_allow("ecr:PutImage", _REPOSITORY_ARN)]),
                _task_definition(image=f"{_REPOSITORY_URL}:development", execution_role_arn=None),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])

    def test_explicit_or_conditional_deny_prevents_deterministic_finding(self) -> None:
        for statements in (
            [
                _allow("ecr:PutImage", _REPOSITORY_ARN),
                _deny("ecr:PutImage", _REPOSITORY_ARN),
            ],
            [
                _allow("ecr:PutImage", _REPOSITORY_ARN),
                _deny(
                    "ecr:PutImage",
                    _REPOSITORY_ARN,
                    condition={"StringNotEquals": {"aws:PrincipalAccount": "111122223333"}},
                ),
            ],
        ):
            with self.subTest(statements=statements):
                findings = _evaluate(
                    [
                        _repository(),
                        _role("task", _TASK_ROLE_ARN, statements),
                        _task_definition(execution_role_arn=None),
                    ]
                )
                self.assertEqual(findings, [])

    def test_layer_upload_without_put_image_is_quiet(self) -> None:
        findings = _evaluate(
            [
                _repository(),
                _role(
                    "task",
                    _TASK_ROLE_ARN,
                    [
                        _allow(
                            [
                                "ecr:InitiateLayerUpload",
                                "ecr:UploadLayerPart",
                                "ecr:CompleteLayerUpload",
                            ],
                            _REPOSITORY_ARN,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )

        self.assertEqual(findings, [])

    def test_unknown_mutability_or_incomplete_role_policy_stays_quiet(self) -> None:
        unknown_mutability = _evaluate(
            [
                _repository(
                    mutability=None,
                    unknown_values={"image_tag_mutability": True},
                ),
                _role("task", _TASK_ROLE_ARN, [_allow("ecr:PutImage", _REPOSITORY_ARN)]),
                _task_definition(execution_role_arn=None),
            ]
        )
        incomplete_role = _evaluate(
            [
                _repository(),
                _role("task", _TASK_ROLE_ARN, [_allow("ecr:PutImage", _REPOSITORY_ARN)]),
                _role_policy_attachment(
                    _TASK_ROLE_ARN,
                    "arn:aws:iam::aws:policy/ExternalEcrPolicy",
                ),
                _task_definition(execution_role_arn=None),
            ]
        )

        self.assertEqual(unknown_mutability, [])
        self.assertEqual(incomplete_role, [])

    def test_self_modification_finding_remains_distinct_from_existing_integrity_findings(self) -> None:
        findings = _evaluate(
            [
                _repository(),
                _role("task", _TASK_ROLE_ARN, [_allow("ecr:PutImage", _REPOSITORY_ARN)]),
                _task_definition(execution_role_arn=None),
            ],
            _IMAGE_PIN_RULE,
            _MUTABLE_TAG_RULE,
            _RULE_ID,
        )

        self.assertEqual(
            Counter(finding.rule_id for finding in findings),
            Counter({_IMAGE_PIN_RULE: 1, _MUTABLE_TAG_RULE: 1, _RULE_ID: 1}),
        )


if __name__ == "__main__":
    unittest.main()
