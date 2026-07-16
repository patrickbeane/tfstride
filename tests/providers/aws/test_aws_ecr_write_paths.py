from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

_ACCOUNT_ID = "111122223333"
_REGION = "us-east-1"
_REPOSITORY_NAME = "orders"
_REPOSITORY_URL = f"{_ACCOUNT_ID}.dkr.ecr.{_REGION}.amazonaws.com/{_REPOSITORY_NAME}"
_REPOSITORY_ARN = f"arn:aws:ecr:{_REGION}:{_ACCOUNT_ID}:repository/{_REPOSITORY_NAME}"
_TASK_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/task"
_EXECUTION_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/execution"
_LAMBDA_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/lambda"


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, Any],
    *,
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


def _repository(
    *,
    name: str = _REPOSITORY_NAME,
    repository_url: str = _REPOSITORY_URL,
    arn: str | None = _REPOSITORY_ARN,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": name,
        "name": name,
        "repository_url": repository_url,
        "image_tag_mutability": "MUTABLE",
    }
    if arn is not None:
        values["arn"] = arn
    return _resource("aws_ecr_repository", name.replace("/", "_"), values)


def _role(
    name: str,
    arn: str,
    statements: list[dict[str, Any]] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {"name": name, "arn": arn}
    if statements is not None:
        values["inline_policy"] = [
            {
                "name": "ecr-access",
                "policy": json.dumps({"Version": "2012-10-17", "Statement": statements}),
            }
        ]
    return _resource("aws_iam_role", name, values)


def _role_policy(
    role_reference: str,
    statements: list[dict[str, Any]],
    *,
    name: str = "ecr_write",
) -> TerraformResource:
    return _resource(
        "aws_iam_role_policy",
        name,
        {
            "name": name,
            "role": role_reference,
            "policy": json.dumps({"Version": "2012-10-17", "Statement": statements}),
        },
    )


def _role_policy_attachment(
    role_reference: str,
    policy_arn: str,
) -> TerraformResource:
    return _resource(
        "aws_iam_role_policy_attachment",
        "external",
        {
            "role": role_reference,
            "policy_arn": policy_arn,
        },
    )


def _allow(actions: str | list[str], resource: str, *, condition: dict[str, Any] | None = None) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "Effect": "Allow",
        "Action": actions,
        "Resource": resource,
    }
    if condition is not None:
        statement["Condition"] = condition
    return statement


def _deny(actions: str | list[str], resource: str, *, condition: dict[str, Any] | None = None) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "Effect": "Deny",
        "Action": actions,
        "Resource": resource,
    }
    if condition is not None:
        statement["Condition"] = condition
    return statement


def _task_definition(
    *,
    image: str = f"{_REPOSITORY_URL}:stable",
    task_role_arn: str | None = _TASK_ROLE_ARN,
    execution_role_arn: str | None = _EXECUTION_ROLE_ARN,
) -> TerraformResource:
    values: dict[str, Any] = {
        "family": "orders",
        "revision": 1,
        "container_definitions": json.dumps([{"name": "orders", "image": image}]),
    }
    if task_role_arn is not None:
        values["task_role_arn"] = task_role_arn
    if execution_role_arn is not None:
        values["execution_role_arn"] = execution_role_arn
    return _resource("aws_ecs_task_definition", "orders", values)


def _lambda_function(
    *,
    image: str = f"{_REPOSITORY_URL}:stable",
    role_arn: str = _LAMBDA_ROLE_ARN,
) -> TerraformResource:
    return _resource(
        "aws_lambda_function",
        "orders",
        {
            "function_name": "orders",
            "package_type": "Image",
            "image_uri": image,
            "role": role_arn,
        },
    )


def _normalize(resources: list[TerraformResource]):
    return AwsNormalizer().normalize(resources)


class AwsEcrWritePathTests(unittest.TestCase):
    def test_ecs_task_and_execution_role_write_paths_keep_credential_context_distinct(self) -> None:
        inventory = _normalize(
            [
                _repository(),
                _role(
                    "task",
                    _TASK_ROLE_ARN,
                    [
                        _allow(
                            [
                                "ecr:BatchCheckLayerAvailability",
                                "ecr:InitiateLayerUpload",
                                "ecr:UploadLayerPart",
                                "ecr:CompleteLayerUpload",
                                "ecr:PutImage",
                            ],
                            _REPOSITORY_ARN,
                        )
                    ],
                ),
                _role("execution", _EXECUTION_ROLE_ARN, [_allow("ecr:*", "*")]),
                _task_definition(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        paths = aws_facts(task_definition).ecr_write_paths
        self.assertEqual(len(paths), 2)
        paths_by_role_kind = {path["role_kind"]: path for path in paths}

        task_path = paths_by_role_kind["ecs_task_role"]
        self.assertEqual(task_path["credential_context"], "workload_runtime")
        self.assertTrue(task_path["runtime_credentials_available"])
        self.assertEqual(task_path["ecr_repository_address"], "aws_ecr_repository.orders")
        self.assertEqual(task_path["ecr_repository_url"], _REPOSITORY_URL)
        self.assertEqual(task_path["ecr_repository_arn"], _REPOSITORY_ARN)
        self.assertEqual(task_path["role_address"], "aws_iam_role.task")
        self.assertEqual(task_path["resource_scope"], "exact_repository")
        self.assertTrue(task_path["can_put_image"])
        self.assertTrue(task_path["can_upload_layers"])
        self.assertTrue(task_path["complete_layer_upload"])
        self.assertEqual(
            task_path["matched_actions"],
            [
                "ecr:BatchCheckLayerAvailability",
                "ecr:CompleteLayerUpload",
                "ecr:InitiateLayerUpload",
                "ecr:PutImage",
                "ecr:UploadLayerPart",
            ],
        )

        execution_path = paths_by_role_kind["ecs_execution_role"]
        self.assertEqual(execution_path["credential_context"], "ecs_agent_control_plane")
        self.assertFalse(execution_path["runtime_credentials_available"])
        self.assertEqual(execution_path["role_address"], "aws_iam_role.execution")
        self.assertEqual(execution_path["policy_action_patterns"], ["ecr:*"])
        self.assertEqual(execution_path["policy_resources"], ["*"])
        self.assertEqual(execution_path["resource_scope"], "all_resources")
        self.assertEqual(aws_facts(task_definition).ecr_write_path_uncertainties, [])

    def test_lambda_execution_role_uses_merged_role_policy_and_runtime_credentials(self) -> None:
        inventory = _normalize(
            [
                _repository(),
                _role("lambda", _LAMBDA_ROLE_ARN),
                _role_policy(
                    _LAMBDA_ROLE_ARN,
                    [_allow("ecr:PutImage", _REPOSITORY_ARN)],
                ),
                _lambda_function(),
            ]
        )
        function = inventory.get_by_address("aws_lambda_function.orders")
        assert function is not None

        self.assertEqual(
            aws_facts(function).ecr_write_paths,
            [
                {
                    "workload_address": "aws_lambda_function.orders",
                    "workload_type": "aws_lambda_function",
                    "image_reference": f"{_REPOSITORY_URL}:stable",
                    "image_reference_path": "image_uri",
                    "image_tag": "stable",
                    "image_digest": None,
                    "image_digest_pinned": False,
                    "ecr_repository_address": "aws_ecr_repository.orders",
                    "ecr_repository_url": _REPOSITORY_URL,
                    "ecr_repository_arn": _REPOSITORY_ARN,
                    "role_kind": "lambda_execution_role",
                    "credential_context": "workload_runtime",
                    "runtime_credentials_available": True,
                    "role_address": "aws_iam_role.lambda",
                    "role_arn": _LAMBDA_ROLE_ARN,
                    "role_policy_complete": True,
                    "grant_basis": "modeled_identity_policy",
                    "can_put_image": True,
                    "can_upload_layers": False,
                    "complete_layer_upload": False,
                    "matched_actions": ["ecr:PutImage"],
                    "policy_action_patterns": ["ecr:PutImage"],
                    "policy_resources": [_REPOSITORY_ARN],
                    "resource_scope": "exact_repository",
                }
            ],
        )
        self.assertEqual(aws_facts(function).ecr_write_path_uncertainties, [])

    def test_repository_scoped_layer_upload_is_preserved_without_overstating_manifest_write(self) -> None:
        inventory = _normalize(
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
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        paths = aws_facts(task_definition).ecr_write_paths
        self.assertEqual(len(paths), 1)
        self.assertFalse(paths[0]["can_put_image"])
        self.assertTrue(paths[0]["can_upload_layers"])
        self.assertTrue(paths[0]["complete_layer_upload"])
        self.assertEqual(
            paths[0]["matched_actions"],
            [
                "ecr:CompleteLayerUpload",
                "ecr:InitiateLayerUpload",
                "ecr:UploadLayerPart",
            ],
        )

    def test_read_only_or_differently_scoped_policy_does_not_create_write_path(self) -> None:
        other_arn = f"arn:aws:ecr:{_REGION}:{_ACCOUNT_ID}:repository/orders-archive"
        inventory = _normalize(
            [
                _repository(),
                _role(
                    "task",
                    _TASK_ROLE_ARN,
                    [
                        _allow("ecr:BatchGetImage", _REPOSITORY_ARN),
                        _allow("ecr:PutImage", other_arn),
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        self.assertEqual(aws_facts(task_definition).ecr_write_paths, [])
        self.assertEqual(aws_facts(task_definition).ecr_write_path_uncertainties, [])

    def test_conditional_allow_and_deny_do_not_become_deterministic_write_paths(self) -> None:
        for statements, expected_uncertainty in (
            (
                [
                    _allow(
                        "ecr:PutImage",
                        _REPOSITORY_ARN,
                        condition={"StringEquals": {"aws:PrincipalAccount": _ACCOUNT_ID}},
                    )
                ],
                "conditional identity-policy allow was not treated as deterministic for actions: ecr:PutImage",
            ),
            (
                [
                    _allow("ecr:PutImage", _REPOSITORY_ARN),
                    _deny(
                        "ecr:PutImage",
                        _REPOSITORY_ARN,
                        condition={"StringNotEquals": {"aws:PrincipalAccount": _ACCOUNT_ID}},
                    ),
                ],
                "conditional identity-policy deny prevents deterministic access for actions: ecr:PutImage",
            ),
        ):
            with self.subTest(expected_uncertainty=expected_uncertainty):
                inventory = _normalize(
                    [
                        _repository(),
                        _role("task", _TASK_ROLE_ARN, statements),
                        _task_definition(execution_role_arn=None),
                    ]
                )
                task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
                assert task_definition is not None
                facts = aws_facts(task_definition)

                self.assertEqual(facts.ecr_write_paths, [])
                self.assertEqual(len(facts.ecr_write_path_uncertainties), 1)
                self.assertIn(expected_uncertainty, facts.ecr_write_path_uncertainties[0])

    def test_explicit_deny_overrides_modeled_allow(self) -> None:
        inventory = _normalize(
            [
                _repository(),
                _role(
                    "task",
                    _TASK_ROLE_ARN,
                    [
                        _allow("ecr:PutImage", _REPOSITORY_ARN),
                        _deny("ecr:PutImage", _REPOSITORY_ARN),
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        self.assertEqual(aws_facts(task_definition).ecr_write_paths, [])
        self.assertEqual(aws_facts(task_definition).ecr_write_path_uncertainties, [])

    def test_unresolved_repository_and_role_relationships_remain_explicit(self) -> None:
        missing_repository_inventory = _normalize(
            [
                _role("task", _TASK_ROLE_ARN, [_allow("ecr:PutImage", _REPOSITORY_ARN)]),
                _task_definition(execution_role_arn=None),
            ]
        )
        missing_repository_task = missing_repository_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert missing_repository_task is not None
        self.assertEqual(aws_facts(missing_repository_task).ecr_write_paths, [])
        self.assertEqual(
            aws_facts(missing_repository_task).ecr_write_path_uncertainties,
            [
                "aws_ecs_task_definition.orders: image container_definitions[0].image targets "
                f"ECR repository {_REPOSITORY_URL}, which is not modeled in the plan"
            ],
        )

        missing_role_inventory = _normalize([_repository(), _task_definition(execution_role_arn=None)])
        missing_role_task = missing_role_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert missing_role_task is not None
        self.assertEqual(aws_facts(missing_role_task).ecr_write_paths, [])
        self.assertEqual(
            aws_facts(missing_role_task).ecr_write_path_uncertainties,
            [f"aws_ecs_task_definition.orders: ecs_task_role {_TASK_ROLE_ARN} is not modeled in the plan"],
        )

    def test_unresolved_attached_policy_is_preserved_as_role_policy_uncertainty(self) -> None:
        external_policy_arn = "arn:aws:iam::aws:policy/ExternalEcrPolicy"
        inventory = _normalize(
            [
                _repository(),
                _role("task", _TASK_ROLE_ARN, [_allow("ecr:PutImage", _REPOSITORY_ARN)]),
                _role_policy_attachment(_TASK_ROLE_ARN, external_policy_arn),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        facts = aws_facts(task_definition)
        self.assertEqual(len(facts.ecr_write_paths), 1)
        self.assertFalse(facts.ecr_write_paths[0]["role_policy_complete"])
        self.assertEqual(
            facts.ecr_write_path_uncertainties,
            ["aws_ecs_task_definition.orders: aws_iam_role.task has unresolved attached policy " + external_policy_arn],
        )

    def test_repository_without_resolved_arn_cannot_create_policy_scope_match(self) -> None:
        inventory = _normalize(
            [
                _repository(arn=None),
                _role("task", _TASK_ROLE_ARN, [_allow("ecr:PutImage", _REPOSITORY_ARN)]),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        self.assertEqual(aws_facts(task_definition).ecr_write_paths, [])
        self.assertEqual(
            aws_facts(task_definition).ecr_write_path_uncertainties,
            [
                "aws_ecs_task_definition.orders: ECR repository aws_ecr_repository.orders "
                "has no resolved ARN for IAM scope matching"
            ],
        )


if __name__ == "__main__":
    unittest.main()
