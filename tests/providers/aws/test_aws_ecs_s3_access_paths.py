from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

_ACCOUNT_ID = "111122223333"
_TASK_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-task"
_EXECUTION_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-execution"
_BUCKET_ARN = "arn:aws:s3:::orders-data"
_ARCHIVE_BUCKET_ARN = "arn:aws:s3:::orders-archive"


def _resource(resource_type: str, name: str, values: dict[str, Any]) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
    )


def _bucket(name: str = "orders", *, arn: str = _BUCKET_ARN) -> TerraformResource:
    bucket_name = arn.removeprefix("arn:aws:s3:::")
    return _resource(
        "aws_s3_bucket",
        name,
        {"id": bucket_name, "bucket": bucket_name, "arn": arn},
    )


def _role(
    name: str,
    arn: str,
    statements: list[dict[str, Any]] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {"name": name, "arn": arn}
    if statements is not None:
        values["inline_policy"] = [
            {
                "name": "storage-access",
                "policy": json.dumps({"Version": "2012-10-17", "Statement": statements}),
            }
        ]
    return _resource("aws_iam_role", name, values)


def _role_policy_attachment(role_reference: str, policy_arn: str) -> TerraformResource:
    return _resource(
        "aws_iam_role_policy_attachment",
        "external",
        {"role": role_reference, "policy_arn": policy_arn},
    )


def _statement(
    effect: str,
    actions: str | list[str],
    resources: str | list[str],
    *,
    condition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "Effect": effect,
        "Action": actions,
        "Resource": resources,
    }
    if condition is not None:
        statement["Condition"] = condition
    return statement


def _task_definition(
    *,
    task_role_arn: str | None = _TASK_ROLE_ARN,
    execution_role_arn: str | None = _EXECUTION_ROLE_ARN,
) -> TerraformResource:
    values: dict[str, Any] = {
        "family": "orders",
        "revision": 1,
        "container_definitions": "[]",
    }
    if task_role_arn is not None:
        values["task_role_arn"] = task_role_arn
    if execution_role_arn is not None:
        values["execution_role_arn"] = execution_role_arn
    return _resource("aws_ecs_task_definition", "orders", values)


def _service(task_definition: str = "orders:1") -> TerraformResource:
    return _resource(
        "aws_ecs_service",
        "orders",
        {"name": "orders", "task_definition": task_definition},
    )


def _normalize(resources: list[TerraformResource]):
    return AwsNormalizer().normalize(resources)


class AwsEcsS3AccessPathTests(unittest.TestCase):
    def test_exact_task_role_grants_are_classified_and_projected_onto_service(self) -> None:
        inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "s3:ListBucket", _BUCKET_ARN),
                        _statement(
                            "Allow",
                            ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                            f"{_BUCKET_ARN}/*",
                        ),
                        _statement("Allow", "s3:PutBucketPolicy", _BUCKET_ARN),
                    ],
                ),
                _task_definition(),
                _service(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        task_path = aws_facts(task_definition).ecs_s3_access_paths[0]
        service_path = aws_facts(service).ecs_s3_access_paths[0]
        self.assertEqual(task_path["workload_address"], task_definition.address)
        self.assertEqual(service_path["workload_address"], service.address)
        self.assertEqual(service_path["task_definition_address"], task_definition.address)
        self.assertEqual(service_path["bucket_address"], "aws_s3_bucket.orders")
        self.assertEqual(service_path["bucket_arn"], _BUCKET_ARN)
        self.assertEqual(service_path["role_kind"], "ecs_task_role")
        self.assertEqual(service_path["credential_context"], "workload_runtime")
        self.assertEqual(service_path["role_address"], "aws_iam_role.orders_task")
        self.assertEqual(service_path["role_arn"], _TASK_ROLE_ARN)
        self.assertEqual(service_path["access_state"], "allowed")
        self.assertEqual(
            service_path["access_classes"],
            ["read", "write", "delete", "administrative"],
        )
        self.assertEqual(
            service_path["matched_actions"],
            [
                "s3:ListBucket",
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:PutBucketPolicy",
            ],
        )
        self.assertEqual(service_path["resource_scopes"], ["all_bucket_objects", "exact_bucket"])
        self.assertFalse(service_path["explicit_deny"])
        self.assertFalse(service_path["conditional_evaluation_required"])
        self.assertEqual(service_path["internet_facing_load_balancers"], [])

    def test_execution_role_grant_does_not_create_runtime_data_path(self) -> None:
        inventory = _normalize(
            [
                _bucket(),
                _role("orders_task", _TASK_ROLE_ARN, []),
                _role(
                    "orders_execution",
                    _EXECUTION_ROLE_ARN,
                    [_statement("Allow", "s3:GetObject", f"{_BUCKET_ARN}/*")],
                ),
                _task_definition(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        self.assertEqual(aws_facts(task_definition).ecs_s3_access_paths, [])
        self.assertEqual(aws_facts(task_definition).ecs_s3_access_path_uncertainties, [])

    def test_exact_object_prefix_resolves_only_its_bucket(self) -> None:
        inventory = _normalize(
            [
                _bucket(),
                _bucket("archive", arn=_ARCHIVE_BUCKET_ARN),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "s3:GetObject", f"{_BUCKET_ARN}/customer/*")],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        paths = aws_facts(task_definition).ecs_s3_access_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["bucket_address"], "aws_s3_bucket.orders")
        self.assertEqual(paths[0]["policy_resources"], [f"{_BUCKET_ARN}/customer/*"])
        self.assertEqual(paths[0]["resource_scopes"], ["object_prefix"])

    def test_explicit_denies_remove_comparable_write_and_delete_actions(self) -> None:
        inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                            f"{_BUCKET_ARN}/*",
                        ),
                        _statement(
                            "Deny",
                            ["s3:PutObject", "s3:DeleteObject"],
                            f"{_BUCKET_ARN}/*",
                        ),
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        path = aws_facts(task_definition).ecs_s3_access_paths[0]
        self.assertEqual(path["access_state"], "allowed")
        self.assertEqual(path["access_classes"], ["read"])
        self.assertEqual(path["matched_actions"], ["s3:GetObject"])
        self.assertEqual(path["denied_access_classes"], ["write", "delete"])
        self.assertEqual(path["denied_actions"], ["s3:PutObject", "s3:DeleteObject"])
        self.assertTrue(path["explicit_deny"])
        self.assertEqual(path["deny_policy_resources"], [f"{_BUCKET_ARN}/*"])

    def test_conditional_allow_is_unknown_and_preserves_condition(self) -> None:
        condition = {"StringLike": {"s3:prefix": ["customer/*"]}}
        inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "s3:GetObject",
                            f"{_BUCKET_ARN}/customer/*",
                            condition=condition,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        facts = aws_facts(task_definition)
        path = facts.ecs_s3_access_paths[0]
        self.assertEqual(path["modeled_access_state"], "unknown")
        self.assertEqual(path["access_state"], "unknown")
        self.assertEqual(path["access_classes"], [])
        self.assertEqual(path["unknown_access_classes"], ["read"])
        self.assertTrue(path["conditional_evaluation_required"])
        self.assertEqual(
            path["policy_statements"][0]["conditions"],
            [{"operator": "StringLike", "key": "s3:prefix", "values": ["customer/*"]}],
        )
        self.assertIn("conditional identity-policy evidence", facts.ecs_s3_access_path_uncertainties[0])

    def test_conditional_deny_prevents_deterministic_allowed_claim(self) -> None:
        inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "s3:GetObject", f"{_BUCKET_ARN}/*"),
                        _statement(
                            "Deny",
                            "s3:GetObject",
                            f"{_BUCKET_ARN}/*",
                            condition={"StringNotEquals": {"aws:SourceVpc": "vpc-123"}},
                        ),
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        path = aws_facts(task_definition).ecs_s3_access_paths[0]
        self.assertEqual(path["modeled_access_state"], "unknown")
        self.assertEqual(path["access_state"], "unknown")
        self.assertEqual(path["matched_actions"], [])
        self.assertEqual(path["unknown_actions"], ["s3:GetObject"])
        self.assertEqual(path["unknown_access_classes"], ["read"])
        self.assertTrue(path["explicit_deny"])
        self.assertTrue(path["conditional_evaluation_required"])

    def test_unresolved_attached_policy_keeps_modeled_access_uncertain(self) -> None:
        policy_arn = "arn:aws:iam::aws:policy/ExternalS3Access"
        inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "s3:GetObject", f"{_BUCKET_ARN}/*")],
                ),
                _role_policy_attachment(_TASK_ROLE_ARN, policy_arn),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        facts = aws_facts(task_definition)
        path = facts.ecs_s3_access_paths[0]
        self.assertEqual(path["modeled_access_state"], "allowed")
        self.assertEqual(path["access_state"], "unknown")
        self.assertFalse(path["role_policy_complete"])
        self.assertEqual(
            facts.ecs_s3_access_path_uncertainties,
            [f"aws_ecs_task_definition.orders: aws_iam_role.orders_task has unresolved attached policy {policy_arn}"],
        )

    def test_unresolved_role_and_non_exact_resources_do_not_invent_paths(self) -> None:
        missing_role_inventory = _normalize([_bucket(), _task_definition(execution_role_arn=None)])
        task_definition = missing_role_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        self.assertEqual(aws_facts(task_definition).ecs_s3_access_paths, [])
        self.assertEqual(
            aws_facts(task_definition).ecs_s3_access_path_uncertainties,
            [f"aws_ecs_task_definition.orders: ECS task role {_TASK_ROLE_ARN} is not modeled in the plan"],
        )

        wildcard_inventory = _normalize(
            [
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "s3:GetObject", "*"),
                        _statement("Allow", "s3:GetObject", "arn:aws:s3:::orders-*/*"),
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        wildcard_task = wildcard_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert wildcard_task is not None
        wildcard_facts = aws_facts(wildcard_task)
        self.assertEqual(wildcard_facts.ecs_s3_access_paths, [])
        self.assertEqual(len(wildcard_facts.ecs_s3_access_path_uncertainties), 2)
        self.assertTrue(
            all(
                "does not identify an exact bucket" in uncertainty
                for uncertainty in wildcard_facts.ecs_s3_access_path_uncertainties
            )
        )


if __name__ == "__main__":
    unittest.main()
