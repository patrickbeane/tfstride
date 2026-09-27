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
_TABLE_ARN = f"arn:aws:dynamodb:us-east-1:{_ACCOUNT_ID}:table/orders"
_INDEX_ARN = f"{_TABLE_ARN}/index/by-status"
_INDEX_PATTERN_ARN = f"{_TABLE_ARN}/index/*"


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, Any],
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
    )


def _table(
    name: str = "orders",
    *,
    arn: str = _TABLE_ARN,
    index_names: tuple[str, ...] = (),
    local_index_names: tuple[str, ...] = (),
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": name,
        "name": name,
        "arn": arn,
    }
    if index_names:
        values["global_secondary_index"] = [{"name": index_name} for index_name in index_names]
    if local_index_names:
        values["local_secondary_index"] = [{"name": index_name} for index_name in local_index_names]
    return _resource(
        "aws_dynamodb_table",
        name,
        values,
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
                "name": "dynamodb-access",
                "policy": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": statements,
                    }
                ),
            }
        ]
    return _resource("aws_iam_role", name, values)


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
        "network_mode": "awsvpc",
        "container_definitions": '[{"name":"orders","portMappings":[{"containerPort":8080,"protocol":"tcp"}]}]',
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
        {
            "name": "orders",
            "task_definition": task_definition,
        },
    )


class AwsEcsDynamoDbAccessPathTests(unittest.TestCase):
    def test_exact_task_role_actions_are_classified_and_projected(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            [
                                "dynamodb:PutItem",
                                "dynamodb:UpdateItem",
                                "dynamodb:BatchWriteItem",
                                "dynamodb:DeleteItem",
                                "dynamodb:DeleteTable",
                                "dynamodb:UpdateTable",
                                "dynamodb:UpdateTimeToLive",
                            ],
                            [_TABLE_ARN, _INDEX_PATTERN_ARN],
                        ),
                        _statement(
                            "Allow",
                            ["dynamodb:Query", "dynamodb:Scan"],
                            _INDEX_ARN,
                        ),
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

        task_facts = aws_facts(task_definition)
        service_facts = aws_facts(service)
        self.assertEqual(len(task_facts.ecs_dynamodb_access_paths), 1)
        self.assertEqual(len(service_facts.ecs_dynamodb_access_paths), 1)

        path = service_facts.ecs_dynamodb_access_paths[0]
        self.assertEqual(path["workload_address"], service.address)
        self.assertEqual(
            path["task_definition_address"],
            task_definition.address,
        )
        self.assertEqual(
            path["dynamodb_table_address"],
            "aws_dynamodb_table.orders",
        )
        self.assertEqual(path["dynamodb_table_name"], "orders")
        self.assertEqual(path["dynamodb_table_arn"], _TABLE_ARN)
        self.assertEqual(path["role_kind"], "ecs_task_role")
        self.assertEqual(path["credential_context"], "workload_runtime")
        self.assertEqual(path["role_address"], "aws_iam_role.orders_task")
        self.assertEqual(path["role_arn"], _TASK_ROLE_ARN)
        self.assertTrue(path["role_policy_complete"])
        self.assertEqual(path["modeled_access_state"], "allowed")
        self.assertEqual(path["access_state"], "allowed")
        self.assertEqual(
            path["access_classes"],
            [
                "return_value_read",
                "entity_write",
                "entity_delete",
                "destructive_administration",
                "configuration_administration",
            ],
        )
        self.assertEqual(
            path["matched_actions"],
            [
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
                "dynamodb:BatchWriteItem",
                "dynamodb:DeleteItem",
                "dynamodb:DeleteTable",
                "dynamodb:UpdateTable",
                "dynamodb:UpdateTimeToLive",
            ],
        )
        self.assertEqual(path["policy_resources"], [_TABLE_ARN])
        self.assertEqual(path["resource_scopes"], ["exact_table"])
        self.assertEqual(path["internet_facing_load_balancers"], [])

        relationships = service_facts.ecs_dynamodb_index_relationships
        self.assertEqual(
            [
                (
                    relationship["dynamodb_index_resource_arn"],
                    relationship["resource_scope"],
                )
                for relationship in relationships
            ],
            [
                (_INDEX_PATTERN_ARN, "index_pattern"),
                (_INDEX_ARN, "exact_index"),
            ],
        )
        for relationship in relationships:
            self.assertEqual(
                relationship["dynamodb_table_address"],
                "aws_dynamodb_table.orders",
            )
            self.assertEqual(
                relationship["dynamodb_table_arn"],
                _TABLE_ARN,
            )
            self.assertEqual(
                relationship["evaluation_basis"],
                "modeled_identity_policy_resource_relationship",
            )
            self.assertNotIn("access_state", relationship)
            self.assertNotIn("access_classes", relationship)

    def test_table_read_actions_share_the_generic_access_path_facade(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            [
                                "dynamodb:GetItem",
                                "dynamodb:ConditionCheckItem",
                                "dynamodb:BatchGetItem",
                                "dynamodb:Query",
                                "dynamodb:Scan",
                                "dynamodb:PartiQLSelect",
                            ],
                            _TABLE_ARN,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert task_definition is not None
        assert service is not None

        task_paths = aws_facts(task_definition).ecs_dynamodb_access_paths
        service_paths = aws_facts(service).ecs_dynamodb_access_paths
        self.assertEqual(len(task_paths), 1)
        self.assertEqual(len(service_paths), 1)
        path = service_paths[0]
        self.assertEqual(path["workload_address"], service.address)
        self.assertEqual(path["task_definition_address"], task_definition.address)
        self.assertEqual(path["dynamodb_target_kind"], "table")
        self.assertEqual(path["dynamodb_target_scope"], "exact_table")
        self.assertEqual(path["dynamodb_target_name"], "orders")
        self.assertEqual(path["dynamodb_target_arn"], _TABLE_ARN)
        self.assertIsNone(path["dynamodb_index_name"])
        self.assertIsNone(path["dynamodb_index_arn"])
        self.assertEqual(path["access_classes"], ["read"])
        self.assertEqual(
            path["matched_actions"],
            [
                "dynamodb:GetItem",
                "dynamodb:ConditionCheckItem",
                "dynamodb:BatchGetItem",
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:PartiQLSelect",
            ],
        )
        self.assertEqual(path["resource_scopes"], ["exact_table"])
        self.assertEqual(path["access_state"], "allowed")
        self.assertEqual(
            aws_facts(service).ecs_dynamodb_index_relationships,
            [],
        )

    def test_index_read_actions_expand_only_to_modeled_indexes(self) -> None:
        by_created_arn = f"{_TABLE_ARN}/index/by-created"
        inventory = AwsNormalizer().normalize(
            [
                _table(index_names=("by-status", "by-created")),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:Query",
                            _INDEX_ARN,
                        ),
                        _statement(
                            "Allow",
                            [
                                "dynamodb:Scan",
                                "dynamodb:PartiQLSelect",
                            ],
                            _INDEX_PATTERN_ARN,
                        ),
                        _statement(
                            "Allow",
                            [
                                "dynamodb:GetItem",
                                "dynamodb:BatchGetItem",
                                "dynamodb:PutItem",
                            ],
                            _INDEX_PATTERN_ARN,
                        ),
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        facts = aws_facts(task_definition)
        self.assertEqual(
            [path["dynamodb_index_arn"] for path in facts.ecs_dynamodb_access_paths],
            [by_created_arn, _INDEX_ARN],
        )
        by_created, by_status = facts.ecs_dynamodb_access_paths
        self.assertEqual(by_created["dynamodb_target_kind"], "index")
        self.assertEqual(by_created["dynamodb_target_scope"], "exact_index")
        self.assertEqual(by_created["dynamodb_index_name"], "by-created")
        self.assertEqual(by_created["access_classes"], ["read"])
        self.assertEqual(
            by_created["matched_actions"],
            ["dynamodb:Scan", "dynamodb:PartiQLSelect"],
        )
        self.assertEqual(by_created["resource_scopes"], ["index_pattern"])

        self.assertEqual(by_status["dynamodb_index_name"], "by-status")
        self.assertEqual(
            by_status["matched_actions"],
            [
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:PartiQLSelect",
            ],
        )
        self.assertEqual(
            by_status["resource_scopes"],
            ["exact_index", "index_pattern"],
        )
        for path in facts.ecs_dynamodb_access_paths:
            self.assertNotIn("dynamodb:GetItem", path["matched_actions"])
            self.assertNotIn("dynamodb:BatchGetItem", path["matched_actions"])
            self.assertNotIn("dynamodb:PutItem", path["matched_actions"])
        self.assertEqual(len(facts.ecs_dynamodb_index_relationships), 3)

    def test_local_secondary_index_read_resolves_exactly(self) -> None:
        local_index_arn = f"{_TABLE_ARN}/index/by-created"
        inventory = AwsNormalizer().normalize(
            [
                _table(local_index_names=("by-created",)),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:Query",
                            local_index_arn,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        path = aws_facts(task_definition).ecs_dynamodb_access_paths[0]
        self.assertEqual(path["dynamodb_target_kind"], "index")
        self.assertEqual(path["dynamodb_index_name"], "by-created")
        self.assertEqual(path["dynamodb_index_arn"], local_index_arn)
        self.assertEqual(path["access_classes"], ["read"])
        self.assertEqual(path["matched_actions"], ["dynamodb:Query"])

    def test_partial_index_inventory_preserves_expanded_paths_and_uncertainty(
        self,
    ) -> None:
        table = TerraformResource(
            address="aws_dynamodb_table.orders",
            mode="managed",
            resource_type="aws_dynamodb_table",
            name="orders",
            provider_name="registry.terraform.io/hashicorp/aws",
            values={
                "id": "orders",
                "name": "orders",
                "arn": _TABLE_ARN,
                "global_secondary_index": [
                    {"name": "by-status"},
                    {},
                ],
            },
            unknown_values={
                "global_secondary_index": [
                    {},
                    {"name": True},
                ]
            },
        )
        inventory = AwsNormalizer().normalize(
            [
                table,
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:Scan",
                            _INDEX_PATTERN_ARN,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        normalized_table = inventory.get_by_address("aws_dynamodb_table.orders")
        assert task_definition is not None
        assert normalized_table is not None

        self.assertEqual(
            aws_facts(normalized_table).dynamodb_index_inventory_state,
            "partial",
        )
        facts = aws_facts(task_definition)
        self.assertEqual(len(facts.ecs_dynamodb_access_paths), 1)
        path = facts.ecs_dynamodb_access_paths[0]
        self.assertEqual(path["dynamodb_index_name"], "by-status")
        self.assertEqual(path["dynamodb_index_inventory_state"], "partial")
        self.assertTrue(
            any(
                "may target additional indexes because the modeled index "
                "inventory on aws_dynamodb_table.orders is partial" in uncertainty
                for uncertainty in facts.ecs_dynamodb_access_path_uncertainties
            )
        )

    def test_index_read_denies_conditions_and_incomplete_policy_stay_conservative(
        self,
    ) -> None:
        condition = {
            "ForAllValues:StringEquals": {
                "dynamodb:LeadingKeys": ["tenant-123"],
            }
        }
        policy_arn = "arn:aws:iam::aws:policy/ExternalDynamoDbRead"
        inventory = AwsNormalizer().normalize(
            [
                _table(index_names=("by-status",)),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            ["dynamodb:Query", "dynamodb:Scan"],
                            _INDEX_ARN,
                        ),
                        _statement(
                            "Deny",
                            "dynamodb:Query",
                            _INDEX_ARN,
                        ),
                        _statement(
                            "Allow",
                            "dynamodb:PartiQLSelect",
                            _INDEX_ARN,
                            condition=condition,
                        ),
                    ],
                ),
                _role_policy_attachment(_TASK_ROLE_ARN, policy_arn),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        facts = aws_facts(task_definition)
        self.assertEqual(len(facts.ecs_dynamodb_access_paths), 1)
        path = facts.ecs_dynamodb_access_paths[0]
        self.assertEqual(path["dynamodb_index_arn"], _INDEX_ARN)
        self.assertEqual(path["modeled_access_state"], "allowed")
        self.assertEqual(path["access_state"], "unknown")
        self.assertFalse(path["role_policy_complete"])
        self.assertEqual(path["access_classes"], ["read"])
        self.assertEqual(path["matched_actions"], ["dynamodb:Scan"])
        self.assertEqual(path["denied_access_classes"], ["read"])
        self.assertEqual(path["denied_actions"], ["dynamodb:Query"])
        self.assertEqual(path["unknown_access_classes"], ["read"])
        self.assertEqual(
            path["unknown_actions"],
            ["dynamodb:PartiQLSelect"],
        )
        self.assertTrue(path["explicit_deny"])
        self.assertTrue(path["conditional_evaluation_required"])
        self.assertTrue(any(policy_arn in uncertainty for uncertainty in facts.ecs_dynamodb_access_path_uncertainties))
        self.assertTrue(
            any(
                "conditional identity-policy evidence" in uncertainty and "DynamoDB index by-status" in uncertainty
                for uncertainty in facts.ecs_dynamodb_access_path_uncertainties
            )
        )

    def test_mutation_return_values_are_distinct_from_direct_reads(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            [
                                "dynamodb:PutItem",
                                "dynamodb:UpdateItem",
                                "dynamodb:DeleteItem",
                                "dynamodb:PartiQLUpdate",
                                "dynamodb:PartiQLDelete",
                            ],
                            _TABLE_ARN,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        path = aws_facts(task_definition).ecs_dynamodb_access_paths[0]
        self.assertEqual(
            path["access_classes"],
            ["return_value_read", "entity_write", "entity_delete"],
        )
        self.assertNotIn("read", path["access_classes"])

    def test_bulk_export_is_not_flattened_into_ordinary_read(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:ExportTableToPointInTime",
                            _TABLE_ARN,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        path = aws_facts(task_definition).ecs_dynamodb_access_paths[0]
        self.assertEqual(path["access_classes"], ["bulk_export"])
        self.assertEqual(
            path["matched_actions"],
            ["dynamodb:ExportTableToPointInTime"],
        )

    def test_deferred_stream_and_metadata_actions_do_not_create_read_paths(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _table(index_names=("by-status",)),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            [
                                "dynamodb:GetRecords",
                                "dynamodb:DescribeTable",
                            ],
                            [_TABLE_ARN, _INDEX_ARN],
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        facts = aws_facts(task_definition)
        self.assertEqual(facts.ecs_dynamodb_access_paths, [])
        self.assertEqual(len(facts.ecs_dynamodb_index_relationships), 1)
        self.assertEqual(
            facts.ecs_dynamodb_index_relationships[0]["policy_actions"],
            ["dynamodb:GetRecords", "dynamodb:DescribeTable"],
        )

    def test_transaction_api_name_is_not_treated_as_an_iam_action(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:TransactWriteItems",
                            _TABLE_ARN,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        facts = aws_facts(task_definition)
        self.assertEqual(facts.ecs_dynamodb_access_paths, [])
        self.assertEqual(facts.ecs_dynamodb_index_relationships, [])
        self.assertEqual(facts.ecs_dynamodb_access_path_uncertainties, [])

    def test_index_only_grant_never_establishes_item_mutation(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            [
                                "dynamodb:PutItem",
                                "dynamodb:DeleteItem",
                                "dynamodb:DeleteTable",
                                "dynamodb:Query",
                            ],
                            _INDEX_ARN,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        facts = aws_facts(task_definition)
        self.assertEqual(facts.ecs_dynamodb_access_paths, [])
        self.assertEqual(len(facts.ecs_dynamodb_index_relationships), 1)
        relationship = facts.ecs_dynamodb_index_relationships[0]
        self.assertEqual(
            relationship["dynamodb_index_resource_arn"],
            _INDEX_ARN,
        )
        self.assertEqual(relationship["resource_scope"], "exact_index")
        self.assertEqual(
            relationship["policy_actions"],
            [
                "dynamodb:PutItem",
                "dynamodb:DeleteItem",
                "dynamodb:DeleteTable",
                "dynamodb:Query",
            ],
        )

    def test_execution_role_actions_do_not_create_runtime_paths(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _table(index_names=("by-status",)),
                _role("orders_task", _TASK_ROLE_ARN, []),
                _role(
                    "orders_execution",
                    _EXECUTION_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            ["dynamodb:GetItem", "dynamodb:PutItem"],
                            _TABLE_ARN,
                        ),
                        _statement(
                            "Allow",
                            "dynamodb:Query",
                            _INDEX_ARN,
                        ),
                    ],
                ),
                _task_definition(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        facts = aws_facts(task_definition)
        self.assertEqual(facts.ecs_dynamodb_access_paths, [])
        self.assertEqual(facts.ecs_dynamodb_index_relationships, [])
        self.assertEqual(facts.ecs_dynamodb_access_path_uncertainties, [])

    def test_exact_table_does_not_expand_to_similarly_named_table(self) -> None:
        archive_arn = f"arn:aws:dynamodb:us-east-1:{_ACCOUNT_ID}:table/orders-archive"
        inventory = AwsNormalizer().normalize(
            [
                _table(),
                _table("archive", arn=archive_arn),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:PutItem",
                            _TABLE_ARN,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        self.assertEqual(
            [path["dynamodb_table_address"] for path in aws_facts(task_definition).ecs_dynamodb_access_paths],
            ["aws_dynamodb_table.orders"],
        )

    def test_explicit_denies_and_conditions_remain_conservative(self) -> None:
        condition = {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["tenant-123"]}}
        inventory = AwsNormalizer().normalize(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            [
                                "dynamodb:PutItem",
                                "dynamodb:DeleteItem",
                                "dynamodb:DeleteTable",
                                "dynamodb:UpdateTable",
                            ],
                            _TABLE_ARN,
                        ),
                        _statement(
                            "Deny",
                            [
                                "dynamodb:PutItem",
                                "dynamodb:DeleteTable",
                            ],
                            "*",
                        ),
                        _statement(
                            "Allow",
                            "dynamodb:UpdateItem",
                            _TABLE_ARN,
                            condition=condition,
                        ),
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        facts = aws_facts(task_definition)
        path = facts.ecs_dynamodb_access_paths[0]
        self.assertEqual(path["access_state"], "allowed")
        self.assertEqual(
            path["access_classes"],
            [
                "return_value_read",
                "entity_delete",
                "configuration_administration",
            ],
        )
        self.assertEqual(
            path["denied_access_classes"],
            [
                "return_value_read",
                "entity_write",
                "destructive_administration",
            ],
        )
        self.assertEqual(
            path["unknown_access_classes"],
            ["return_value_read", "entity_write"],
        )
        self.assertEqual(
            path["matched_actions"],
            ["dynamodb:DeleteItem", "dynamodb:UpdateTable"],
        )
        self.assertEqual(
            path["denied_actions"],
            ["dynamodb:PutItem", "dynamodb:DeleteTable"],
        )
        self.assertEqual(
            path["unknown_actions"],
            ["dynamodb:UpdateItem"],
        )
        self.assertEqual(path["deny_policy_resources"], ["*"])
        self.assertTrue(path["explicit_deny"])
        self.assertTrue(path["conditional_evaluation_required"])
        conditional_record = next(record for record in path["policy_statements"] if record["conditional"])
        self.assertEqual(
            conditional_record["conditions"],
            [
                {
                    "operator": "ForAllValues:StringEquals",
                    "key": "dynamodb:LeadingKeys",
                    "values": ["tenant-123"],
                }
            ],
        )
        self.assertTrue(
            any(
                "conditional identity-policy evidence" in uncertainty
                for uncertainty in facts.ecs_dynamodb_access_path_uncertainties
            )
        )

    def test_conditional_only_grant_remains_unknown(self) -> None:
        condition = {
            "ForAllValues:StringEquals": {
                "dynamodb:LeadingKeys": ["tenant-123"],
            }
        }
        inventory = AwsNormalizer().normalize(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:UpdateItem",
                            _TABLE_ARN,
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
        path = facts.ecs_dynamodb_access_paths[0]
        self.assertEqual(path["modeled_access_state"], "unknown")
        self.assertEqual(path["access_state"], "unknown")
        self.assertEqual(path["access_classes"], [])
        self.assertEqual(
            path["unknown_access_classes"],
            ["return_value_read", "entity_write"],
        )
        self.assertEqual(path["matched_actions"], [])
        self.assertEqual(path["unknown_actions"], ["dynamodb:UpdateItem"])
        self.assertTrue(path["conditional_evaluation_required"])

    def test_unresolved_attached_policy_keeps_access_unknown(self) -> None:
        policy_arn = "arn:aws:iam::aws:policy/ExternalDynamoDbAccess"
        inventory = AwsNormalizer().normalize(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:PutItem",
                            _TABLE_ARN,
                        )
                    ],
                ),
                _role_policy_attachment(_TASK_ROLE_ARN, policy_arn),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        facts = aws_facts(task_definition)
        path = facts.ecs_dynamodb_access_paths[0]
        self.assertEqual(path["modeled_access_state"], "allowed")
        self.assertEqual(path["access_state"], "unknown")
        self.assertFalse(path["role_policy_complete"])
        self.assertEqual(
            facts.ecs_dynamodb_access_path_uncertainties,
            [f"aws_ecs_task_definition.orders: aws_iam_role.orders_task has unresolved attached policy {policy_arn}"],
        )

    def test_unresolved_role_and_non_exact_tables_do_not_invent_paths(
        self,
    ) -> None:
        missing_role_inventory = AwsNormalizer().normalize([_table(), _task_definition(execution_role_arn=None)])
        task_definition = missing_role_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        self.assertEqual(
            aws_facts(task_definition).ecs_dynamodb_access_paths,
            [],
        )
        self.assertEqual(
            aws_facts(task_definition).ecs_dynamodb_access_path_uncertainties,
            [f"aws_ecs_task_definition.orders: ECS task role {_TASK_ROLE_ARN} is not modeled in the plan"],
        )

        external_arn = "arn:aws:dynamodb:us-west-2:999900001111:table/external"
        unresolved_inventory = AwsNormalizer().normalize(
            [
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:PutItem",
                            "arn:aws:dynamodb:us-east-1:*:table/orders-*",
                        ),
                        _statement(
                            "Allow",
                            "dynamodb:DeleteItem",
                            "*",
                        ),
                        _statement(
                            "Allow",
                            "dynamodb:UpdateTable",
                            external_arn,
                        ),
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        unresolved_task = unresolved_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert unresolved_task is not None

        facts = aws_facts(unresolved_task)
        self.assertEqual(facts.ecs_dynamodb_access_paths, [])
        self.assertEqual(facts.ecs_dynamodb_index_relationships, [])
        self.assertEqual(len(facts.ecs_dynamodb_access_path_uncertainties), 3)
        self.assertTrue(
            any(
                "does not identify an exact table" in uncertainty
                for uncertainty in facts.ecs_dynamodb_access_path_uncertainties
            )
        )
        self.assertTrue(
            any(
                external_arn in uncertainty and "not modeled in the plan" in uncertainty
                for uncertainty in facts.ecs_dynamodb_access_path_uncertainties
            )
        )


if __name__ == "__main__":
    unittest.main()
