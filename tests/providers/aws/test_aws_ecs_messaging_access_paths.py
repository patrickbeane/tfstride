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
_TOPIC_ARN = f"arn:aws:sns:us-east-1:{_ACCOUNT_ID}:orders-events"
_QUEUE_ARN = f"arn:aws:sqs:us-east-1:{_ACCOUNT_ID}:orders"


def _resource(resource_type: str, name: str, values: dict[str, Any]) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
    )


def _topic(name: str = "orders", *, arn: str = _TOPIC_ARN) -> TerraformResource:
    return _resource(
        "aws_sns_topic",
        name,
        {"name": arn.rsplit(":", 1)[-1], "arn": arn},
    )


def _queue(name: str = "orders", *, arn: str = _QUEUE_ARN) -> TerraformResource:
    queue_name = arn.rsplit(":", 1)[-1]
    return _resource(
        "aws_sqs_queue",
        name,
        {
            "name": queue_name,
            "arn": arn,
            "id": f"https://sqs.us-east-1.amazonaws.com/{_ACCOUNT_ID}/{queue_name}",
        },
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
                "name": "messaging-access",
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


class AwsEcsMessagingAccessPathTests(unittest.TestCase):
    def test_exact_task_role_grants_are_classified_and_projected_onto_service(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _topic(),
                _queue(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            ["sns:Publish", "sns:Subscribe", "sns:AddPermission"],
                            _TOPIC_ARN,
                        ),
                        _statement(
                            "Allow",
                            [
                                "sqs:SendMessage",
                                "sqs:ReceiveMessage",
                                "sqs:DeleteMessage",
                                "sqs:SetQueueAttributes",
                            ],
                            _QUEUE_ARN,
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

        task_paths = {path["messaging_service"]: path for path in aws_facts(task_definition).ecs_messaging_access_paths}
        service_paths = {path["messaging_service"]: path for path in aws_facts(service).ecs_messaging_access_paths}
        self.assertEqual(set(task_paths), {"sns", "sqs"})
        self.assertEqual(set(service_paths), {"sns", "sqs"})

        topic_path = service_paths["sns"]
        self.assertEqual(topic_path["workload_address"], service.address)
        self.assertEqual(topic_path["task_definition_address"], task_definition.address)
        self.assertEqual(topic_path["messaging_resource_address"], "aws_sns_topic.orders")
        self.assertEqual(topic_path["messaging_resource_type"], "aws_sns_topic")
        self.assertEqual(topic_path["messaging_resource_name"], "orders-events")
        self.assertEqual(topic_path["messaging_resource_arn"], _TOPIC_ARN)
        self.assertEqual(topic_path["role_kind"], "ecs_task_role")
        self.assertEqual(topic_path["credential_context"], "workload_runtime")
        self.assertEqual(topic_path["role_address"], "aws_iam_role.orders_task")
        self.assertEqual(topic_path["role_arn"], _TASK_ROLE_ARN)
        self.assertEqual(topic_path["access_state"], "allowed")
        self.assertEqual(topic_path["access_classes"], ["publish", "write", "administrative"])
        self.assertEqual(
            topic_path["matched_actions"],
            ["sns:Publish", "sns:Subscribe", "sns:AddPermission"],
        )
        self.assertEqual(topic_path["resource_scopes"], ["exact_topic"])
        self.assertEqual(topic_path["internet_facing_load_balancers"], [])

        queue_path = service_paths["sqs"]
        self.assertEqual(queue_path["messaging_resource_address"], "aws_sqs_queue.orders")
        self.assertEqual(queue_path["messaging_resource_arn"], _QUEUE_ARN)
        self.assertEqual(
            queue_path["access_classes"],
            ["write", "consume", "delete", "administrative"],
        )
        self.assertEqual(
            queue_path["matched_actions"],
            [
                "sqs:SendMessage",
                "sqs:ReceiveMessage",
                "sqs:DeleteMessage",
                "sqs:SetQueueAttributes",
            ],
        )
        self.assertEqual(queue_path["resource_scopes"], ["exact_queue"])

    def test_execution_role_grant_does_not_create_runtime_messaging_path(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _topic(),
                _queue(),
                _role("orders_task", _TASK_ROLE_ARN, []),
                _role(
                    "orders_execution",
                    _EXECUTION_ROLE_ARN,
                    [
                        _statement("Allow", "sns:Publish", _TOPIC_ARN),
                        _statement("Allow", "sqs:SendMessage", _QUEUE_ARN),
                    ],
                ),
                _task_definition(),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        facts = aws_facts(task_definition)
        self.assertEqual(facts.ecs_messaging_access_paths, [])
        self.assertEqual(facts.ecs_messaging_access_path_uncertainties, [])

    def test_exact_policy_target_does_not_expand_to_similarly_named_resources(self) -> None:
        archive_topic_arn = f"arn:aws:sns:us-east-1:{_ACCOUNT_ID}:orders-events-archive"
        archive_queue_arn = f"arn:aws:sqs:us-east-1:{_ACCOUNT_ID}:orders-archive"
        inventory = AwsNormalizer().normalize(
            [
                _topic(),
                _topic("archive", arn=archive_topic_arn),
                _queue(),
                _queue("archive", arn=archive_queue_arn),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "sns:Publish", _TOPIC_ARN),
                        _statement("Allow", "sqs:SendMessage", _QUEUE_ARN),
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        self.assertEqual(
            [path["messaging_resource_address"] for path in aws_facts(task_definition).ecs_messaging_access_paths],
            ["aws_sns_topic.orders", "aws_sqs_queue.orders"],
        )

    def test_explicit_denies_remove_comparable_publish_and_delete_actions(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _topic(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "sns:*", _TOPIC_ARN),
                        _statement(
                            "Deny",
                            ["sns:Publish", "sns:DeleteTopic"],
                            _TOPIC_ARN,
                        ),
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        path = aws_facts(task_definition).ecs_messaging_access_paths[0]
        self.assertEqual(path["access_state"], "allowed")
        self.assertEqual(path["access_classes"], ["write", "administrative"])
        self.assertEqual(path["denied_access_classes"], ["publish", "delete"])
        self.assertEqual(path["denied_actions"], ["sns:Publish", "sns:DeleteTopic"])
        self.assertTrue(path["explicit_deny"])
        self.assertEqual(path["deny_policy_resources"], [_TOPIC_ARN])

    def test_conditional_effects_remain_unknown_with_condition_evidence(self) -> None:
        condition = {"StringEquals": {"aws:SourceAccount": _ACCOUNT_ID}}
        inventory = AwsNormalizer().normalize(
            [
                _queue(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "sqs:SendMessage", _QUEUE_ARN, condition=condition)],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        facts = aws_facts(task_definition)
        path = facts.ecs_messaging_access_paths[0]
        self.assertEqual(path["modeled_access_state"], "unknown")
        self.assertEqual(path["access_state"], "unknown")
        self.assertEqual(path["access_classes"], [])
        self.assertEqual(path["unknown_access_classes"], ["write"])
        self.assertEqual(path["unknown_actions"], ["sqs:SendMessage"])
        self.assertTrue(path["conditional_evaluation_required"])
        self.assertEqual(
            path["policy_statements"][0]["conditions"],
            [{"operator": "StringEquals", "key": "aws:SourceAccount", "values": [_ACCOUNT_ID]}],
        )
        self.assertIn(
            "conditional identity-policy evidence",
            facts.ecs_messaging_access_path_uncertainties[0],
        )

    def test_unresolved_attached_policy_keeps_modeled_access_uncertain(self) -> None:
        policy_arn = "arn:aws:iam::aws:policy/ExternalMessagingAccess"
        inventory = AwsNormalizer().normalize(
            [
                _topic(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "sns:Publish", _TOPIC_ARN)],
                ),
                _role_policy_attachment(_TASK_ROLE_ARN, policy_arn),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        facts = aws_facts(task_definition)
        path = facts.ecs_messaging_access_paths[0]
        self.assertEqual(path["modeled_access_state"], "allowed")
        self.assertEqual(path["access_state"], "unknown")
        self.assertFalse(path["role_policy_complete"])
        self.assertEqual(
            facts.ecs_messaging_access_path_uncertainties,
            [f"aws_ecs_task_definition.orders: aws_iam_role.orders_task has unresolved attached policy {policy_arn}"],
        )

    def test_modeled_deny_with_unresolved_policy_keeps_target_access_unknown(self) -> None:
        policy_arn = "arn:aws:iam::aws:policy/ExternalMessagingAccess"
        inventory = AwsNormalizer().normalize(
            [
                _topic(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Deny", "sns:DeleteTopic", _TOPIC_ARN)],
                ),
                _role_policy_attachment(_TASK_ROLE_ARN, policy_arn),
                _task_definition(execution_role_arn=None),
            ]
        )
        task_definition = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None

        facts = aws_facts(task_definition)
        path = facts.ecs_messaging_access_paths[0]
        self.assertEqual(path["modeled_access_state"], "denied")
        self.assertEqual(path["access_state"], "unknown")
        self.assertEqual(path["denied_actions"], ["sns:DeleteTopic"])
        self.assertEqual(path["denied_access_classes"], ["delete"])
        self.assertTrue(path["explicit_deny"])
        self.assertFalse(path["role_policy_complete"])
        self.assertEqual(
            facts.ecs_messaging_access_path_uncertainties,
            [f"aws_ecs_task_definition.orders: aws_iam_role.orders_task has unresolved attached policy {policy_arn}"],
        )

    def test_unresolved_role_and_non_exact_resources_do_not_invent_paths(self) -> None:
        missing_role_inventory = AwsNormalizer().normalize(
            [_topic(), _queue(), _task_definition(execution_role_arn=None)]
        )
        task_definition = missing_role_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task_definition is not None
        self.assertEqual(aws_facts(task_definition).ecs_messaging_access_paths, [])
        self.assertEqual(
            aws_facts(task_definition).ecs_messaging_access_path_uncertainties,
            [f"aws_ecs_task_definition.orders: ECS task role {_TASK_ROLE_ARN} is not modeled in the plan"],
        )

        external_topic_arn = "arn:aws:sns:us-west-2:999900001111:external-events"
        unresolved_inventory = AwsNormalizer().normalize(
            [
                _topic(),
                _queue(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "sns:Publish", "arn:aws:sns:us-east-1:*:orders-*"),
                        _statement("Allow", "sqs:SendMessage", "*"),
                        _statement("Allow", "sns:Publish", external_topic_arn),
                    ],
                ),
                _task_definition(execution_role_arn=None),
            ]
        )
        unresolved_task = unresolved_inventory.get_by_address("aws_ecs_task_definition.orders")
        assert unresolved_task is not None
        unresolved_facts = aws_facts(unresolved_task)
        self.assertEqual(unresolved_facts.ecs_messaging_access_paths, [])
        self.assertEqual(len(unresolved_facts.ecs_messaging_access_path_uncertainties), 3)
        self.assertTrue(
            any(
                "does not identify an exact SNS topic or SQS queue" in uncertainty
                for uncertainty in unresolved_facts.ecs_messaging_access_path_uncertainties
            )
        )
        self.assertTrue(
            any(
                external_topic_arn in uncertainty and "not modeled in the plan" in uncertainty
                for uncertainty in unresolved_facts.ecs_messaging_access_path_uncertainties
            )
        )


if __name__ == "__main__":
    unittest.main()
