from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

_ACCOUNT_ID = "111122223333"
_EXTERNAL_ACCOUNT_ID = "999900001111"
_TASK_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-task"
_EXECUTION_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-execution"
_QUEUE_ARN = f"arn:aws:sqs:us-east-1:{_ACCOUNT_ID}:orders"
_EXTERNAL_QUEUE_ARN = f"arn:aws:sqs:us-east-1:{_EXTERNAL_ACCOUNT_ID}:orders"
_RECEIVE = "sqs:ReceiveMessage"
_DELETE = "sqs:DeleteMessage"
_PURGE = "sqs:PurgeQueue"


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


def _statement(
    effect: str,
    actions: str | list[str],
    resources: str | list[str],
    *,
    principal: str | dict[str, Any] | None = None,
    condition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "Effect": effect,
        "Action": actions,
        "Resource": resources,
    }
    if principal is not None:
        statement["Principal"] = principal
    if condition is not None:
        statement["Condition"] = condition
    return statement


def _role(
    statements: list[dict[str, Any]],
    *,
    arn: str = _TASK_ROLE_ARN,
    name: str = "orders_task",
) -> TerraformResource:
    values: dict[str, Any] = {"name": name, "arn": arn}
    if statements:
        values["inline_policy"] = [
            {
                "name": "sqs-removal",
                "policy": json.dumps({"Version": "2012-10-17", "Statement": statements}),
            }
        ]
    return _resource("aws_iam_role", name, values)


def _queue(
    *,
    arn: str = _QUEUE_ARN,
    resource_name: str = "orders",
    policy: list[dict[str, Any]] | None = None,
    policy_unknown: bool = False,
    delivery_posture: bool = False,
) -> TerraformResource:
    name = arn.rsplit(":", 1)[-1]
    values: dict[str, Any] = {
        "name": name,
        "arn": arn,
        "id": f"https://sqs.us-east-1.amazonaws.com/{arn.split(':')[4]}/{name}",
    }
    if policy is not None:
        values["policy"] = json.dumps({"Version": "2012-10-17", "Statement": policy})
    if delivery_posture:
        values.update(
            {
                "message_retention_seconds": 345_600,
                "redrive_policy": json.dumps(
                    {
                        "deadLetterTargetArn": (f"arn:aws:sqs:us-east-1:{arn.split(':')[4]}:orders-dlq"),
                        "maxReceiveCount": 5,
                    }
                ),
            }
        )
    return _resource(
        "aws_sqs_queue",
        resource_name,
        values,
        unknown_values={"policy": True} if policy_unknown else None,
    )


def _task_definition(
    *,
    task_role_arn: str = _TASK_ROLE_ARN,
    execution_role_arn: str | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "family": "orders",
        "revision": 1,
        "network_mode": "awsvpc",
        "container_definitions": '[{"name":"orders","portMappings":[{"containerPort":8080,"protocol":"tcp"}]}]',
        "task_role_arn": task_role_arn,
    }
    if execution_role_arn is not None:
        values["execution_role_arn"] = execution_role_arn
    return _resource("aws_ecs_task_definition", "orders", values)


def _service() -> TerraformResource:
    return _resource(
        "aws_ecs_service",
        "orders",
        {"name": "orders", "task_definition": "orders:1"},
    )


def _normalize(
    role_statements: list[dict[str, Any]],
    *,
    queue: TerraformResource | None = None,
    extra: list[TerraformResource] | None = None,
) -> tuple[Any, Any]:
    inventory = AwsNormalizer().normalize(
        [
            queue or _queue(),
            _role(role_statements),
            _task_definition(),
            _service(),
            *(extra or []),
        ]
    )
    task = inventory.get_by_address("aws_ecs_task_definition.orders")
    service = inventory.get_by_address("aws_ecs_service.orders")
    assert task is not None
    assert service is not None
    return task, service


class AwsEcsSqsMessageRemovalPathTests(unittest.TestCase):
    def test_queue_policy_state_distinguishes_absent_configured_and_unknown(self) -> None:
        configured = _queue(
            policy=[
                _statement(
                    "Allow",
                    _PURGE,
                    _QUEUE_ARN,
                    principal={"AWS": _TASK_ROLE_ARN},
                )
            ]
        )
        malformed = _queue()
        malformed.values["policy"] = "{"
        cases = (
            (_queue(), "not_configured", []),
            (configured, "configured", []),
            (_queue(policy_unknown=True), "unknown", ["policy is unknown after planning"]),
            (
                malformed,
                "unknown",
                ["policy has an unrecognized or malformed value shape"],
            ),
        )
        for queue, state, uncertainties in cases:
            with self.subTest(state=state, uncertainties=uncertainties):
                inventory = AwsNormalizer().normalize([queue])
                normalized = inventory.get_by_address("aws_sqs_queue.orders")
                assert normalized is not None
                facts = aws_facts(normalized)
                self.assertEqual(facts.sqs_queue_policy_state, state)
                self.assertEqual(facts.sqs_queue_policy_uncertainties, uncertainties)
                self.assertFalse(any("policy" in uncertainty for uncertainty in facts.sqs_posture_uncertainties))

    def test_receive_and_delete_form_one_receipt_handle_deletion_path(self) -> None:
        task, service = _normalize(
            [_statement("Allow", [_RECEIVE, _DELETE], _QUEUE_ARN)],
            queue=_queue(delivery_posture=True),
        )

        task_path = aws_facts(task).ecs_sqs_message_removal_paths[0]
        service_path = aws_facts(service).ecs_sqs_message_removal_paths[0]
        self.assertEqual(task_path["operation"], _DELETE)
        self.assertEqual(task_path["prerequisite_operation"], _RECEIVE)
        self.assertEqual(task_path["target_granularity"], "queue_received_message_namespace")
        self.assertEqual(task_path["receipt_handle_source"], "runtime_receive_response")
        self.assertIsNone(task_path["receipt_handle_value"])
        self.assertEqual(task_path["receive_authorization"]["matched_actions"], [_RECEIVE])
        self.assertEqual(task_path["removal_authorization"]["matched_actions"], [_DELETE])
        self.assertEqual(task_path["role_arn"], _TASK_ROLE_ARN)
        self.assertEqual(task_path["queue_arn"], _QUEUE_ARN)
        self.assertEqual(
            task_path["delivery_evidence"],
            {
                "delivery_evidence_scope": "sqs_retention_and_redrive_posture",
                "message_retention_seconds": 345_600,
                "redrive_state": "configured",
                "redrive_target_arn": (f"arn:aws:sqs:us-east-1:{_ACCOUNT_ID}:orders-dlq"),
                "redrive_max_receive_count": 5,
                "removed_message_recovery_state": ("not_established_by_modeled_sqs_delivery_controls"),
                "uncertainties": [],
            },
        )
        self.assertEqual(service_path["workload_address"], service.address)
        self.assertEqual(service_path["task_definition_address"], task.address)
        self.assertEqual(service_path["internet_facing_load_balancers"], [])

    def test_delete_without_receive_does_not_invent_receipt_handle_authority(self) -> None:
        task, service = _normalize([_statement("Allow", _DELETE, _QUEUE_ARN)])
        self.assertEqual(aws_facts(task).ecs_sqs_message_removal_paths, [])
        self.assertEqual(aws_facts(service).ecs_sqs_message_removal_paths, [])
        self.assertTrue(
            any(
                "receipt-handle prerequisite" in uncertainty
                for uncertainty in aws_facts(task).ecs_sqs_message_removal_path_uncertainties
            )
        )

    def test_purge_queue_is_independent_from_receive_and_delete(self) -> None:
        task, _ = _normalize([_statement("Allow", _PURGE, _QUEUE_ARN)])
        path = aws_facts(task).ecs_sqs_message_removal_paths[0]
        self.assertEqual(path["operation"], _PURGE)
        self.assertEqual(path["operation_class"], "queue_message_purge")
        self.assertEqual(path["target_granularity"], "queue_message_namespace")
        self.assertIsNone(path["prerequisite_operation"])
        self.assertIsNone(path["receipt_handle_source"])
        self.assertEqual(path["removal_authorization"]["matched_actions"], [_PURGE])

    def test_receive_delete_and_purge_remain_two_operation_exact_paths(self) -> None:
        task, _ = _normalize([_statement("Allow", [_RECEIVE, _DELETE, _PURGE], _QUEUE_ARN)])
        paths = aws_facts(task).ecs_sqs_message_removal_paths
        self.assertEqual([path["operation"] for path in paths], [_DELETE, _PURGE])
        self.assertEqual(
            [path["target_scope"] for path in paths],
            [
                "exact_queue_received_message_namespace",
                "exact_queue_message_namespace",
            ],
        )

    def test_operation_local_denies_do_not_suppress_unrelated_removal(self) -> None:
        queue = _queue(
            policy=[
                _statement(
                    "Deny",
                    _DELETE,
                    _QUEUE_ARN,
                    principal={"AWS": _TASK_ROLE_ARN},
                )
            ]
        )
        task, _ = _normalize(
            [_statement("Allow", [_RECEIVE, _DELETE, _PURGE], _QUEUE_ARN)],
            queue=queue,
        )
        self.assertEqual(
            [path["operation"] for path in aws_facts(task).ecs_sqs_message_removal_paths],
            [_PURGE],
        )

    def test_conditional_deny_and_incomplete_identity_evidence_fail_closed(self) -> None:
        condition = {"StringEquals": {"aws:SourceAccount": _ACCOUNT_ID}}
        conditional_queue = _queue(
            policy=[
                _statement(
                    "Deny",
                    _DELETE,
                    _QUEUE_ARN,
                    principal={"AWS": _TASK_ROLE_ARN},
                    condition=condition,
                )
            ]
        )
        conditional_task, _ = _normalize(
            [_statement("Allow", [_RECEIVE, _DELETE], _QUEUE_ARN)],
            queue=conditional_queue,
        )
        self.assertEqual(
            aws_facts(conditional_task).ecs_sqs_message_removal_paths,
            [],
        )
        self.assertTrue(
            any(
                "condition-dependent explicit-deny" in uncertainty
                for uncertainty in aws_facts(conditional_task).ecs_sqs_message_removal_path_uncertainties
            )
        )

        external_policy_arn = "arn:aws:iam::aws:policy/ExternalMessagingAccess"
        attachment = _resource(
            "aws_iam_role_policy_attachment",
            "external",
            {"role": _TASK_ROLE_ARN, "policy_arn": external_policy_arn},
        )
        incomplete_task, _ = _normalize(
            [_statement("Allow", [_RECEIVE, _DELETE], _QUEUE_ARN)],
            extra=[attachment],
        )
        self.assertEqual(
            aws_facts(incomplete_task).ecs_sqs_message_removal_paths,
            [],
        )
        self.assertTrue(aws_facts(incomplete_task).ecs_sqs_message_removal_path_uncertainties)

    def test_same_account_queue_policy_can_establish_direct_authority(self) -> None:
        queue = _queue(
            policy=[
                _statement(
                    "Allow",
                    [_RECEIVE, _DELETE],
                    _QUEUE_ARN,
                    principal={"AWS": _TASK_ROLE_ARN},
                )
            ]
        )
        task, _ = _normalize([], queue=queue)
        path = aws_facts(task).ecs_sqs_message_removal_paths[0]
        receive = path["receive_authorization"]
        removal = path["removal_authorization"]
        self.assertEqual(receive["authorization_bases"], ["queue_policy_direct"])
        self.assertEqual(removal["authorization_bases"], ["queue_policy_direct"])
        self.assertFalse(receive["identity_policy_required"])
        self.assertTrue(receive["queue_policy_required"])
        self.assertEqual(receive["queue_policy_source_addresses"], ["aws_sqs_queue.orders"])

    def test_cross_account_removal_requires_identity_and_queue_policy(self) -> None:
        queue_policy = [
            _statement(
                "Allow",
                [_RECEIVE, _DELETE, _PURGE],
                _EXTERNAL_QUEUE_ARN,
                principal={"AWS": _TASK_ROLE_ARN},
            )
        ]
        task, _ = _normalize(
            [
                _statement(
                    "Allow",
                    [_RECEIVE, _DELETE, _PURGE],
                    _EXTERNAL_QUEUE_ARN,
                )
            ],
            queue=_queue(arn=_EXTERNAL_QUEUE_ARN, policy=queue_policy),
        )
        paths = aws_facts(task).ecs_sqs_message_removal_paths
        self.assertEqual([path["operation"] for path in paths], [_DELETE, _PURGE])
        for path in paths:
            authorization = path["removal_authorization"]
            self.assertEqual(
                authorization["authorization_bases"],
                ["cross_account_identity_and_queue_policy"],
            )
            self.assertFalse(authorization["same_account"])
            self.assertTrue(authorization["identity_policy_required"])
            self.assertTrue(authorization["queue_policy_required"])

        identity_only, _ = _normalize(
            [_statement("Allow", [_RECEIVE, _DELETE], _EXTERNAL_QUEUE_ARN)],
            queue=_queue(arn=_EXTERNAL_QUEUE_ARN),
        )
        self.assertEqual(aws_facts(identity_only).ecs_sqs_message_removal_paths, [])

        queue_only, _ = _normalize(
            [],
            queue=_queue(arn=_EXTERNAL_QUEUE_ARN, policy=queue_policy),
        )
        self.assertEqual(aws_facts(queue_only).ecs_sqs_message_removal_paths, [])

    def test_queue_arn_resource_matching_preserves_queue_name_case(self) -> None:
        upper_arn = f"arn:aws:sqs:us-east-1:{_ACCOUNT_ID}:Orders"
        inventory = AwsNormalizer().normalize(
            [
                _queue(arn=upper_arn, resource_name="upper"),
                _queue(arn=_QUEUE_ARN, resource_name="lower"),
                _role(
                    [
                        _statement(
                            "Allow",
                            [_RECEIVE, _DELETE],
                            upper_arn,
                        )
                    ]
                ),
                _task_definition(),
            ]
        )
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task is not None

        paths = aws_facts(task).ecs_sqs_message_removal_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["queue_address"], "aws_sqs_queue.upper")
        self.assertEqual(paths[0]["queue_arn"], upper_arn)
        self.assertNotEqual(paths[0]["queue_arn"], _QUEUE_ARN)

    def test_symbolic_queue_reference_resolves_only_to_the_exact_modeled_queue(self) -> None:
        task, _ = _normalize(
            [
                _statement(
                    "Allow",
                    [_RECEIVE, _DELETE],
                    "aws_sqs_queue.orders.arn",
                )
            ]
        )
        path = aws_facts(task).ecs_sqs_message_removal_paths[0]
        self.assertEqual(path["queue_arn"], _QUEUE_ARN)
        self.assertEqual(
            path["removal_authorization"]["identity_policy_statements"][0]["matching_resources"],
            ["aws_sqs_queue.orders.arn"],
        )

    def test_unknown_queue_policy_fails_closed_without_erasing_delivery_posture(self) -> None:
        task, _ = _normalize(
            [_statement("Allow", [_RECEIVE, _DELETE], _QUEUE_ARN)],
            queue=_queue(policy_unknown=True, delivery_posture=True),
        )
        facts = aws_facts(task)
        self.assertEqual(facts.ecs_sqs_message_removal_paths, [])
        self.assertTrue(
            any("queue policy" in uncertainty for uncertainty in facts.ecs_sqs_message_removal_path_uncertainties)
        )

    def test_incomplete_queue_policy_is_operation_local(self) -> None:
        queue = _queue(
            policy=[
                _statement(
                    "Allow",
                    _DELETE,
                    _QUEUE_ARN,
                )
            ]
        )
        task, _ = _normalize(
            [_statement("Allow", [_RECEIVE, _DELETE, _PURGE], _QUEUE_ARN)],
            queue=queue,
        )
        facts = aws_facts(task)
        self.assertEqual(
            [path["operation"] for path in facts.ecs_sqs_message_removal_paths],
            [_PURGE],
        )
        self.assertTrue(any(_DELETE in uncertainty for uncertainty in facts.ecs_sqs_message_removal_path_uncertainties))
        self.assertFalse(
            any(
                _PURGE in uncertainty and "incomplete" in uncertainty
                for uncertainty in facts.ecs_sqs_message_removal_path_uncertainties
            )
        )

    def test_execution_role_authority_never_becomes_runtime_removal(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _queue(),
                _role([], name="orders_task"),
                _role(
                    [
                        _statement(
                            "Allow",
                            [_RECEIVE, _DELETE, _PURGE],
                            _QUEUE_ARN,
                        )
                    ],
                    arn=_EXECUTION_ROLE_ARN,
                    name="orders_execution",
                ),
                _task_definition(execution_role_arn=_EXECUTION_ROLE_ARN),
            ]
        )
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task is not None
        self.assertEqual(aws_facts(task).ecs_sqs_message_removal_paths, [])


if __name__ == "__main__":
    unittest.main()
