from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_ecs_messaging_access_paths import (
    _EXECUTION_ROLE_ARN,
    _QUEUE_ARN,
    _TASK_ROLE_ARN,
    _queue,
    _role,
    _role_policy_attachment,
    _statement,
    _task_definition,
)
from tests.providers.aws.test_aws_public_ecs_messaging_mutation_rules import (
    _load_balancer_path,
    _service,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_RULE_ID = "aws-public-ecs-sqs-receive-access"


def _evaluate(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )
    return inventory, boundaries, findings


class AwsPublicEcsSqsReceiveRuleTests(unittest.TestCase):
    def test_rule_id_is_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_public_service_with_exact_task_role_receive_access_is_reported(self) -> None:
        _, _, findings = _evaluate(
            [
                *_load_balancer_path(),
                _queue(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            [
                                "sqs:ReceiveMessage",
                                "sqs:ChangeMessageVisibility",
                                "sqs:DeleteMessage",
                            ],
                            _QUEUE_ARN,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "aws_lb.public",
                "aws_ecs_service.orders",
                "aws_ecs_task_definition.orders",
                "aws_iam_role.orders_task",
                "aws_sqs_queue.orders",
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->aws_lb.public",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["network_path"],
            [
                "internet reaches aws_lb.public",
                "aws_lb.public fronts aws_ecs_service.orders",
            ],
        )
        self.assertEqual(
            evidence["task_definitions"],
            ["address=aws_ecs_task_definition.orders"],
        )
        self.assertIn("address=aws_iam_role.orders_task", evidence["task_roles"][0])
        self.assertIn("role_kind=ecs_task_role", evidence["task_roles"][0])
        self.assertEqual(len(evidence["sqs_receive_paths"]), 1)
        receive_path = evidence["sqs_receive_paths"][0]
        self.assertIn("queue_address=aws_sqs_queue.orders", receive_path)
        self.assertIn(f"queue_arn={_QUEUE_ARN}", receive_path)
        self.assertIn("action=sqs:ReceiveMessage", receive_path)
        self.assertIn("resource_scopes=exact_queue", receive_path)
        self.assertNotIn("sqs:ChangeMessageVisibility", receive_path)
        self.assertNotIn("sqs:DeleteMessage", receive_path)
        self.assertEqual(
            evidence["assessment_scope"],
            [
                "establishes=unconditional identity-policy allow for sqs:ReceiveMessage",
                (
                    "does_not_establish=plaintext message disclosure; SQS encryption and KMS "
                    "authorization are independent controls"
                ),
            ],
        )
        self.assertIn(
            "unconditional identity-policy allow for `sqs:ReceiveMessage`",
            finding.rationale,
        )
        self.assertIn(
            "not guaranteed message retrieval or plaintext disclosure",
            finding.rationale,
        )
        self.assertIn("queue policies, endpoint policies", finding.rationale)
        self.assertIn("The queue itself is not public", finding.rationale)

    def test_visibility_or_delete_permissions_without_receive_remain_quiet(self) -> None:
        cases = {
            "visibility only": ["sqs:ChangeMessageVisibility"],
            "delete only": ["sqs:DeleteMessage"],
            "visibility and delete": [
                "sqs:ChangeMessageVisibility",
                "sqs:DeleteMessage",
            ],
        }

        for case, actions in cases.items():
            with self.subTest(case=case):
                _, _, findings = _evaluate(
                    [
                        *_load_balancer_path(),
                        _queue(),
                        _role(
                            "orders_task",
                            _TASK_ROLE_ARN,
                            [_statement("Allow", actions, _QUEUE_ARN)],
                        ),
                        _task_definition(execution_role_arn=None),
                        _service(),
                    ]
                )

                self.assertEqual(findings, [])

    def test_non_deterministic_or_non_public_receive_paths_remain_quiet(self) -> None:
        external_policy_arn = "arn:aws:iam::aws:policy/ExternalMessagingAccess"
        external_queue_arn = "arn:aws:sqs:us-west-2:999900001111:external"
        cases = {
            "comparable explicit deny": [
                *_load_balancer_path(),
                _queue(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "sqs:ReceiveMessage", _QUEUE_ARN),
                        _statement("Deny", "sqs:ReceiveMessage", _QUEUE_ARN),
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "conditional allow": [
                *_load_balancer_path(),
                _queue(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "sqs:ReceiveMessage",
                            _QUEUE_ARN,
                            condition={
                                "StringEquals": {
                                    "aws:SourceVpc": "vpc-123",
                                }
                            },
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "incomplete task role policy": [
                *_load_balancer_path(),
                _queue(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "sqs:ReceiveMessage", _QUEUE_ARN)],
                ),
                _role_policy_attachment(_TASK_ROLE_ARN, external_policy_arn),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "execution role only": [
                *_load_balancer_path(),
                _queue(),
                _role("orders_task", _TASK_ROLE_ARN, []),
                _role(
                    "orders_execution",
                    _EXECUTION_ROLE_ARN,
                    [_statement("Allow", "sqs:ReceiveMessage", _QUEUE_ARN)],
                ),
                _task_definition(),
                _service(),
            ],
            "external exact queue": [
                *_load_balancer_path(),
                _queue(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "sqs:ReceiveMessage", external_queue_arn)],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "wildcard queue scope": [
                *_load_balancer_path(),
                _queue(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "sqs:ReceiveMessage",
                            "arn:aws:sqs:us-east-1:111122223333:*",
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "internal load balancer": [
                *_load_balancer_path(internal=True),
                _queue(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "sqs:ReceiveMessage", _QUEUE_ARN)],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "unresolved task definition": [
                *_load_balancer_path(),
                _queue(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "sqs:ReceiveMessage", _QUEUE_ARN)],
                ),
                _service("missing:1"),
            ],
        }

        for case, resources in cases.items():
            with self.subTest(case=case):
                _, _, findings = _evaluate(resources)
                self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
