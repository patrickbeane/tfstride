from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_ecs_messaging_access_paths import (
    _EXECUTION_ROLE_ARN,
    _QUEUE_ARN,
    _TASK_ROLE_ARN,
    _TOPIC_ARN,
    _queue,
    _resource,
    _role,
    _role_policy_attachment,
    _statement,
    _task_definition,
    _topic,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_RULE_ID = "aws-public-ecs-messaging-mutation-access"


def _load_balancer(*, internal: bool = False) -> TerraformResource:
    return _resource(
        "aws_lb",
        "public",
        {
            "name": "public",
            "arn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/public/abc",
            "internal": internal,
            "load_balancer_type": "application",
        },
    )


def _service(task_definition: str = "orders:1") -> TerraformResource:
    return _resource(
        "aws_ecs_service",
        "orders",
        {
            "name": "orders",
            "task_definition": task_definition,
            "load_balancer": [
                {
                    "elb_name": "public",
                    "container_name": "orders",
                    "container_port": 8080,
                }
            ],
        },
    )


def _evaluate(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )
    return inventory, boundaries, findings


class AwsPublicEcsMessagingMutationRuleTests(unittest.TestCase):
    def test_rule_id_is_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_public_service_with_exact_task_role_mutation_access_is_reported(self) -> None:
        _, _, findings = _evaluate(
            [
                _load_balancer(),
                _topic(),
                _queue(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            ["sns:Publish", "sns:DeleteTopic"],
                            _TOPIC_ARN,
                        ),
                        _statement(
                            "Allow",
                            [
                                "sqs:SendMessage",
                                "sqs:ReceiveMessage",
                                "sqs:PurgeQueue",
                                "sqs:SetQueueAttributes",
                            ],
                            _QUEUE_ARN,
                        ),
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
                "aws_sns_topic.orders",
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
        self.assertEqual(len(evidence["messaging_mutation_paths"]), 2)
        topic_evidence, queue_evidence = evidence["messaging_mutation_paths"]
        self.assertIn("target_address=aws_sns_topic.orders", topic_evidence)
        self.assertIn(f"target_arn={_TOPIC_ARN}", topic_evidence)
        self.assertIn("mutation_classes=publish,delete", topic_evidence)
        self.assertIn("actions=sns:Publish,sns:DeleteTopic", topic_evidence)
        self.assertIn("target_address=aws_sqs_queue.orders", queue_evidence)
        self.assertIn(f"target_arn={_QUEUE_ARN}", queue_evidence)
        self.assertIn("mutation_classes=write,delete,administrative", queue_evidence)
        self.assertIn("actions=sqs:SendMessage,sqs:PurgeQueue,sqs:SetQueueAttributes", queue_evidence)
        self.assertNotIn("sqs:ReceiveMessage", queue_evidence)
        self.assertIn("access_state=allowed", queue_evidence)
        self.assertIn("does not mean that the topic or queue itself is public", finding.rationale)

    def test_receive_only_access_remains_quiet(self) -> None:
        _, _, findings = _evaluate(
            [
                _load_balancer(),
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
                                "sqs:StartMessageMoveTask",
                                "sqs:CancelMessageMoveTask",
                            ],
                            _QUEUE_ARN,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ]
        )

        self.assertEqual(findings, [])

    def test_excluded_move_task_action_does_not_inflate_triggering_write_access(self) -> None:
        _, _, findings = _evaluate(
            [
                _load_balancer(),
                _queue(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            ["sqs:SendMessage", "sqs:StartMessageMoveTask"],
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
        self.assertEqual(finding.severity_reasoning.privilege_breadth, 1)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertIn("mutation_classes=write", evidence["messaging_mutation_paths"][0])
        self.assertIn("actions=sqs:SendMessage", evidence["messaging_mutation_paths"][0])
        self.assertNotIn("sqs:StartMessageMoveTask", evidence["messaging_mutation_paths"][0])
        self.assertIn("could send messages or manage subscriptions", finding.rationale)
        self.assertNotIn("delete or purge", finding.rationale)
        self.assertNotIn("administrative", finding.rationale)

    def test_non_deterministic_or_non_public_mutation_paths_remain_quiet(self) -> None:
        external_policy_arn = "arn:aws:iam::aws:policy/ExternalMessagingAccess"
        external_topic_arn = "arn:aws:sns:us-west-2:999900001111:external-events"
        cases = {
            "comparable explicit deny": [
                _load_balancer(),
                _topic(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "sns:Publish", _TOPIC_ARN),
                        _statement("Deny", "sns:Publish", _TOPIC_ARN),
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "conditional allow": [
                _load_balancer(),
                _queue(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "sqs:SendMessage",
                            _QUEUE_ARN,
                            condition={"StringEquals": {"aws:SourceVpc": "vpc-123"}},
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "incomplete task role policy": [
                _load_balancer(),
                _topic(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "sns:Publish", _TOPIC_ARN)],
                ),
                _role_policy_attachment(_TASK_ROLE_ARN, external_policy_arn),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "execution role only": [
                _load_balancer(),
                _topic(),
                _role("orders_task", _TASK_ROLE_ARN, []),
                _role(
                    "orders_execution",
                    _EXECUTION_ROLE_ARN,
                    [_statement("Allow", "sns:Publish", _TOPIC_ARN)],
                ),
                _task_definition(),
                _service(),
            ],
            "external exact target": [
                _load_balancer(),
                _topic(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "sns:Publish", external_topic_arn)],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "non-exact target": [
                _load_balancer(),
                _topic(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "sns:Publish", "arn:aws:sns:us-east-1:*:orders-*")],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "internal load balancer": [
                _load_balancer(internal=True),
                _topic(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "sns:Publish", _TOPIC_ARN)],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "unresolved task definition": [
                _load_balancer(),
                _topic(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "sns:Publish", _TOPIC_ARN)],
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
