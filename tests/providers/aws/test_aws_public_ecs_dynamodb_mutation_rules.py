from __future__ import annotations

import unittest

from tests.providers.aws.ecs_forwarding_support import load_balancer_path
from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _EXECUTION_ROLE_ARN,
    _INDEX_ARN,
    _TABLE_ARN,
    _TASK_ROLE_ARN,
    _resource,
    _role,
    _role_policy_attachment,
    _statement,
    _table,
    _task_definition,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_RULE_ID = "aws-public-ecs-dynamodb-mutation-access"
_LOAD_BALANCER_ARN = "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/public/abc"
_LISTENER_ARN = "arn:aws:elasticloadbalancing:us-east-1:111122223333:listener/app/public/abc/ghi"
_TARGET_GROUP_ARN = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/orders/def"


def _load_balancer(*, internal: bool = False) -> TerraformResource:
    return _resource(
        "aws_lb",
        "public",
        {
            "name": "public",
            "arn": _LOAD_BALANCER_ARN,
            "internal": internal,
            "load_balancer_type": "application",
            "security_groups": ["aws_security_group.public_alb"],
        },
    )


def _target_group() -> TerraformResource:
    return _resource(
        "aws_lb_target_group",
        "orders",
        {
            "id": _TARGET_GROUP_ARN,
            "arn": _TARGET_GROUP_ARN,
            "name": "orders",
            "port": 8080,
            "protocol": "HTTP",
            "target_type": "ip",
        },
    )


def _listener() -> TerraformResource:
    return _resource(
        "aws_lb_listener",
        "https",
        {
            "id": _LISTENER_ARN,
            "arn": _LISTENER_ARN,
            "load_balancer_arn": _LOAD_BALANCER_ARN,
            "port": 443,
            "protocol": "HTTPS",
            "default_action": [
                {
                    "type": "forward",
                    "target_group_arn": _TARGET_GROUP_ARN,
                }
            ],
        },
    )


def _service(task_definition: str = "aws_ecs_task_definition.orders") -> TerraformResource:
    return _resource(
        "aws_ecs_service",
        "orders",
        {
            "name": "orders",
            "task_definition": task_definition,
            "network_configuration": [{"security_groups": ["aws_security_group.public_tasks"]}],
            "load_balancer": [
                {
                    "target_group_arn": _TARGET_GROUP_ARN,
                    "container_name": "orders",
                    "container_port": 8080,
                }
            ],
        },
    )


def _public_edge(*, internal: bool = False) -> list[TerraformResource]:
    return [
        _load_balancer(internal=internal),
        _target_group(),
        _listener(),
        *(item for item in load_balancer_path() if item.resource_type == "aws_security_group"),
    ]


def _evaluate(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )
    return inventory, boundaries, findings


def _finding_for_action(action: str):
    _, _, findings = _evaluate(
        [
            *_public_edge(),
            _table(),
            _role(
                "orders_task",
                _TASK_ROLE_ARN,
                [_statement("Allow", action, _TABLE_ARN)],
            ),
            _task_definition(execution_role_arn=None),
            _service(),
        ]
    )
    if len(findings) != 1:
        raise AssertionError(f"Expected one finding for {action}, got {findings!r}")
    return findings[0]


class AwsPublicEcsDynamoDbMutationRuleTests(unittest.TestCase):
    def test_rule_id_is_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_action_classes_drive_impact_and_severity(self) -> None:
        cases = {
            "dynamodb:PutItem": (
                "entity_write",
                1,
                1,
                7,
                "create or update items in the modeled table",
            ),
            "dynamodb:UpdateTable": (
                "configuration_administration",
                2,
                1,
                8,
                ("change DynamoDB table configuration or controls without directly modifying item contents"),
            ),
            "dynamodb:DeleteTableReplica": (
                "destructive_administration",
                3,
                2,
                10,
                "delete complete DynamoDB tables or replicas and their stored data",
            ),
        }
        findings = {}
        for action, (
            access_class,
            privilege_breadth,
            blast_radius,
            final_score,
            capability,
        ) in cases.items():
            with self.subTest(action=action):
                finding = _finding_for_action(action)
                findings[action] = finding
                self.assertEqual(finding.rule_id, _RULE_ID)
                self.assertEqual(finding.severity.value, "high")
                self.assertEqual(
                    finding.severity_reasoning.privilege_breadth,
                    privilege_breadth,
                )
                self.assertEqual(
                    finding.severity_reasoning.blast_radius,
                    blast_radius,
                )
                self.assertEqual(
                    finding.severity_reasoning.final_score,
                    final_score,
                )
                self.assertIn(capability, finding.rationale)
                evidence = {item.key: item.values for item in finding.evidence}
                self.assertIn(
                    f"mutation_classes={access_class}",
                    evidence["dynamodb_mutation_paths"][0],
                )
                self.assertIn(
                    f"actions={action}",
                    evidence["dynamodb_mutation_paths"][0],
                )
                self.assertIn(
                    f"class={access_class}; capability={capability}; privilege_breadth={privilege_breadth}",
                    evidence["impact_profile"],
                )

        self.assertGreater(
            findings["dynamodb:DeleteTableReplica"].severity_reasoning.final_score,
            findings["dynamodb:PutItem"].severity_reasoning.final_score,
        )
        self.assertNotIn(
            "create or update items",
            findings["dynamodb:UpdateTable"].rationale,
        )
        self.assertIn(
            "configuration or control mutation rather than a claim",
            findings["dynamodb:UpdateTable"].rationale,
        )

    def test_read_actions_do_not_leak_into_mutation_evidence(self) -> None:
        _, _, findings = _evaluate(
            [
                *_public_edge(),
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
                                "dynamodb:ExportTableToPointInTime",
                                "dynamodb:PutItem",
                            ],
                            _TABLE_ARN,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = {item.key: item.values for item in findings[0].evidence}
        mutation_path = evidence["dynamodb_mutation_paths"][0]
        self.assertIn("actions=dynamodb:PutItem", mutation_path)
        self.assertNotIn("dynamodb:GetItem", mutation_path)
        self.assertNotIn("dynamodb:ConditionCheckItem", mutation_path)
        self.assertNotIn("dynamodb:ExportTableToPointInTime", mutation_path)

    def test_exact_public_path_retains_identity_target_and_exposure_evidence(
        self,
    ) -> None:
        _, _, findings = _evaluate(
            [
                *_public_edge(),
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
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ]
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [_RULE_ID],
        )
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            [
                "aws_lb.public",
                "aws_lb_listener.https",
                "aws_lb_target_group.orders",
                "aws_ecs_service.orders",
                "aws_ecs_task_definition.orders",
                "aws_iam_role.orders_task",
                "aws_dynamodb_table.orders",
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
                "internet reaches aws_lb.public through aws_lb_listener.https (HTTPS TCP 443)",
                "aws_lb_listener.https forwards through aws_lb_target_group.orders to "
                "aws_ecs_service.orders container=orders (HTTP TCP 8080)",
            ],
        )
        self.assertEqual(
            evidence["task_definitions"],
            ["address=aws_ecs_task_definition.orders"],
        )
        self.assertIn(
            "address=aws_iam_role.orders_task",
            evidence["task_roles"][0],
        )
        self.assertIn(
            "role_kind=ecs_task_role",
            evidence["task_roles"][0],
        )
        mutation_path = evidence["dynamodb_mutation_paths"][0]
        self.assertIn(
            "table_address=aws_dynamodb_table.orders",
            mutation_path,
        )
        self.assertIn(f"table_arn={_TABLE_ARN}", mutation_path)
        self.assertIn(
            ("mutation_classes=entity_write,configuration_administration"),
            mutation_path,
        )
        self.assertIn(
            ("actions=dynamodb:PutItem,dynamodb:UpdateTable"),
            mutation_path,
        )
        self.assertIn("resource_scopes=exact_table", mutation_path)
        self.assertIn("access_state=allowed", mutation_path)
        self.assertIn(
            "unconditional identity-policy allow for DynamoDB mutation",
            finding.rationale,
        )
        self.assertIn(
            "The DynamoDB table itself is not public",
            finding.rationale,
        )
        self.assertEqual(
            evidence["assessment_scope"],
            [
                ("establishes=unconditional identity-policy allow for exact DynamoDB mutation actions"),
                (
                    "does_not_establish=effective authorization after DynamoDB "
                    "resource policies, permissions boundaries, service control "
                    "policies, or deletion protection"
                ),
            ],
        )

    def test_non_deterministic_or_non_public_paths_remain_quiet(self) -> None:
        external_policy_arn = "arn:aws:iam::aws:policy/ExternalDynamoDbAccess"
        external_table_arn = "arn:aws:dynamodb:us-west-2:999900001111:table/external"
        cases = {
            "comparable explicit deny": [
                *_public_edge(),
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "dynamodb:PutItem", _TABLE_ARN),
                        _statement("Deny", "dynamodb:PutItem", _TABLE_ARN),
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "conditional allow": [
                *_public_edge(),
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:UpdateItem",
                            _TABLE_ARN,
                            condition={"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["tenant-123"]}},
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "incomplete task role policy": [
                *_public_edge(),
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:DeleteTable",
                            _TABLE_ARN,
                        )
                    ],
                ),
                _role_policy_attachment(
                    _TASK_ROLE_ARN,
                    external_policy_arn,
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "execution role only": [
                *_public_edge(),
                _table(),
                _role("orders_task", _TASK_ROLE_ARN, []),
                _role(
                    "orders_execution",
                    _EXECUTION_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:DeleteTable",
                            _TABLE_ARN,
                        )
                    ],
                ),
                _task_definition(),
                _service(),
            ],
            "index only": [
                *_public_edge(),
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:PutItem",
                            _INDEX_ARN,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "external exact table": [
                *_public_edge(),
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:PutItem",
                            external_table_arn,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "non-exact table": [
                *_public_edge(),
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:PutItem",
                            ("arn:aws:dynamodb:us-east-1:111122223333:table/orders-*"),
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "internal load balancer": [
                *_public_edge(internal=True),
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:DeleteTable",
                            _TABLE_ARN,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "unresolved task definition": [
                *_public_edge(),
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:DeleteTable",
                            _TABLE_ARN,
                        )
                    ],
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
