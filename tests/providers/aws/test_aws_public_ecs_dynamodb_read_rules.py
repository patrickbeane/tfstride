from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _EXECUTION_ROLE_ARN,
    _INDEX_ARN,
    _INDEX_PATTERN_ARN,
    _TABLE_ARN,
    _TASK_ROLE_ARN,
    _role,
    _role_policy_attachment,
    _statement,
    _table,
    _task_definition,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _public_edge,
    _service,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_RULE_ID = "aws-public-ecs-dynamodb-read-access"
_MUTATION_RULE_ID = "aws-public-ecs-dynamodb-mutation-access"


def _evaluate(
    resources: list[TerraformResource],
    *,
    rule_ids: frozenset[str] = frozenset({_RULE_ID}),
):
    inventory = AwsNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )
    return inventory, boundaries, findings


class AwsPublicEcsDynamoDbReadRuleTests(unittest.TestCase):
    def test_rule_id_is_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_public_service_with_exact_table_reads_is_reported(self) -> None:
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
        read_path = evidence["dynamodb_read_paths"][0]
        self.assertIn("target_kind=table", read_path)
        self.assertIn("target_scope=exact_table", read_path)
        self.assertIn(f"target_arn={_TABLE_ARN}", read_path)
        self.assertIn("disclosure_classes=read", read_path)
        self.assertIn(
            "actions=dynamodb:GetItem,dynamodb:ConditionCheckItem",
            read_path,
        )
        self.assertIn("resource_scopes=exact_table", read_path)
        self.assertIn(
            "read_evaluation=unconditional_identity_policy_allow",
            read_path,
        )
        self.assertEqual(
            evidence["scope_profile"],
            [
                "target_count=1",
                "table_count=1",
                "broad_scope=false",
                "broad_scope_reasons=none",
            ],
        )
        self.assertIn(
            "unconditional identity-policy allow for DynamoDB read-capable actions",
            finding.rationale,
        )
        self.assertIn(
            "not guaranteed effective authorization",
            finding.rationale,
        )
        self.assertIn(
            "The DynamoDB resource itself is not public",
            finding.rationale,
        )

    def test_table_scan_has_broader_blast_radius_than_exact_index_scan(
        self,
    ) -> None:
        _, _, index_findings = _evaluate(
            [
                *_public_edge(),
                _table(index_names=("by-status",)),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "dynamodb:Scan", _INDEX_ARN)],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ]
        )
        _, _, table_findings = _evaluate(
            [
                *_public_edge(),
                _table(index_names=("by-status",)),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "dynamodb:Scan", _TABLE_ARN)],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ]
        )

        index_finding = index_findings[0]
        table_finding = table_findings[0]
        self.assertEqual(index_finding.severity_reasoning.blast_radius, 1)
        self.assertEqual(table_finding.severity_reasoning.blast_radius, 2)
        self.assertGreater(
            table_finding.severity_reasoning.final_score,
            index_finding.severity_reasoning.final_score,
        )
        index_evidence = {item.key: item.values for item in index_finding.evidence}
        table_evidence = {item.key: item.values for item in table_finding.evidence}
        self.assertIn(
            "target_kind=index",
            index_evidence["dynamodb_read_paths"][0],
        )
        self.assertIn(
            "index_name=by-status",
            index_evidence["dynamodb_read_paths"][0],
        )
        self.assertIn(
            "broad_scope_reasons=none",
            index_evidence["scope_profile"],
        )
        self.assertIn(
            "broad_scope_reasons=table_scan",
            table_evidence["scope_profile"],
        )
        self.assertIn(
            "exact index ARN",
            index_finding.rationale,
        )
        self.assertIn(
            "traverse broad table contents",
            table_finding.rationale,
        )

    def test_multiple_exact_targets_increase_blast_radius(self) -> None:
        archive_arn = "arn:aws:dynamodb:us-east-1:111122223333:table/orders-archive"
        _, _, findings = _evaluate(
            [
                *_public_edge(),
                _table(),
                _table("orders_archive", arn=archive_arn),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:GetItem",
                            [_TABLE_ARN, archive_arn],
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ]
        )

        finding = findings[0]
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(len(evidence["dynamodb_read_paths"]), 2)
        self.assertIn("target_count=2", evidence["scope_profile"])
        self.assertIn("table_count=2", evidence["scope_profile"])
        self.assertIn(
            "broad_scope_reasons=multiple_targets",
            evidence["scope_profile"],
        )

    def test_return_value_disclosure_remains_distinct_from_mutation(self) -> None:
        _, _, findings = _evaluate(
            [
                *_public_edge(),
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "dynamodb:PutItem", _TABLE_ARN)],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            rule_ids=frozenset({_RULE_ID, _MUTATION_RULE_ID}),
        )

        self.assertEqual(
            {finding.rule_id for finding in findings},
            {_RULE_ID, _MUTATION_RULE_ID},
        )
        read_finding = next(finding for finding in findings if finding.rule_id == _RULE_ID)
        evidence = {item.key: item.values for item in read_finding.evidence}
        self.assertIn(
            "disclosure_classes=return_value_read",
            evidence["dynamodb_read_paths"][0],
        )
        self.assertIn(
            "return_value_read=stored attributes may be returned",
            evidence["assessment_scope"][2],
        )

    def test_bulk_export_is_broad_but_keeps_s3_authorization_separate(
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
                            "dynamodb:ExportTableToPointInTime",
                            _TABLE_ARN,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ]
        )

        finding = findings[0]
        self.assertEqual(finding.severity_reasoning.privilege_breadth, 2)
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertIn(
            "disclosure_classes=bulk_export",
            evidence["dynamodb_read_paths"][0],
        )
        self.assertIn(
            "broad_scope_reasons=bulk_export",
            evidence["scope_profile"],
        )
        self.assertIn("destination S3 authorization", finding.rationale)
        self.assertIn(
            "destination S3 authorization is independent",
            evidence["assessment_scope"][-1],
        )

    def test_partial_index_inventory_retains_known_finding_and_broad_scope(
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
        _, _, findings = _evaluate(
            [
                *_public_edge(),
                table,
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "dynamodb:Query", _INDEX_PATTERN_ARN)],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ]
        )

        finding = findings[0]
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertIn(
            "index_inventory_state=partial",
            evidence["dynamodb_read_paths"][0],
        )
        self.assertIn(
            "broad_scope_reasons=incomplete_index_inventory",
            evidence["scope_profile"],
        )
        self.assertIn(
            "may cover additional unresolved indexes",
            finding.rationale,
        )

    def test_non_deterministic_or_non_public_paths_remain_quiet(self) -> None:
        external_policy_arn = "arn:aws:iam::aws:policy/ExternalDynamoDbRead"
        external_table_arn = "arn:aws:dynamodb:us-west-2:999900001111:table/external"
        cases = {
            "comparable explicit deny": [
                *_public_edge(),
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "dynamodb:GetItem", _TABLE_ARN),
                        _statement("Deny", "dynamodb:GetItem", _TABLE_ARN),
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
                            "dynamodb:GetItem",
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
                    [_statement("Allow", "dynamodb:Scan", _TABLE_ARN)],
                ),
                _role_policy_attachment(_TASK_ROLE_ARN, external_policy_arn),
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
                    [_statement("Allow", "dynamodb:GetItem", _TABLE_ARN)],
                ),
                _task_definition(),
                _service(),
            ],
            "external table": [
                *_public_edge(),
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "dynamodb:GetItem",
                            external_table_arn,
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "wildcard table": [
                *_public_edge(),
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "dynamodb:Scan", "*")],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "unmodeled exact index": [
                *_public_edge(),
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "dynamodb:Query", _INDEX_ARN)],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "non-disclosing batch write": [
                *_public_edge(),
                _table(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "dynamodb:BatchWriteItem", _TABLE_ARN)],
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
                    [_statement("Allow", "dynamodb:GetItem", _TABLE_ARN)],
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
                    [_statement("Allow", "dynamodb:GetItem", _TABLE_ARN)],
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
