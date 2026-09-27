from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_ecs_dynamodb_access_paths import (
    _EXECUTION_ROLE_ARN,
    _TABLE_ARN,
    _TASK_ROLE_ARN,
    _task_definition,
)
from tests.providers.aws.test_aws_ecs_dynamodb_item_deletion_paths import (
    _resource,
    _role,
    _statement,
    _symbolic_resolution,
    _table,
)
from tests.providers.aws.test_aws_public_ecs_dynamodb_mutation_rules import (
    _public_edge,
    _service,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_DISRUPTION_RULE_ID = "aws-public-ecs-dynamodb-item-disruption"
_MUTATION_RULE_ID = "aws-public-ecs-dynamodb-mutation-access"


def _evaluate(
    resources: list[TerraformResource],
    rule_ids: set[str],
):
    inventory = AwsNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )
    return inventory, findings


def _runtime_resources(
    actions: str | list[str],
    *,
    pitr: str = "enabled",
) -> list[TerraformResource]:
    return [
        *_public_edge(),
        _table(pitr=pitr),
        _role(
            "orders_task",
            _TASK_ROLE_ARN,
            [_statement("Allow", actions, _TABLE_ARN)],
        ),
        _task_definition(execution_role_arn=None),
        _service(),
    ]


def _reevaluate(inventory):
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_DISRUPTION_RULE_ID})),
    )


class AwsPublicEcsDynamoDbItemDisruptionRuleTests(unittest.TestCase):
    def test_rule_id_is_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_DISRUPTION_RULE_ID, registered)

    def test_delete_operations_emit_dos_with_operation_exact_evidence(
        self,
    ) -> None:
        _, findings = _evaluate(
            _runtime_resources(
                [
                    "dynamodb:DeleteItem",
                    "dynamodb:PartiQLDelete",
                    "dynamodb:BatchWriteItem",
                ]
            ),
            {_DISRUPTION_RULE_ID},
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [_DISRUPTION_RULE_ID],
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
        deletion_paths = evidence["dynamodb_item_deletion_paths"]
        self.assertEqual(len(deletion_paths), 3)
        expected = {
            "dynamodb:DeleteItem": (
                "operation_class=item_deletion",
                "internal_operation=delete_item",
            ),
            "dynamodb:PartiQLDelete": (
                "operation_class=item_deletion",
                "internal_operation=partiql_delete",
            ),
            "dynamodb:BatchWriteItem": (
                "operation_class=batch_item_deletion",
                "internal_operation=batch_write_delete",
            ),
        }
        for operation, fragments in expected.items():
            record = next(value for value in deletion_paths if f"operation={operation}" in value)
            self.assertIn(fragments[0], record)
            self.assertIn(fragments[1], record)
            self.assertIn(
                "target_granularity=table_item_namespace",
                record,
            )
            self.assertIn(
                "target_scope=exact_table_item_namespace",
                record,
            )
            self.assertIn("authorization_state=allowed", record)

        self.assertEqual(len(evidence["recovery_evidence"]), 3)
        self.assertTrue(
            all("recovery_state=point_in_time_recovery_enabled" in value for value in evidence["recovery_evidence"])
        )
        self.assertTrue(
            all("successful_recovery_not_established=true" in value for value in evidence["recovery_evidence"])
        )
        self.assertIn(
            "does not establish a specific item target",
            finding.rationale,
        )

    def test_item_deletion_is_dos_while_batch_write_remains_tampering(
        self,
    ) -> None:
        cases = {
            "dynamodb:PutItem": {_MUTATION_RULE_ID},
            "dynamodb:DeleteItem": {_DISRUPTION_RULE_ID},
            "dynamodb:PartiQLDelete": {_DISRUPTION_RULE_ID},
            "dynamodb:BatchWriteItem": {
                _MUTATION_RULE_ID,
                _DISRUPTION_RULE_ID,
            },
            "write_and_delete": {
                _MUTATION_RULE_ID,
                _DISRUPTION_RULE_ID,
            },
        }
        for case, expected_rule_ids in cases.items():
            actions: str | list[str] = (
                ["dynamodb:PutItem", "dynamodb:DeleteItem"] if case == "write_and_delete" else case
            )
            with self.subTest(case=case):
                _, findings = _evaluate(
                    _runtime_resources(actions),
                    {_MUTATION_RULE_ID, _DISRUPTION_RULE_ID},
                )

                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    expected_rule_ids,
                )

    def test_batch_write_tampering_evidence_excludes_delete_class(self) -> None:
        _, findings = _evaluate(
            _runtime_resources("dynamodb:BatchWriteItem"),
            {_MUTATION_RULE_ID},
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [_MUTATION_RULE_ID],
        )
        evidence = {item.key: item.values for item in findings[0].evidence}
        path = evidence["dynamodb_mutation_paths"][0]
        self.assertIn("mutation_classes=entity_write", path)
        self.assertNotIn("entity_delete", path)
        self.assertIn("actions=dynamodb:BatchWriteItem", path)

    def test_multiple_exact_tables_increase_blast_radius(self) -> None:
        archive_arn = "arn:aws:dynamodb:us-east-1:111122223333:table/archive"
        archive = _resource(
            "aws_dynamodb_table",
            "archive",
            {
                "id": "archive",
                "name": "archive",
                "arn": archive_arn,
            },
        )
        resources = [
            *_public_edge(),
            _table(),
            archive,
            _role(
                "orders_task",
                _TASK_ROLE_ARN,
                [
                    _statement(
                        "Allow",
                        "dynamodb:DeleteItem",
                        [_TABLE_ARN, archive_arn],
                    )
                ],
            ),
            _task_definition(execution_role_arn=None),
            _service(),
        ]

        _, findings = _evaluate(resources, {_DISRUPTION_RULE_ID})

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity_reasoning.blast_radius, 2)
        self.assertIn("across 2 exact modeled DynamoDB tables", finding.rationale)
        self.assertTrue(
            {
                "aws_dynamodb_table.orders",
                "aws_dynamodb_table.archive",
            }
            <= set(finding.affected_resources)
        )

    def test_private_service_retains_path_but_emits_no_finding(self) -> None:
        resources = [
            resource for resource in _runtime_resources("dynamodb:DeleteItem") if resource.resource_type != "aws_lb"
        ]
        inventory, findings = _evaluate(
            resources,
            {_DISRUPTION_RULE_ID},
        )
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None

        self.assertEqual(
            len(aws_facts(service).ecs_dynamodb_item_deletion_paths),
            1,
        )
        self.assertEqual(findings, [])

    def test_pitr_posture_changes_recovery_evidence_not_authority(
        self,
    ) -> None:
        expected_states = {
            "enabled": (
                "pitr_state=enabled",
                "recovery_state=point_in_time_recovery_enabled",
            ),
            "disabled": (
                "pitr_state=disabled",
                "recovery_state=point_in_time_recovery_not_enabled",
            ),
            "omitted": (
                "pitr_state=not_configured",
                "recovery_state=point_in_time_recovery_not_enabled",
            ),
            "unknown": (
                "pitr_state=unknown",
                "recovery_state=recovery_posture_unknown",
            ),
        }
        for pitr, fragments in expected_states.items():
            with self.subTest(pitr=pitr):
                _, findings = _evaluate(
                    _runtime_resources(
                        "dynamodb:DeleteItem",
                        pitr=pitr,
                    ),
                    {_DISRUPTION_RULE_ID},
                )

                self.assertEqual(len(findings), 1)
                evidence = {item.key: item.values for item in findings[0].evidence}
                recovery = evidence["recovery_evidence"][0]
                self.assertIn(fragments[0], recovery)
                self.assertIn(fragments[1], recovery)
                if pitr == "unknown":
                    self.assertTrue(evidence["dynamodb_item_deletion_path_uncertainties"])

    def test_exact_symbolic_runtime_and_table_references_survive_rule_revalidation(
        self,
    ) -> None:
        role_reference = "aws_iam_role.orders_task.arn"
        table_reference = "aws_dynamodb_table.orders.arn"
        table = _resource(
            "aws_dynamodb_table",
            "orders",
            {"id": "orders", "name": "orders"},
            unknown_values={"arn": True},
        )
        role = _role(
            "orders_task",
            None,
            [
                _statement(
                    "Allow",
                    "dynamodb:DeleteItem",
                    table_reference,
                )
            ],
        )
        role.reference_resolutions = (
            _symbolic_resolution(
                ("inline_policy", 0, "policy"),
                table_reference,
                "aws_dynamodb_table.orders",
            ),
        )
        task = _resource(
            "aws_ecs_task_definition",
            "orders",
            {
                "family": "orders",
                "revision": 1,
                "network_mode": "awsvpc",
                "container_definitions": '[{"name":"orders","portMappings":[{"containerPort":8080,"protocol":"tcp"}]}]',
            },
            unknown_values={"task_role_arn": True},
            reference_resolutions=(
                _symbolic_resolution(
                    ("task_role_arn",),
                    role_reference,
                    "aws_iam_role.orders_task",
                ),
            ),
        )

        _, findings = _evaluate(
            [
                *_public_edge(),
                table,
                role,
                task,
                _service(),
            ],
            {_DISRUPTION_RULE_ID},
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [_DISRUPTION_RULE_ID],
        )
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertIn(
            f"reference={role_reference}",
            evidence["task_roles"][0],
        )
        self.assertIn("arn=unknown", evidence["task_roles"][0])
        self.assertIn(
            f"table_reference={table_reference}",
            evidence["dynamodb_item_deletion_paths"][0],
        )
        self.assertIn(
            "table_arn=unknown",
            evidence["dynamodb_item_deletion_paths"][0],
        )

    def test_symbolic_policy_reference_with_known_table_arn_emits_finding(
        self,
    ) -> None:
        table_reference = "aws_dynamodb_table.orders.arn"
        role = _role(
            "orders_task",
            _TASK_ROLE_ARN,
            [
                _statement(
                    "Allow",
                    "dynamodb:DeleteItem",
                    table_reference,
                )
            ],
        )
        role.reference_resolutions = (
            _symbolic_resolution(
                ("inline_policy", 0, "policy"),
                table_reference,
                "aws_dynamodb_table.orders",
            ),
        )

        _, findings = _evaluate(
            [
                *_public_edge(),
                _table(),
                role,
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            {_DISRUPTION_RULE_ID},
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [_DISRUPTION_RULE_ID],
        )
        evidence = {item.key: item.values for item in findings[0].evidence}
        deletion_path = evidence["dynamodb_item_deletion_paths"][0]
        self.assertIn(
            f"table_reference={table_reference}",
            deletion_path,
        )
        self.assertIn(f"table_arn={_TABLE_ARN}", deletion_path)
        self.assertIn(
            f"policy_resources={table_reference}",
            deletion_path,
        )

    def test_current_service_task_role_operation_and_recovery_are_revalidated(
        self,
    ) -> None:
        inventory, findings = _evaluate(
            _runtime_resources("dynamodb:DeleteItem"),
            {_DISRUPTION_RULE_ID},
        )
        self.assertEqual(len(findings), 1)
        service = inventory.get_by_address("aws_ecs_service.orders")
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        table = inventory.get_by_address("aws_dynamodb_table.orders")
        assert service is not None
        assert task is not None
        assert table is not None
        service_facts = aws_facts(service)
        task_facts = aws_facts(task)
        path = dict(service_facts.ecs_dynamodb_item_deletion_paths[0])

        service.set_metadata_field(
            AwsResourceMetadata.RESOLVED_TASK_DEFINITION_ADDRESSES,
            [],
        )
        self.assertEqual(_reevaluate(inventory), [])
        service.set_metadata_field(
            AwsResourceMetadata.RESOLVED_TASK_DEFINITION_ADDRESSES,
            [task.address],
        )

        task_facts.set_task_role_arn(_EXECUTION_ROLE_ARN)
        self.assertEqual(_reevaluate(inventory), [])
        task_facts.set_task_role_arn(_TASK_ROLE_ARN)

        stale = dict(path)
        stale["matched_actions"] = [
            "dynamodb:DeleteItem",
            "dynamodb:PartiQLDelete",
        ]
        service_facts.set_ecs_dynamodb_item_deletion_paths([stale])
        self.assertEqual(_reevaluate(inventory), [])

        service_facts.set_ecs_dynamodb_item_deletion_paths([path])
        recovery = dict(path["recovery_evidence"])
        recovery["pitr_state"] = "disabled"
        stale = {**path, "recovery_evidence": recovery}
        service_facts.set_ecs_dynamodb_item_deletion_paths([stale])
        self.assertEqual(_reevaluate(inventory), [])

        service_facts.set_ecs_dynamodb_item_deletion_paths([path])
        current_access_paths = task_facts.ecs_dynamodb_access_paths
        task_facts.set_ecs_dynamodb_access_paths([])
        self.assertEqual(_reevaluate(inventory), [])
        task_facts.set_ecs_dynamodb_access_paths(current_access_paths)

        table.set_metadata_field(
            AwsResourceMetadata.DYNAMODB_PITR_STATE,
            "disabled",
        )
        table.set_metadata_field(
            AwsResourceMetadata.DYNAMODB_PITR_RECOVERY_PERIOD_DAYS,
            None,
        )
        self.assertEqual(_reevaluate(inventory), [])

    def test_conditional_denied_and_incomplete_authority_stays_quiet(
        self,
    ) -> None:
        cases = {
            "conditional": [
                _statement(
                    "Allow",
                    "dynamodb:DeleteItem",
                    _TABLE_ARN,
                    condition={
                        "ForAllValues:StringEquals": {
                            "dynamodb:LeadingKeys": ["tenant-123"],
                        }
                    },
                )
            ],
            "denied": [
                _statement(
                    "Allow",
                    "dynamodb:DeleteItem",
                    _TABLE_ARN,
                ),
                _statement(
                    "Deny",
                    "dynamodb:DeleteItem",
                    _TABLE_ARN,
                ),
            ],
        }
        for case, statements in cases.items():
            with self.subTest(case=case):
                resources = [
                    *_public_edge(),
                    _table(),
                    _role(
                        "orders_task",
                        _TASK_ROLE_ARN,
                        statements,
                    ),
                    _task_definition(execution_role_arn=None),
                    _service(),
                ]
                _, findings = _evaluate(
                    resources,
                    {_DISRUPTION_RULE_ID},
                )

                self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
