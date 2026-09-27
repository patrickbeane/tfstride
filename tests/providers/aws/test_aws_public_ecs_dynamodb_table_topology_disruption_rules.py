from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_ecs_dynamodb_table_topology_destruction_paths import (
    _DELETE_TABLE,
    _TABLE_ARN,
    _role,
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
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_decoration.ecs_dynamodb_table_topology_destruction_paths import (
    current_ecs_dynamodb_table_topology_destruction_path,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import (
    AwsDecorationContext,
    AwsResourceIndexBuilder,
)
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_RULE_ID = "aws-public-ecs-dynamodb-table-topology-disruption"
_MUTATION_RULE_ID = "aws-public-ecs-dynamodb-mutation-access"
_ITEM_RULE_ID = "aws-public-ecs-dynamodb-item-disruption"


def _runtime_resources(
    actions: str | list[str],
    *,
    pitr: str = "enabled",
) -> list[TerraformResource]:
    return [
        *_public_edge(),
        _table(pitr=pitr),
        _role([_statement("Allow", actions, _TABLE_ARN)]),
        _task_definition(execution_role_arn=None),
        _service(),
    ]


def _evaluate(
    resources: list[TerraformResource],
    rule_ids: set[str],
):
    inventory = AwsNormalizer().normalize(resources)
    findings = StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )
    return inventory, findings


def _reevaluate(inventory, rule_ids: set[str]):
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


class AwsPublicEcsDynamoDbTableTopologyDisruptionRuleTests(unittest.TestCase):
    def test_rule_is_registered_and_positive_path_is_reported(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

        _, findings = _evaluate(
            _runtime_resources(_DELETE_TABLE),
            {_RULE_ID},
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
        evidence = {item.key: item.values for item in finding.evidence}
        path = evidence["dynamodb_table_topology_destruction_paths"][0]
        self.assertIn("operation=dynamodb:DeleteTable", path)
        self.assertIn("target_granularity=table_topology", path)
        self.assertIn("target_scope=exact_dynamodb_table", path)
        self.assertIn("grant_basis=same_account_identity_policy", path)
        self.assertIn("authorization_state=allowed", path)
        self.assertIn(
            "pitr_state=enabled",
            evidence["table_deletion_recovery_evidence"][0],
        )
        self.assertIn(
            "successful_deletion_observed=false",
            evidence["table_deletion_recovery_evidence"][0],
        )
        self.assertIn("dynamodb:DeleteTable", finding.rationale)
        self.assertIn("does_not_establish=table emptiness", " ".join(evidence["assessment_scope"]))

    def test_table_deletion_is_topology_dos_only_and_mixed_mutation_is_separate(
        self,
    ) -> None:
        for actions, expected_rule_ids in (
            (_DELETE_TABLE, {_RULE_ID}),
            (["dynamodb:PutItem", _DELETE_TABLE], {_RULE_ID, _MUTATION_RULE_ID}),
        ):
            with self.subTest(actions=actions):
                _, findings = _evaluate(
                    _runtime_resources(actions),
                    {_RULE_ID, _MUTATION_RULE_ID, _ITEM_RULE_ID},
                )
                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    expected_rule_ids,
                )
                topology = next(finding for finding in findings if finding.rule_id == _RULE_ID)
                topology_evidence = {item.key: item.values for item in topology.evidence}
                self.assertTrue(
                    all(
                        "dynamodb:DeleteTable" in value
                        for value in topology_evidence["dynamodb_table_topology_destruction_paths"]
                    )
                )
                if isinstance(actions, list):
                    mutation = next(finding for finding in findings if finding.rule_id == _MUTATION_RULE_ID)
                    mutation_evidence = {item.key: item.values for item in mutation.evidence}
                    mutation_path = mutation_evidence["dynamodb_mutation_paths"][0]
                    self.assertIn("actions=dynamodb:PutItem", mutation_path)
                    self.assertNotIn("dynamodb:DeleteTable", mutation_path)

    def test_private_service_retains_path_but_emits_no_public_finding(self) -> None:
        resources = [resource for resource in _runtime_resources(_DELETE_TABLE) if resource.resource_type != "aws_lb"]
        inventory, findings = _evaluate(resources, {_RULE_ID})
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None

        self.assertEqual(
            len(aws_facts(service).ecs_dynamodb_table_topology_destruction_paths),
            1,
        )
        self.assertEqual(findings, [])

    def test_current_allow_removal_and_deny_suppress_cached_finding(self) -> None:
        inventory, findings = _evaluate(
            _runtime_resources(_DELETE_TABLE),
            {_RULE_ID},
        )
        self.assertEqual(len(findings), 1)
        role = inventory.get_by_address("aws_iam_role.orders_task")
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        table = inventory.get_by_address("aws_dynamodb_table.orders")
        assert role is not None
        assert task is not None
        assert table is not None
        original = role.policy_statements

        role.policy_statements = ()
        self.assertEqual(_reevaluate(inventory, {_RULE_ID}), [])

        role.policy_statements = original
        deny = _statement("Deny", _DELETE_TABLE, _TABLE_ARN)
        from tfstride.providers.aws.policy_documents import parse_policy_statement

        role.policy_statements = (
            *original,
            parse_policy_statement(deny),
        )
        self.assertEqual(_reevaluate(inventory, {_RULE_ID}), [])

        role.policy_statements = original
        context = AwsDecorationContext(
            index=AwsResourceIndexBuilder().build(list(inventory.resources)),
        )
        self.assertIsNotNone(
            current_ecs_dynamodb_table_topology_destruction_path(
                task,
                table,
                context,
            )
        )

    def test_recovery_and_permission_drift_refreshes_fresh_evidence(self) -> None:
        inventory, findings = _evaluate(
            _runtime_resources(_DELETE_TABLE, pitr="unknown"),
            {_RULE_ID},
        )
        self.assertEqual(len(findings), 1)
        table = inventory.get_by_address("aws_dynamodb_table.orders")
        role = inventory.get_by_address("aws_iam_role.orders_task")
        assert table is not None
        assert role is not None
        table.set_metadata_field(AwsResourceMetadata.DYNAMODB_PITR_STATE, "enabled")
        table.set_metadata_field(
            AwsResourceMetadata.DYNAMODB_PITR_RECOVERY_PERIOD_DAYS,
            14,
        )
        table.set_metadata_field(
            AwsResourceMetadata.DYNAMODB_POSTURE_UNCERTAINTIES,
            [],
        )

        from tfstride.providers.aws.policy_documents import parse_policy_statement

        role.policy_statements = (
            parse_policy_statement(
                {
                    "Effect": "Allow",
                    "Action": [_DELETE_TABLE, "dynamodb:DescribeTable"],
                    "Resource": _TABLE_ARN,
                }
            ),
        )

        findings = _reevaluate(inventory, {_RULE_ID})
        self.assertEqual(len(findings), 1)
        evidence = {item.key: item.values for item in findings[0].evidence}
        recovery = evidence["table_deletion_recovery_evidence"][0]
        self.assertIn("pitr_state=enabled", recovery)
        self.assertNotIn("pitr_state=unknown", recovery)
        self.assertNotIn(
            "point-in-time recovery posture is unresolved",
            " ".join(
                evidence.get(
                    "dynamodb_table_topology_destruction_path_uncertainties",
                    [],
                )
            ),
        )
        self.assertIn(
            "matched_actions=dynamodb:DeleteTable",
            evidence["dynamodb_table_topology_destruction_paths"][0],
        )

    def test_stale_cached_target_is_rejected(self) -> None:
        inventory, findings = _evaluate(
            _runtime_resources(_DELETE_TABLE),
            {_RULE_ID},
        )
        self.assertEqual(len(findings), 1)
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None
        service_facts = aws_facts(service)
        stale = dict(service_facts.ecs_dynamodb_table_topology_destruction_paths[0])
        stale["table_address"] = "aws_dynamodb_table.missing"
        service_facts.set_ecs_dynamodb_table_topology_destruction_paths([stale])
        self.assertEqual(_reevaluate(inventory, {_RULE_ID}), [])


if __name__ == "__main__":
    unittest.main()
