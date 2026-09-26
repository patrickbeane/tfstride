from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_ecs_messaging_topology_destruction_paths import (
    _ACCOUNT_ID,
    _QUEUE_ARN,
    _TOPIC_ARN,
    _queue,
    _resource_policy_statement,
    _role,
    _statement,
    _task_definition,
    _topic,
    _with_policy,
)
from tests.providers.aws.test_aws_public_ecs_messaging_mutation_rules import (
    _load_balancer_path,
    _service,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, ResourceInventory, StrideCategory, TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.policy_documents import parse_policy_statement
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_RULE_ID = "aws-public-ecs-messaging-topology-disruption"
_MUTATION_RULE_ID = "aws-public-ecs-messaging-mutation-access"
_DELETE_QUEUE = "sqs:DeleteQueue"
_DELETE_TOPIC = "sns:DeleteTopic"


def _evaluate(
    resources: list[TerraformResource],
    *,
    rule_ids: frozenset[str] = frozenset({_RULE_ID}),
) -> tuple[ResourceInventory, list[Finding]]:
    inventory = AwsNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )
    return inventory, findings


def _reevaluate(inventory: ResourceInventory) -> list[Finding]:
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _public_resources(
    actions: list[tuple[str, str]],
    *,
    internal: bool = False,
    queue: TerraformResource | None = None,
    topic: TerraformResource | None = None,
) -> list[TerraformResource]:
    queue_resource = queue or _queue()
    topic_resource = topic or _topic()
    statements = [_statement("Allow", operation, resource) for operation, resource in actions]
    return [
        *_load_balancer_path(internal=internal),
        queue_resource,
        topic_resource,
        _role("orders_task", f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-task", statements),
        _task_definition(execution_role_arn=None),
        _service(),
    ]


class AwsPublicEcsMessagingTopologyDisruptionRuleTests(unittest.TestCase):
    def test_rule_id_is_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

    def test_topology_deletion_is_not_tampering_when_both_rules_are_enabled(self) -> None:
        cases = (
            ("queue", [(_DELETE_QUEUE, _QUEUE_ARN)]),
            ("topic", [(_DELETE_TOPIC, _TOPIC_ARN)]),
        )
        for case, actions in cases:
            with self.subTest(case=case):
                _, findings = _evaluate(
                    _public_resources(actions),
                    rule_ids=frozenset({_RULE_ID, _MUTATION_RULE_ID}),
                )
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [_RULE_ID],
                )

    def test_send_or_publish_remains_tampering_without_topology_disruption(self) -> None:
        _, findings = _evaluate(
            _public_resources([("sqs:SendMessage", _QUEUE_ARN)]),
            rule_ids=frozenset({_RULE_ID, _MUTATION_RULE_ID}),
        )
        self.assertEqual(
            [finding.rule_id for finding in findings],
            [_MUTATION_RULE_ID],
        )

    def test_public_queue_and_topic_deletion_emit_one_dos_finding(self) -> None:
        inventory, findings = _evaluate(
            _public_resources(
                [
                    (_DELETE_QUEUE, _QUEUE_ARN),
                    (_DELETE_TOPIC, _TOPIC_ARN),
                ]
            )
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, _RULE_ID)
        self.assertEqual(finding.category, StrideCategory.DENIAL_OF_SERVICE)
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
        self.assertEqual(len(evidence["messaging_topology_destruction_paths"]), 2)
        self.assertEqual(len(evidence["topology_deletion_outcome_evidence"]), 2)
        self.assertTrue(
            all(
                "successful_deletion_observed=False" in value
                and "descendant_impact_evaluated=False" in value
                and "out_of_plan_topology_evaluated=False" in value
                for value in evidence["topology_deletion_outcome_evidence"]
            )
        )
        self.assertIn("delete exact modeled SQS queues or SNS topics", finding.rationale)
        self.assertIn("does not establish successful deletion", finding.rationale)
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None
        self.assertEqual(
            {path["operation"] for path in aws_facts(service).ecs_messaging_topology_destruction_paths},
            {_DELETE_QUEUE, _DELETE_TOPIC},
        )

    def test_single_operation_rationales_do_not_claim_other_topology(self) -> None:
        _, queue_findings = _evaluate(_public_resources([(_DELETE_QUEUE, _QUEUE_ARN)]))
        self.assertEqual(len(queue_findings), 1)
        self.assertIn("delete exact modeled SQS queues", queue_findings[0].rationale)
        self.assertNotIn("SNS topics", queue_findings[0].rationale)

        _, topic_findings = _evaluate(_public_resources([(_DELETE_TOPIC, _TOPIC_ARN)]))
        self.assertEqual(len(topic_findings), 1)
        self.assertIn("delete exact modeled SNS topics", topic_findings[0].rationale)
        self.assertNotIn("SQS queues", topic_findings[0].rationale)

    def test_private_paths_survive_without_public_finding(self) -> None:
        inventory, findings = _evaluate(
            _public_resources(
                [(_DELETE_QUEUE, _QUEUE_ARN)],
                internal=True,
            )
        )
        self.assertEqual(findings, [])
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None
        self.assertEqual(
            len(aws_facts(service).ecs_messaging_topology_destruction_paths),
            1,
        )

    def test_duplicate_paths_on_one_target_count_target_once(self) -> None:
        inventory, _ = _evaluate(_public_resources([(_DELETE_QUEUE, _QUEUE_ARN)]))
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None
        service_paths = aws_facts(service).ecs_messaging_topology_destruction_paths
        service_paths.append(service_paths[0].copy())

        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity_reasoning.blast_radius, 1)
        self.assertEqual(
            findings[0].affected_resources.count("aws_sqs_queue.orders"),
            1,
        )

    def test_stale_projected_target_evidence_is_rejected(self) -> None:
        inventory, _ = _evaluate(_public_resources([(_DELETE_QUEUE, _QUEUE_ARN)]))
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None
        service_paths = aws_facts(service).ecs_messaging_topology_destruction_paths
        stale_paths = [path.copy() for path in service_paths]
        stale_paths[0]["messaging_resource_arn"] = "arn:aws:sqs:us-east-1:111122223333:stale"
        aws_facts(service).set(
            AwsResourceMetadata.ECS_MESSAGING_TOPOLOGY_DESTRUCTION_PATHS,
            stale_paths,
        )

        boundaries = detect_trust_boundaries(inventory)
        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
        )
        self.assertEqual(findings, [])

    def test_current_identity_delete_allow_removal_rejects_cached_path(self) -> None:
        cases = (
            ("queue", _DELETE_QUEUE, _QUEUE_ARN),
            ("topic", _DELETE_TOPIC, _TOPIC_ARN),
        )
        for case, operation, target_arn in cases:
            with self.subTest(case=case):
                inventory, initial_findings = _evaluate(_public_resources([(operation, target_arn)]))
                self.assertEqual(
                    [finding.rule_id for finding in initial_findings],
                    [_RULE_ID],
                )

                role = inventory.get_by_address("aws_iam_role.orders_task")
                assert role is not None
                role.policy_statements = ()

                self.assertEqual(_reevaluate(inventory), [])

    def test_current_identity_explicit_deny_rejects_cached_path(self) -> None:
        cases = (
            ("queue", _DELETE_QUEUE, _QUEUE_ARN),
            ("topic", _DELETE_TOPIC, _TOPIC_ARN),
        )
        for case, operation, target_arn in cases:
            with self.subTest(case=case):
                inventory, initial_findings = _evaluate(_public_resources([(operation, target_arn)]))
                self.assertEqual(len(initial_findings), 1)

                role = inventory.get_by_address("aws_iam_role.orders_task")
                assert role is not None
                role.policy_statements = (
                    *role.policy_statements,
                    parse_policy_statement(_statement("Deny", operation, target_arn)),
                )

                self.assertEqual(_reevaluate(inventory), [])

    def test_current_resource_policy_allow_removal_rejects_cached_path(self) -> None:
        cases = (
            (
                "queue",
                "aws_sqs_queue.orders",
                _with_policy(
                    _queue(),
                    [
                        _resource_policy_statement(
                            "Allow",
                            _DELETE_QUEUE,
                            _QUEUE_ARN,
                        )
                    ],
                ),
                None,
                ("sqs:SendMessage", _QUEUE_ARN),
            ),
            (
                "topic",
                "aws_sns_topic.orders",
                None,
                _with_policy(
                    _topic(),
                    [
                        _resource_policy_statement(
                            "Allow",
                            _DELETE_TOPIC,
                            _TOPIC_ARN,
                        )
                    ],
                ),
                ("sns:Publish", _TOPIC_ARN),
            ),
        )
        for case, target_address, queue, topic, identity_action in cases:
            with self.subTest(case=case):
                inventory, initial_findings = _evaluate(
                    _public_resources(
                        [identity_action],
                        queue=queue,
                        topic=topic,
                    )
                )
                self.assertEqual(len(initial_findings), 1)

                target = inventory.get_by_address(target_address)
                assert target is not None
                target.policy_statements = ()
                aws_facts(target).set_policy_document({"Version": "2012-10-17", "Statement": []})

                self.assertEqual(_reevaluate(inventory), [])

    def test_current_resource_policy_explicit_deny_rejects_cached_path(self) -> None:
        cases = (
            (
                "queue",
                _DELETE_QUEUE,
                _QUEUE_ARN,
                "aws_sqs_queue.orders",
                _queue(),
            ),
            (
                "topic",
                _DELETE_TOPIC,
                _TOPIC_ARN,
                "aws_sns_topic.orders",
                _topic(),
            ),
        )
        for case, operation, target_arn, target_address, target_resource in cases:
            with self.subTest(case=case):
                inventory, initial_findings = _evaluate(
                    _public_resources(
                        [(operation, target_arn)],
                        queue=target_resource if case == "queue" else None,
                        topic=target_resource if case == "topic" else None,
                    )
                )
                self.assertEqual(len(initial_findings), 1)

                target = inventory.get_by_address(target_address)
                assert target is not None
                deny = _resource_policy_statement(
                    "Deny",
                    operation,
                    target_arn,
                )
                target.policy_statements = (parse_policy_statement(deny),)
                aws_facts(target).set_policy_document(
                    {
                        "Version": "2012-10-17",
                        "Statement": [deny],
                    }
                )
                aws_facts(target).set(
                    (
                        AwsResourceMetadata.SQS_QUEUE_POLICY_STATE
                        if case == "queue"
                        else AwsResourceMetadata.SNS_TOPIC_POLICY_STATE
                    ),
                    "configured",
                )

                self.assertEqual(_reevaluate(inventory), [])

    def test_current_conditional_or_retargeted_allow_rejects_cached_path(self) -> None:
        inventory, initial_findings = _evaluate(_public_resources([(_DELETE_QUEUE, _QUEUE_ARN)]))
        self.assertEqual(len(initial_findings), 1)
        role = inventory.get_by_address("aws_iam_role.orders_task")
        assert role is not None
        role.policy_statements = (
            parse_policy_statement(
                _statement(
                    "Allow",
                    _DELETE_QUEUE,
                    _QUEUE_ARN,
                    condition={
                        "StringEquals": {
                            "aws:RequestedRegion": "us-east-1",
                        }
                    },
                )
            ),
        )
        self.assertEqual(_reevaluate(inventory), [])

        role.policy_statements = (parse_policy_statement(_statement("Allow", _DELETE_QUEUE, _TOPIC_ARN)),)
        self.assertEqual(_reevaluate(inventory), [])

    def test_current_deterministic_allow_remains_valid(self) -> None:
        cases = (
            ("queue", _DELETE_QUEUE, _QUEUE_ARN),
            ("topic", _DELETE_TOPIC, _TOPIC_ARN),
        )
        for case, operation, target_arn in cases:
            with self.subTest(case=case):
                inventory, initial_findings = _evaluate(_public_resources([(operation, target_arn)]))
                self.assertEqual(len(initial_findings), 1)
                self.assertEqual(
                    [finding.rule_id for finding in _reevaluate(inventory)],
                    [_RULE_ID],
                )

    def test_current_target_policy_unknown_rejects_cached_path(self) -> None:
        inventory, _ = _evaluate(_public_resources([(_DELETE_QUEUE, _QUEUE_ARN)]))
        queue = inventory.get_by_address("aws_sqs_queue.orders")
        assert queue is not None
        aws_facts(queue).set(AwsResourceMetadata.SQS_QUEUE_POLICY_STATE, "unknown")

        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
        )
        self.assertEqual(findings, [])

    def test_no_execution_role_topology_authority_is_reported(self) -> None:
        resources = _public_resources([])
        resources[3] = _role(
            "orders_execution",
            f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-execution",
            [_statement("Allow", _DELETE_QUEUE, _QUEUE_ARN)],
        )
        inventory, findings = _evaluate(resources)
        self.assertEqual(findings, [])
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task is not None
        self.assertEqual(
            aws_facts(task).ecs_messaging_topology_destruction_paths,
            [],
        )
