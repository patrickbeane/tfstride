from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_ecs_sqs_message_removal_paths import (
    _ACCOUNT_ID,
    _DELETE,
    _PURGE,
    _QUEUE_ARN,
    _RECEIVE,
    _queue,
    _role,
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
from tfstride.models import StrideCategory, TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_RULE_ID = "aws-public-ecs-sqs-message-disruption"
_MUTATION_RULE = "aws-public-ecs-messaging-mutation-access"


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
    return inventory, findings


def _public_resources(
    actions: str | list[str],
    *,
    queue: TerraformResource | None = None,
    internal: bool = False,
) -> list[TerraformResource]:
    return [
        *_load_balancer_path(internal=internal),
        queue or _queue(),
        _role([_statement("Allow", actions, (queue or _queue()).values["arn"])]),
        _task_definition(),
        _service(),
    ]


class AwsPublicEcsSqsMessageDisruptionRuleTests(unittest.TestCase):
    def test_rule_id_is_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}
        self.assertIn(_RULE_ID, registered)

    def test_receive_delete_and_purge_emit_dos_without_tampering_leakage(self) -> None:
        queue = _queue(delivery_posture=True)
        inventory, findings = _evaluate(
            _public_resources([_RECEIVE, _DELETE, _PURGE], queue=queue),
            rule_ids=frozenset({_RULE_ID, _MUTATION_RULE}),
        )
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.category, StrideCategory.DENIAL_OF_SERVICE)
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
        self.assertEqual(len(evidence["sqs_message_removal_paths"]), 2)
        self.assertTrue(
            any(
                "operation=sqs:DeleteMessage" in value
                and "prerequisite_operation=sqs:ReceiveMessage" in value
                and "receipt_handle_source=runtime_receive_response" in value
                for value in evidence["sqs_message_removal_paths"]
            )
        )
        self.assertTrue(
            any(
                "operation=sqs:PurgeQueue" in value and "prerequisite_operation=none" in value
                for value in evidence["sqs_message_removal_paths"]
            )
        )
        self.assertEqual(len(evidence["delivery_and_recovery_evidence"]), 2)
        for value in evidence["delivery_and_recovery_evidence"]:
            self.assertIn("message_retention_seconds=345600", value)
            self.assertIn("redrive_state=configured", value)
            self.assertIn(
                "removed_message_recovery_state=not_established_by_modeled_sqs_delivery_controls",
                value,
            )
            self.assertIn("successful_removal_not_established=true", value)
            self.assertIn("successful_recovery_not_established=true", value)
        self.assertIn("required receipt handle", finding.rationale)
        self.assertIn("do not establish successful removal", finding.rationale)
        self.assertEqual(
            [path["operation"] for path in aws_facts(service).ecs_sqs_message_removal_paths],
            [_DELETE, _PURGE],
        )

    def test_send_and_removal_authority_emit_both_categories(self) -> None:
        _, findings = _evaluate(
            _public_resources(["sqs:SendMessage", _RECEIVE, _DELETE]),
            rule_ids=frozenset({_RULE_ID, _MUTATION_RULE}),
        )
        self.assertEqual(
            {finding.rule_id for finding in findings},
            {_RULE_ID, _MUTATION_RULE},
        )
        by_rule = {finding.rule_id: finding for finding in findings}
        mutation_evidence = {item.key: item.values for item in by_rule[_MUTATION_RULE].evidence}
        disruption_evidence = {item.key: item.values for item in by_rule[_RULE_ID].evidence}
        self.assertIn(
            "actions=sqs:SendMessage",
            mutation_evidence["messaging_mutation_paths"][0],
        )
        self.assertNotIn(
            _DELETE,
            mutation_evidence["messaging_mutation_paths"][0],
        )
        self.assertIn(
            f"operation={_DELETE}",
            disruption_evidence["sqs_message_removal_paths"][0],
        )

    def test_delete_requires_receive_but_purge_is_independent(self) -> None:
        delete_inventory, delete_findings = _evaluate(_public_resources(_DELETE))
        delete_service = delete_inventory.get_by_address("aws_ecs_service.orders")
        assert delete_service is not None
        self.assertEqual(delete_findings, [])
        self.assertEqual(
            aws_facts(delete_service).ecs_sqs_message_removal_paths,
            [],
        )

        _, purge_findings = _evaluate(_public_resources(_PURGE))
        self.assertEqual([finding.rule_id for finding in purge_findings], [_RULE_ID])
        evidence = {item.key: item.values for item in purge_findings[0].evidence}
        self.assertIn(
            f"operation={_PURGE}",
            evidence["sqs_message_removal_paths"][0],
        )
        self.assertIn(
            "prerequisite_operation=none",
            evidence["sqs_message_removal_paths"][0],
        )

    def test_single_operation_rationales_do_not_claim_other_removal_authority(
        self,
    ) -> None:
        _, delete_findings = _evaluate(
            _public_resources([_RECEIVE, _DELETE]),
        )
        self.assertEqual(len(delete_findings), 1)
        delete_rationale = delete_findings[0].rationale
        self.assertIn(
            "remove messages after receiving the required runtime receipt handles",
            delete_rationale,
        )
        self.assertNotIn("purge", delete_rationale.casefold())

        _, purge_findings = _evaluate(_public_resources(_PURGE))
        self.assertEqual(len(purge_findings), 1)
        purge_rationale = purge_findings[0].rationale
        self.assertIn(
            "purge the queue's available messages",
            purge_rationale,
        )
        self.assertNotIn("receipt handle", purge_rationale.casefold())
        self.assertNotIn("remove messages after receiving", purge_rationale)

    def test_redrive_evidence_preserves_configured_absent_and_unknown_states(
        self,
    ) -> None:
        configured = _queue(delivery_posture=True)
        not_configured = _queue()
        unknown = _queue()
        unknown.unknown_values["redrive_policy"] = True
        cases = (
            (
                "configured",
                configured,
                (
                    "redrive_state=configured",
                    f"redrive_target_arn=arn:aws:sqs:us-east-1:{_ACCOUNT_ID}:orders-dlq",
                    "redrive_max_receive_count=5",
                ),
            ),
            (
                "not configured",
                not_configured,
                (
                    "redrive_state=not_configured",
                    "redrive_target_arn=not_applicable",
                    "redrive_max_receive_count=not_applicable",
                ),
            ),
            (
                "unknown",
                unknown,
                (
                    "redrive_state=unknown",
                    "redrive_target_arn=unknown",
                    "redrive_max_receive_count=unknown",
                ),
            ),
        )
        for case, queue, expected_fragments in cases:
            with self.subTest(case=case):
                _, findings = _evaluate(
                    _public_resources([_RECEIVE, _DELETE], queue=queue),
                )
                self.assertEqual(len(findings), 1)
                evidence = {item.key: item.values for item in findings[0].evidence}
                delivery_values = evidence["delivery_and_recovery_evidence"]
                self.assertEqual(len(delivery_values), 1)
                for fragment in expected_fragments:
                    self.assertIn(fragment, delivery_values[0])

    def test_private_service_retains_paths_without_public_finding(self) -> None:
        inventory, findings = _evaluate(_public_resources([_RECEIVE, _DELETE], internal=True))
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert service is not None
        self.assertEqual(findings, [])
        self.assertEqual(
            [path["operation"] for path in aws_facts(service).ecs_sqs_message_removal_paths],
            [_DELETE],
        )

    def test_valid_purge_path_preserves_unresolved_delete_prerequisite(self) -> None:
        _, findings = _evaluate(_public_resources([_DELETE, _PURGE]))
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertEqual(len(evidence["sqs_message_removal_paths"]), 1)
        self.assertIn(
            f"operation={_PURGE}",
            evidence["sqs_message_removal_paths"][0],
        )
        self.assertTrue(evidence["sqs_message_removal_path_uncertainties"])
        self.assertTrue(
            any("receipt-handle prerequisite" in value for value in evidence["sqs_message_removal_path_uncertainties"])
        )

    def test_multiple_exact_queues_expand_blast_radius(self) -> None:
        second_arn = f"arn:aws:sqs:us-east-1:{_ACCOUNT_ID}:archive"
        resources = [
            *_load_balancer_path(),
            _queue(resource_name="orders"),
            _queue(arn=second_arn, resource_name="archive"),
            _role(
                [
                    _statement(
                        "Allow",
                        [_RECEIVE, _DELETE],
                        f"arn:aws:sqs:us-east-1:{_ACCOUNT_ID}:*",
                    )
                ]
            ),
            _task_definition(),
            _service(),
        ]
        _, findings = _evaluate(resources)
        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        self.assertEqual(findings[0].severity_reasoning.blast_radius, 2)
        self.assertIn("aws_sqs_queue.orders", findings[0].affected_resources)
        self.assertIn("aws_sqs_queue.archive", findings[0].affected_resources)
        self.assertIn("across 2 exact modeled SQS queues", findings[0].rationale)

    def test_stale_service_path_evidence_fails_closed(self) -> None:
        mutators = {
            "task path removed": lambda inventory, service, path: aws_facts(
                inventory.get_by_address("aws_ecs_task_definition.orders")
            ).set_ecs_sqs_message_removal_paths([]),
            "authorization sources changed": lambda inventory, service, path: path.__setitem__(
                "authorization_source_addresses",
                [],
            ),
            "queue arn changed": lambda inventory, service, path: path.__setitem__(
                "queue_arn",
                "arn:aws:sqs:us-east-1:111122223333:other",
            ),
            "delivery evidence changed": lambda inventory, service, path: path["delivery_evidence"].__setitem__(
                "redrive_state", "configured"
            ),
            "authorization operation changed": lambda inventory, service, path: path[
                "removal_authorization"
            ].__setitem__("matched_actions", [_PURGE]),
        }
        for case, mutate in mutators.items():
            with self.subTest(case=case):
                inventory = AwsNormalizer().normalize(_public_resources([_RECEIVE, _DELETE]))
                service = inventory.get_by_address("aws_ecs_service.orders")
                assert service is not None
                service_facts = aws_facts(service)
                paths = service_facts.ecs_sqs_message_removal_paths
                path = paths[0]
                mutate(inventory, service, path)
                service_facts.set_ecs_sqs_message_removal_paths(paths)
                findings = StrideRuleEngine().evaluate(
                    inventory,
                    detect_trust_boundaries(inventory),
                    rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
                )
                self.assertEqual(findings, [])

    def test_current_unsupported_queue_policy_invalidates_cached_allow_path(
        self,
    ) -> None:
        allow = _statement(
            "Allow",
            [_RECEIVE, _DELETE],
            _QUEUE_ARN,
            principal={"AWS": f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-task"},
        )
        inventory = AwsNormalizer().normalize(
            [
                *_load_balancer_path(),
                _queue(policy=[allow]),
                _role([]),
                _task_definition(),
                _service(),
            ]
        )
        service = inventory.get_by_address("aws_ecs_service.orders")
        queue = inventory.get_by_address("aws_sqs_queue.orders")
        assert service is not None
        assert queue is not None
        self.assertEqual(
            [path["operation"] for path in aws_facts(service).ecs_sqs_message_removal_paths],
            [_DELETE],
        )

        replacement_inventory = AwsNormalizer().normalize(
            [
                _queue(
                    policy=[
                        allow,
                        {
                            "Effect": "Deny",
                            "Principal": {"AWS": (f"arn:aws:iam::{_ACCOUNT_ID}:role/orders-task")},
                            "NotAction": "sqs:SendMessage",
                            "Resource": _QUEUE_ARN,
                        },
                    ]
                )
            ]
        )
        replacement = replacement_inventory.get_by_address("aws_sqs_queue.orders")
        assert replacement is not None
        queue.policy_statements = replacement.policy_statements
        queue.set_metadata_field(
            AwsResourceMetadata.POLICY_DOCUMENT,
            aws_facts(replacement).policy_document,
        )
        self.assertEqual(aws_facts(queue).sqs_queue_policy_state, "configured")

        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
        )
        self.assertEqual(findings, [])

    def test_current_policy_deny_invalidates_cached_allow_path(self) -> None:
        inventory = AwsNormalizer().normalize(_public_resources([_RECEIVE, _DELETE]))
        role = inventory.get_by_address("aws_iam_role.orders_task")
        assert role is not None
        deny_inventory = AwsNormalizer().normalize(
            [
                _role(
                    [
                        _statement(
                            "Deny",
                            _DELETE,
                            _QUEUE_ARN,
                        )
                    ]
                )
            ]
        )
        deny_role = deny_inventory.get_by_address("aws_iam_role.orders_task")
        assert deny_role is not None
        role.policy_statements = (*role.policy_statements, *deny_role.policy_statements)

        findings = StrideRuleEngine().evaluate(
            inventory,
            detect_trust_boundaries(inventory),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
