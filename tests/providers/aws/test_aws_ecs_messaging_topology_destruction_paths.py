from __future__ import annotations

import json
import unittest
from typing import Any

from tests.providers.aws.test_aws_ecs_messaging_access_paths import (
    _ACCOUNT_ID,
    _EXECUTION_ROLE_ARN,
    _QUEUE_ARN,
    _TASK_ROLE_ARN,
    _TOPIC_ARN,
    _queue,
    _resource,
    _role,
    _role_policy_attachment,
    _service,
    _statement,
    _task_definition,
    _topic,
)
from tfstride.models import (
    TerraformReferenceProvenance,
    TerraformReferenceResolution,
    TerraformReferenceResolutionState,
    TerraformReferenceTarget,
    TerraformResource,
)
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts

_DELETE_QUEUE = "sqs:DeleteQueue"
_DELETE_TOPIC = "sns:DeleteTopic"
_EXTERNAL_ACCOUNT_ID = "999900001111"


def _symbolic_resolution(
    path: tuple[str | int, ...],
    reference: str,
    *target_addresses: str,
    state: TerraformReferenceResolutionState = (TerraformReferenceResolutionState.SYMBOLIC),
) -> TerraformReferenceResolution:
    return TerraformReferenceResolution(
        path=path,
        state=state,
        provenance=TerraformReferenceProvenance.CONFIGURATION_REFERENCE,
        references=(reference,),
        targets=tuple(
            TerraformReferenceTarget(
                address=address,
                reference=reference,
            )
            for address in target_addresses
        ),
    )


def _resource_policy_statement(
    effect: str,
    action: str,
    resource: str,
    *,
    principal: object = None,
    condition: dict[str, object] | None = None,
) -> dict[str, object]:
    statement: dict[str, object] = {
        "Effect": effect,
        "Action": action,
        "Resource": resource,
        "Principal": ({"AWS": _TASK_ROLE_ARN} if principal is None else principal),
    }
    if condition is not None:
        statement["Condition"] = condition
    return statement


def _with_policy(
    resource: TerraformResource,
    statements: list[dict[str, object]],
) -> TerraformResource:
    resource.values["policy"] = json.dumps({"Version": "2012-10-17", "Statement": statements})
    return resource


def _normalize(
    *,
    role_statements: list[dict[str, Any]] | None = None,
    queue: TerraformResource | None = None,
    topic: TerraformResource | None = None,
    task_definition: TerraformResource | None = None,
    extra: list[TerraformResource] | None = None,
):
    inventory = AwsNormalizer().normalize(
        [
            queue or _queue(),
            topic or _topic(),
            _role(
                "orders_task",
                _TASK_ROLE_ARN,
                role_statements,
            ),
            task_definition or _task_definition(),
            _service(),
            *(extra or []),
        ]
    )
    task = inventory.get_by_address("aws_ecs_task_definition.orders")
    service = inventory.get_by_address("aws_ecs_service.orders")
    assert task is not None
    assert service is not None
    return inventory, task, service


class AwsEcsMessagingTopologyDestructionPathTests(unittest.TestCase):
    def test_exact_task_role_authority_models_queue_and_topic_deletion(self) -> None:
        _inventory, task, service = _normalize(
            role_statements=[
                _statement("Allow", _DELETE_QUEUE, _QUEUE_ARN),
                _statement("Allow", _DELETE_TOPIC, _TOPIC_ARN),
            ]
        )

        task_paths = aws_facts(task).ecs_messaging_topology_destruction_paths
        service_paths = aws_facts(service).ecs_messaging_topology_destruction_paths
        paths_by_operation = {path["operation"]: path for path in task_paths}
        self.assertEqual(
            set(paths_by_operation),
            {_DELETE_QUEUE, _DELETE_TOPIC},
        )
        queue_path = paths_by_operation[_DELETE_QUEUE]
        self.assertEqual(queue_path["target_scope"], "exact_sqs_queue")
        self.assertEqual(queue_path["queue_address"], "aws_sqs_queue.orders")
        self.assertEqual(queue_path["queue_arn"], _QUEUE_ARN)
        self.assertIsNone(queue_path["topic_address"])
        self.assertEqual(queue_path["authorization_bases"], ["identity_policy"])
        self.assertEqual(
            queue_path["authorization_statements"][0]["matching_resources"],
            [_QUEUE_ARN],
        )

        topic_path = paths_by_operation[_DELETE_TOPIC]
        self.assertEqual(topic_path["target_scope"], "exact_sns_topic")
        self.assertEqual(topic_path["topic_address"], "aws_sns_topic.orders")
        self.assertEqual(topic_path["topic_arn"], _TOPIC_ARN)
        self.assertIsNone(topic_path["queue_address"])
        self.assertTrue(topic_path["same_account"])
        self.assertEqual(
            topic_path["outcome_evidence"],
            {
                "outcome_evidence_scope": ("plan_local_messaging_topology_deletion_authority"),
                "successful_deletion_observed": False,
                "recovery_state": ("not_established_by_modeled_aws_messaging_topology_evidence"),
                "descendant_impact_evaluated": False,
                "out_of_plan_topology_evaluated": False,
                "uncertainties": [],
            },
        )

        self.assertEqual(
            {path["operation"] for path in service_paths},
            {_DELETE_QUEUE, _DELETE_TOPIC},
        )
        self.assertEqual(
            {path["workload_address"] for path in service_paths},
            {service.address},
        )
        self.assertEqual(
            {path["task_definition_address"] for path in service_paths},
            {task.address},
        )
        self.assertEqual(
            {tuple(path["internet_facing_load_balancers"]) for path in service_paths},
            {()},
        )

    def test_same_account_direct_queue_and_topic_policies_are_effective(self) -> None:
        queue = _with_policy(
            _queue(),
            [
                _resource_policy_statement(
                    "Allow",
                    _DELETE_QUEUE,
                    _QUEUE_ARN,
                )
            ],
        )
        topic = _with_policy(
            _topic(),
            [
                _resource_policy_statement(
                    "Allow",
                    _DELETE_TOPIC,
                    _TOPIC_ARN,
                )
            ],
        )
        inventory, task, _service_resource = _normalize(
            queue=queue,
            topic=topic,
        )

        paths = aws_facts(task).ecs_messaging_topology_destruction_paths
        paths_by_operation = {path["operation"]: path for path in paths}
        self.assertEqual(
            paths_by_operation[_DELETE_QUEUE]["authorization_bases"],
            ["queue_policy_direct"],
        )
        self.assertEqual(
            paths_by_operation[_DELETE_TOPIC]["authorization_bases"],
            ["topic_policy_direct"],
        )
        self.assertEqual(
            paths_by_operation[_DELETE_QUEUE]["authorization_statements"][0]["source_kind"],
            "queue_policy",
        )
        self.assertEqual(
            paths_by_operation[_DELETE_TOPIC]["authorization_statements"][0]["source_kind"],
            "topic_policy",
        )
        normalized_topic = inventory.get_by_address("aws_sns_topic.orders")
        assert normalized_topic is not None
        self.assertEqual(
            aws_facts(normalized_topic).sns_topic_policy_state,
            "configured",
        )

    def test_cross_account_queue_and_topic_deletion_are_not_projected(self) -> None:
        external_queue_arn = f"arn:aws:sqs:us-east-1:{_EXTERNAL_ACCOUNT_ID}:orders"
        external_topic_arn = f"arn:aws:sns:us-east-1:{_EXTERNAL_ACCOUNT_ID}:orders-events"
        queue = _with_policy(
            _queue(arn=external_queue_arn),
            [
                _resource_policy_statement(
                    "Allow",
                    _DELETE_QUEUE,
                    external_queue_arn,
                )
            ],
        )
        queue.values["id"] = f"https://sqs.us-east-1.amazonaws.com/{_EXTERNAL_ACCOUNT_ID}/orders"
        topic = _with_policy(
            _topic(arn=external_topic_arn),
            [
                _resource_policy_statement(
                    "Allow",
                    _DELETE_TOPIC,
                    external_topic_arn,
                )
            ],
        )
        _inventory, task, service = _normalize(
            role_statements=[
                _statement("Allow", _DELETE_QUEUE, external_queue_arn),
                _statement("Allow", _DELETE_TOPIC, external_topic_arn),
            ],
            queue=queue,
            topic=topic,
        )

        self.assertEqual(
            aws_facts(task).ecs_messaging_topology_destruction_paths,
            [],
        )
        self.assertEqual(
            aws_facts(service).ecs_messaging_topology_destruction_paths,
            [],
        )

    def test_explicit_and_conditional_denies_fail_closed_by_target(self) -> None:
        queue = _with_policy(
            _queue(),
            [
                _resource_policy_statement(
                    "Deny",
                    _DELETE_QUEUE,
                    "*",
                )
            ],
        )
        topic = _with_policy(
            _topic(),
            [
                _resource_policy_statement(
                    "Deny",
                    _DELETE_TOPIC,
                    _TOPIC_ARN,
                    condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                )
            ],
        )
        _inventory, task, _service_resource = _normalize(
            role_statements=[
                _statement("Allow", _DELETE_QUEUE, _QUEUE_ARN),
                _statement("Allow", _DELETE_TOPIC, _TOPIC_ARN),
            ],
            queue=queue,
            topic=topic,
        )

        self.assertEqual(
            aws_facts(task).ecs_messaging_topology_destruction_paths,
            [],
        )
        self.assertTrue(
            any(
                "condition-dependent explicit-deny" in uncertainty
                for uncertainty in (aws_facts(task).ecs_messaging_topology_destruction_path_uncertainties)
            )
        )

    def test_unknown_and_relevant_unsupported_resource_policies_fail_closed(
        self,
    ) -> None:
        topic = _topic()
        topic.unknown_values["policy"] = True
        _inventory, task, _service_resource = _normalize(
            role_statements=[
                _statement("Allow", _DELETE_TOPIC, _TOPIC_ARN),
            ],
            topic=topic,
        )
        self.assertEqual(
            aws_facts(task).ecs_messaging_topology_destruction_paths,
            [],
        )
        self.assertTrue(
            any(
                "topic policy evidence is incomplete" in uncertainty
                for uncertainty in (aws_facts(task).ecs_messaging_topology_destruction_path_uncertainties)
            )
        )

        queue = _queue()
        queue.values["policy"] = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": {"AWS": _TASK_ROLE_ARN},
                        "Action": _DELETE_QUEUE,
                        "NotResource": "arn:aws:sqs:us-east-1:*:unrelated",
                    }
                ],
            }
        )
        _inventory, task, _service_resource = _normalize(
            role_statements=[
                _statement("Allow", _DELETE_QUEUE, _QUEUE_ARN),
            ],
            queue=queue,
        )
        self.assertEqual(
            aws_facts(task).ecs_messaging_topology_destruction_paths,
            [],
        )
        self.assertTrue(
            any(
                "incomplete or unsupported" in uncertainty
                for uncertainty in (aws_facts(task).ecs_messaging_topology_destruction_path_uncertainties)
            )
        )

    def test_unsupported_unrelated_resource_policy_operation_does_not_suppress(
        self,
    ) -> None:
        queue = _queue()
        queue.values["policy"] = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": {"AWS": _TASK_ROLE_ARN},
                        "Action": "sqs:SendMessage",
                        "NotResource": "arn:aws:sqs:us-east-1:*:unrelated",
                    }
                ],
            }
        )
        _inventory, task, _service_resource = _normalize(
            role_statements=[
                _statement("Allow", _DELETE_QUEUE, _QUEUE_ARN),
            ],
            queue=queue,
        )

        paths = aws_facts(task).ecs_messaging_topology_destruction_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["operation"], _DELETE_QUEUE)

    def test_covering_wildcard_allows_project_queue_and_topic_pattern_paths(self) -> None:
        cases = {
            "star": ("*", "*"),
            "region wildcard": (f"arn:aws:sqs:*:{_ACCOUNT_ID}:*", f"arn:aws:sns:*:{_ACCOUNT_ID}:*"),
            "name prefix": (
                f"arn:aws:sqs:us-east-1:{_ACCOUNT_ID}:ord*",
                f"arn:aws:sns:us-east-1:{_ACCOUNT_ID}:orders-*",
            ),
        }
        for case, (queue_resource, topic_resource) in cases.items():
            with self.subTest(case=case):
                _inventory, task, service = _normalize(
                    role_statements=[
                        _statement("Allow", _DELETE_QUEUE, queue_resource),
                        _statement("Allow", _DELETE_TOPIC, topic_resource),
                    ]
                )
                for workload in (task, service):
                    paths = {
                        path["operation"]: path for path in aws_facts(workload).ecs_messaging_topology_destruction_paths
                    }
                    self.assertEqual(set(paths), {_DELETE_QUEUE, _DELETE_TOPIC})
                    queue_statement = paths[_DELETE_QUEUE]["authorization_statements"][0]
                    topic_statement = paths[_DELETE_TOPIC]["authorization_statements"][0]
                    self.assertEqual(queue_statement["resource_scopes"], ["queue_pattern"])
                    self.assertEqual(queue_statement["matching_resources"], [queue_resource])
                    self.assertEqual(topic_statement["resource_scopes"], ["topic_pattern"])
                    self.assertEqual(topic_statement["matching_resources"], [topic_resource])
                    self.assertEqual(paths[_DELETE_QUEUE]["target_scope"], "exact_sqs_queue")
                    self.assertEqual(paths[_DELETE_TOPIC]["target_scope"], "exact_sns_topic")

    def test_non_covering_patterns_produce_no_path_or_uncertainty(self) -> None:
        for queue_resource, topic_resource in (
            (f"arn:aws:sqs:us-east-1:{_ACCOUNT_ID}:orders-*", f"arn:aws:sns:us-east-1:{_ACCOUNT_ID}:audit-*"),
            (f"arn:aws:sqs:us-east-1:{_EXTERNAL_ACCOUNT_ID}:*", f"arn:aws:sns:us-east-1:{_EXTERNAL_ACCOUNT_ID}:*"),
            ("arn:aws:s3:::*", "arn:aws:s3:::*"),
        ):
            with self.subTest(queue_resource=queue_resource):
                _inventory, task, _service_resource = _normalize(
                    role_statements=[
                        _statement("Allow", _DELETE_QUEUE, queue_resource),
                        _statement("Allow", _DELETE_TOPIC, topic_resource),
                    ]
                )
                facts = aws_facts(task)
                self.assertEqual(facts.ecs_messaging_topology_destruction_paths, [])
                self.assertEqual(facts.ecs_messaging_topology_destruction_path_uncertainties, [])

    def test_wildcard_resource_in_a_direct_queue_or_topic_policy_is_effective(self) -> None:
        queue = _with_policy(_queue(), [_resource_policy_statement("Allow", _DELETE_QUEUE, "*")])
        topic = _with_policy(_topic(), [_resource_policy_statement("Allow", _DELETE_TOPIC, "*")])
        _inventory, task, _service_resource = _normalize(queue=queue, topic=topic)

        paths = {path["operation"]: path for path in aws_facts(task).ecs_messaging_topology_destruction_paths}
        self.assertEqual(set(paths), {_DELETE_QUEUE, _DELETE_TOPIC})
        self.assertEqual(paths[_DELETE_QUEUE]["authorization_bases"], ["queue_policy_direct"])
        self.assertEqual(paths[_DELETE_TOPIC]["authorization_bases"], ["topic_policy_direct"])
        self.assertEqual(paths[_DELETE_QUEUE]["authorization_statements"][0]["resource_scopes"], ["queue_pattern"])
        self.assertEqual(paths[_DELETE_TOPIC]["authorization_statements"][0]["resource_scopes"], ["topic_pattern"])

    def test_non_arn_wildcard_allow_scope_is_uncertain_and_not_promoted(self) -> None:
        _inventory, task, _service_resource = _normalize(
            role_statements=[
                _statement(
                    "Allow",
                    _DELETE_QUEUE,
                    "orders*",
                )
            ]
        )

        self.assertEqual(
            aws_facts(task).ecs_messaging_topology_destruction_paths,
            [],
        )
        self.assertTrue(
            any(
                "does not identify an exact messaging resource scope" in uncertainty
                for uncertainty in (aws_facts(task).ecs_messaging_topology_destruction_path_uncertainties)
            )
        )

    def test_exact_symbolic_role_and_queue_references_preserve_provenance(
        self,
    ) -> None:
        role_reference = "aws_iam_role.orders_task.arn"
        queue_reference = "aws_sqs_queue.orders.arn"
        task_definition = _resource(
            "aws_ecs_task_definition",
            "orders",
            {
                "family": "orders",
                "revision": 1,
                "container_definitions": "[]",
                "execution_role_arn": _EXECUTION_ROLE_ARN,
            },
        )
        task_definition.unknown_values["task_role_arn"] = True
        task_definition.reference_resolutions = (
            _symbolic_resolution(
                ("task_role_arn",),
                role_reference,
                "aws_iam_role.orders_task",
            ),
        )
        role = _role(
            "orders_task",
            _TASK_ROLE_ARN,
            [_statement("Allow", _DELETE_QUEUE, queue_reference)],
        )
        role.reference_resolutions = (
            _symbolic_resolution(
                ("inline_policy", 0, "policy"),
                queue_reference,
                "aws_sqs_queue.orders",
            ),
        )
        inventory = AwsNormalizer().normalize(
            [
                _queue(),
                _topic(),
                role,
                task_definition,
                _service(),
            ]
        )
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task is not None

        paths = aws_facts(task).ecs_messaging_topology_destruction_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["role_reference"], role_reference)
        self.assertEqual(paths[0]["role_arn"], _TASK_ROLE_ARN)
        self.assertEqual(
            paths[0]["authorization_statements"][0]["matching_resources"],
            [queue_reference],
        )

    def test_symbolic_looking_policy_string_without_provenance_is_quiet(self) -> None:
        _inventory, task, _service_resource = _normalize(
            role_statements=[
                _statement(
                    "Allow",
                    _DELETE_QUEUE,
                    "aws_sqs_queue.orders.arn",
                )
            ]
        )

        self.assertEqual(
            aws_facts(task).ecs_messaging_topology_destruction_paths,
            [],
        )
        self.assertEqual(
            aws_facts(task).ecs_messaging_topology_destruction_path_uncertainties,
            [],
        )

    def test_ambiguous_symbolic_task_role_fails_closed_with_uncertainty(self) -> None:
        role_reference = "aws_iam_role.orders_task.arn"
        task_definition = _resource(
            "aws_ecs_task_definition",
            "orders",
            {
                "family": "orders",
                "revision": 1,
                "container_definitions": "[]",
            },
        )
        task_definition.unknown_values["task_role_arn"] = True
        task_definition.reference_resolutions = (
            _symbolic_resolution(
                ("task_role_arn",),
                role_reference,
                "aws_iam_role.orders_task",
                "aws_iam_role.other_task",
                state=TerraformReferenceResolutionState.AMBIGUOUS,
            ),
        )
        inventory = AwsNormalizer().normalize(
            [
                _queue(),
                _topic(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", _DELETE_QUEUE, _QUEUE_ARN)],
                ),
                _role(
                    "other_task",
                    f"arn:aws:iam::{_ACCOUNT_ID}:role/other-task",
                    [],
                ),
                task_definition,
            ]
        )
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task is not None

        self.assertEqual(
            aws_facts(task).ecs_messaging_topology_destruction_paths,
            [],
        )
        self.assertTrue(aws_facts(task).ecs_messaging_topology_destruction_path_uncertainties)

    def test_execution_role_authority_never_becomes_runtime_deletion(self) -> None:
        execution_role = _role(
            "orders_execution",
            _EXECUTION_ROLE_ARN,
            [
                _statement(
                    "Allow",
                    [_DELETE_QUEUE, _DELETE_TOPIC],
                    [_QUEUE_ARN, _TOPIC_ARN],
                )
            ],
        )
        _inventory, task, service = _normalize(extra=[execution_role])

        self.assertEqual(
            aws_facts(task).ecs_messaging_topology_destruction_paths,
            [],
        )
        self.assertEqual(
            aws_facts(service).ecs_messaging_topology_destruction_paths,
            [],
        )

    def test_incomplete_identity_policy_suppresses_paths(self) -> None:
        _inventory, task, _service_resource = _normalize(
            role_statements=[
                _statement("Allow", _DELETE_QUEUE, _QUEUE_ARN),
            ],
            extra=[
                _role_policy_attachment(
                    _TASK_ROLE_ARN,
                    "arn:aws:iam::aws:policy/ExternalMessagingAdministration",
                )
            ],
        )

        self.assertEqual(
            aws_facts(task).ecs_messaging_topology_destruction_paths,
            [],
        )
        self.assertTrue(
            any(
                "identity policy evidence is incomplete" in uncertainty
                for uncertainty in (aws_facts(task).ecs_messaging_topology_destruction_path_uncertainties)
            )
        )

    def test_queue_arn_matching_remains_case_sensitive(self) -> None:
        upper_arn = f"arn:aws:sqs:us-east-1:{_ACCOUNT_ID}:Orders"
        lower_arn = f"arn:aws:sqs:us-east-1:{_ACCOUNT_ID}:orders"
        inventory = AwsNormalizer().normalize(
            [
                _queue("upper", arn=upper_arn),
                _queue("lower", arn=lower_arn),
                _topic(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", _DELETE_QUEUE, upper_arn)],
                ),
                _task_definition(),
            ]
        )
        task = inventory.get_by_address("aws_ecs_task_definition.orders")
        assert task is not None

        paths = aws_facts(task).ecs_messaging_topology_destruction_paths
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["queue_address"], "aws_sqs_queue.upper")
        self.assertEqual(paths[0]["queue_arn"], upper_arn)
