from __future__ import annotations

import json
import unittest
from typing import Any

from tests.providers.aws.test_aws_ecs_messaging_access_paths import (
    _EXECUTION_ROLE_ARN as AWS_EXECUTION_ROLE_ARN,
)
from tests.providers.aws.test_aws_ecs_messaging_access_paths import (
    _QUEUE_ARN as AWS_QUEUE_ARN,
)
from tests.providers.aws.test_aws_ecs_messaging_access_paths import (
    _TASK_ROLE_ARN as AWS_TASK_ROLE_ARN,
)
from tests.providers.aws.test_aws_ecs_messaging_access_paths import (
    _queue as aws_queue,
)
from tests.providers.aws.test_aws_ecs_messaging_access_paths import (
    _role as aws_role,
)
from tests.providers.aws.test_aws_ecs_messaging_access_paths import (
    _role_policy_attachment as aws_role_policy_attachment,
)
from tests.providers.aws.test_aws_ecs_messaging_access_paths import (
    _statement as aws_statement,
)
from tests.providers.aws.test_aws_ecs_messaging_access_paths import (
    _task_definition as aws_task_definition,
)
from tests.providers.aws.test_aws_public_ecs_messaging_mutation_rules import (
    _load_balancer_path as aws_load_balancer_path,
)
from tests.providers.aws.test_aws_public_ecs_messaging_mutation_rules import (
    _service as aws_service,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _QUEUE_ID as AZURE_QUEUE_ID,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _SYSTEM_PRINCIPAL_ID as AZURE_SYSTEM_PRINCIPAL_ID,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _TOPIC_ID as AZURE_TOPIC_ID,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _USER_PRINCIPAL_ID as AZURE_USER_PRINCIPAL_ID,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _custom_role as azure_custom_role,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _custom_role_assignment as azure_custom_role_assignment,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _entity as azure_entity,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _function_app as azure_function_app,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _namespace as azure_namespace,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _role_assignment as azure_role_assignment,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _subscription as azure_subscription,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _user_assigned_identity as azure_user_assigned_identity,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _web_app as azure_web_app,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _PROJECT as GCP_PROJECT,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _SERVICE_ACCOUNT_EMAIL as GCP_SERVICE_ACCOUNT_EMAIL,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _SERVICE_ACCOUNT_MEMBER as GCP_SERVICE_ACCOUNT_MEMBER,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _WORKLOAD_ADDRESS as GCP_WORKLOAD_ADDRESS,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _cloud_run as gcp_cloud_run,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _custom_role as gcp_custom_role,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _subscription as gcp_subscription,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _subscription_iam_member as gcp_subscription_iam_member,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _topic as gcp_topic,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _topic_iam_member as gcp_topic_iam_member,
)
from tests.providers.gcp.test_gcp_public_cloud_run_pubsub_consume_rules import (
    _public_cloud_run as gcp_public_cloud_run,
)
from tests.providers.gcp.test_gcp_public_cloud_run_pubsub_consume_rules import (
    _public_invoker as gcp_public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, StrideCategory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts

_AWS_READ_RULE = "aws-public-ecs-sqs-receive-access"
_GCP_READ_RULE = "gcp-public-cloud-run-pubsub-consume-access"
_AZURE_READ_RULE = "azure-public-app-service-service-bus-receive-access"

_AWS_MUTATION_RULE = "aws-public-ecs-messaging-mutation-access"
_GCP_MUTATION_RULE = "gcp-public-cloud-run-pubsub-mutation-access"
_AZURE_MUTATION_RULE = "azure-public-app-service-service-bus-mutation-access"

_AWS_RECEIVE = "sqs:ReceiveMessage"
_AWS_DELETE = "sqs:DeleteMessage"
_AWS_PURGE = "sqs:PurgeQueue"
_GCP_CONSUME = "pubsub.subscriptions.consume"
_GCP_SUBSCRIPTION_DELETE = "pubsub.subscriptions.delete"
_AZURE_SEND = "microsoft.servicebus/namespaces/messages/send/action"
_AZURE_RECEIVE = "microsoft.servicebus/namespaces/messages/receive/action"

_AZURE_SENDER_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/69a216fc-b8fb-44d8-bc22-1f3c2cd27a39"
)
_AZURE_RECEIVER_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0"
)
_AZURE_OWNER_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/090c5cfd-751d-490a-894a-3ce6f1109419"
)


def _evaluate(
    normalizer: ProviderNormalizer,
    resources: list[Any],
    rule_ids: frozenset[str],
) -> list[Finding]:
    inventory = normalizer.normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )


def _aws_queue_with_delivery_posture() -> TerraformResource:
    queue = aws_queue()
    queue.values.update(
        {
            "message_retention_seconds": 345_600,
            "redrive_policy": json.dumps(
                {
                    "deadLetterTargetArn": ("arn:aws:sqs:us-east-1:111122223333:orders-dead-letter"),
                    "maxReceiveCount": 5,
                }
            ),
        }
    )
    return queue


def _aws_resources(
    actions: str | list[str],
    *,
    internal: bool = False,
    condition: dict[str, object] | None = None,
    deny_actions: str | list[str] | None = None,
    incomplete: bool = False,
    execution_only: bool = False,
    queue: TerraformResource | None = None,
) -> list[TerraformResource]:
    statements = [
        aws_statement(
            "Allow",
            actions,
            AWS_QUEUE_ARN,
            condition=condition,
        )
    ]
    if deny_actions is not None:
        statements.append(
            aws_statement("Deny", deny_actions, AWS_QUEUE_ARN),
        )

    resources = [
        *aws_load_balancer_path(internal=internal),
        queue or aws_queue(),
    ]
    if execution_only:
        resources.extend(
            [
                aws_role("orders_task", AWS_TASK_ROLE_ARN, []),
                aws_role(
                    "orders_execution",
                    AWS_EXECUTION_ROLE_ARN,
                    statements,
                ),
            ]
        )
    else:
        resources.append(
            aws_role("orders_task", AWS_TASK_ROLE_ARN, statements),
        )
    if incomplete:
        resources.append(
            aws_role_policy_attachment(
                AWS_TASK_ROLE_ARN,
                "arn:aws:iam::aws:policy/ExternalMessagingAccess",
            )
        )
    resources.extend(
        [
            aws_task_definition(),
            aws_service(),
        ]
    )
    return resources


def _gcp_workload(*, public: bool = True) -> TerraformResource:
    workload = gcp_public_cloud_run(public_ingress=public)
    assert isinstance(workload, TerraformResource)
    return workload


def _gcp_subscription_with_delivery_posture() -> TerraformResource:
    subscription = gcp_subscription()
    assert isinstance(subscription, TerraformResource)
    subscription.values.update(
        {
            "ack_deadline_seconds": 20,
            "message_retention_duration": "86400s",
            "retain_acked_messages": True,
            "dead_letter_policy": [
                {
                    "dead_letter_topic": (f"projects/{GCP_PROJECT}/topics/orders-dead-letter"),
                    "max_delivery_attempts": 5,
                }
            ],
        }
    )
    return subscription


def _gcp_subscription_resources(
    *,
    role: str = "roles/pubsub.subscriber",
    public: bool = True,
    condition: dict[str, str] | None = None,
    subscription_reference: str = "google_pubsub_subscription.orders.name",
    subscription: TerraformResource | None = None,
) -> list[Any]:
    return [
        _gcp_workload(public=public),
        gcp_public_invoker(),
        gcp_topic(),
        subscription or gcp_subscription(),
        gcp_subscription_iam_member(
            role=role,
            condition=condition,
            subscription=subscription_reference,
        ),
    ]


def _public_azure_app(*, public: object = True) -> TerraformResource:
    app = azure_web_app()
    app.values["public_network_access_enabled"] = public
    return app


def _azure_queue_resources(
    *,
    public: object = True,
    role_name: object = "Azure Service Bus Data Receiver",
    role_definition_id: object = _AZURE_RECEIVER_ROLE_ID,
    condition: object | None = None,
) -> list[TerraformResource]:
    return [
        azure_namespace(),
        azure_entity(AzureResourceType.SERVICE_BUS_QUEUE, AZURE_QUEUE_ID),
        _public_azure_app(public=public),
        azure_role_assignment(
            scope="azurerm_servicebus_queue.orders.id",
            role_name=role_name,
            role_definition_id=role_definition_id,
            condition=condition,
        ),
    ]


class PublicWorkloadMessageRemovalBoundaryTests(unittest.TestCase):
    """Pin message-removal prerequisites without constructing removal paths."""

    def test_send_and_publish_authority_remains_tampering(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources("sqs:SendMessage"),
                _AWS_MUTATION_RULE,
                _AWS_READ_RULE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                [
                    _gcp_workload(),
                    gcp_public_invoker(),
                    gcp_topic(),
                    gcp_topic_iam_member(),
                ],
                _GCP_MUTATION_RULE,
                _GCP_READ_RULE,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_queue_resources(
                    role_name="Azure Service Bus Data Sender",
                    role_definition_id=_AZURE_SENDER_ROLE_ID,
                ),
                _AZURE_MUTATION_RULE,
                _AZURE_READ_RULE,
            ),
        )

        for provider, normalizer, resources, mutation_rule, read_rule in cases:
            with self.subTest(provider=provider):
                findings = _evaluate(
                    normalizer,
                    resources,
                    frozenset({mutation_rule, read_rule}),
                )
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [mutation_rule],
                )
                self.assertEqual(findings[0].category, StrideCategory.TAMPERING)

    def test_receive_authority_remains_information_disclosure(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(_AWS_RECEIVE),
                _AWS_READ_RULE,
                _AWS_MUTATION_RULE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_subscription_resources(),
                _GCP_READ_RULE,
                _GCP_MUTATION_RULE,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_queue_resources(),
                _AZURE_READ_RULE,
                _AZURE_MUTATION_RULE,
            ),
        )

        for provider, normalizer, resources, read_rule, mutation_rule in cases:
            with self.subTest(provider=provider):
                findings = _evaluate(
                    normalizer,
                    resources,
                    frozenset({read_rule, mutation_rule}),
                )
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [read_rule],
                )
                self.assertEqual(
                    findings[0].category,
                    StrideCategory.INFORMATION_DISCLOSURE,
                )

    def test_aws_preserves_receive_delete_and_purge_as_distinct_prerequisites(
        self,
    ) -> None:
        inventory = AwsNormalizer().normalize(
            _aws_resources(
                [_AWS_RECEIVE, _AWS_DELETE, _AWS_PURGE],
                queue=_aws_queue_with_delivery_posture(),
            )
        )
        service = inventory.get_by_address("aws_ecs_service.orders")
        queue = inventory.get_by_address("aws_sqs_queue.orders")
        assert service is not None
        assert queue is not None

        path = aws_facts(service).ecs_messaging_access_paths[0]
        self.assertEqual(path["credential_context"], "workload_runtime")
        self.assertEqual(path["role_kind"], "ecs_task_role")
        self.assertEqual(path["role_arn"], AWS_TASK_ROLE_ARN)
        self.assertEqual(path["messaging_resource_address"], queue.address)
        self.assertEqual(path["messaging_resource_arn"], AWS_QUEUE_ARN)
        self.assertEqual(path["resource_scopes"], ["exact_queue"])
        self.assertEqual(path["access_classes"], ["consume", "delete"])
        self.assertEqual(
            path["matched_actions"],
            [_AWS_RECEIVE, _AWS_DELETE, _AWS_PURGE],
        )
        self.assertEqual(path["access_state"], "allowed")
        self.assertFalse(path["conditional_evaluation_required"])
        self.assertEqual(path["internet_facing_load_balancers"], ["aws_lb.public"])
        self.assertNotIn("receipt_handle", path)
        self.assertNotIn("message_id", path)
        self.assertNotIn("recovery_evidence", path)

        queue_facts = aws_facts(queue)
        self.assertEqual(queue_facts.sqs_message_retention_seconds, 345_600)
        self.assertEqual(queue_facts.sqs_redrive_state, "configured")
        self.assertEqual(queue_facts.sqs_redrive_max_receive_count, 5)
        self.assertEqual(
            queue_facts.sqs_redrive_target_arn,
            "arn:aws:sqs:us-east-1:111122223333:orders-dead-letter",
        )

    def test_aws_delete_message_does_not_invent_receive_or_receipt_handle(
        self,
    ) -> None:
        expectations = (
            ([_AWS_DELETE], [_AWS_DELETE]),
            ([_AWS_RECEIVE, _AWS_DELETE], [_AWS_RECEIVE, _AWS_DELETE]),
            ([_AWS_PURGE], [_AWS_PURGE]),
        )
        for actions, expected in expectations:
            with self.subTest(actions=actions):
                inventory = AwsNormalizer().normalize(_aws_resources(actions))
                service = inventory.get_by_address("aws_ecs_service.orders")
                assert service is not None
                path = aws_facts(service).ecs_messaging_access_paths[0]
                self.assertEqual(path["matched_actions"], expected)
                self.assertNotIn("receipt_handle", path)
                self.assertNotIn("message", path)

    def test_aws_denied_conditional_incomplete_and_execution_role_evidence_is_not_deterministic(
        self,
    ) -> None:
        denied_inventory = AwsNormalizer().normalize(
            _aws_resources(
                [_AWS_RECEIVE, _AWS_DELETE],
                deny_actions=_AWS_DELETE,
            )
        )
        denied_service = denied_inventory.get_by_address("aws_ecs_service.orders")
        assert denied_service is not None
        denied_path = aws_facts(denied_service).ecs_messaging_access_paths[0]
        self.assertEqual(denied_path["matched_actions"], [_AWS_RECEIVE])
        self.assertEqual(denied_path["denied_actions"], [_AWS_DELETE])
        self.assertTrue(denied_path["explicit_deny"])

        condition = {"StringEquals": {"aws:SourceAccount": "111122223333"}}
        conditional_inventory = AwsNormalizer().normalize(_aws_resources(_AWS_DELETE, condition=condition))
        conditional_service = conditional_inventory.get_by_address("aws_ecs_service.orders")
        assert conditional_service is not None
        conditional_facts = aws_facts(conditional_service)
        self.assertEqual(
            conditional_facts.ecs_messaging_access_paths[0]["access_state"],
            "unknown",
        )
        self.assertTrue(conditional_facts.ecs_messaging_access_path_uncertainties)

        incomplete_inventory = AwsNormalizer().normalize(_aws_resources(_AWS_DELETE, incomplete=True))
        incomplete_service = incomplete_inventory.get_by_address("aws_ecs_service.orders")
        assert incomplete_service is not None
        incomplete_path = aws_facts(incomplete_service).ecs_messaging_access_paths[0]
        self.assertEqual(incomplete_path["modeled_access_state"], "allowed")
        self.assertEqual(incomplete_path["access_state"], "unknown")
        self.assertFalse(incomplete_path["role_policy_complete"])

        execution_inventory = AwsNormalizer().normalize(
            _aws_resources(
                [_AWS_RECEIVE, _AWS_DELETE, _AWS_PURGE],
                execution_only=True,
            )
        )
        execution_service = execution_inventory.get_by_address("aws_ecs_service.orders")
        assert execution_service is not None
        self.assertEqual(
            aws_facts(execution_service).ecs_messaging_access_paths,
            [],
        )

    def test_aws_queue_policy_evidence_remains_separate_from_identity_path(
        self,
    ) -> None:
        queue = aws_queue()
        queue.values["policy"] = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Principal": {"AWS": AWS_TASK_ROLE_ARN},
                        "Action": _AWS_DELETE,
                        "Resource": AWS_QUEUE_ARN,
                    }
                ],
            }
        )
        inventory = AwsNormalizer().normalize(_aws_resources(_AWS_DELETE, queue=queue))
        normalized_queue = inventory.get_by_address("aws_sqs_queue.orders")
        service = inventory.get_by_address("aws_ecs_service.orders")
        assert normalized_queue is not None
        assert service is not None

        self.assertEqual(len(normalized_queue.policy_statements), 1)
        statement = normalized_queue.policy_statements[0]
        self.assertEqual(statement.effect, "Deny")
        self.assertEqual(statement.actions, [_AWS_DELETE])
        self.assertEqual(statement.resources, [AWS_QUEUE_ARN])
        path = aws_facts(service).ecs_messaging_access_paths[0]
        self.assertEqual(path["evaluation_basis"], "modeled_identity_policy")
        self.assertNotIn("queue_policy_statements", path)

    def test_gcp_consume_preserves_exact_subscription_and_runtime_identity(
        self,
    ) -> None:
        inventory = GcpNormalizer().normalize(
            _gcp_subscription_resources(
                subscription=_gcp_subscription_with_delivery_posture(),
            )
        )
        workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        subscription = inventory.get_by_address("google_pubsub_subscription.orders")
        assert workload is not None
        assert subscription is not None

        path = gcp_facts(workload).cloud_run_pubsub_access_paths[0]
        self.assertEqual(path["service_account_email"], GCP_SERVICE_ACCOUNT_EMAIL)
        self.assertEqual(path["service_account_member"], GCP_SERVICE_ACCOUNT_MEMBER)
        self.assertEqual(path["identity_kind"], "cloud_run_service_account")
        self.assertEqual(path["credential_context"], "workload_runtime")
        self.assertEqual(path["messaging_resource_kind"], "subscription")
        self.assertEqual(path["messaging_resource_address"], subscription.address)
        self.assertEqual(path["resource_scope"], "exact_subscription")
        self.assertEqual(path["role_kind"], "subscriber")
        self.assertEqual(path["access_classes"], ["consume"])
        self.assertEqual(path["access_state"], "granted")
        self.assertEqual(path["condition_state"], "not_configured")
        self.assertNotIn("ack_id", path)
        self.assertNotIn("message_id", path)
        self.assertNotIn("recovery_evidence", path)

        subscription_facts = gcp_facts(subscription)
        self.assertEqual(
            subscription_facts.pubsub_subscription_message_retention_state,
            "configured",
        )
        self.assertEqual(
            subscription_facts.pubsub_subscription_message_retention_seconds,
            86_400,
        )
        self.assertTrue(subscription_facts.pubsub_subscription_retain_acked_messages)
        self.assertEqual(
            subscription_facts.pubsub_subscription_dead_letter_policy_state,
            "configured",
        )
        self.assertEqual(
            subscription_facts.pubsub_subscription_dead_letter_max_delivery_attempts,
            5,
        )

    def test_gcp_consume_and_subscription_deletion_remain_distinct_capabilities(
        self,
    ) -> None:
        inventory = GcpNormalizer().normalize(_gcp_subscription_resources(role="roles/pubsub.admin"))
        workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert workload is not None
        path = gcp_facts(workload).cloud_run_pubsub_access_paths[0]

        self.assertEqual(path["role_kind"], "admin")
        self.assertEqual(
            path["access_classes"],
            ["read", "consume", "delete", "administrative"],
        )
        self.assertEqual(path["matched_permissions"], [])

        custom_role_name = f"projects/{GCP_PROJECT}/roles/cloudRunMessaging"
        custom_inventory = GcpNormalizer().normalize(
            [
                _gcp_workload(),
                gcp_public_invoker(),
                gcp_topic(),
                gcp_subscription(),
                gcp_custom_role(permissions=[_GCP_CONSUME, _GCP_SUBSCRIPTION_DELETE]),
                gcp_subscription_iam_member(role=custom_role_name),
            ]
        )
        custom_workload = custom_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert custom_workload is not None
        custom_path = gcp_facts(custom_workload).cloud_run_pubsub_access_paths[0]
        self.assertEqual(custom_path["access_classes"], ["consume", "delete"])
        self.assertEqual(
            custom_path["matched_permissions"],
            [_GCP_CONSUME, _GCP_SUBSCRIPTION_DELETE],
        )

    def test_gcp_conditional_unresolved_identity_role_and_target_fail_closed(
        self,
    ) -> None:
        condition = {
            "title": "business-hours",
            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
        }
        conditional_inventory = GcpNormalizer().normalize(_gcp_subscription_resources(condition=condition))
        conditional_workload = conditional_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert conditional_workload is not None
        conditional_path = gcp_facts(conditional_workload).cloud_run_pubsub_access_paths[0]
        self.assertEqual(conditional_path["access_state"], "conditional")
        self.assertEqual(conditional_path["condition_state"], "configured")

        unresolved_role_inventory = GcpNormalizer().normalize(
            _gcp_subscription_resources(role=f"projects/{GCP_PROJECT}/roles/missingMessagingRole")
        )
        unresolved_role_workload = unresolved_role_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert unresolved_role_workload is not None
        unresolved_role_facts = gcp_facts(unresolved_role_workload)
        self.assertEqual(unresolved_role_facts.cloud_run_pubsub_access_paths, [])
        self.assertTrue(unresolved_role_facts.cloud_run_pubsub_access_path_uncertainties)

        identity = gcp_cloud_run(service_account=None)
        assert isinstance(identity, TerraformResource)
        identity.values["ingress"] = "INGRESS_TRAFFIC_ALL"
        identity_inventory = GcpNormalizer().normalize(
            [
                identity,
                gcp_public_invoker(),
                gcp_topic(),
                gcp_subscription(),
                gcp_subscription_iam_member(),
            ]
        )
        identity_workload = identity_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert identity_workload is not None
        identity_facts = gcp_facts(identity_workload)
        self.assertEqual(identity_facts.cloud_run_pubsub_access_paths, [])
        self.assertTrue(identity_facts.cloud_run_pubsub_access_path_uncertainties)

        target_inventory = GcpNormalizer().normalize(
            _gcp_subscription_resources(subscription_reference="google_pubsub_subscription.external.name")
        )
        target_workload = target_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert target_workload is not None
        target_facts = gcp_facts(target_workload)
        self.assertEqual(target_facts.cloud_run_pubsub_access_paths, [])
        self.assertEqual(
            target_facts.cloud_run_pubsub_access_path_uncertainties,
            [],
        )

    def test_azure_receive_preserves_queue_and_subscription_ancestry_and_identity(
        self,
    ) -> None:
        queue_inventory = AzureNormalizer().normalize(_azure_queue_resources())
        queue_workload = queue_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert queue_workload is not None
        queue_path = azure_facts(queue_workload).app_service_service_bus_access_paths[0]
        self.assertEqual(queue_path["identity_kind"], "system_assigned")
        self.assertEqual(queue_path["principal_id"], AZURE_SYSTEM_PRINCIPAL_ID)
        self.assertEqual(queue_path["credential_context"], "workload_runtime")
        self.assertEqual(
            queue_path["service_bus_resource_address"],
            "azurerm_servicebus_queue.orders",
        )
        self.assertEqual(queue_path["service_bus_resource_id"], AZURE_QUEUE_ID)
        self.assertEqual(
            queue_path["service_bus_namespace_address"],
            "azurerm_servicebus_namespace.orders",
        )
        self.assertEqual(queue_path["queue_address"], "azurerm_servicebus_queue.orders")
        self.assertIsNone(queue_path["topic_address"])
        self.assertEqual(queue_path["access_classes"], ["receive"])
        self.assertEqual(queue_path["matched_data_actions"], [])
        self.assertEqual(queue_path["resource_scope"], "exact_service_bus_queue")
        self.assertNotIn("message", queue_path)
        self.assertNotIn("lock_token", queue_path)
        self.assertNotIn("recovery_evidence", queue_path)

        function = azure_function_app()
        function.values["public_network_access_enabled"] = True
        subscription_inventory = AzureNormalizer().normalize(
            [
                azure_namespace(),
                azure_entity(AzureResourceType.SERVICE_BUS_TOPIC, AZURE_TOPIC_ID),
                azure_subscription(),
                azure_user_assigned_identity(),
                function,
                azure_role_assignment(
                    principal_id=AZURE_USER_PRINCIPAL_ID,
                    scope="azurerm_servicebus_subscription.orders.id",
                    role_name="Azure Service Bus Data Receiver",
                    role_definition_id=_AZURE_RECEIVER_ROLE_ID,
                ),
            ]
        )
        subscription_workload = subscription_inventory.get_by_address("azurerm_linux_function_app.orders_worker")
        assert subscription_workload is not None
        subscription_path = azure_facts(subscription_workload).app_service_service_bus_access_paths[0]
        self.assertEqual(subscription_path["identity_kind"], "user_assigned")
        self.assertEqual(
            subscription_path["principal_id"],
            AZURE_USER_PRINCIPAL_ID,
        )
        self.assertEqual(
            subscription_path["service_bus_resource_address"],
            "azurerm_servicebus_subscription.orders",
        )
        self.assertEqual(
            subscription_path["service_bus_namespace_address"],
            "azurerm_servicebus_namespace.orders",
        )
        self.assertEqual(
            subscription_path["topic_address"],
            "azurerm_servicebus_topic.orders",
        )
        self.assertEqual(
            subscription_path["subscription_address"],
            "azurerm_servicebus_subscription.orders",
        )
        self.assertEqual(
            subscription_path["resource_scope"],
            "exact_service_bus_subscription",
        )

    def test_azure_send_receive_conditions_and_not_data_actions_remain_distinct(
        self,
    ) -> None:
        owner_inventory = AzureNormalizer().normalize(
            _azure_queue_resources(
                role_name="Azure Service Bus Data Owner",
                role_definition_id=_AZURE_OWNER_ROLE_ID,
            )
        )
        owner_workload = owner_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert owner_workload is not None
        owner_path = azure_facts(owner_workload).app_service_service_bus_access_paths[0]
        self.assertEqual(owner_path["access_classes"], ["send", "receive"])
        self.assertEqual(owner_path["access_state"], "granted")

        custom_inventory = AzureNormalizer().normalize(
            [
                azure_namespace(),
                azure_entity(AzureResourceType.SERVICE_BUS_QUEUE, AZURE_QUEUE_ID),
                _public_azure_app(),
                azure_custom_role(
                    data_actions=["Microsoft.ServiceBus/namespaces/messages/*"],
                    not_data_actions=[_AZURE_RECEIVE],
                ),
                azure_custom_role_assignment(scope="azurerm_servicebus_queue.orders.id"),
            ]
        )
        custom_workload = custom_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert custom_workload is not None
        custom_path = azure_facts(custom_workload).app_service_service_bus_access_paths[0]
        self.assertEqual(custom_path["access_classes"], ["send"])
        self.assertEqual(custom_path["matched_data_actions"], [_AZURE_SEND])
        self.assertEqual(custom_path["excluded_data_actions"], [_AZURE_RECEIVE])

        condition = "@Resource[Microsoft.ServiceBus/namespaces/queues:name] StringEquals 'orders'"
        conditional_inventory = AzureNormalizer().normalize(_azure_queue_resources(condition=condition))
        conditional_workload = conditional_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert conditional_workload is not None
        conditional_path = azure_facts(conditional_workload).app_service_service_bus_access_paths[0]
        self.assertEqual(conditional_path["access_state"], "conditional")
        self.assertEqual(conditional_path["condition_state"], "configured")
        self.assertEqual(conditional_path["condition"], condition)

    def test_azure_topic_receive_and_unresolved_role_evidence_do_not_create_paths(
        self,
    ) -> None:
        topic_inventory = AzureNormalizer().normalize(
            [
                azure_namespace(),
                azure_entity(AzureResourceType.SERVICE_BUS_TOPIC, AZURE_TOPIC_ID),
                _public_azure_app(),
                azure_role_assignment(
                    scope="azurerm_servicebus_topic.orders.id",
                    role_name="Azure Service Bus Data Receiver",
                    role_definition_id=_AZURE_RECEIVER_ROLE_ID,
                ),
            ]
        )
        topic_workload = topic_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert topic_workload is not None
        self.assertEqual(
            azure_facts(topic_workload).app_service_service_bus_access_paths,
            [],
        )

        unresolved_inventory = AzureNormalizer().normalize(
            [
                azure_namespace(),
                azure_entity(AzureResourceType.SERVICE_BUS_QUEUE, AZURE_QUEUE_ID),
                _public_azure_app(),
                azure_custom_role(
                    data_actions=[],
                    unknown_values={
                        "permissions": [{"data_actions": True}],
                    },
                ),
                azure_custom_role_assignment(scope="azurerm_servicebus_queue.orders.id"),
            ]
        )
        unresolved_workload = unresolved_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert unresolved_workload is not None
        unresolved_facts = azure_facts(unresolved_workload)
        self.assertEqual(
            unresolved_facts.app_service_service_bus_access_paths,
            [],
        )
        self.assertTrue(unresolved_facts.app_service_service_bus_access_path_uncertainties)

    def test_private_workloads_retain_receive_paths_but_public_findings_stay_quiet(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(_AWS_RECEIVE, internal=True),
                "aws_ecs_service.orders",
                _AWS_READ_RULE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_subscription_resources(public=False),
                GCP_WORKLOAD_ADDRESS,
                _GCP_READ_RULE,
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_queue_resources(public=False),
                "azurerm_linux_web_app.orders",
                _AZURE_READ_RULE,
            ),
        )

        for provider, normalizer, resources, workload_address, rule_id in cases:
            with self.subTest(provider=provider):
                inventory = normalizer.normalize(resources)
                workload = inventory.get_by_address(workload_address)
                assert workload is not None
                if provider == "aws":
                    paths = aws_facts(workload).ecs_messaging_access_paths
                elif provider == "gcp":
                    paths = gcp_facts(workload).cloud_run_pubsub_access_paths
                else:
                    paths = azure_facts(workload).app_service_service_bus_access_paths
                self.assertTrue(paths)
                self.assertEqual(
                    _evaluate(normalizer, resources, frozenset({rule_id})),
                    [],
                )

    def test_resource_destruction_and_delivery_controls_remain_separate(
        self,
    ) -> None:
        aws_inventory = AwsNormalizer().normalize(
            _aws_resources(
                [
                    "sqs:DeleteQueue",
                    "sqs:ChangeMessageVisibility",
                    "sqs:SetQueueAttributes",
                ]
            )
        )
        aws_service_resource = aws_inventory.get_by_address("aws_ecs_service.orders")
        assert aws_service_resource is not None
        aws_path = aws_facts(aws_service_resource).ecs_messaging_access_paths[0]
        self.assertEqual(
            aws_path["access_classes"],
            ["consume", "delete", "administrative"],
        )
        self.assertNotIn(_AWS_DELETE, aws_path["matched_actions"])
        self.assertNotIn(_AWS_PURGE, aws_path["matched_actions"])

        gcp_inventory = GcpNormalizer().normalize(_gcp_subscription_resources(role="roles/pubsub.admin"))
        gcp_workload_resource = gcp_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert gcp_workload_resource is not None
        gcp_path = gcp_facts(gcp_workload_resource).cloud_run_pubsub_access_paths[0]
        self.assertIn("delete", gcp_path["access_classes"])
        self.assertIn("administrative", gcp_path["access_classes"])
        self.assertEqual(gcp_path["messaging_resource_kind"], "subscription")

        azure_inventory = AzureNormalizer().normalize(
            [
                azure_namespace(),
                azure_entity(AzureResourceType.SERVICE_BUS_QUEUE, AZURE_QUEUE_ID),
                _public_azure_app(),
                azure_custom_role(
                    data_actions=[
                        _AZURE_RECEIVE,
                        "Microsoft.ServiceBus/namespaces/queues/delete",
                    ]
                ),
                azure_custom_role_assignment(scope="azurerm_servicebus_queue.orders.id"),
            ]
        )
        azure_workload_resource = azure_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert azure_workload_resource is not None
        azure_path = azure_facts(azure_workload_resource).app_service_service_bus_access_paths[0]
        self.assertEqual(azure_path["access_classes"], ["receive"])
        self.assertEqual(azure_path["matched_data_actions"], [_AZURE_RECEIVE])

    def test_provider_local_evidence_does_not_cross_messaging_boundaries(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources([_AWS_RECEIVE, _AWS_DELETE, _AWS_PURGE]),
                "aws_ecs_service.orders",
                ("google_", "azurerm_"),
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_subscription_resources(role="roles/pubsub.admin"),
                GCP_WORKLOAD_ADDRESS,
                ("aws_", "azurerm_"),
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_queue_resources(
                    role_name="Azure Service Bus Data Owner",
                    role_definition_id=_AZURE_OWNER_ROLE_ID,
                ),
                "azurerm_linux_web_app.orders",
                ("aws_", "google_"),
            ),
        )

        for provider, normalizer, resources, workload_address, foreign in cases:
            with self.subTest(provider=provider):
                inventory = normalizer.normalize(resources)
                workload = inventory.get_by_address(workload_address)
                assert workload is not None
                if provider == "aws":
                    payload = {
                        "paths": aws_facts(workload).ecs_messaging_access_paths,
                        "uncertainties": aws_facts(workload).ecs_messaging_access_path_uncertainties,
                    }
                elif provider == "gcp":
                    payload = {
                        "paths": gcp_facts(workload).cloud_run_pubsub_access_paths,
                        "uncertainties": gcp_facts(workload).cloud_run_pubsub_access_path_uncertainties,
                    }
                else:
                    payload = {
                        "paths": azure_facts(workload).app_service_service_bus_access_paths,
                        "uncertainties": azure_facts(workload).app_service_service_bus_access_path_uncertainties,
                    }
                serialized = json.dumps(payload, sort_keys=True)
                for prefix in foreign:
                    self.assertNotIn(prefix, serialized)


if __name__ == "__main__":
    unittest.main()
