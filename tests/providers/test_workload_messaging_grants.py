from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_AWS_ACCOUNT_ID = "111122223333"
_AWS_TASK_ROLE_ARN = f"arn:aws:iam::{_AWS_ACCOUNT_ID}:role/orders-task"
_AWS_TOPIC_ARN = f"arn:aws:sns:us-east-1:{_AWS_ACCOUNT_ID}:orders-events"
_AWS_QUEUE_ARN = f"arn:aws:sqs:us-east-1:{_AWS_ACCOUNT_ID}:orders"
_GCP_SERVICE_ACCOUNT_EMAIL = "orders@tfstride-demo.iam.gserviceaccount.com"
_GCP_SERVICE_ACCOUNT_MEMBER = f"serviceAccount:{_GCP_SERVICE_ACCOUNT_EMAIL}"
_AZURE_PRINCIPAL_ID = "orders-app-principal-id"
_AZURE_SERVICE_BUS_ID = (
    "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ServiceBus/namespaces/orders-events"
)


def _resource(
    provider: str,
    resource_type: str,
    name: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name=f"registry.terraform.io/hashicorp/{provider}",
        values=values,
        unknown_values=unknown_values or {},
    )


def _aws_role(statements: list[dict[str, Any]]) -> TerraformResource:
    return _resource(
        "aws",
        "aws_iam_role",
        "orders_task",
        {
            "name": "orders-task",
            "arn": _AWS_TASK_ROLE_ARN,
            "inline_policy": [
                {
                    "name": "orders-messaging",
                    "policy": json.dumps({"Version": "2012-10-17", "Statement": statements}),
                }
            ],
        },
    )


def _aws_task_definition(*, task_role_arn: str = _AWS_TASK_ROLE_ARN) -> TerraformResource:
    return _resource(
        "aws",
        "aws_ecs_task_definition",
        "orders",
        {
            "family": "orders",
            "revision": 1,
            "task_role_arn": task_role_arn,
            "container_definitions": "[]",
        },
    )


def _aws_service() -> TerraformResource:
    return _resource(
        "aws",
        "aws_ecs_service",
        "orders",
        {"name": "orders", "task_definition": "orders:1"},
    )


def _aws_topic() -> TerraformResource:
    return _resource(
        "aws",
        "aws_sns_topic",
        "orders",
        {"name": "orders-events", "arn": _AWS_TOPIC_ARN},
    )


def _aws_queue() -> TerraformResource:
    return _resource(
        "aws",
        "aws_sqs_queue",
        "orders",
        {
            "name": "orders",
            "arn": _AWS_QUEUE_ARN,
            "id": f"https://sqs.us-east-1.amazonaws.com/{_AWS_ACCOUNT_ID}/orders",
        },
    )


def _gcp_cloud_run(*, service_account: object = _GCP_SERVICE_ACCOUNT_EMAIL) -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        "orders",
        {
            "name": "orders",
            "project": "tfstride-demo",
            "location": "us-central1",
            "template": [{"service_account": service_account}],
        },
    )


def _gcp_topic() -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.PUBSUB_TOPIC,
        "orders",
        {"name": "orders-events", "project": "tfstride-demo"},
    )


def _gcp_subscription() -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.PUBSUB_SUBSCRIPTION,
        "orders",
        {
            "name": "orders-worker",
            "project": "tfstride-demo",
            "topic": "google_pubsub_topic.orders.id",
        },
    )


def _gcp_topic_iam_member(
    *,
    topic: str = "google_pubsub_topic.orders.name",
    role: str = "roles/pubsub.publisher",
    condition: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.PUBSUB_TOPIC_IAM_MEMBER,
        "orders_publisher",
        {
            "topic": topic,
            "role": role,
            "member": _GCP_SERVICE_ACCOUNT_MEMBER,
            **({"condition": [condition]} if condition else {}),
        },
    )


def _gcp_subscription_iam_member() -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.PUBSUB_SUBSCRIPTION_IAM_MEMBER,
        "orders_subscriber",
        {
            "subscription": "google_pubsub_subscription.orders.name",
            "role": "roles/pubsub.subscriber",
            "member": _GCP_SERVICE_ACCOUNT_MEMBER,
        },
    )


def _gcp_custom_pubsub_role() -> TerraformResource:
    return _resource(
        "google",
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        "pubsub_writer",
        {
            "project": "tfstride-demo",
            "role_id": "pubsubWriter",
            "title": "Pub/Sub Writer",
            "permissions": [
                "pubsub.topics.publish",
                "pubsub.topics.update",
                "pubsub.subscriptions.consume",
            ],
            "stage": "GA",
        },
    )


def _azure_web_app() -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.LINUX_WEB_APP,
        "orders",
        {
            "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/orders",
            "name": "orders",
            "identity": [
                {
                    "type": "SystemAssigned",
                    "principal_id": _AZURE_PRINCIPAL_ID,
                    "tenant_id": "tenant-id",
                    "identity_ids": [],
                }
            ],
        },
    )


def _azure_service_bus_namespace() -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.SERVICE_BUS_NAMESPACE,
        "orders",
        {
            "id": _AZURE_SERVICE_BUS_ID,
            "name": "orders-events",
            "sku": "Premium",
            "public_network_access_enabled": False,
            "local_auth_enabled": False,
            "minimum_tls_version": "1.2",
            "network_rule_set": [{"default_action": "Deny"}],
        },
    )


def _azure_role_assignment(
    *,
    scope: object = "azurerm_servicebus_namespace.orders.id",
    principal_id: object = _AZURE_PRINCIPAL_ID,
    role_definition_name: object = "Azure Service Bus Data Sender",
    role_definition_id: object = (
        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/service-bus-data-sender"
    ),
    condition: object | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "scope": scope,
        "role_definition_name": role_definition_name,
        "role_definition_id": role_definition_id,
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if condition is not None:
        values["condition"] = condition
    return _resource(
        "azurerm",
        AzureResourceType.ROLE_ASSIGNMENT,
        "orders_messaging",
        values,
        unknown_values=unknown_values,
    )


def _azure_custom_messaging_role() -> TerraformResource:
    return _resource(
        "azurerm",
        AzureResourceType.ROLE_DEFINITION,
        "messaging_writer",
        {
            "id": "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom-messaging-writer",
            "name": "Custom Service Bus Writer",
            "scope": "/subscriptions/sub-0001",
            "assignable_scopes": ["/subscriptions/sub-0001"],
            "permissions": [
                {
                    "actions": [],
                    "not_actions": [],
                    "data_actions": ["Microsoft.ServiceBus/namespaces/topics/messages/send/action"],
                    "not_data_actions": ["Microsoft.ServiceBus/namespaces/queues/messages/receive/action"],
                }
            ],
        },
    )


class WorkloadMessagingGrantCharacterizationTests(unittest.TestCase):
    def test_aws_task_role_preserves_exact_messaging_scopes_conditions_and_denies(self) -> None:
        condition = {"StringEquals": {"aws:SourceAccount": _AWS_ACCOUNT_ID}}
        inventory = AwsNormalizer().normalize(
            [
                _aws_topic(),
                _aws_queue(),
                _aws_role(
                    [
                        {
                            "Effect": "Allow",
                            "Action": "sns:Publish",
                            "Resource": _AWS_TOPIC_ARN,
                            "Condition": condition,
                        },
                        {
                            "Effect": "Deny",
                            "Action": "sns:DeleteTopic",
                            "Resource": _AWS_TOPIC_ARN,
                        },
                        {
                            "Effect": "Allow",
                            "Action": ["sqs:SendMessage", "sqs:GetQueueAttributes"],
                            "Resource": _AWS_QUEUE_ARN,
                        },
                        {
                            "Effect": "Deny",
                            "Action": "sqs:PurgeQueue",
                            "Resource": _AWS_QUEUE_ARN,
                        },
                    ]
                ),
                _aws_task_definition(),
                _aws_service(),
            ]
        )
        service = inventory.get_by_address("aws_ecs_service.orders")
        role = inventory.get_by_address("aws_iam_role.orders_task")
        assert service is not None
        assert role is not None

        self.assertEqual(aws_facts(service).task_role_arn, _AWS_TASK_ROLE_ARN)
        self.assertEqual(service.attached_role_arns, (_AWS_TASK_ROLE_ARN,))
        self.assertEqual(
            service.get_metadata_field(AwsResourceMetadata.RESOLVED_TASK_ROLE_ADDRESSES),
            ["aws_iam_role.orders_task"],
        )
        self.assertEqual(len(role.policy_statements), 4)
        topic_allow, topic_deny, queue_allow, queue_deny = role.policy_statements
        self.assertEqual(topic_allow.actions, ["sns:Publish"])
        self.assertEqual(topic_allow.resources, [_AWS_TOPIC_ARN])
        self.assertEqual(
            [(item.operator, item.key, item.values) for item in topic_allow.conditions],
            [("StringEquals", "aws:SourceAccount", [_AWS_ACCOUNT_ID])],
        )
        self.assertEqual(topic_deny.effect, "Deny")
        self.assertEqual(topic_deny.actions, ["sns:DeleteTopic"])
        self.assertEqual(topic_deny.resources, [_AWS_TOPIC_ARN])
        self.assertEqual(queue_allow.actions, ["sqs:SendMessage", "sqs:GetQueueAttributes"])
        self.assertEqual(queue_allow.resources, [_AWS_QUEUE_ARN])
        self.assertEqual(queue_deny.effect, "Deny")
        self.assertEqual(queue_deny.actions, ["sqs:PurgeQueue"])
        self.assertEqual(queue_deny.resources, [_AWS_QUEUE_ARN])

    def test_aws_external_targets_and_unresolved_task_role_remain_explicit(self) -> None:
        external_topic_arn = "arn:aws:sns:us-west-2:999900001111:external-events"
        missing_role_arn = f"arn:aws:iam::{_AWS_ACCOUNT_ID}:role/missing-task"
        inventory = AwsNormalizer().normalize(
            [
                _aws_role(
                    [
                        {
                            "Effect": "Allow",
                            "Action": "sns:Publish",
                            "Resource": external_topic_arn,
                        }
                    ]
                ),
                _aws_task_definition(task_role_arn=missing_role_arn),
                _aws_service(),
            ]
        )
        service = inventory.get_by_address("aws_ecs_service.orders")
        role = inventory.get_by_address("aws_iam_role.orders_task")
        assert service is not None
        assert role is not None

        self.assertEqual(role.policy_statements[0].resources, [external_topic_arn])
        self.assertEqual(aws_facts(service).task_role_arn, missing_role_arn)
        self.assertEqual(service.attached_role_arns, (missing_role_arn,))
        self.assertEqual(
            service.get_metadata_field(AwsResourceMetadata.RESOLVED_TASK_ROLE_ADDRESSES),
            [],
        )
        self.assertEqual(
            service.get_metadata_field(AwsResourceMetadata.UNRESOLVED_TASK_ROLE_ARNS),
            [missing_role_arn],
        )

    def test_gcp_service_account_pubsub_grants_preserve_exact_scope_and_condition(self) -> None:
        condition = {
            "title": "business-hours",
            "description": "Limit publishing to an approved context",
            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
        }
        inventory = GcpNormalizer().normalize(
            [
                _gcp_cloud_run(),
                _gcp_topic(),
                _gcp_subscription(),
                _gcp_topic_iam_member(condition=condition),
                _gcp_subscription_iam_member(),
            ]
        )
        workload = inventory.get_by_address("google_cloud_run_v2_service.orders")
        topic = inventory.get_by_address("google_pubsub_topic.orders")
        subscription = inventory.get_by_address("google_pubsub_subscription.orders")
        assert workload is not None
        assert topic is not None
        assert subscription is not None

        self.assertEqual(gcp_facts(workload).service_account_email, _GCP_SERVICE_ACCOUNT_EMAIL)
        self.assertEqual(gcp_facts(workload).service_account_member, _GCP_SERVICE_ACCOUNT_MEMBER)
        self.assertEqual(gcp_facts(workload).identity_members, [_GCP_SERVICE_ACCOUNT_MEMBER])
        self.assertEqual(
            gcp_facts(topic).bindings,
            [
                {
                    "role": "roles/pubsub.publisher",
                    "members": [_GCP_SERVICE_ACCOUNT_MEMBER],
                    "source": "google_pubsub_topic_iam_member.orders_publisher",
                    "condition": condition,
                }
            ],
        )
        self.assertEqual(
            gcp_facts(subscription).bindings,
            [
                {
                    "role": "roles/pubsub.subscriber",
                    "members": [_GCP_SERVICE_ACCOUNT_MEMBER],
                    "source": "google_pubsub_subscription_iam_member.orders_subscriber",
                }
            ],
        )

    def test_gcp_custom_permissions_are_preserved_for_exact_topic_grant(self) -> None:
        role_reference = "google_project_iam_custom_role.pubsub_writer.name"
        inventory = GcpNormalizer().normalize(
            [
                _gcp_cloud_run(),
                _gcp_topic(),
                _gcp_custom_pubsub_role(),
                _gcp_topic_iam_member(role=role_reference),
            ]
        )
        role = inventory.get_by_address("google_project_iam_custom_role.pubsub_writer")
        topic = inventory.get_by_address("google_pubsub_topic.orders")
        assert role is not None
        assert topic is not None

        self.assertEqual(
            gcp_facts(role).custom_role_permissions,
            [
                "pubsub.topics.publish",
                "pubsub.topics.update",
                "pubsub.subscriptions.consume",
            ],
        )
        self.assertEqual(gcp_facts(topic).bindings[0]["role"], role_reference)
        self.assertEqual(
            gcp_facts(topic).bindings[0]["source"],
            "google_pubsub_topic_iam_member.orders_publisher",
        )

    def test_gcp_unresolved_topic_reference_does_not_attach_by_name(self) -> None:
        unresolved_reference = "google_pubsub_topic.external.name"
        inventory = GcpNormalizer().normalize(
            [
                _gcp_cloud_run(),
                _gcp_topic(),
                _gcp_topic_iam_member(topic=unresolved_reference),
            ]
        )
        topic = inventory.get_by_address("google_pubsub_topic.orders")
        iam_member = inventory.get_by_address("google_pubsub_topic_iam_member.orders_publisher")
        assert topic is not None
        assert iam_member is not None

        self.assertEqual(
            iam_member.get_metadata_field(GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE),
            unresolved_reference,
        )
        self.assertEqual(gcp_facts(topic).bindings, [])
        self.assertEqual(gcp_facts(topic).resource_policy_source_addresses, [])

    def test_azure_managed_identity_service_bus_assignment_preserves_scope_and_condition(self) -> None:
        condition = "@Resource[Microsoft.ServiceBus/namespaces:name] StringEquals 'orders-events'"
        inventory = AzureNormalizer().normalize(
            [
                _azure_service_bus_namespace(),
                _azure_web_app(),
                _azure_role_assignment(condition=condition),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assignment = inventory.get_by_address("azurerm_role_assignment.orders_messaging")
        assert workload is not None
        assert assignment is not None

        assignment_facts = azure_facts(assignment)
        self.assertEqual(assignment_facts.resolved_managed_identity_address, workload.address)
        self.assertEqual(assignment_facts.role_assignment_scope, "azurerm_servicebus_namespace.orders.id")
        self.assertEqual(assignment_facts.role_assignment_scope_kind, "resource")
        self.assertEqual(
            assignment_facts.role_assignment_target_resource_address,
            "azurerm_servicebus_namespace.orders",
        )
        self.assertEqual(
            assignment_facts.role_assignment_target_resource_type,
            AzureResourceType.SERVICE_BUS_NAMESPACE,
        )
        self.assertEqual(assignment_facts.role_assignment_condition, condition)
        projected = azure_facts(workload).managed_identity_role_assignments[0]
        self.assertEqual(projected["target_resource_address"], "azurerm_servicebus_namespace.orders")
        self.assertEqual(projected["role_definition_name"], "Azure Service Bus Data Sender")

    def test_azure_custom_messaging_data_actions_are_preserved(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _azure_service_bus_namespace(),
                _azure_web_app(),
                _azure_custom_messaging_role(),
                _azure_role_assignment(
                    role_definition_name=None,
                    role_definition_id=("azurerm_role_definition.messaging_writer.role_definition_resource_id"),
                ),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        role = inventory.get_by_address("azurerm_role_definition.messaging_writer")
        assignment = inventory.get_by_address("azurerm_role_assignment.orders_messaging")
        assert workload is not None
        assert role is not None
        assert assignment is not None

        role_facts = azure_facts(role)
        assignment_facts = azure_facts(assignment)
        self.assertEqual(
            role_facts.role_definition_data_actions,
            ["Microsoft.ServiceBus/namespaces/topics/messages/send/action"],
        )
        self.assertEqual(
            role_facts.role_definition_not_data_actions,
            ["Microsoft.ServiceBus/namespaces/queues/messages/receive/action"],
        )
        self.assertEqual(
            assignment_facts.resolved_role_definition_address,
            "azurerm_role_definition.messaging_writer",
        )
        self.assertEqual(
            azure_facts(workload).managed_identity_role_assignments[0]["target_resource_address"],
            "azurerm_servicebus_namespace.orders",
        )

    def test_azure_external_scope_and_unknown_principal_do_not_invent_relationships(self) -> None:
        external_scope = (
            "/subscriptions/sub-9999/resourceGroups/external/providers/Microsoft.ServiceBus/namespaces/external-events"
        )
        external_inventory = AzureNormalizer().normalize(
            [
                _azure_service_bus_namespace(),
                _azure_web_app(),
                _azure_role_assignment(scope=external_scope),
            ]
        )
        external_assignment = external_inventory.get_by_address("azurerm_role_assignment.orders_messaging")
        assert external_assignment is not None
        external_facts = azure_facts(external_assignment)

        self.assertEqual(external_facts.resolved_managed_identity_address, "azurerm_linux_web_app.orders")
        self.assertEqual(external_facts.role_assignment_scope, external_scope)
        self.assertIsNone(external_facts.role_assignment_target_resource_address)
        self.assertIsNone(external_facts.role_assignment_target_resource_type)

        unknown_inventory = AzureNormalizer().normalize(
            [
                _azure_service_bus_namespace(),
                _azure_web_app(),
                _azure_role_assignment(
                    principal_id=None,
                    unknown_values={"principal_id": True},
                ),
            ]
        )
        workload = unknown_inventory.get_by_address("azurerm_linux_web_app.orders")
        assignment = unknown_inventory.get_by_address("azurerm_role_assignment.orders_messaging")
        assert workload is not None
        assert assignment is not None

        assignment_facts = azure_facts(assignment)
        self.assertIsNone(assignment_facts.resolved_managed_identity_address)
        self.assertEqual(azure_facts(workload).managed_identity_role_assignments, [])
        self.assertIn(
            "principal_id is unknown after planning",
            assignment_facts.key_vault_authorization_uncertainties,
        )


if __name__ == "__main__":
    unittest.main()
