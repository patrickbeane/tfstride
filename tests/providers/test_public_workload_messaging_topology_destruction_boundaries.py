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
    _TOPIC_ARN as AWS_TOPIC_ARN,
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
from tests.providers.aws.test_aws_ecs_messaging_access_paths import (
    _topic as aws_topic,
)
from tests.providers.aws.test_aws_public_ecs_messaging_mutation_rules import (
    _load_balancer_path as aws_load_balancer_path,
)
from tests.providers.aws.test_aws_public_ecs_messaging_mutation_rules import (
    _service as aws_service,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _NAMESPACE_ID as AZURE_NAMESPACE_ID,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _QUEUE_ID as AZURE_QUEUE_ID,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _SUBSCRIPTION_ID as AZURE_SUBSCRIPTION_ID,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _SYSTEM_PRINCIPAL_ID as AZURE_SYSTEM_PRINCIPAL_ID,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _TOPIC_ID as AZURE_TOPIC_ID,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _USER_IDENTITY_ID as AZURE_USER_IDENTITY_ID,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _USER_PRINCIPAL_ID as AZURE_USER_PRINCIPAL_ID,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _entity as azure_entity,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _namespace as azure_namespace,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _resource as azure_resource,
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
from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _PROJECT as GCP_PROJECT,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _SERVICE_ACCOUNT_MEMBER as GCP_SERVICE_ACCOUNT_MEMBER,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _SUBSCRIPTION_ADDRESS as GCP_SUBSCRIPTION_ADDRESS,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _TOPIC_ADDRESS as GCP_TOPIC_ADDRESS,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _WORKLOAD_ADDRESS as GCP_WORKLOAD_ADDRESS,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _cloud_run as gcp_cloud_run,
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
from tests.providers.gcp.test_gcp_cloud_run_pubsub_message_removal_paths import (
    _cross_project_topic_and_subscription,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_message_removal_paths import (
    _project_iam_member as gcp_project_iam_member,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_message_removal_paths import (
    _subscription_iam_binding as gcp_subscription_iam_binding,
)
from tests.providers.gcp.test_gcp_public_cloud_run_pubsub_mutation_rules import (
    _public_invoker as gcp_public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import ResourceInventory, TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.azure.arm_control_plane_authorization import (
    AzureArmControlPlaneAuthorityResult,
    model_arm_control_plane_action_authority,
)
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_decoration.workload_identities import (
    workload_managed_identities,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import (
    AzureDecorationContext,
    AzureResourceIndexBuilder,
)
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType

_AWS_MUTATION_RULE = "aws-public-ecs-messaging-mutation-access"
_GCP_MUTATION_RULE = "gcp-public-cloud-run-pubsub-mutation-access"

_AWS_DELETE_QUEUE = "sqs:DeleteQueue"
_AWS_DELETE_TOPIC = "sns:DeleteTopic"
_GCP_CONSUME = "pubsub.subscriptions.consume"
_GCP_DELETE_SUBSCRIPTION = "pubsub.subscriptions.delete"
_GCP_DELETE_TOPIC = "pubsub.topics.delete"

_AZURE_RECEIVE = "microsoft.servicebus/namespaces/messages/receive/action"
_AZURE_DELETE_NAMESPACE = "Microsoft.ServiceBus/namespaces/delete"
_AZURE_DELETE_QUEUE = "Microsoft.ServiceBus/namespaces/queues/delete"
_AZURE_DELETE_TOPIC = "Microsoft.ServiceBus/namespaces/topics/delete"
_AZURE_DELETE_SUBSCRIPTION = "Microsoft.ServiceBus/namespaces/topics/subscriptions/delete"
_AZURE_CONTROL_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/messaging-topology-operator"
)


def _evaluate(
    normalizer: ProviderNormalizer,
    resources: list[TerraformResource],
    rule_ids: frozenset[str],
):
    inventory = normalizer.normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=rule_ids),
    )


def _aws_resources(
    statements: list[dict[str, Any]],
    *,
    internal: bool = False,
    queue: TerraformResource | None = None,
    topic: TerraformResource | None = None,
    execution_statements: list[dict[str, Any]] | None = None,
    incomplete: bool = False,
) -> list[TerraformResource]:
    resources = [
        *aws_load_balancer_path(internal=internal),
        topic or aws_topic(),
        queue or aws_queue(),
        aws_role("orders_task", AWS_TASK_ROLE_ARN, statements),
    ]
    if execution_statements is not None:
        resources.append(
            aws_role(
                "orders_execution",
                AWS_EXECUTION_ROLE_ARN,
                execution_statements,
            )
        )
    if incomplete:
        resources.append(
            aws_role_policy_attachment(
                AWS_TASK_ROLE_ARN,
                "arn:aws:iam::aws:policy/ExternalMessagingAdministration",
            )
        )
    resources.extend([aws_task_definition(), aws_service()])
    return resources


def _aws_service_facts(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(resources)
    service = inventory.get_by_address("aws_ecs_service.orders")
    assert service is not None
    return inventory, aws_facts(service)


def _gcp_custom_role(
    permissions: list[str],
    *,
    project: str = GCP_PROJECT,
    stage: str | None = "GA",
    deleted: bool | None = False,
    unknown_stage: bool = False,
    unknown_deleted: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "project": project,
        "role_id": "messagingTopology",
        "name": f"projects/{project}/roles/messagingTopology",
        "permissions": permissions,
    }
    if stage is not None:
        values["stage"] = stage
    if deleted is not None:
        values["deleted"] = deleted
    unknown_values: dict[str, object] = {}
    if unknown_stage:
        unknown_values["stage"] = True
    if unknown_deleted:
        unknown_values["deleted"] = True
    return _terraform_resource(
        "google_project_iam_custom_role.messaging_topology",
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        values,
        unknown_values=unknown_values or None,
    )


def _gcp_role_name(project: str = GCP_PROJECT) -> str:
    return f"projects/{project}/roles/messagingTopology"


def _gcp_workload(*, public: bool = True) -> TerraformResource:
    workload = gcp_cloud_run()
    assert isinstance(workload, TerraformResource)
    workload.values["ingress"] = "INGRESS_TRAFFIC_ALL" if public else "INGRESS_TRAFFIC_INTERNAL_ONLY"
    return workload


def _azure_workload(*, public: bool = True) -> TerraformResource:
    workload = azure_web_app()
    workload.values["public_network_access_enabled"] = public
    return workload


def _azure_control_role(
    *,
    actions: list[str],
    not_actions: list[str] | None = None,
    data_actions: list[str] | None = None,
    not_data_actions: list[str] | None = None,
    assignable_scopes: list[str] | None = None,
) -> TerraformResource:
    return azure_resource(
        AzureResourceType.ROLE_DEFINITION,
        {
            "id": _AZURE_CONTROL_ROLE_ID,
            "name": "Messaging Topology Operator",
            "scope": "/subscriptions/sub-0001",
            "assignable_scopes": assignable_scopes or ["/subscriptions/sub-0001"],
            "permissions": [
                {
                    "actions": actions,
                    "not_actions": not_actions or [],
                    "data_actions": data_actions or [],
                    "not_data_actions": not_data_actions or [],
                }
            ],
        },
        name="messaging_topology",
    )


def _azure_control_assignment(
    *,
    scope: object = AZURE_NAMESPACE_ID,
    principal_id: object = AZURE_SYSTEM_PRINCIPAL_ID,
    condition: object | None = None,
    name: str = "messaging_topology",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "scope": scope,
        "role_definition_id": _AZURE_CONTROL_ROLE_ID,
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if condition is not None:
        values["condition"] = condition
        values["condition_version"] = "2.0"
    return azure_resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        values,
        name=name,
        unknown_values=unknown_values,
    )


def _azure_inventory_and_context(
    resources: list[TerraformResource],
) -> tuple[ResourceInventory, AzureDecorationContext]:
    inventory = AzureNormalizer().normalize(resources)
    return (
        inventory,
        AzureDecorationContext(index=AzureResourceIndexBuilder().build(inventory.resources)),
    )


def _azure_authority(
    inventory: ResourceInventory,
    context: AzureDecorationContext,
    *,
    target_arm_id: str,
    action: str,
    principal_id: str = AZURE_SYSTEM_PRINCIPAL_ID,
    assignment_address: str = "azurerm_role_assignment.messaging_topology",
) -> AzureArmControlPlaneAuthorityResult:
    assignment = inventory.get_by_address(assignment_address)
    assert assignment is not None
    return model_arm_control_plane_action_authority(
        assignment,
        context,
        principal_id=principal_id,
        target_arm_id=target_arm_id,
        requested_actions=(action,),
    )


class PublicWorkloadMessagingTopologyDestructionBoundaryTests(unittest.TestCase):
    """Pin topology-deletion prerequisites and provider-native paths."""

    def test_topology_deletion_remains_distinct_from_message_removal(self) -> None:
        aws_inventory, aws_service = _aws_service_facts(
            _aws_resources(
                [
                    aws_statement("Allow", _AWS_DELETE_TOPIC, AWS_TOPIC_ARN),
                    aws_statement("Allow", _AWS_DELETE_QUEUE, AWS_QUEUE_ARN),
                ]
            )
        )
        self.assertEqual(
            {action for path in aws_service.ecs_messaging_access_paths for action in path["matched_actions"]},
            {_AWS_DELETE_QUEUE, _AWS_DELETE_TOPIC},
        )
        self.assertEqual(aws_service.ecs_sqs_message_removal_paths, [])
        self.assertEqual(
            {path["operation"] for path in aws_service.ecs_messaging_topology_destruction_paths},
            {_AWS_DELETE_QUEUE, _AWS_DELETE_TOPIC},
        )
        self.assertEqual(
            {
                tuple(path["internet_facing_load_balancers"])
                for path in aws_service.ecs_messaging_topology_destruction_paths
            },
            {("aws_lb.public",)},
        )
        self.assertIsNotNone(aws_inventory.get_by_address("aws_sns_topic.orders"))

        gcp_inventory = GcpNormalizer().normalize(
            [
                _gcp_workload(),
                gcp_public_invoker(),
                gcp_topic(),
                gcp_subscription(),
                _gcp_custom_role([_GCP_DELETE_TOPIC, _GCP_DELETE_SUBSCRIPTION]),
                gcp_topic_iam_member(role=_gcp_role_name()),
                gcp_subscription_iam_member(role=_gcp_role_name()),
            ]
        )
        gcp_workload = gcp_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert gcp_workload is not None
        self.assertTrue(gcp_workload.public_exposure)
        gcp_workload_facts = gcp_facts(gcp_workload)
        self.assertEqual(
            {
                permission
                for path in gcp_workload_facts.cloud_run_pubsub_access_paths
                for permission in path["matched_permissions"]
            },
            {_GCP_DELETE_SUBSCRIPTION, _GCP_DELETE_TOPIC},
        )
        self.assertEqual(
            gcp_workload_facts.cloud_run_pubsub_message_removal_paths,
            [],
        )
        self.assertEqual(
            {path["operation"] for path in gcp_workload_facts.cloud_run_pubsub_topology_destruction_paths},
            {_GCP_DELETE_SUBSCRIPTION, _GCP_DELETE_TOPIC},
        )

        azure_inventory, azure_context = _azure_inventory_and_context(
            [
                azure_namespace(),
                azure_entity(AzureResourceType.SERVICE_BUS_QUEUE, AZURE_QUEUE_ID),
                _azure_workload(),
                _azure_control_role(actions=[_AZURE_DELETE_QUEUE]),
                _azure_control_assignment(scope=AZURE_QUEUE_ID),
            ]
        )
        azure_workload = azure_inventory.get_by_address("azurerm_linux_web_app.orders")
        assert azure_workload is not None
        self.assertTrue(azure_facts(azure_workload).public_network_access_enabled)
        self.assertEqual(
            azure_facts(azure_workload).app_service_service_bus_message_removal_paths,
            [],
        )
        self.assertEqual(
            _azure_authority(
                azure_inventory,
                azure_context,
                target_arm_id=AZURE_QUEUE_ID,
                action=_AZURE_DELETE_QUEUE,
            ).state,
            "granted",
        )

    def test_aws_task_role_preserves_exact_queue_and_topic_delete_authority(
        self,
    ) -> None:
        _inventory, facts = _aws_service_facts(
            _aws_resources(
                [
                    aws_statement("Allow", _AWS_DELETE_TOPIC, AWS_TOPIC_ARN),
                    aws_statement("Allow", _AWS_DELETE_QUEUE, AWS_QUEUE_ARN),
                ],
                execution_statements=[
                    aws_statement(
                        "Allow",
                        [_AWS_DELETE_TOPIC, _AWS_DELETE_QUEUE],
                        [AWS_TOPIC_ARN, AWS_QUEUE_ARN],
                    )
                ],
            )
        )

        paths = {path["messaging_resource_address"]: path for path in facts.ecs_messaging_access_paths}
        self.assertEqual(
            set(paths),
            {"aws_sns_topic.orders", "aws_sqs_queue.orders"},
        )
        self.assertEqual(paths["aws_sns_topic.orders"]["matched_actions"], [_AWS_DELETE_TOPIC])
        self.assertEqual(paths["aws_sns_topic.orders"]["resource_scopes"], ["exact_topic"])
        self.assertEqual(paths["aws_sns_topic.orders"]["messaging_resource_arn"], AWS_TOPIC_ARN)
        self.assertEqual(paths["aws_sqs_queue.orders"]["matched_actions"], [_AWS_DELETE_QUEUE])
        self.assertEqual(paths["aws_sqs_queue.orders"]["resource_scopes"], ["exact_queue"])
        self.assertEqual(paths["aws_sqs_queue.orders"]["messaging_resource_arn"], AWS_QUEUE_ARN)
        self.assertEqual(
            {path["role_arn"] for path in paths.values()},
            {AWS_TASK_ROLE_ARN},
        )
        self.assertEqual(
            {path["credential_context"] for path in paths.values()},
            {"workload_runtime"},
        )
        topology_paths = {
            path["messaging_resource_address"]: path for path in facts.ecs_messaging_topology_destruction_paths
        }
        self.assertEqual(set(topology_paths), set(paths))
        self.assertEqual(
            topology_paths["aws_sns_topic.orders"]["operation"],
            _AWS_DELETE_TOPIC,
        )
        self.assertEqual(
            topology_paths["aws_sqs_queue.orders"]["operation"],
            _AWS_DELETE_QUEUE,
        )
        self.assertEqual(
            {path["authorization_state"] for path in topology_paths.values()},
            {"allowed"},
        )
        self.assertEqual(
            {path["same_account"] for path in topology_paths.values()},
            {True},
        )

    def test_aws_denied_conditional_incomplete_and_non_exact_authority_fails_closed(
        self,
    ) -> None:
        cases = {
            "explicit deny": _aws_resources(
                [
                    aws_statement("Allow", _AWS_DELETE_QUEUE, AWS_QUEUE_ARN),
                    aws_statement("Deny", _AWS_DELETE_QUEUE, AWS_QUEUE_ARN),
                ]
            ),
            "conditional": _aws_resources(
                [
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_QUEUE,
                        AWS_QUEUE_ARN,
                        condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
                    )
                ]
            ),
            "incomplete": _aws_resources(
                [aws_statement("Allow", _AWS_DELETE_QUEUE, AWS_QUEUE_ARN)],
                incomplete=True,
            ),
            "non exact": _aws_resources(
                [
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_QUEUE,
                        "arn:aws:sqs:us-east-1:111122223333:orders-*",
                    )
                ]
            ),
        }

        for case, resources in cases.items():
            with self.subTest(case=case):
                _inventory, facts = _aws_service_facts(resources)
                paths = facts.ecs_messaging_access_paths
                deterministic = [
                    path
                    for path in paths
                    if path["access_state"] == "allowed" and _AWS_DELETE_QUEUE in path["matched_actions"]
                ]
                self.assertEqual(deterministic, [])
                self.assertEqual(
                    facts.ecs_messaging_topology_destruction_paths,
                    [],
                )
                self.assertTrue(paths or facts.ecs_messaging_access_path_uncertainties)

    def test_aws_delete_queue_account_compatibility_and_queue_policy_stay_separate(
        self,
    ) -> None:
        external_queue_arn = "arn:aws:sqs:us-east-1:999900001111:orders"
        queue = aws_queue(arn=external_queue_arn)
        queue.values["id"] = "https://sqs.us-east-1.amazonaws.com/999900001111/orders"
        queue.values["policy"] = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": AWS_TASK_ROLE_ARN},
                        "Action": _AWS_DELETE_QUEUE,
                        "Resource": external_queue_arn,
                    }
                ],
            }
        )
        inventory, facts = _aws_service_facts(
            _aws_resources(
                [
                    aws_statement(
                        "Allow",
                        _AWS_DELETE_QUEUE,
                        external_queue_arn,
                    )
                ],
                queue=queue,
            )
        )
        path = next(path for path in facts.ecs_messaging_access_paths if path["messaging_service"] == "sqs")
        normalized_queue = inventory.get_by_address("aws_sqs_queue.orders")
        assert normalized_queue is not None

        self.assertEqual(path["evaluation_basis"], "modeled_identity_policy")
        self.assertEqual(path["role_arn"], AWS_TASK_ROLE_ARN)
        self.assertEqual(path["messaging_resource_arn"], external_queue_arn)
        self.assertNotEqual(
            AWS_TASK_ROLE_ARN.split(":")[4],
            external_queue_arn.split(":")[4],
        )
        self.assertEqual(
            aws_facts(normalized_queue).sqs_queue_policy_state,
            "configured",
        )
        self.assertEqual(
            facts.ecs_messaging_topology_destruction_paths,
            [],
        )
        self.assertEqual(len(normalized_queue.policy_statements), 1)
        queue_policy = normalized_queue.policy_statements[0]
        self.assertEqual(queue_policy.effect, "Allow")
        self.assertEqual(queue_policy.actions, [_AWS_DELETE_QUEUE])
        self.assertEqual(queue_policy.resources, [external_queue_arn])
        self.assertEqual(queue_policy.principals, [AWS_TASK_ROLE_ARN])

    def test_aws_private_topology_authority_survives_without_public_finding(
        self,
    ) -> None:
        resources = _aws_resources(
            [aws_statement("Allow", _AWS_DELETE_QUEUE, AWS_QUEUE_ARN)],
            internal=True,
        )
        _inventory, facts = _aws_service_facts(resources)

        self.assertEqual(
            facts.ecs_messaging_access_paths[0]["matched_actions"],
            [_AWS_DELETE_QUEUE],
        )
        self.assertEqual(
            [path["operation"] for path in facts.ecs_messaging_topology_destruction_paths],
            [_AWS_DELETE_QUEUE],
        )
        self.assertEqual(
            facts.ecs_messaging_topology_destruction_paths[0]["internet_facing_load_balancers"],
            [],
        )
        self.assertEqual(
            _evaluate(
                AwsNormalizer(),
                resources,
                frozenset({_AWS_MUTATION_RULE}),
            ),
            [],
        )

    def test_gcp_topic_and_subscription_delete_permissions_preserve_exact_targets(
        self,
    ) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _gcp_workload(),
                gcp_public_invoker(),
                gcp_topic(),
                gcp_subscription(),
                _gcp_custom_role([_GCP_DELETE_TOPIC, _GCP_DELETE_SUBSCRIPTION]),
                gcp_topic_iam_member(role=_gcp_role_name()),
                gcp_subscription_iam_member(role=_gcp_role_name()),
            ]
        )
        workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        subscription = inventory.get_by_address(GCP_SUBSCRIPTION_ADDRESS)
        assert workload is not None
        assert subscription is not None

        paths = {path["messaging_resource_kind"]: path for path in gcp_facts(workload).cloud_run_pubsub_access_paths}
        self.assertEqual(paths["topic"]["matched_permissions"], [_GCP_DELETE_TOPIC])
        self.assertEqual(paths["topic"]["messaging_resource_address"], GCP_TOPIC_ADDRESS)
        self.assertEqual(paths["topic"]["resource_scope"], "exact_topic")
        self.assertEqual(
            paths["subscription"]["matched_permissions"],
            [_GCP_DELETE_SUBSCRIPTION],
        )
        self.assertEqual(
            paths["subscription"]["messaging_resource_address"],
            GCP_SUBSCRIPTION_ADDRESS,
        )
        self.assertEqual(
            paths["subscription"]["resource_scope"],
            "exact_subscription",
        )
        self.assertEqual(
            gcp_facts(subscription).pubsub_topic_reference,
            f"{GCP_TOPIC_ADDRESS}.id",
        )
        topology_paths = {
            path["messaging_resource_kind"]: path
            for path in gcp_facts(workload).cloud_run_pubsub_topology_destruction_paths
        }
        self.assertEqual(set(topology_paths), {"topic", "subscription"})
        self.assertEqual(topology_paths["topic"]["operation"], _GCP_DELETE_TOPIC)
        self.assertEqual(
            topology_paths["topic"]["target_model_evidence_addresses"],
            [GCP_TOPIC_ADDRESS],
        )
        self.assertEqual(
            topology_paths["subscription"]["operation"],
            _GCP_DELETE_SUBSCRIPTION,
        )
        self.assertEqual(
            topology_paths["subscription"]["target_model_evidence_addresses"],
            [GCP_TOPIC_ADDRESS, GCP_SUBSCRIPTION_ADDRESS],
        )

    def test_gcp_project_scope_fans_only_to_consumer_project_subscriptions(
        self,
    ) -> None:
        topic, subscription = _cross_project_topic_and_subscription()
        resources = [
            _gcp_workload(),
            gcp_public_invoker(),
            topic,
            subscription,
            _gcp_custom_role(
                [
                    _GCP_CONSUME,
                    _GCP_DELETE_SUBSCRIPTION,
                    _GCP_DELETE_TOPIC,
                ],
                project="consumer-project",
            ),
            gcp_project_iam_member(
                project="consumer-project",
                role=_gcp_role_name("consumer-project"),
            ),
        ]
        inventory = GcpNormalizer().normalize(resources)
        workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        normalized_topic = inventory.get_by_address(GCP_TOPIC_ADDRESS)
        normalized_subscription = inventory.get_by_address(GCP_SUBSCRIPTION_ADDRESS)
        project_grant = inventory.get_by_address("google_project_iam_member.project_subscriber")
        custom_role = inventory.get_by_address("google_project_iam_custom_role.messaging_topology")
        assert workload is not None
        assert normalized_topic is not None
        assert normalized_subscription is not None
        assert project_grant is not None
        assert custom_role is not None

        self.assertEqual(gcp_facts(project_grant).project, "consumer-project")
        self.assertEqual(
            gcp_facts(project_grant).role,
            _gcp_role_name("consumer-project"),
        )
        self.assertEqual(gcp_facts(project_grant).member, GCP_SERVICE_ACCOUNT_MEMBER)
        self.assertEqual(
            gcp_facts(custom_role).custom_role_permissions,
            [_GCP_CONSUME, _GCP_DELETE_SUBSCRIPTION, _GCP_DELETE_TOPIC],
        )

        removal_paths = gcp_facts(workload).cloud_run_pubsub_message_removal_paths
        self.assertEqual(len(removal_paths), 1)
        path = removal_paths[0]
        self.assertEqual(path["scope_type"], "project")
        self.assertEqual(path["scope"], "consumer-project")
        self.assertEqual(path["subscription_project"], "consumer-project")
        self.assertEqual(path["topic_project"], "producer-project")
        self.assertEqual(path["subscription_address"], GCP_SUBSCRIPTION_ADDRESS)
        self.assertEqual(path["topic_address"], GCP_TOPIC_ADDRESS)
        topology_paths = gcp_facts(workload).cloud_run_pubsub_topology_destruction_paths
        self.assertEqual(len(topology_paths), 1)
        self.assertEqual(topology_paths[0]["operation"], _GCP_DELETE_SUBSCRIPTION)
        self.assertEqual(topology_paths[0]["scope_type"], "project")
        self.assertEqual(topology_paths[0]["scope"], "consumer-project")
        self.assertEqual(topology_paths[0]["subscription_project"], "consumer-project")
        self.assertEqual(topology_paths[0]["topic_project"], "producer-project")
        self.assertEqual(gcp_facts(normalized_topic).project, "producer-project")
        self.assertEqual(
            gcp_facts(normalized_subscription).project,
            "consumer-project",
        )

    def test_gcp_conditions_custom_role_lifecycle_and_manager_overlap_stay_uncertain(
        self,
    ) -> None:
        condition = {
            "title": "runtime-window",
            "expression": "request.time < timestamp('2030-01-01T00:00:00Z')",
        }
        conditional_inventory = GcpNormalizer().normalize(
            [
                _gcp_workload(),
                gcp_public_invoker(),
                gcp_topic(),
                _gcp_custom_role([_GCP_DELETE_TOPIC]),
                gcp_topic_iam_member(
                    role=_gcp_role_name(),
                    condition=condition,
                ),
            ]
        )
        conditional_workload = conditional_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert conditional_workload is not None
        conditional_path = gcp_facts(conditional_workload).cloud_run_pubsub_access_paths[0]
        self.assertEqual(conditional_path["condition_state"], "configured")
        self.assertEqual(conditional_path["access_state"], "conditional")
        self.assertEqual(
            gcp_facts(conditional_workload).cloud_run_pubsub_topology_destruction_paths,
            [],
        )
        self.assertTrue(gcp_facts(conditional_workload).cloud_run_pubsub_topology_destruction_path_uncertainties)

        lifecycle_cases = {
            "disabled": _gcp_custom_role(
                [_GCP_CONSUME, _GCP_DELETE_SUBSCRIPTION],
                stage="DISABLED",
            ),
            "deleted": _gcp_custom_role(
                [_GCP_CONSUME, _GCP_DELETE_SUBSCRIPTION],
                deleted=True,
            ),
            "unknown deleted": _gcp_custom_role(
                [_GCP_CONSUME, _GCP_DELETE_SUBSCRIPTION],
                deleted=None,
                unknown_deleted=True,
            ),
        }
        for case, role in lifecycle_cases.items():
            with self.subTest(case=case):
                inventory = GcpNormalizer().normalize(
                    [
                        _gcp_workload(),
                        gcp_public_invoker(),
                        gcp_topic(),
                        gcp_subscription(),
                        role,
                        gcp_subscription_iam_member(role=_gcp_role_name()),
                    ]
                )
                workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
                normalized_role = inventory.get_by_address("google_project_iam_custom_role.messaging_topology")
                assert workload is not None
                assert normalized_role is not None
                self.assertEqual(
                    gcp_facts(workload).cloud_run_pubsub_message_removal_paths,
                    [],
                )
                self.assertEqual(
                    gcp_facts(workload).cloud_run_pubsub_topology_destruction_paths,
                    [],
                )
                role_facts = gcp_facts(normalized_role)
                if case == "disabled":
                    self.assertEqual(role_facts.custom_role_stage, "DISABLED")
                elif case == "deleted":
                    self.assertTrue(role_facts.custom_role_deleted)
                else:
                    self.assertIsNone(role_facts.custom_role_deleted)
                    self.assertTrue(role_facts.custom_role_deleted_uncertainties)

        manager_inventory = GcpNormalizer().normalize(
            [
                _gcp_workload(),
                gcp_public_invoker(),
                gcp_topic(),
                gcp_subscription(),
                _gcp_custom_role([_GCP_CONSUME, _GCP_DELETE_SUBSCRIPTION]),
                gcp_subscription_iam_member(role=("google_project_iam_custom_role.messaging_topology.name")),
                gcp_subscription_iam_binding(
                    role=_gcp_role_name(),
                    members=["serviceAccount:other@tfstride-demo.iam.gserviceaccount.com"],
                ),
            ]
        )
        manager_workload = manager_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert manager_workload is not None
        manager_facts = gcp_facts(manager_workload)
        self.assertEqual(manager_facts.cloud_run_pubsub_message_removal_paths, [])
        self.assertEqual(
            manager_facts.cloud_run_pubsub_topology_destruction_paths,
            [],
        )
        self.assertTrue(
            any(
                "overlapping" in uncertainty or "ambiguous" in uncertainty
                for uncertainty in manager_facts.cloud_run_pubsub_message_removal_path_uncertainties
            )
        )

    def test_gcp_private_topology_authority_survives_without_public_finding(
        self,
    ) -> None:
        resources = [
            _gcp_workload(public=False),
            gcp_public_invoker(),
            gcp_topic(),
            _gcp_custom_role([_GCP_DELETE_TOPIC]),
            gcp_topic_iam_member(role=_gcp_role_name()),
        ]
        inventory = GcpNormalizer().normalize(resources)
        workload = inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert workload is not None
        self.assertFalse(workload.public_exposure)

        self.assertEqual(
            gcp_facts(workload).cloud_run_pubsub_access_paths[0]["matched_permissions"],
            [_GCP_DELETE_TOPIC],
        )
        self.assertEqual(
            [path["operation"] for path in gcp_facts(workload).cloud_run_pubsub_topology_destruction_paths],
            [_GCP_DELETE_TOPIC],
        )
        self.assertEqual(
            _evaluate(
                GcpNormalizer(),
                resources,
                frozenset({_GCP_MUTATION_RULE}),
            ),
            [],
        )

    def test_azure_arm_actions_and_service_bus_data_actions_remain_distinct(
        self,
    ) -> None:
        resources = [
            azure_namespace(),
            azure_entity(AzureResourceType.SERVICE_BUS_QUEUE, AZURE_QUEUE_ID),
            _azure_workload(),
            _azure_control_role(
                actions=[_AZURE_DELETE_QUEUE],
                data_actions=[_AZURE_RECEIVE],
            ),
            _azure_control_assignment(scope=AZURE_QUEUE_ID),
        ]
        inventory, context = _azure_inventory_and_context(resources)
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None

        data_paths = azure_facts(workload).app_service_service_bus_access_paths
        self.assertEqual(len(data_paths), 1)
        self.assertEqual(data_paths[0]["matched_data_actions"], [_AZURE_RECEIVE])
        authority = _azure_authority(
            inventory,
            context,
            target_arm_id=AZURE_QUEUE_ID,
            action=_AZURE_DELETE_QUEUE,
        )
        self.assertEqual(authority.state, "granted")
        assert authority.grant is not None
        self.assertEqual(authority.grant["matched_actions"], [_AZURE_DELETE_QUEUE])
        self.assertEqual(authority.grant["role_actions"], [_AZURE_DELETE_QUEUE])

        data_only_inventory, data_only_context = _azure_inventory_and_context(
            [
                azure_namespace(),
                azure_entity(AzureResourceType.SERVICE_BUS_QUEUE, AZURE_QUEUE_ID),
                _azure_workload(),
                _azure_control_role(
                    actions=[],
                    data_actions=[_AZURE_DELETE_QUEUE],
                ),
                _azure_control_assignment(scope=AZURE_QUEUE_ID),
            ]
        )
        self.assertEqual(
            _azure_authority(
                data_only_inventory,
                data_only_context,
                target_arm_id=AZURE_QUEUE_ID,
                action=_AZURE_DELETE_QUEUE,
            ).state,
            "not_granted",
        )

    def test_azure_namespace_scope_preserves_exact_modeled_topology_targets(
        self,
    ) -> None:
        resources = [
            azure_namespace(),
            azure_entity(AzureResourceType.SERVICE_BUS_QUEUE, AZURE_QUEUE_ID),
            azure_entity(AzureResourceType.SERVICE_BUS_TOPIC, AZURE_TOPIC_ID),
            azure_subscription(),
            _azure_workload(),
            _azure_control_role(
                actions=[
                    _AZURE_DELETE_NAMESPACE,
                    _AZURE_DELETE_QUEUE,
                    _AZURE_DELETE_TOPIC,
                    _AZURE_DELETE_SUBSCRIPTION,
                ]
            ),
            _azure_control_assignment(),
        ]
        inventory, context = _azure_inventory_and_context(resources)
        cases = (
            (
                "azurerm_servicebus_namespace.orders",
                AZURE_NAMESPACE_ID,
                _AZURE_DELETE_NAMESPACE,
            ),
            (
                "azurerm_servicebus_queue.orders",
                AZURE_QUEUE_ID,
                _AZURE_DELETE_QUEUE,
            ),
            (
                "azurerm_servicebus_topic.orders",
                AZURE_TOPIC_ID,
                _AZURE_DELETE_TOPIC,
            ),
            (
                "azurerm_servicebus_subscription.orders",
                AZURE_SUBSCRIPTION_ID,
                _AZURE_DELETE_SUBSCRIPTION,
            ),
        )

        for address, target_id, action in cases:
            with self.subTest(address=address):
                self.assertIsNotNone(inventory.get_by_address(address))
                result = _azure_authority(
                    inventory,
                    context,
                    target_arm_id=target_id,
                    action=action,
                )
                self.assertEqual(result.state, "granted")
                assert result.grant is not None
                self.assertEqual(result.grant["target_arm_id"], target_id)
                self.assertEqual(result.grant["matched_actions"], [action])
                self.assertEqual(
                    result.grant["assignment_scope_arm_id"],
                    AZURE_NAMESPACE_ID,
                )
                self.assertEqual(result.grant["assignment_scope_type"], "resource")

        queue = inventory.get_by_address("azurerm_servicebus_queue.orders")
        topic = inventory.get_by_address("azurerm_servicebus_topic.orders")
        subscription = inventory.get_by_address("azurerm_servicebus_subscription.orders")
        assert queue is not None
        assert topic is not None
        assert subscription is not None
        self.assertEqual(
            azure_facts(queue).resolved_service_bus_namespace_address,
            "azurerm_servicebus_namespace.orders",
        )
        self.assertEqual(
            azure_facts(topic).resolved_service_bus_namespace_address,
            "azurerm_servicebus_namespace.orders",
        )
        self.assertEqual(
            azure_facts(subscription).resolved_service_bus_topic_address,
            "azurerm_servicebus_topic.orders",
        )

    def test_azure_conditions_exclusions_assignable_scope_and_identity_fail_closed(
        self,
    ) -> None:
        cases = {
            "condition": (
                _azure_control_role(actions=[_AZURE_DELETE_QUEUE]),
                _azure_control_assignment(
                    scope=AZURE_QUEUE_ID,
                    condition="@Resource[Microsoft.ServiceBus/namespaces/queues:Name] StringEquals 'orders'",
                ),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unknown",
            ),
            "unknown condition": (
                _azure_control_role(actions=[_AZURE_DELETE_QUEUE]),
                _azure_control_assignment(
                    scope=AZURE_QUEUE_ID,
                    unknown_values={"condition": True},
                ),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unknown",
            ),
            "unknown condition version": (
                _azure_control_role(actions=[_AZURE_DELETE_QUEUE]),
                _azure_control_assignment(
                    scope=AZURE_QUEUE_ID,
                    unknown_values={"condition_version": True},
                ),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unknown",
            ),
            "not action": (
                _azure_control_role(
                    actions=["Microsoft.ServiceBus/namespaces/*"],
                    not_actions=[_AZURE_DELETE_QUEUE],
                ),
                _azure_control_assignment(scope=AZURE_QUEUE_ID),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "not_granted",
            ),
            "outside assignable scope": (
                _azure_control_role(
                    actions=[_AZURE_DELETE_QUEUE],
                    assignable_scopes=["/subscriptions/other-subscription"],
                ),
                _azure_control_assignment(scope=AZURE_QUEUE_ID),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unknown",
            ),
            "unknown identity": (
                _azure_control_role(actions=[_AZURE_DELETE_QUEUE]),
                _azure_control_assignment(
                    scope=AZURE_QUEUE_ID,
                    principal_id=None,
                    unknown_values={"principal_id": True},
                ),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unknown",
            ),
            "other identity": (
                _azure_control_role(actions=[_AZURE_DELETE_QUEUE]),
                _azure_control_assignment(
                    scope=AZURE_QUEUE_ID,
                    principal_id="other-principal",
                ),
                AZURE_SYSTEM_PRINCIPAL_ID,
                "unrelated",
            ),
        }

        for case, (role, assignment, principal_id, expected) in cases.items():
            with self.subTest(case=case):
                inventory, context = _azure_inventory_and_context(
                    [
                        azure_namespace(),
                        azure_entity(
                            AzureResourceType.SERVICE_BUS_QUEUE,
                            AZURE_QUEUE_ID,
                        ),
                        _azure_workload(),
                        role,
                        assignment,
                    ]
                )
                self.assertEqual(
                    _azure_authority(
                        inventory,
                        context,
                        target_arm_id=AZURE_QUEUE_ID,
                        action=_AZURE_DELETE_QUEUE,
                        principal_id=principal_id,
                    ).state,
                    expected,
                )

    def test_azure_system_and_user_assigned_runtime_identities_remain_distinct(
        self,
    ) -> None:
        app = _azure_workload()
        identity = app.values["identity"]
        assert isinstance(identity, list)
        identity_record = identity[0]
        assert isinstance(identity_record, dict)
        identity_record["type"] = "SystemAssigned, UserAssigned"
        identity_record["identity_ids"] = [AZURE_USER_IDENTITY_ID]
        resources = [
            azure_namespace(),
            azure_entity(AzureResourceType.SERVICE_BUS_QUEUE, AZURE_QUEUE_ID),
            azure_user_assigned_identity(),
            app,
            _azure_control_role(actions=[_AZURE_DELETE_QUEUE]),
            _azure_control_assignment(
                scope=AZURE_QUEUE_ID,
                name="system_topology",
            ),
            _azure_control_assignment(
                scope=AZURE_QUEUE_ID,
                principal_id=AZURE_USER_PRINCIPAL_ID,
                name="user_topology",
            ),
        ]
        inventory, context = _azure_inventory_and_context(resources)
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None
        identities, uncertainties = workload_managed_identities(workload, context)
        self.assertEqual(uncertainties, [])
        self.assertEqual(
            {(identity_resource.address, identity_kind) for identity_resource, identity_kind in identities},
            {
                ("azurerm_linux_web_app.orders", "system_assigned"),
                (
                    "azurerm_user_assigned_identity.orders_runtime",
                    "user_assigned",
                ),
            },
        )

        system = _azure_authority(
            inventory,
            context,
            target_arm_id=AZURE_QUEUE_ID,
            action=_AZURE_DELETE_QUEUE,
            assignment_address="azurerm_role_assignment.system_topology",
        )
        user = _azure_authority(
            inventory,
            context,
            target_arm_id=AZURE_QUEUE_ID,
            action=_AZURE_DELETE_QUEUE,
            principal_id=AZURE_USER_PRINCIPAL_ID,
            assignment_address="azurerm_role_assignment.user_topology",
        )
        self.assertEqual(system.state, "granted")
        self.assertEqual(user.state, "granted")
        assert system.grant is not None
        assert user.grant is not None
        self.assertNotEqual(system.grant["principal_id"], user.grant["principal_id"])

    def test_azure_management_lock_input_is_lifecycle_compatibility_not_recovery(
        self,
    ) -> None:
        lock = azure_resource(
            "azurerm_management_lock",
            {
                "name": "protect-messaging-topology",
                "scope": "azurerm_servicebus_namespace.orders.id",
                "lock_level": "CanNotDelete",
                "notes": "Protect the production namespace",
            },
            name="orders",
        )
        self.assertEqual(
            lock.values,
            {
                "name": "protect-messaging-topology",
                "scope": "azurerm_servicebus_namespace.orders.id",
                "lock_level": "CanNotDelete",
                "notes": "Protect the production namespace",
            },
        )
        self.assertNotIn("recovery", lock.values)
        self.assertNotIn("restored", lock.values)

    def test_private_topology_authority_is_independent_from_public_exposure(
        self,
    ) -> None:
        app = _azure_workload(public=False)
        inventory, context = _azure_inventory_and_context(
            [
                azure_namespace(),
                azure_entity(AzureResourceType.SERVICE_BUS_QUEUE, AZURE_QUEUE_ID),
                app,
                _azure_control_role(actions=[_AZURE_DELETE_QUEUE]),
                _azure_control_assignment(scope=AZURE_QUEUE_ID),
            ]
        )
        workload = inventory.get_by_address("azurerm_linux_web_app.orders")
        assert workload is not None
        self.assertFalse(azure_facts(workload).public_network_access_enabled)
        self.assertEqual(
            _azure_authority(
                inventory,
                context,
                target_arm_id=AZURE_QUEUE_ID,
                action=_AZURE_DELETE_QUEUE,
            ).state,
            "granted",
        )

    def test_provider_local_evidence_does_not_cross_topology_boundaries(
        self,
    ) -> None:
        _aws_inventory, aws_service_resource = _aws_service_facts(
            _aws_resources([aws_statement("Allow", _AWS_DELETE_QUEUE, AWS_QUEUE_ARN)])
        )
        aws_payload = json.dumps(
            aws_service_resource.ecs_messaging_access_paths,
            sort_keys=True,
        )

        gcp_inventory = GcpNormalizer().normalize(
            [
                _gcp_workload(),
                gcp_public_invoker(),
                gcp_topic(),
                _gcp_custom_role([_GCP_DELETE_TOPIC]),
                gcp_topic_iam_member(role=_gcp_role_name()),
            ]
        )
        gcp_workload = gcp_inventory.get_by_address(GCP_WORKLOAD_ADDRESS)
        assert gcp_workload is not None
        gcp_payload = json.dumps(
            gcp_facts(gcp_workload).cloud_run_pubsub_access_paths,
            sort_keys=True,
        )

        azure_inventory, azure_context = _azure_inventory_and_context(
            [
                azure_namespace(),
                azure_entity(AzureResourceType.SERVICE_BUS_QUEUE, AZURE_QUEUE_ID),
                _azure_workload(),
                _azure_control_role(actions=[_AZURE_DELETE_QUEUE]),
                _azure_control_assignment(scope=AZURE_QUEUE_ID),
            ]
        )
        azure_result = _azure_authority(
            azure_inventory,
            azure_context,
            target_arm_id=AZURE_QUEUE_ID,
            action=_AZURE_DELETE_QUEUE,
        )
        assert azure_result.grant is not None
        azure_payload = json.dumps(azure_result.grant, sort_keys=True)

        for payload, foreign_prefixes in (
            (aws_payload, ("google_", "azurerm_", "Microsoft.ServiceBus")),
            (gcp_payload, ("aws_", "azurerm_", "Microsoft.ServiceBus")),
            (azure_payload, ("aws_", "google_", "pubsub.")),
        ):
            for prefix in foreign_prefixes:
                self.assertNotIn(prefix, payload)


if __name__ == "__main__":
    unittest.main()
