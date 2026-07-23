from __future__ import annotations

import unittest
from typing import Any

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
    _load_balancer as aws_load_balancer,
)
from tests.providers.aws.test_aws_public_ecs_messaging_mutation_rules import (
    _service as aws_service,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _QUEUE_ID as AZURE_QUEUE_ID,
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
    _namespace as azure_namespace,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _role_assignment as azure_role_assignment,
)
from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _web_app as azure_web_app,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _PROJECT as GCP_PROJECT,
)
from tests.providers.gcp.test_gcp_cloud_run_pubsub_access_paths import (
    _SERVICE_ACCOUNT_MEMBER as GCP_SERVICE_ACCOUNT_MEMBER,
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
from tests.providers.gcp.test_gcp_public_cloud_run_pubsub_mutation_rules import (
    _public_cloud_run as gcp_public_cloud_run,
)
from tests.providers.gcp.test_gcp_public_cloud_run_pubsub_mutation_rules import (
    _public_invoker as gcp_public_invoker,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import Finding, ResourceInventory, StrideCategory, TerraformResource, TrustBoundary
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

AWS_MUTATION_RULE = "aws-public-ecs-messaging-mutation-access"
GCP_MUTATION_RULE = "gcp-public-cloud-run-pubsub-mutation-access"
AZURE_MUTATION_RULE = "azure-public-app-service-service-bus-mutation-access"

MUTATION_RULE_IDS = frozenset(
    {
        AWS_MUTATION_RULE,
        GCP_MUTATION_RULE,
        AZURE_MUTATION_RULE,
    }
)


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for group in rule_groups for rule_id in group)


def _evaluate(
    normalizer: ProviderNormalizer,
    resources: list[Any],
) -> tuple[ResourceInventory, list[TrustBoundary], list[Finding]]:
    inventory = normalizer.normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=MUTATION_RULE_IDS),
    )
    return inventory, boundaries, findings


def _evidence(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


def _aws_resources(
    *,
    actions: str | list[str] = "sns:Publish",
    target: str = AWS_TOPIC_ARN,
    internal: bool = False,
    condition: dict[str, object] | None = None,
) -> list[TerraformResource]:
    return [
        aws_load_balancer(internal=internal),
        aws_topic(),
        aws_role(
            "orders_task",
            AWS_TASK_ROLE_ARN,
            [
                aws_statement(
                    "Allow",
                    actions,
                    target,
                    condition=condition,
                )
            ],
        ),
        aws_task_definition(execution_role_arn=None),
        aws_service(),
    ]


def _gcp_resources(
    *,
    role: str = "roles/pubsub.publisher",
    public: bool = True,
    member: str = GCP_SERVICE_ACCOUNT_MEMBER,
    topic: str = "google_pubsub_topic.orders.name",
    condition: dict[str, str] | None = None,
) -> list[object]:
    return [
        gcp_public_cloud_run(public_ingress=public),
        gcp_public_invoker(),
        gcp_topic(),
        gcp_topic_iam_member(
            role=role,
            member=member,
            topic=topic,
            condition=condition,
        ),
    ]


def _public_azure_app(*, public: object = True) -> TerraformResource:
    app = azure_web_app()
    app.values["public_network_access_enabled"] = public
    return app


def _azure_resources(
    *,
    public: object = True,
    principal_id: object = "app-system-principal-id",
    scope: object = "azurerm_servicebus_namespace.orders.id",
    role_name: object = "Azure Service Bus Data Sender",
    role_definition_id: object = (
        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/69a216fc-b8fb-44d8-bc22-1f3c2cd27a39"
    ),
    condition: object | None = None,
) -> list[TerraformResource]:
    return [
        azure_namespace(),
        _public_azure_app(public=public),
        azure_role_assignment(
            principal_id=principal_id,
            scope=scope,
            role_name=role_name,
            role_definition_id=role_definition_id,
            condition=condition,
        ),
    ]


class PublicWorkloadMessagingMutationPathParityTests(unittest.TestCase):
    def test_provider_local_messaging_mutation_rules_are_registered(self) -> None:
        self.assertIn(AWS_MUTATION_RULE, _flatten(AWS_RULE_GROUP_IDS))
        self.assertIn(GCP_MUTATION_RULE, _flatten(GCP_RULE_GROUP_IDS))
        self.assertIn(AZURE_MUTATION_RULE, _flatten(AZURE_RULE_GROUP_IDS))

    def test_public_workload_with_exact_publish_or_send_access_emits_only_provider_rule(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(),
                AWS_MUTATION_RULE,
                "aws_ecs_service.orders",
                "internet-to-service:internet->aws_lb.public",
                (
                    (
                        "network_path",
                        ("aws_lb.public fronts aws_ecs_service.orders",),
                    ),
                    (
                        "task_roles",
                        (
                            "address=aws_iam_role.orders_task",
                            "credential_context=workload_runtime",
                        ),
                    ),
                    (
                        "messaging_mutation_paths",
                        (
                            "target_address=aws_sns_topic.orders",
                            "mutation_classes=publish",
                            "actions=sns:Publish",
                            "resource_scopes=exact_topic",
                        ),
                    ),
                ),
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(),
                GCP_MUTATION_RULE,
                "google_cloud_run_v2_service.orders",
                "internet-to-service:internet->google_cloud_run_v2_service.orders",
                (
                    (
                        "public_invoker_bindings",
                        (
                            "role=roles/run.invoker",
                            "member=allUsers",
                        ),
                    ),
                    (
                        "runtime_identity",
                        (
                            f"member={GCP_SERVICE_ACCOUNT_MEMBER}",
                            "credential_context=workload_runtime",
                        ),
                    ),
                    (
                        "pubsub_mutation_paths",
                        (
                            "target_address=google_pubsub_topic.orders",
                            "role=roles/pubsub.publisher",
                            "mutation_classes=publish",
                            "resource_scope=exact_topic",
                        ),
                    ),
                ),
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_resources(),
                AZURE_MUTATION_RULE,
                "azurerm_linux_web_app.orders",
                None,
                (
                    (
                        "public_endpoint",
                        ("address=azurerm_linux_web_app.orders",),
                    ),
                    (
                        "public_endpoint",
                        ("public_network_access_enabled=true",),
                    ),
                    (
                        "runtime_identity",
                        (
                            "identity_address=azurerm_linux_web_app.orders",
                            "principal_id=app-system-principal-id",
                            "credential_context=workload_runtime",
                        ),
                    ),
                    (
                        "service_bus_mutation_paths",
                        (
                            "service_bus_resource_address=azurerm_servicebus_namespace.orders",
                            "role_definition_name=Azure Service Bus Data Sender",
                            "mutation_classes=send",
                            "resource_scope=exact_service_bus_namespace",
                        ),
                    ),
                ),
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            expected_rule,
            workload_address,
            trust_boundary_id,
            evidence_expectations,
        ) in cases:
            with self.subTest(provider=provider):
                _, _, findings = _evaluate(normalizer, resources)

                self.assertEqual([finding.rule_id for finding in findings], [expected_rule])
                finding = findings[0]
                self.assertEqual(finding.category, StrideCategory.TAMPERING)
                self.assertIn(workload_address, finding.affected_resources)
                self.assertEqual(finding.trust_boundary_id, trust_boundary_id)
                self.assertTrue(finding.rule_id.startswith(f"{provider}-"))
                evidence = _evidence(finding)
                for evidence_key, fragments in evidence_expectations:
                    self.assertTrue(
                        any(all(fragment in value for fragment in fragments) for value in evidence[evidence_key]),
                        (evidence_key, fragments, evidence[evidence_key]),
                    )

    def test_exact_administrative_messaging_access_emits(self) -> None:
        azure_permission = "Microsoft.ServiceBus/namespaces/generateUserDelegationKey/action"
        cases = (
            (
                "aws",
                AwsNormalizer(),
                [
                    aws_load_balancer(),
                    aws_queue(),
                    aws_role(
                        "orders_task",
                        AWS_TASK_ROLE_ARN,
                        [
                            aws_statement(
                                "Allow",
                                "sqs:SetQueueAttributes",
                                AWS_QUEUE_ARN,
                            )
                        ],
                    ),
                    aws_task_definition(execution_role_arn=None),
                    aws_service(),
                ],
                AWS_MUTATION_RULE,
                "messaging_mutation_paths",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_resources(role="roles/pubsub.subscriber"),
                GCP_MUTATION_RULE,
                "pubsub_mutation_paths",
            ),
            (
                "azure",
                AzureNormalizer(),
                [
                    azure_namespace(),
                    _public_azure_app(),
                    azure_custom_role(data_actions=[azure_permission]),
                    azure_custom_role_assignment(scope="azurerm_servicebus_namespace.orders.id"),
                ],
                AZURE_MUTATION_RULE,
                "service_bus_mutation_paths",
            ),
        )

        for provider, normalizer, resources, expected_rule, evidence_key in cases:
            with self.subTest(provider=provider):
                _, _, findings = _evaluate(normalizer, resources)

                self.assertEqual([finding.rule_id for finding in findings], [expected_rule])
                self.assertTrue(any("administrative" in value for value in _evidence(findings[0])[evidence_key]))

    def test_private_workloads_and_read_or_receive_only_grants_stay_quiet(self) -> None:
        receiver_role_id = (
            "/subscriptions/sub-0001/providers/Microsoft.Authorization/"
            "roleDefinitions/4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0"
        )
        cases = (
            ("aws-private", AwsNormalizer(), _aws_resources(internal=True)),
            (
                "aws-receive-only",
                AwsNormalizer(),
                [
                    aws_load_balancer(),
                    aws_queue(),
                    aws_role(
                        "orders_task",
                        AWS_TASK_ROLE_ARN,
                        [
                            aws_statement(
                                "Allow",
                                "sqs:ReceiveMessage",
                                AWS_QUEUE_ARN,
                            )
                        ],
                    ),
                    aws_task_definition(execution_role_arn=None),
                    aws_service(),
                ],
            ),
            ("gcp-private", GcpNormalizer(), _gcp_resources(public=False)),
            (
                "gcp-read-only",
                GcpNormalizer(),
                _gcp_resources(role="roles/pubsub.viewer"),
            ),
            (
                "gcp-receive-only",
                GcpNormalizer(),
                [
                    gcp_public_cloud_run(),
                    gcp_public_invoker(),
                    gcp_topic(),
                    gcp_subscription(),
                    gcp_subscription_iam_member(),
                ],
            ),
            ("azure-private", AzureNormalizer(), _azure_resources(public=False)),
            (
                "azure-receive-only",
                AzureNormalizer(),
                [
                    azure_namespace(),
                    azure_entity(
                        AzureResourceType.SERVICE_BUS_QUEUE,
                        AZURE_QUEUE_ID,
                    ),
                    _public_azure_app(),
                    azure_role_assignment(
                        scope="azurerm_servicebus_queue.orders.id",
                        role_name="Azure Service Bus Data Receiver",
                        role_definition_id=receiver_role_id,
                    ),
                ],
            ),
        )

        for case, normalizer, resources in cases:
            with self.subTest(case=case):
                _, _, findings = _evaluate(normalizer, resources)
                self.assertEqual(findings, [])

    def test_non_exact_or_uncertain_grants_do_not_become_mutation_findings(self) -> None:
        aws_external_policy_arn = "arn:aws:iam::aws:policy/ExternalMessagingAccess"
        aws_external_topic_arn = "arn:aws:sns:us-west-2:999900001111:external-events"
        gcp_condition = {
            "title": "business-hours",
            "expression": ('request.time < timestamp("2030-01-01T00:00:00Z")'),
        }
        azure_condition = "@Resource[Microsoft.ServiceBus/namespaces:name] StringEquals 'orders-events'"
        cases = (
            (
                "aws-denied",
                AwsNormalizer(),
                [
                    aws_load_balancer(),
                    aws_topic(),
                    aws_role(
                        "orders_task",
                        AWS_TASK_ROLE_ARN,
                        [
                            aws_statement(
                                "Allow",
                                "sns:Publish",
                                AWS_TOPIC_ARN,
                            ),
                            aws_statement(
                                "Deny",
                                "sns:Publish",
                                AWS_TOPIC_ARN,
                            ),
                        ],
                    ),
                    aws_task_definition(execution_role_arn=None),
                    aws_service(),
                ],
            ),
            (
                "aws-conditional",
                AwsNormalizer(),
                _aws_resources(condition={"StringEquals": {"aws:SourceVpc": "vpc-123"}}),
            ),
            (
                "aws-external-target",
                AwsNormalizer(),
                _aws_resources(target=aws_external_topic_arn),
            ),
            (
                "aws-wildcard-only-target",
                AwsNormalizer(),
                _aws_resources(target="arn:aws:sns:us-east-1:*:orders-*"),
            ),
            (
                "aws-unresolved-policy",
                AwsNormalizer(),
                [
                    *_aws_resources(),
                    aws_role_policy_attachment(
                        AWS_TASK_ROLE_ARN,
                        aws_external_policy_arn,
                    ),
                ],
            ),
            (
                "gcp-conditional",
                GcpNormalizer(),
                _gcp_resources(condition=gcp_condition),
            ),
            (
                "gcp-external-identity",
                GcpNormalizer(),
                _gcp_resources(member=("serviceAccount:external@partner-project.iam.gserviceaccount.com")),
            ),
            (
                "gcp-unresolved-target",
                GcpNormalizer(),
                _gcp_resources(topic="google_pubsub_topic.missing.name"),
            ),
            (
                "gcp-unresolved-role",
                GcpNormalizer(),
                _gcp_resources(role=f"projects/{GCP_PROJECT}/roles/externalMessagingRole"),
            ),
            (
                "azure-denied-custom-role",
                AzureNormalizer(),
                [
                    azure_namespace(),
                    _public_azure_app(),
                    azure_custom_role(
                        data_actions=["Microsoft.ServiceBus/*/send/action"],
                        not_data_actions=["Microsoft.ServiceBus/*/send/action"],
                    ),
                    azure_custom_role_assignment(scope="azurerm_servicebus_namespace.orders.id"),
                ],
            ),
            (
                "azure-conditional",
                AzureNormalizer(),
                _azure_resources(condition=azure_condition),
            ),
            (
                "azure-external-identity",
                AzureNormalizer(),
                _azure_resources(principal_id="external-principal-id"),
            ),
            (
                "azure-external-target",
                AzureNormalizer(),
                _azure_resources(
                    scope=(
                        "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ServiceBus/namespaces/external"
                    )
                ),
            ),
            (
                "azure-broad-scope",
                AzureNormalizer(),
                _azure_resources(scope="/subscriptions/sub-0001"),
            ),
            (
                "azure-unresolved-role",
                AzureNormalizer(),
                [
                    azure_namespace(),
                    _public_azure_app(),
                    azure_custom_role(
                        data_actions=[],
                        unknown_values={"permissions": [{"data_actions": True}]},
                    ),
                    azure_custom_role_assignment(scope="azurerm_servicebus_namespace.orders.id"),
                ],
            ),
        )

        for case, normalizer, resources in cases:
            with self.subTest(case=case):
                _, _, findings = _evaluate(normalizer, resources)
                self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
