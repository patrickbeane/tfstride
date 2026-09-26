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
    _TOPIC_ID as AZURE_TOPIC_ID,
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
    _subscription as azure_subscription,
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
from tests.providers.gcp.test_gcp_public_cloud_run_pubsub_consume_rules import (
    _public_cloud_run as gcp_public_cloud_run,
)
from tests.providers.gcp.test_gcp_public_cloud_run_pubsub_consume_rules import (
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

AWS_READ_RULE = "aws-public-ecs-sqs-receive-access"
GCP_READ_RULE = "gcp-public-cloud-run-pubsub-consume-access"
AZURE_READ_RULE = "azure-public-app-service-service-bus-receive-access"

AWS_MUTATION_RULE = "aws-public-ecs-messaging-mutation-access"
GCP_MUTATION_RULE = "gcp-public-cloud-run-pubsub-mutation-access"
AZURE_MUTATION_RULE = "azure-public-app-service-service-bus-mutation-access"

READ_RULE_IDS = frozenset({AWS_READ_RULE, GCP_READ_RULE, AZURE_READ_RULE})
MUTATION_RULE_IDS = frozenset(
    {
        AWS_MUTATION_RULE,
        GCP_MUTATION_RULE,
        AZURE_MUTATION_RULE,
    }
)
MESSAGING_PATH_RULE_IDS = READ_RULE_IDS | MUTATION_RULE_IDS

_AZURE_RECEIVER_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0"
)
_AZURE_OWNER_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/090c5cfd-751d-490a-894a-3ce6f1109419"
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
        rule_policy=RulePolicy(enabled_rule_ids=MESSAGING_PATH_RULE_IDS),
    )
    return inventory, boundaries, findings


def _evidence(finding: Finding) -> dict[str, list[str]]:
    return {item.key: item.values for item in finding.evidence}


def _assert_evidence_fragments(
    test_case: unittest.TestCase,
    evidence: dict[str, list[str]],
    expectations: tuple[tuple[str, tuple[str, ...]], ...],
) -> None:
    for evidence_key, fragments in expectations:
        test_case.assertTrue(
            any(all(fragment in value for fragment in fragments) for value in evidence[evidence_key]),
            (evidence_key, fragments, evidence[evidence_key]),
        )


def _aws_resources(
    *,
    actions: str | list[str] = "sqs:ReceiveMessage",
    target: str = AWS_QUEUE_ARN,
    internal: bool = False,
    condition: dict[str, object] | None = None,
    deny: bool = False,
    incomplete_policy: bool = False,
) -> list[TerraformResource]:
    statements = [
        aws_statement(
            "Allow",
            actions,
            target,
            condition=condition,
        )
    ]
    if deny:
        statements.append(aws_statement("Deny", "sqs:ReceiveMessage", target))
    resources = [
        *aws_load_balancer_path(internal=internal),
        aws_queue(),
        aws_role("orders_task", AWS_TASK_ROLE_ARN, statements),
    ]
    if incomplete_policy:
        resources.append(
            aws_role_policy_attachment(
                AWS_TASK_ROLE_ARN,
                "arn:aws:iam::aws:policy/ExternalMessagingAccess",
            )
        )
    resources.extend(
        [
            aws_task_definition(execution_role_arn=None),
            aws_service(),
        ]
    )
    return resources


def _gcp_subscription_resources(
    *,
    role: str = "roles/pubsub.subscriber",
    public: bool = True,
    subscription: str = "google_pubsub_subscription.orders.name",
    condition: dict[str, str] | None = None,
) -> list[object]:
    return [
        gcp_public_cloud_run(public_ingress=public),
        gcp_public_invoker(),
        gcp_topic(),
        gcp_subscription(),
        gcp_subscription_iam_member(
            role=role,
            subscription=subscription,
            condition=condition,
        ),
    ]


def _gcp_publish_resources() -> list[object]:
    return [
        gcp_public_cloud_run(),
        gcp_public_invoker(),
        gcp_topic(),
        gcp_topic_iam_member(),
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
    scope: object = "azurerm_servicebus_queue.orders.id",
    condition: object | None = None,
) -> list[TerraformResource]:
    return [
        azure_namespace(),
        azure_entity(AzureResourceType.SERVICE_BUS_QUEUE, AZURE_QUEUE_ID),
        _public_azure_app(public=public),
        azure_role_assignment(
            scope=scope,
            role_name=role_name,
            role_definition_id=role_definition_id,
            condition=condition,
        ),
    ]


class PublicWorkloadMessagingReadPathParityTests(unittest.TestCase):
    def test_provider_local_read_rules_are_registered(self) -> None:
        self.assertIn(AWS_READ_RULE, _flatten(AWS_RULE_GROUP_IDS))
        self.assertIn(GCP_READ_RULE, _flatten(GCP_RULE_GROUP_IDS))
        self.assertIn(AZURE_READ_RULE, _flatten(AZURE_RULE_GROUP_IDS))

    def test_public_workload_with_exact_receive_grant_emits_only_provider_read_rule(
        self,
    ) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(),
                AWS_READ_RULE,
                "aws_sqs_queue.orders",
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
                        "sqs_receive_paths",
                        (
                            "queue_address=aws_sqs_queue.orders",
                            "task_role=aws_iam_role.orders_task",
                            "action=sqs:ReceiveMessage",
                            "resource_scopes=exact_queue",
                            "receive_evaluation=unconditional_identity_policy_allow",
                        ),
                    ),
                    (
                        "assessment_scope",
                        ("establishes=unconditional identity-policy allow",),
                    ),
                ),
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_subscription_resources(),
                GCP_READ_RULE,
                "google_pubsub_subscription.orders",
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
                            "role=roles/pubsub.subscriber",
                            "credential_context=workload_runtime",
                        ),
                    ),
                    (
                        "pubsub_consume_paths",
                        (
                            "subscription_address=google_pubsub_subscription.orders",
                            "iam_resource=google_pubsub_subscription_iam_member.orders_access",
                            "permission=pubsub.subscriptions.consume",
                            "resource_scope=exact_subscription",
                            "condition_state=not_configured",
                        ),
                    ),
                    (
                        "assessment_scope",
                        ("establishes=unconditional IAM allow grant",),
                    ),
                ),
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_queue_resources(),
                AZURE_READ_RULE,
                "azurerm_servicebus_queue.orders",
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
                        "service_bus_receive_paths",
                        (
                            "service_bus_resource_address=azurerm_servicebus_queue.orders",
                            "role_assignment_address=azurerm_role_assignment.orders_messaging",
                            "role_definition_name=Azure Service Bus Data Receiver",
                            "resource_scope=exact_service_bus_queue",
                            "receive_evaluation=unconditional_modeled_rbac_allow_assignment",
                        ),
                    ),
                    (
                        "assessment_scope",
                        ("establishes=unconditional modeled RBAC allow assignment",),
                    ),
                ),
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            expected_rule,
            target_address,
            trust_boundary_id,
            evidence_expectations,
        ) in cases:
            with self.subTest(provider=provider):
                _, _, findings = _evaluate(normalizer, resources)

                self.assertEqual([finding.rule_id for finding in findings], [expected_rule])
                finding = findings[0]
                self.assertEqual(finding.category, StrideCategory.INFORMATION_DISCLOSURE)
                self.assertIn(target_address, finding.affected_resources)
                self.assertEqual(finding.trust_boundary_id, trust_boundary_id)
                self.assertTrue(finding.rule_id.startswith(f"{provider}-"))
                self.assertTrue(all(item.rule_id.startswith(f"{provider}-") for item in findings))
                _assert_evidence_fragments(
                    self,
                    _evidence(finding),
                    evidence_expectations,
                )

    def test_private_workloads_stay_quiet(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(internal=True),
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_subscription_resources(public=False),
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_queue_resources(public=False),
            ),
        )

        for provider, normalizer, resources in cases:
            with self.subTest(provider=provider):
                _, _, findings = _evaluate(normalizer, resources)
                self.assertEqual(findings, [])

    def test_send_only_access_stays_quiet_for_read_rules(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(actions="sqs:SendMessage"),
                AWS_MUTATION_RULE,
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_publish_resources(),
                GCP_MUTATION_RULE,
            ),
            (
                "azure",
                AzureNormalizer(),
                [
                    azure_namespace(),
                    _public_azure_app(),
                    azure_role_assignment(),
                ],
                AZURE_MUTATION_RULE,
            ),
        )

        for provider, normalizer, resources, expected_mutation_rule in cases:
            with self.subTest(provider=provider):
                _, _, findings = _evaluate(normalizer, resources)
                self.assertEqual(
                    [finding.rule_id for finding in findings],
                    [expected_mutation_rule],
                )
                self.assertNotIn(
                    next(rule_id for rule_id in READ_RULE_IDS if rule_id.startswith(f"{provider}-")),
                    {finding.rule_id for finding in findings},
                )

    def test_uncertain_or_non_exact_receive_grants_stay_quiet(self) -> None:
        condition = {
            "StringEquals": {
                "aws:SourceVpc": "vpc-123",
            }
        }
        gcp_condition = {
            "title": "business-hours",
            "expression": 'request.time < timestamp("2030-01-01T00:00:00Z")',
        }
        azure_condition = "@Resource[Microsoft.ServiceBus/namespaces:name] StringEquals 'orders-events'"
        cases = (
            (
                "aws-denied",
                AwsNormalizer(),
                _aws_resources(deny=True),
            ),
            (
                "aws-conditional",
                AwsNormalizer(),
                _aws_resources(condition=condition),
            ),
            (
                "aws-wildcard-only",
                AwsNormalizer(),
                _aws_resources(
                    target="arn:aws:sqs:us-east-1:111122223333:*",
                ),
            ),
            (
                "aws-external",
                AwsNormalizer(),
                _aws_resources(
                    target="arn:aws:sqs:us-west-2:999900001111:external",
                ),
            ),
            (
                "aws-unresolved",
                AwsNormalizer(),
                _aws_resources(incomplete_policy=True),
            ),
            (
                "gcp-conditional",
                GcpNormalizer(),
                _gcp_subscription_resources(condition=gcp_condition),
            ),
            (
                "gcp-external",
                GcpNormalizer(),
                _gcp_subscription_resources(
                    subscription="projects/external/subscriptions/orders-worker",
                ),
            ),
            (
                "gcp-unresolved",
                GcpNormalizer(),
                _gcp_subscription_resources(
                    role=f"projects/{GCP_PROJECT}/roles/externalMessagingRole",
                ),
            ),
            (
                "azure-conditional",
                AzureNormalizer(),
                _azure_queue_resources(condition=azure_condition),
            ),
            (
                "azure-external",
                AzureNormalizer(),
                _azure_queue_resources(
                    scope=(
                        "/subscriptions/sub-0001/resourceGroups/app/providers/"
                        "Microsoft.ServiceBus/namespaces/external/queues/orders"
                    ),
                ),
            ),
            (
                "azure-unresolved",
                AzureNormalizer(),
                [
                    azure_namespace(),
                    _public_azure_app(),
                    azure_custom_role(
                        data_actions=[],
                        unknown_values={"permissions": [{"data_actions": True}]},
                    ),
                    azure_custom_role_assignment(
                        scope="azurerm_servicebus_namespace.orders.id",
                    ),
                ],
            ),
        )

        for case, normalizer, resources in cases:
            with self.subTest(case=case):
                _, _, findings = _evaluate(normalizer, resources)
                self.assertEqual(findings, [])

    def test_mutation_and_receive_findings_remain_distinct(self) -> None:
        cases = (
            (
                "aws",
                AwsNormalizer(),
                _aws_resources(
                    actions=[
                        "sqs:ReceiveMessage",
                        "sqs:SendMessage",
                    ]
                ),
                AWS_READ_RULE,
                AWS_MUTATION_RULE,
                "sqs_receive_paths",
                "messaging_mutation_paths",
            ),
            (
                "gcp",
                GcpNormalizer(),
                _gcp_subscription_resources(role="roles/pubsub.admin"),
                GCP_READ_RULE,
                GCP_MUTATION_RULE,
                "pubsub_consume_paths",
                "pubsub_mutation_paths",
            ),
            (
                "azure",
                AzureNormalizer(),
                _azure_queue_resources(
                    role_name="Azure Service Bus Data Owner",
                    role_definition_id=_AZURE_OWNER_ROLE_ID,
                ),
                AZURE_READ_RULE,
                AZURE_MUTATION_RULE,
                "service_bus_receive_paths",
                "service_bus_mutation_paths",
            ),
        )

        for (
            provider,
            normalizer,
            resources,
            read_rule,
            mutation_rule,
            read_evidence_key,
            mutation_evidence_key,
        ) in cases:
            with self.subTest(provider=provider):
                _, _, findings = _evaluate(normalizer, resources)
                findings_by_rule = {finding.rule_id: finding for finding in findings}

                self.assertEqual(
                    set(findings_by_rule),
                    {read_rule, mutation_rule},
                )
                self.assertEqual(
                    findings_by_rule[read_rule].category,
                    StrideCategory.INFORMATION_DISCLOSURE,
                )
                self.assertEqual(
                    findings_by_rule[mutation_rule].category,
                    StrideCategory.TAMPERING,
                )
                self.assertIn(
                    read_evidence_key,
                    _evidence(findings_by_rule[read_rule]),
                )
                self.assertNotIn(
                    mutation_evidence_key,
                    _evidence(findings_by_rule[read_rule]),
                )
                self.assertIn(
                    mutation_evidence_key,
                    _evidence(findings_by_rule[mutation_rule]),
                )
                self.assertNotIn(
                    read_evidence_key,
                    _evidence(findings_by_rule[mutation_rule]),
                )
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))

    def test_azure_subscription_owner_emits_receive_without_mutation(self) -> None:
        _, _, findings = _evaluate(
            AzureNormalizer(),
            [
                azure_namespace(),
                azure_entity(
                    AzureResourceType.SERVICE_BUS_TOPIC,
                    AZURE_TOPIC_ID,
                ),
                azure_subscription(),
                _public_azure_app(),
                azure_role_assignment(
                    scope="azurerm_servicebus_subscription.orders.id",
                    role_name="Azure Service Bus Data Owner",
                    role_definition_id=_AZURE_OWNER_ROLE_ID,
                ),
            ],
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [AZURE_READ_RULE],
        )


if __name__ == "__main__":
    unittest.main()
