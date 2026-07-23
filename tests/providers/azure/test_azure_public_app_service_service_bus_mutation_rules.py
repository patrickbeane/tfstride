from __future__ import annotations

import unittest

from tests.providers.azure.test_azure_app_service_service_bus_access_paths import (
    _QUEUE_ID,
    _SYSTEM_PRINCIPAL_ID,
    _TOPIC_ID,
    _USER_PRINCIPAL_ID,
    _custom_role,
    _custom_role_assignment,
    _entity,
    _function_app,
    _namespace,
    _role_assignment,
    _subscription,
    _user_assigned_identity,
    _web_app,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_RULE_ID = "azure-public-app-service-service-bus-mutation-access"


def _public(resource: TerraformResource) -> TerraformResource:
    resource.values["public_network_access_enabled"] = True
    return resource


def _evaluate(resources: list[TerraformResource]):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _evidence(finding):
    return {item.key: item.values for item in finding.evidence}


class AzurePublicAppServiceServiceBusMutationRuleTests(unittest.TestCase):
    def test_rule_is_registered(self) -> None:
        registered = {rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_public_system_assigned_app_with_namespace_sender_is_detected(self) -> None:
        findings = _evaluate([_namespace(), _public(_web_app()), _role_assignment()])

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "azurerm_linux_web_app.orders",
                "azurerm_servicebus_namespace.orders",
                "azurerm_role_assignment.orders_messaging",
            ],
        )
        self.assertIn("injecting messages", finding.rationale)
        self.assertIn(
            "does not mean that the Service Bus target itself is public",
            finding.rationale,
        )
        self.assertIn(
            "mutation paths included in this finding do not establish message receive access",
            finding.rationale,
        )
        evidence = _evidence(finding)
        self.assertIn(
            "public_network_access_enabled=true",
            evidence["public_endpoint"],
        )
        self.assertTrue(
            any(
                f"principal_id={_SYSTEM_PRINCIPAL_ID}" in value and "role_kind=service_bus_data_sender" in value
                for value in evidence["runtime_identity"]
            )
        )
        self.assertTrue(
            any(
                "service_bus_resource_address=azurerm_servicebus_namespace.orders" in value
                and "mutation_classes=send" in value
                and "resource_scope=exact_service_bus_namespace" in value
                and "condition_state=not_configured" in value
                for value in evidence["service_bus_mutation_paths"]
            )
        )
        self.assertNotIn("custom_role_permissions", evidence)

    def test_public_function_user_identity_with_queue_owner_is_detected(self) -> None:
        findings = _evaluate(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _user_assigned_identity(),
                _public(_function_app()),
                _role_assignment(
                    principal_id=_USER_PRINCIPAL_ID,
                    scope="azurerm_servicebus_queue.orders.id",
                    role_name="Azure Service Bus Data Owner",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/"
                        "roleDefinitions/090c5cfd-751d-490a-894a-3ce6f1109419"
                    ),
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(
            finding.affected_resources,
            [
                "azurerm_linux_function_app.orders_worker",
                "azurerm_user_assigned_identity.orders_runtime",
                "azurerm_servicebus_namespace.orders",
                "azurerm_servicebus_queue.orders",
                "azurerm_role_assignment.orders_messaging",
            ],
        )
        evidence = _evidence(finding)
        self.assertTrue(
            any(
                "identity_kind=user_assigned" in value and f"principal_id={_USER_PRINCIPAL_ID}" in value
                for value in evidence["runtime_identity"]
            )
        )
        self.assertTrue(
            any(
                "service_bus_resource_id=" + _QUEUE_ID in value
                and "queue_address=azurerm_servicebus_queue.orders" in value
                and "mutation_classes=send" in value
                and "access_classes=send,receive" in value
                for value in evidence["service_bus_mutation_paths"]
            )
        )
        self.assertNotIn(
            "mutation paths included in this finding do not establish message receive access",
            finding.rationale,
        )

    def test_public_topic_owner_is_detected_from_target_filtered_send_access(self) -> None:
        findings = _evaluate(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _public(_web_app()),
                _role_assignment(
                    scope="azurerm_servicebus_topic.orders.id",
                    role_name="Azure Service Bus Data Owner",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/"
                        "roleDefinitions/090c5cfd-751d-490a-894a-3ce6f1109419"
                    ),
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        path_evidence = _evidence(findings[0])["service_bus_mutation_paths"]
        self.assertTrue(
            any(
                "service_bus_resource_id=" + _TOPIC_ID in value
                and "topic_address=azurerm_servicebus_topic.orders" in value
                and "mutation_classes=send" in value
                and "access_classes=send" in value
                for value in path_evidence
            )
        )

    def test_public_app_with_custom_namespace_administration_is_detected(self) -> None:
        permission = "Microsoft.ServiceBus/namespaces/generateUserDelegationKey/action"
        findings = _evaluate(
            [
                _namespace(),
                _public(_web_app()),
                _custom_role(data_actions=[permission]),
                _custom_role_assignment(
                    scope="azurerm_servicebus_namespace.orders.id",
                ),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertIn(
            "issuing or revoking namespace user-delegation keys",
            finding.rationale,
        )
        evidence = _evidence(finding)
        self.assertTrue(
            any(
                "mutation_classes=administrative" in value and "role_kind=custom" in value
                for value in evidence["service_bus_mutation_paths"]
            )
        )
        self.assertTrue(
            any(
                "role_definition_address=azurerm_role_definition.service_bus_operator" in value
                and "matched_data_actions=microsoft.servicebus/namespaces/generateuserdelegationkey/action"
                in value.lower()
                for value in evidence["custom_role_permissions"]
            )
        )

    def test_private_unknown_receiver_and_conditional_paths_stay_quiet(self) -> None:
        private = _evaluate([_namespace(), _web_app(), _role_assignment()])

        unknown_app = _web_app()
        unknown_app.values["public_network_access_enabled"] = None
        unknown_app.unknown_values["public_network_access_enabled"] = True
        unknown = _evaluate([_namespace(), unknown_app, _role_assignment()])

        receiver = _evaluate(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _public(_web_app()),
                _role_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                    role_name="Azure Service Bus Data Receiver",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/"
                        "roleDefinitions/4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0"
                    ),
                ),
            ]
        )
        conditional = _evaluate(
            [
                _namespace(),
                _public(_web_app()),
                _role_assignment(
                    condition=("@Resource[Microsoft.ServiceBus/namespaces:name] StringEquals 'orders-events'")
                ),
            ]
        )

        self.assertEqual(private, [])
        self.assertEqual(unknown, [])
        self.assertEqual(receiver, [])
        self.assertEqual(conditional, [])

    def test_subscription_owner_receive_only_path_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _subscription(),
                _public(_web_app()),
                _role_assignment(
                    scope="azurerm_servicebus_subscription.orders.id",
                    role_name="Azure Service Bus Data Owner",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/"
                        "roleDefinitions/090c5cfd-751d-490a-894a-3ce6f1109419"
                    ),
                ),
            ]
        )

        self.assertEqual(findings, [])

    def test_custom_not_data_actions_removing_mutation_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _namespace(),
                _public(_web_app()),
                _custom_role(
                    data_actions=["Microsoft.ServiceBus/*"],
                    not_data_actions=[
                        "Microsoft.ServiceBus/*/send/action",
                        ("Microsoft.ServiceBus/namespaces/generateUserDelegationKey/action"),
                        ("Microsoft.ServiceBus/namespaces/revokeUserDelegationKeys/action"),
                    ],
                ),
                _custom_role_assignment(
                    scope="azurerm_servicebus_namespace.orders.id",
                ),
            ]
        )

        self.assertEqual(findings, [])

    def test_unresolved_custom_permissions_and_external_scope_stay_quiet(self) -> None:
        unresolved = _evaluate(
            [
                _namespace(),
                _public(_web_app()),
                _custom_role(
                    data_actions=[],
                    unknown_values={"permissions": [{"data_actions": True}]},
                ),
                _custom_role_assignment(
                    scope="azurerm_servicebus_namespace.orders.id",
                ),
            ]
        )
        external = _evaluate(
            [
                _namespace(),
                _public(_web_app()),
                _role_assignment(
                    scope=(
                        "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ServiceBus/namespaces/external"
                    )
                ),
            ]
        )

        self.assertEqual(unresolved, [])
        self.assertEqual(external, [])


if __name__ == "__main__":
    unittest.main()
