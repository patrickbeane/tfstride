from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_NAMESPACE_ID = "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ServiceBus/namespaces/orders-events"
_QUEUE_ID = f"{_NAMESPACE_ID}/queues/orders"
_TOPIC_ID = f"{_NAMESPACE_ID}/topics/orders"
_SUBSCRIPTION_ID = f"{_TOPIC_ID}/subscriptions/worker"
_SYSTEM_PRINCIPAL_ID = "app-system-principal-id"
_USER_PRINCIPAL_ID = "app-user-principal-id"
_USER_IDENTITY_ID = (
    "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ManagedIdentity/"
    "userAssignedIdentities/orders-runtime"
)
_CUSTOM_ROLE_ID = (
    "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/custom-service-bus-operator"
)


def _resource(
    resource_type: str,
    values: dict[str, object],
    *,
    name: str,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values=unknown_values or {},
    )


def _namespace() -> TerraformResource:
    return _resource(
        AzureResourceType.SERVICE_BUS_NAMESPACE,
        {
            "id": _NAMESPACE_ID,
            "name": "orders-events",
            "sku": "Premium",
            "public_network_access_enabled": False,
            "local_auth_enabled": False,
            "minimum_tls_version": "1.2",
        },
        name="orders",
    )


def _entity(resource_type: str, entity_id: str) -> TerraformResource:
    return _resource(
        resource_type,
        {
            "id": entity_id,
            "name": "orders",
            "namespace_id": "azurerm_servicebus_namespace.orders.id",
        },
        name="orders",
    )


def _subscription() -> TerraformResource:
    return _resource(
        AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
        {
            "id": _SUBSCRIPTION_ID,
            "name": "worker",
            "topic_id": "azurerm_servicebus_topic.orders.id",
        },
        name="orders",
    )


def _web_app(*, principal_id: object = _SYSTEM_PRINCIPAL_ID) -> TerraformResource:
    return _resource(
        AzureResourceType.LINUX_WEB_APP,
        {
            "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/orders",
            "name": "orders",
            "identity": [
                {
                    "type": "SystemAssigned",
                    "principal_id": principal_id,
                    "tenant_id": "tenant-id",
                    "identity_ids": [],
                }
            ],
        },
        name="orders",
    )


def _function_app() -> TerraformResource:
    return _resource(
        AzureResourceType.LINUX_FUNCTION_APP,
        {
            "id": "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.Web/sites/orders-worker",
            "name": "orders-worker",
            "identity": [
                {
                    "type": "UserAssigned",
                    "identity_ids": ["azurerm_user_assigned_identity.orders_runtime.id"],
                }
            ],
        },
        name="orders_worker",
    )


def _user_assigned_identity() -> TerraformResource:
    return _resource(
        AzureResourceType.USER_ASSIGNED_IDENTITY,
        {
            "id": _USER_IDENTITY_ID,
            "name": "orders-runtime",
            "principal_id": _USER_PRINCIPAL_ID,
            "client_id": "orders-runtime-client-id",
            "tenant_id": "tenant-id",
        },
        name="orders_runtime",
    )


def _role_assignment(
    *,
    principal_id: object = _SYSTEM_PRINCIPAL_ID,
    scope: object = "azurerm_servicebus_namespace.orders.id",
    role_name: object = "Azure Service Bus Data Sender",
    role_definition_id: object = (
        "/subscriptions/sub-0001/providers/Microsoft.Authorization/roleDefinitions/69a216fc-b8fb-44d8-bc22-1f3c2cd27a39"
    ),
    condition: object | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "scope": scope,
        "role_definition_name": role_name,
        "role_definition_id": role_definition_id,
        "principal_id": principal_id,
        "principal_type": "ServicePrincipal",
    }
    if condition is not None:
        values["condition"] = condition
    return _resource(
        AzureResourceType.ROLE_ASSIGNMENT,
        values,
        name="orders_messaging",
        unknown_values=unknown_values,
    )


def _custom_role(
    *,
    data_actions: list[str],
    not_data_actions: list[str] | None = None,
    definition_name: str = "Custom Service Bus Operator",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.ROLE_DEFINITION,
        {
            "id": _CUSTOM_ROLE_ID,
            "name": definition_name,
            "scope": "/subscriptions/sub-0001",
            "assignable_scopes": ["/subscriptions/sub-0001"],
            "permissions": [
                {
                    "actions": [],
                    "not_actions": [],
                    "data_actions": data_actions,
                    "not_data_actions": not_data_actions or [],
                }
            ],
        },
        name="service_bus_operator",
        unknown_values=unknown_values,
    )


def _custom_role_assignment(
    *,
    scope: object = "azurerm_servicebus_topic.orders.id",
    role_name: object = None,
) -> TerraformResource:
    return _role_assignment(
        scope=scope,
        role_name=role_name,
        role_definition_id=("azurerm_role_definition.service_bus_operator.role_definition_resource_id"),
    )


def _workload_paths(
    resources: list[TerraformResource],
    *,
    address: str = "azurerm_linux_web_app.orders",
) -> tuple[list[dict[str, object]], list[str]]:
    inventory = AzureNormalizer().normalize(resources)
    workload = inventory.get_by_address(address)
    assert workload is not None
    facts = azure_facts(workload)
    return (
        facts.app_service_service_bus_access_paths,
        facts.app_service_service_bus_access_path_uncertainties,
    )


class AzureAppServiceServiceBusAccessPathTests(unittest.TestCase):
    def test_system_assigned_sender_namespace_path_is_modeled(self) -> None:
        paths, uncertainties = _workload_paths([_namespace(), _web_app(), _role_assignment()])

        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(path["identity_kind"], "system_assigned")
        self.assertEqual(path["principal_id"], _SYSTEM_PRINCIPAL_ID)
        self.assertEqual(
            path["service_bus_resource_address"],
            "azurerm_servicebus_namespace.orders",
        )
        self.assertEqual(path["service_bus_resource_id"], _NAMESPACE_ID)
        self.assertEqual(path["service_bus_namespace_id"], _NAMESPACE_ID)
        self.assertEqual(path["role_kind"], "service_bus_data_sender")
        self.assertEqual(path["access_classes"], ["send"])
        self.assertEqual(path["resource_scope"], "exact_service_bus_namespace")
        self.assertEqual(path["access_state"], "granted")
        self.assertEqual(uncertainties, [])

    def test_user_assigned_function_receiver_queue_path_is_modeled(self) -> None:
        paths, _uncertainties = _workload_paths(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _user_assigned_identity(),
                _function_app(),
                _role_assignment(
                    principal_id=_USER_PRINCIPAL_ID,
                    scope="azurerm_servicebus_queue.orders.id",
                    role_name="Azure Service Bus Data Receiver",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/"
                        "roleDefinitions/4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0"
                    ),
                ),
            ],
            address="azurerm_linux_function_app.orders_worker",
        )

        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(
            path["identity_address"],
            "azurerm_user_assigned_identity.orders_runtime",
        )
        self.assertEqual(path["identity_kind"], "user_assigned")
        self.assertEqual(
            path["service_bus_resource_address"],
            "azurerm_servicebus_queue.orders",
        )
        self.assertEqual(path["service_bus_resource_id"], _QUEUE_ID)
        self.assertEqual(
            path["service_bus_namespace_address"],
            "azurerm_servicebus_namespace.orders",
        )
        self.assertEqual(path["queue_address"], "azurerm_servicebus_queue.orders")
        self.assertIsNone(path["topic_address"])
        self.assertEqual(path["role_kind"], "service_bus_data_receiver")
        self.assertEqual(path["access_classes"], ["receive"])
        self.assertEqual(path["resource_scope"], "exact_service_bus_queue")

    def test_user_assigned_function_receiver_subscription_path_is_modeled(self) -> None:
        paths, _uncertainties = _workload_paths(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _subscription(),
                _user_assigned_identity(),
                _function_app(),
                _role_assignment(
                    principal_id=_USER_PRINCIPAL_ID,
                    scope="azurerm_servicebus_subscription.orders.id",
                    role_name="Azure Service Bus Data Receiver",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/"
                        "roleDefinitions/4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0"
                    ),
                ),
            ],
            address="azurerm_linux_function_app.orders_worker",
        )

        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(
            path["service_bus_resource_address"],
            "azurerm_servicebus_subscription.orders",
        )
        self.assertEqual(path["service_bus_resource_id"], _SUBSCRIPTION_ID)
        self.assertEqual(
            path["service_bus_namespace_address"],
            "azurerm_servicebus_namespace.orders",
        )
        self.assertEqual(path["topic_address"], "azurerm_servicebus_topic.orders")
        self.assertEqual(
            path["subscription_address"],
            "azurerm_servicebus_subscription.orders",
        )
        self.assertIsNone(path["queue_address"])
        self.assertEqual(path["role_kind"], "service_bus_data_receiver")
        self.assertEqual(path["access_classes"], ["receive"])
        self.assertEqual(path["resource_scope"], "exact_service_bus_subscription")

    def test_owner_role_id_is_authoritative_for_exact_topic_scope(self) -> None:
        paths, _uncertainties = _workload_paths(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _web_app(),
                _role_assignment(
                    scope="azurerm_servicebus_topic.orders.id",
                    role_name="Azure Service Bus Data Sender",
                    role_definition_id=(
                        "/subscriptions/sub-0001/providers/Microsoft.Authorization/"
                        "roleDefinitions/090c5cfd-751d-490a-894a-3ce6f1109419"
                    ),
                ),
            ]
        )

        path = paths[0]
        self.assertEqual(
            path["service_bus_resource_address"],
            "azurerm_servicebus_topic.orders",
        )
        self.assertEqual(path["service_bus_resource_id"], _TOPIC_ID)
        self.assertEqual(path["topic_address"], "azurerm_servicebus_topic.orders")
        self.assertEqual(path["role_definition_name"], "Azure Service Bus Data Owner")
        self.assertEqual(path["role_kind"], "service_bus_data_owner")
        self.assertEqual(path["access_classes"], ["send"])
        self.assertEqual(path["resource_scope"], "exact_service_bus_topic")

    def test_built_in_capabilities_are_filtered_by_exact_target(self) -> None:
        owner_id = (
            "/subscriptions/sub-0001/providers/Microsoft.Authorization/"
            "roleDefinitions/090c5cfd-751d-490a-894a-3ce6f1109419"
        )
        receiver_id = (
            "/subscriptions/sub-0001/providers/Microsoft.Authorization/"
            "roleDefinitions/4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0"
        )
        queue_owner_paths, _ = _workload_paths(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _web_app(),
                _role_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                    role_name="Azure Service Bus Data Owner",
                    role_definition_id=owner_id,
                ),
            ]
        )
        topic_receiver_paths, _ = _workload_paths(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _web_app(),
                _role_assignment(
                    scope="azurerm_servicebus_topic.orders.id",
                    role_name="Azure Service Bus Data Receiver",
                    role_definition_id=receiver_id,
                ),
            ]
        )
        subscription_sender_paths, _ = _workload_paths(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _subscription(),
                _web_app(),
                _role_assignment(
                    scope="azurerm_servicebus_subscription.orders.id",
                ),
            ]
        )

        self.assertEqual(
            queue_owner_paths[0]["access_classes"],
            ["send", "receive"],
        )
        self.assertEqual(topic_receiver_paths, [])
        self.assertEqual(subscription_sender_paths, [])

    def test_custom_data_actions_and_not_data_actions_are_classified(self) -> None:
        permission = "Microsoft.ServiceBus/*"
        excluded = "Microsoft.ServiceBus/*/receive/action"
        paths, _uncertainties = _workload_paths(
            [
                _namespace(),
                _web_app(),
                _custom_role(
                    data_actions=[permission],
                    not_data_actions=[excluded],
                ),
                _custom_role_assignment(scope="azurerm_servicebus_namespace.orders.id"),
            ]
        )

        path = paths[0]
        self.assertEqual(path["role_kind"], "custom")
        self.assertEqual(
            path["grant_basis"],
            "azure_custom_role_service_bus_scoped_rbac",
        )
        self.assertEqual(
            path["role_definition_address"],
            "azurerm_role_definition.service_bus_operator",
        )
        self.assertEqual(path["custom_role_data_actions"], [permission])
        self.assertEqual(path["custom_role_not_data_actions"], [excluded])
        self.assertEqual(path["access_classes"], ["send", "administrative"])
        self.assertEqual(
            path["matched_data_actions"],
            [
                "microsoft.servicebus/namespaces/messages/send/action",
                "microsoft.servicebus/namespaces/generateuserdelegationkey/action",
                "microsoft.servicebus/namespaces/revokeuserdelegationkeys/action",
            ],
        )
        self.assertEqual(
            path["excluded_data_actions"],
            ["microsoft.servicebus/namespaces/messages/receive/action"],
        )

    def test_custom_role_id_prevents_built_in_name_fallback(self) -> None:
        paths, _uncertainties = _workload_paths(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _web_app(),
                _custom_role(
                    data_actions=["Microsoft.ServiceBus/namespaces/messages/receive/action"],
                    definition_name="Azure Service Bus Data Sender",
                ),
                _custom_role_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                    role_name="Azure Service Bus Data Sender",
                ),
            ]
        )

        self.assertEqual(len(paths), 1)
        path = paths[0]
        self.assertEqual(path["role_kind"], "custom")
        self.assertEqual(path["access_classes"], ["receive"])
        self.assertEqual(
            path["matched_data_actions"],
            ["microsoft.servicebus/namespaces/messages/receive/action"],
        )

    def test_custom_wildcards_are_filtered_by_exact_target(self) -> None:
        topic_paths, _ = _workload_paths(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _web_app(),
                _custom_role(data_actions=["Microsoft.ServiceBus/*"]),
                _custom_role_assignment(),
            ]
        )
        subscription_paths, _ = _workload_paths(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _subscription(),
                _web_app(),
                _custom_role(data_actions=["Microsoft.ServiceBus/*"]),
                _custom_role_assignment(scope="azurerm_servicebus_subscription.orders.id"),
            ]
        )

        self.assertEqual(topic_paths[0]["access_classes"], ["send"])
        self.assertEqual(
            topic_paths[0]["matched_data_actions"],
            ["microsoft.servicebus/namespaces/messages/send/action"],
        )
        self.assertEqual(subscription_paths[0]["access_classes"], ["receive"])
        self.assertEqual(
            subscription_paths[0]["matched_data_actions"],
            ["microsoft.servicebus/namespaces/messages/receive/action"],
        )

    def test_conditions_and_unresolved_inputs_are_conservative(self) -> None:
        condition = "@Resource[Microsoft.ServiceBus/namespaces/queues:name] StringEquals 'orders'"
        conditional_paths, _ = _workload_paths(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_QUEUE, _QUEUE_ID),
                _web_app(),
                _role_assignment(
                    scope="azurerm_servicebus_queue.orders.id",
                    condition=condition,
                ),
            ]
        )
        unknown_paths, unknown_uncertainties = _workload_paths(
            [
                _namespace(),
                _web_app(),
                _role_assignment(unknown_values={"condition": True}),
            ]
        )
        action_paths, action_uncertainties = _workload_paths(
            [
                _namespace(),
                _entity(AzureResourceType.SERVICE_BUS_TOPIC, _TOPIC_ID),
                _web_app(),
                _custom_role(
                    data_actions=[],
                    unknown_values={"permissions": [{"data_actions": True}]},
                ),
                _custom_role_assignment(),
            ]
        )

        self.assertEqual(conditional_paths[0]["condition"], condition)
        self.assertEqual(conditional_paths[0]["access_state"], "conditional")
        self.assertEqual(unknown_paths, [])
        self.assertTrue(any("condition is unresolved" in value for value in unknown_uncertainties))
        self.assertEqual(action_paths, [])
        self.assertTrue(any("data actions are unresolved" in value for value in action_uncertainties))

    def test_non_exact_scopes_and_other_principals_do_not_invent_paths(self) -> None:
        external_paths, external_uncertainties = _workload_paths(
            [
                _namespace(),
                _web_app(),
                _role_assignment(
                    scope=(
                        "/subscriptions/sub-0001/resourceGroups/app/providers/Microsoft.ServiceBus/namespaces/external"
                    )
                ),
            ]
        )
        other_principal_paths, _ = _workload_paths(
            [
                _namespace(),
                _web_app(),
                _role_assignment(principal_id="other-principal-id"),
            ]
        )

        self.assertEqual(external_paths, [])
        self.assertTrue(
            any(
                "does not resolve to an exact Service Bus namespace, queue, topic, or subscription" in value
                for value in external_uncertainties
            )
        )
        self.assertEqual(other_principal_paths, [])


if __name__ == "__main__":
    unittest.main()
