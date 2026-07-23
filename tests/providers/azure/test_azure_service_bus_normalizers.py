from __future__ import annotations

import unittest

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.catalog import default_resource_capability_registry
from tfstride.providers.resource_capabilities import ResourceCapability

_NAMESPACE_ID = "/subscriptions/example/resourceGroups/app/providers/Microsoft.ServiceBus/namespaces/events"
_QUEUE_ID = f"{_NAMESPACE_ID}/queues/orders"
_TOPIC_ID = f"{_NAMESPACE_ID}/topics/events"
_SUBSCRIPTION_ID = f"{_TOPIC_ID}/subscriptions/worker"
_KEY_ID = "azurerm_key_vault_key.service_bus.id"


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, object],
    *,
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


def _namespace(
    *,
    name: str = "events",
    values: dict[str, object] | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _resource(
        AzureResourceType.SERVICE_BUS_NAMESPACE,
        name,
        {
            "id": _NAMESPACE_ID,
            "name": "events",
            "sku": "Premium",
            **(values or {}),
        },
        unknown_values=unknown_values,
    )


class AzureServiceBusNormalizerTests(unittest.TestCase):
    def test_namespace_normalizes_inline_network_cmk_tls_and_local_auth_posture(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _namespace(
                    values={
                        "tier": "Premium",
                        "public_network_access_enabled": True,
                        "minimum_tls_version": "1.2",
                        "local_auth_enabled": False,
                        "network_rule_set": [{"default_action": "Deny"}],
                        "customer_managed_key": [{"key_vault_key_id": _KEY_ID}],
                    }
                )
            ]
        )
        namespace = inventory.resources[0]
        facts = azure_facts(namespace)

        self.assertEqual(namespace.category, ResourceCategory.DATA)
        self.assertEqual(namespace.identifier, _NAMESPACE_ID)
        self.assertEqual(namespace.data_sensitivity, "sensitive")
        self.assertEqual(facts.service_bus_namespace_id, _NAMESPACE_ID)
        self.assertEqual(facts.service_bus_sku, "Premium")
        self.assertEqual(facts.service_bus_tier, "Premium")
        self.assertTrue(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "enabled")
        self.assertEqual(facts.network_default_action, "Deny")
        self.assertEqual(facts.service_bus_network_rule_source_address, namespace.address)
        self.assertEqual(facts.min_tls_version, "1.2")
        self.assertEqual(facts.service_bus_local_auth_state, "disabled")
        self.assertFalse(facts.service_bus_local_auth_enabled)
        self.assertEqual(facts.service_bus_customer_managed_key_state, "configured")
        self.assertEqual(facts.service_bus_key_vault_key_id, _KEY_ID)
        self.assertEqual(facts.service_bus_customer_managed_key_source_address, namespace.address)
        self.assertEqual(facts.service_bus_posture_uncertainties, [])

    def test_companion_network_rules_and_cmk_resolve_by_namespace_id_or_address(self) -> None:
        namespace = _namespace(values={"public_network_access_enabled": True, "local_auth_enabled": True})
        network_rules = _resource(
            AzureResourceType.SERVICE_BUS_NAMESPACE_NETWORK_RULE_SET,
            "events",
            {
                "namespace_id": "azurerm_servicebus_namespace.events.id",
                "default_action": "Deny",
                "public_network_access_enabled": True,
            },
        )
        customer_managed_key = _resource(
            AzureResourceType.SERVICE_BUS_NAMESPACE_CUSTOMER_MANAGED_KEY,
            "events",
            {"namespace_id": _NAMESPACE_ID, "key_vault_key_id": _KEY_ID},
        )

        inventory = AzureNormalizer().normalize([namespace, network_rules, customer_managed_key])
        resources = {resource.address: resource for resource in inventory.resources}
        namespace_resource = resources[namespace.address]
        namespace_facts = azure_facts(namespace_resource)
        network_facts = azure_facts(resources[network_rules.address])
        cmk_facts = azure_facts(resources[customer_managed_key.address])

        self.assertTrue(namespace_facts.public_network_access_enabled)
        self.assertEqual(namespace_facts.public_network_fallback_state, "enabled")
        self.assertEqual(namespace_facts.network_default_action, "Deny")
        self.assertEqual(namespace_facts.service_bus_network_rule_source_address, network_rules.address)
        self.assertEqual(namespace_facts.service_bus_customer_managed_key_state, "configured")
        self.assertEqual(namespace_facts.service_bus_key_vault_key_id, _KEY_ID)
        self.assertEqual(namespace_facts.service_bus_customer_managed_key_source_address, customer_managed_key.address)
        self.assertEqual(network_facts.resolved_service_bus_namespace_address, namespace.address)
        self.assertEqual(cmk_facts.resolved_service_bus_namespace_address, namespace.address)
        self.assertEqual(namespace_facts.service_bus_posture_uncertainties, [])

    def test_unknown_posture_and_basic_sku_remain_explicit(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _namespace(
                    values={
                        "sku": "Basic",
                        "public_network_access_enabled": None,
                        "minimum_tls_version": None,
                        "local_auth_enabled": None,
                        "network_rule_set": [{"default_action": None}],
                        "customer_managed_key": [{"key_vault_key_id": None}],
                    },
                    unknown_values={
                        "public_network_access_enabled": True,
                        "minimum_tls_version": True,
                        "local_auth_enabled": True,
                        "network_rule_set": [{"default_action": True}],
                        "customer_managed_key": [{"key_vault_key_id": True}],
                    },
                )
            ]
        )
        facts = azure_facts(inventory.resources[0])

        self.assertEqual(facts.service_bus_sku, "Basic")
        self.assertEqual(facts.public_network_fallback_state, "unknown")
        self.assertIsNone(facts.public_network_access_enabled)
        self.assertIsNone(facts.min_tls_version)
        self.assertEqual(facts.service_bus_local_auth_state, "unknown")
        self.assertIsNone(facts.service_bus_local_auth_enabled)
        self.assertIsNone(facts.network_default_action)
        self.assertEqual(facts.service_bus_customer_managed_key_state, "unknown")
        self.assertIsNone(facts.service_bus_key_vault_key_id)
        self.assertEqual(
            facts.service_bus_posture_uncertainties,
            [
                "public_network_access_enabled is unknown after planning",
                "minimum_tls_version is unknown after planning",
                "local_auth_enabled is unknown after planning",
                "network_rule_set.default_action is unknown after planning",
                "customer_managed_key.key_vault_key_id is unknown after planning",
            ],
        )

    def test_entities_preserve_exact_identity_and_resolve_namespace_and_topic(self) -> None:
        namespace = _namespace()
        queue = _resource(
            AzureResourceType.SERVICE_BUS_QUEUE,
            "orders",
            {
                "id": _QUEUE_ID,
                "name": "orders",
                "namespace_id": _NAMESPACE_ID,
            },
        )
        topic = _resource(
            AzureResourceType.SERVICE_BUS_TOPIC,
            "events",
            {
                "id": _TOPIC_ID,
                "name": "events",
                "namespace_id": _NAMESPACE_ID,
            },
        )
        subscription = _resource(
            AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
            "worker",
            {
                "id": _SUBSCRIPTION_ID,
                "name": "worker",
                "topic_id": _TOPIC_ID,
            },
        )

        inventory = AzureNormalizer().normalize([subscription, topic, namespace, queue])
        resources = {resource.address: resource for resource in inventory.resources}
        queue_facts = azure_facts(resources[queue.address])
        topic_facts = azure_facts(resources[topic.address])
        subscription_facts = azure_facts(resources[subscription.address])

        self.assertEqual(queue_facts.service_bus_entity_id, _QUEUE_ID)
        self.assertEqual(queue_facts.service_bus_entity_name, "orders")
        self.assertEqual(queue_facts.service_bus_entity_kind, "queue")
        self.assertEqual(queue_facts.service_bus_namespace_reference, _NAMESPACE_ID)
        self.assertEqual(queue_facts.resolved_service_bus_namespace_address, namespace.address)
        self.assertEqual(resources[queue.address].identifier, _QUEUE_ID)

        self.assertEqual(topic_facts.service_bus_entity_id, _TOPIC_ID)
        self.assertEqual(topic_facts.service_bus_entity_kind, "topic")
        self.assertEqual(topic_facts.resolved_service_bus_namespace_address, namespace.address)

        self.assertEqual(subscription_facts.service_bus_entity_id, _SUBSCRIPTION_ID)
        self.assertEqual(subscription_facts.service_bus_entity_kind, "subscription")
        self.assertIsNone(subscription_facts.service_bus_namespace_reference)
        self.assertEqual(subscription_facts.service_bus_topic_reference, _TOPIC_ID)
        self.assertEqual(subscription_facts.resolved_service_bus_namespace_address, namespace.address)
        self.assertEqual(subscription_facts.resolved_service_bus_topic_address, topic.address)
        self.assertEqual(subscription_facts.service_bus_posture_uncertainties, [])
        self.assertEqual(subscription_facts.unresolved_service_bus_namespace_references, [])
        self.assertEqual(subscription_facts.unresolved_service_bus_topic_references, [])

    def test_entity_terraform_references_resolve_without_name_matching(self) -> None:
        namespace = _namespace()
        topic = _resource(
            AzureResourceType.SERVICE_BUS_TOPIC,
            "events",
            {
                "id": _TOPIC_ID,
                "name": "events",
                "namespace_id": "azurerm_servicebus_namespace.events.id",
            },
        )
        subscription = _resource(
            AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
            "worker",
            {
                "id": _SUBSCRIPTION_ID,
                "name": "worker",
                "topic_id": "azurerm_servicebus_topic.events.id",
            },
        )

        inventory = AzureNormalizer().normalize([namespace, topic, subscription])
        resources = {resource.address: resource for resource in inventory.resources}
        topic_facts = azure_facts(resources[topic.address])
        subscription_facts = azure_facts(resources[subscription.address])

        self.assertEqual(topic_facts.service_bus_namespace_reference, "azurerm_servicebus_namespace.events.id")
        self.assertEqual(topic_facts.resolved_service_bus_namespace_address, namespace.address)
        self.assertEqual(subscription_facts.resolved_service_bus_topic_address, topic.address)
        self.assertEqual(subscription_facts.unresolved_service_bus_namespace_references, [])
        self.assertEqual(subscription_facts.unresolved_service_bus_topic_references, [])

    def test_entity_references_that_are_names_remain_unresolved(self) -> None:
        namespace = _namespace()
        topic = _resource(
            AzureResourceType.SERVICE_BUS_TOPIC,
            "events",
            {
                "id": _TOPIC_ID,
                "name": "events",
                "namespace_id": _NAMESPACE_ID,
            },
        )
        queue = _resource(
            AzureResourceType.SERVICE_BUS_QUEUE,
            "orders",
            {
                "id": _QUEUE_ID,
                "name": "orders",
                "namespace_id": "events",
            },
        )
        subscription = _resource(
            AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
            "worker",
            {
                "id": _SUBSCRIPTION_ID,
                "name": "worker",
                "topic_id": "events",
            },
        )

        inventory = AzureNormalizer().normalize([namespace, topic, queue, subscription])
        resources = {resource.address: resource for resource in inventory.resources}
        queue_facts = azure_facts(resources[queue.address])
        subscription_facts = azure_facts(resources[subscription.address])

        self.assertIsNone(queue_facts.resolved_service_bus_namespace_address)
        self.assertEqual(queue_facts.unresolved_service_bus_namespace_references, ["events"])
        self.assertIsNone(subscription_facts.resolved_service_bus_namespace_address)
        self.assertIsNone(subscription_facts.resolved_service_bus_topic_address)
        self.assertEqual(subscription_facts.unresolved_service_bus_namespace_references, [])
        self.assertEqual(subscription_facts.unresolved_service_bus_topic_references, ["events"])

    def test_subscription_preserves_the_topics_unresolved_namespace(self) -> None:
        topic = _resource(
            AzureResourceType.SERVICE_BUS_TOPIC,
            "events",
            {
                "id": _TOPIC_ID,
                "name": "events",
                "namespace_id": "external-events",
            },
        )
        subscription = _resource(
            AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
            "worker",
            {
                "id": _SUBSCRIPTION_ID,
                "name": "worker",
                "topic_id": _TOPIC_ID,
            },
        )

        inventory = AzureNormalizer().normalize([subscription, topic])
        resource = inventory.get_by_address(subscription.address)
        assert resource is not None
        facts = azure_facts(resource)

        self.assertEqual(facts.resolved_service_bus_topic_address, topic.address)
        self.assertIsNone(facts.resolved_service_bus_namespace_address)
        self.assertEqual(facts.unresolved_service_bus_namespace_references, ["external-events"])

    def test_unknown_entity_name_does_not_become_the_terraform_label(self) -> None:
        queue = _resource(
            AzureResourceType.SERVICE_BUS_QUEUE,
            "orders",
            {
                "id": _QUEUE_ID,
                "name": None,
                "namespace_id": _NAMESPACE_ID,
            },
            unknown_values={"name": True},
        )

        inventory = AzureNormalizer().normalize([_namespace(), queue])
        resource = inventory.get_by_address(queue.address)
        assert resource is not None
        facts = azure_facts(resource)

        self.assertIsNone(facts.service_bus_entity_name)
        self.assertEqual(facts.name, "orders")
        self.assertEqual(resource.name, "orders")
        self.assertEqual(facts.service_bus_posture_uncertainties, ["name is unknown after planning"])

    def test_unknown_entity_identity_and_relationship_are_explicit(self) -> None:
        queue = _resource(
            AzureResourceType.SERVICE_BUS_QUEUE,
            "orders",
            {
                "id": None,
                "name": "orders",
                "namespace_id": None,
            },
            unknown_values={
                "id": True,
                "namespace_id": True,
            },
        )

        inventory = AzureNormalizer().normalize([queue])
        resource = inventory.resources[0]
        facts = azure_facts(resource)

        self.assertIsNone(facts.service_bus_entity_id)
        self.assertIsNone(facts.service_bus_namespace_reference)
        self.assertEqual(resource.identifier, queue.address)
        self.assertIsNone(facts.resolved_service_bus_namespace_address)
        self.assertEqual(
            facts.service_bus_posture_uncertainties,
            [
                "id is unknown after planning",
                "namespace_id is unknown after planning",
            ],
        )

    def test_namespace_is_a_data_store(self) -> None:
        inventory = AzureNormalizer().normalize([_namespace(values={"public_network_access_enabled": True})])
        namespace = inventory.resources[0]

        self.assertTrue(default_resource_capability_registry().has_capability(namespace, ResourceCapability.DATA_STORE))

    def test_companion_resources_do_not_resolve_bare_namespace_names(self) -> None:
        namespace = _namespace()
        network_rules = _resource(
            AzureResourceType.SERVICE_BUS_NAMESPACE_NETWORK_RULE_SET,
            "unresolved",
            {"namespace_id": "events", "default_action": "Deny"},
        )
        customer_managed_key = _resource(
            AzureResourceType.SERVICE_BUS_NAMESPACE_CUSTOMER_MANAGED_KEY,
            "unresolved",
            {"namespace_id": "events", "key_vault_key_id": _KEY_ID},
        )

        inventory = AzureNormalizer().normalize([namespace, network_rules, customer_managed_key])
        resources = {resource.address: resource for resource in inventory.resources}
        namespace_facts = azure_facts(resources[namespace.address])

        self.assertIsNone(namespace_facts.network_default_action)
        self.assertEqual(namespace_facts.service_bus_customer_managed_key_state, "not_configured")
        self.assertEqual(
            azure_facts(resources[network_rules.address]).unresolved_service_bus_namespace_references,
            ["events"],
        )
        self.assertEqual(
            azure_facts(resources[customer_managed_key.address]).unresolved_service_bus_namespace_references,
            ["events"],
        )


if __name__ == "__main__":
    unittest.main()
