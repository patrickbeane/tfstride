from __future__ import annotations

import unittest

from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.catalog import default_resource_capability_registry
from tfstride.providers.resource_capabilities import ResourceCapability

_NAMESPACE_ID = "/subscriptions/example/resourceGroups/app/providers/Microsoft.ServiceBus/namespaces/events"
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

    def test_namespace_is_a_data_store_without_new_findings(self) -> None:
        inventory = AzureNormalizer().normalize([_namespace(values={"public_network_access_enabled": True})])
        namespace = inventory.resources[0]

        self.assertTrue(default_resource_capability_registry().has_capability(namespace, ResourceCapability.DATA_STORE))
        self.assertEqual(StrideRuleEngine().evaluate(inventory, []), [])

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
