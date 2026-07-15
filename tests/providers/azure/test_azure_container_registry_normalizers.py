from __future__ import annotations

import unittest

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_REGISTRY_ID = "/subscriptions/example/resourceGroups/apps/providers/Microsoft.ContainerRegistry/registries/images"
_KEY_ID = "azurerm_key_vault_key.registry.id"
_IDENTITY_ID = "azurerm_user_assigned_identity.registry.id"


def _registry(
    *,
    name: str = "images",
    values: dict[str, object] | None = None,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"azurerm_container_registry.{name}",
        mode="managed",
        resource_type=AzureResourceType.CONTAINER_REGISTRY,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values={
            "id": _REGISTRY_ID,
            "name": name,
            "location": "eastus",
            **(values or {}),
        },
        unknown_values=unknown_values or {},
    )


class AzureContainerRegistryNormalizerTests(unittest.TestCase):
    def test_premium_registry_normalizes_network_identity_cmk_and_security_controls(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _registry(
                    values={
                        "sku": "Premium",
                        "login_server": "images.azurecr.io",
                        "public_network_access_enabled": False,
                        "admin_enabled": False,
                        "anonymous_pull_enabled": False,
                        "network_rule_set": [
                            {
                                "default_action": "Deny",
                                "ip_rule": [{"action": "Allow", "ip_range": "198.51.100.0/24"}],
                            }
                        ],
                        "identity": [
                            {
                                "type": "UserAssigned",
                                "principal_id": "principal-id",
                                "client_id": "client-id",
                                "tenant_id": "tenant-id",
                                "identity_ids": [_IDENTITY_ID],
                            }
                        ],
                        "encryption": [
                            {
                                "key_vault_key_id": _KEY_ID,
                                "identity_client_id": "client-id",
                            }
                        ],
                        "retention_policy_in_days": 30,
                        "export_policy_enabled": False,
                        "quarantine_policy_enabled": True,
                        "trust_policy_enabled": True,
                        "zone_redundancy_enabled": True,
                        "data_endpoint_enabled": True,
                        "network_rule_bypass_option": "None",
                    }
                )
            ]
        )
        registry = inventory.resources[0]
        facts = azure_facts(registry)

        self.assertEqual(registry.category, ResourceCategory.DATA)
        self.assertEqual(registry.identifier, _REGISTRY_ID)
        self.assertEqual(registry.data_sensitivity, "sensitive")
        self.assertTrue(registry.storage_encrypted)
        self.assertEqual(facts.container_registry_id, _REGISTRY_ID)
        self.assertEqual(facts.container_registry_sku, "Premium")
        self.assertEqual(facts.container_registry_login_server, "images.azurecr.io")
        self.assertEqual(facts.container_registry_premium_tier_state, "enabled")
        self.assertTrue(facts.container_registry_is_premium)
        self.assertFalse(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "disabled")
        self.assertEqual(facts.network_default_action, "Deny")
        self.assertEqual(facts.network_rule_source_address, registry.address)
        self.assertEqual(
            facts.container_registry_network_rule_set,
            {
                "default_action": "Deny",
                "ip_rules": [{"action": "Allow", "ip_range": "198.51.100.0/24"}],
            },
        )
        self.assertEqual(facts.container_registry_admin_state, "disabled")
        self.assertFalse(facts.container_registry_admin_enabled)
        self.assertEqual(facts.container_registry_anonymous_pull_state, "disabled")
        self.assertFalse(facts.container_registry_anonymous_pull_enabled)
        self.assertEqual(facts.container_registry_customer_managed_key_state, "configured")
        self.assertEqual(facts.container_registry_key_vault_key_id, _KEY_ID)
        self.assertEqual(facts.container_registry_encryption_identity_client_id, "client-id")
        self.assertEqual(
            facts.container_registry_encryption_configuration,
            {"key_vault_key_id": _KEY_ID, "identity_client_id": "client-id"},
        )
        self.assertEqual(facts.identity_type, "UserAssigned")
        self.assertEqual(facts.principal_id, "principal-id")
        self.assertEqual(facts.client_id, "client-id")
        self.assertEqual(facts.tenant_id, "tenant-id")
        self.assertEqual(facts.attached_identity_references, [_IDENTITY_ID])
        self.assertEqual(facts.container_registry_retention_state, "configured")
        self.assertEqual(facts.container_registry_retention_days, 30)
        self.assertEqual(facts.container_registry_export_policy_state, "disabled")
        self.assertFalse(facts.container_registry_export_policy_enabled)
        self.assertEqual(facts.container_registry_quarantine_policy_state, "enabled")
        self.assertTrue(facts.container_registry_quarantine_policy_enabled)
        self.assertEqual(facts.container_registry_trust_policy_state, "enabled")
        self.assertTrue(facts.container_registry_trust_policy_enabled)
        self.assertEqual(facts.container_registry_zone_redundancy_state, "enabled")
        self.assertTrue(facts.container_registry_zone_redundancy_enabled)
        self.assertEqual(facts.container_registry_data_endpoint_state, "enabled")
        self.assertTrue(facts.container_registry_data_endpoint_enabled)
        self.assertEqual(facts.container_registry_network_rule_bypass_option, "None")
        self.assertEqual(facts.container_registry_posture_uncertainties, [])
        self.assertEqual(facts.managed_identity_uncertainties, [])

    def test_standard_registry_preserves_public_local_auth_and_premium_applicability(self) -> None:
        facts = azure_facts(
            AzureNormalizer()
            .normalize(
                [
                    _registry(
                        values={
                            "sku": "Standard",
                            "public_network_access_enabled": True,
                            "admin_enabled": True,
                            "anonymous_pull_enabled": True,
                        }
                    )
                ]
            )
            .resources[0]
        )

        self.assertEqual(facts.container_registry_premium_tier_state, "disabled")
        self.assertFalse(facts.container_registry_is_premium)
        self.assertTrue(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "enabled")
        self.assertTrue(facts.container_registry_admin_enabled)
        self.assertTrue(facts.container_registry_anonymous_pull_enabled)
        self.assertEqual(facts.container_registry_customer_managed_key_state, "not_configured")
        self.assertEqual(facts.container_registry_retention_state, "not_applicable")
        self.assertEqual(facts.container_registry_export_policy_state, "not_applicable")
        self.assertEqual(facts.container_registry_quarantine_policy_state, "not_applicable")
        self.assertEqual(facts.container_registry_trust_policy_state, "not_applicable")
        self.assertEqual(facts.container_registry_zone_redundancy_state, "not_applicable")
        self.assertEqual(facts.container_registry_data_endpoint_state, "not_applicable")
        self.assertIsNone(facts.network_default_action)
        self.assertEqual(facts.container_registry_posture_uncertainties, [])

    def test_legacy_retention_and_trust_policy_blocks_are_preserved(self) -> None:
        facts = azure_facts(
            AzureNormalizer()
            .normalize(
                [
                    _registry(
                        values={
                            "sku": "Premium",
                            "retention_policy": [{"enabled": True, "days": 14}],
                            "trust_policy": [{"enabled": True}],
                        }
                    )
                ]
            )
            .resources[0]
        )

        self.assertEqual(facts.container_registry_retention_state, "enabled")
        self.assertEqual(facts.container_registry_retention_days, 14)
        self.assertEqual(facts.container_registry_trust_policy_state, "enabled")
        self.assertTrue(facts.container_registry_trust_policy_enabled)

    def test_unknown_registry_posture_remains_explicit(self) -> None:
        facts = azure_facts(
            AzureNormalizer()
            .normalize(
                [
                    _registry(
                        values={
                            "sku": None,
                            "public_network_access_enabled": None,
                            "admin_enabled": None,
                            "anonymous_pull_enabled": None,
                            "network_rule_set": [{"default_action": None, "ip_rule": []}],
                            "encryption": [{"key_vault_key_id": None, "identity_client_id": None}],
                            "retention_policy_in_days": None,
                            "export_policy_enabled": None,
                            "quarantine_policy_enabled": None,
                            "trust_policy_enabled": None,
                            "zone_redundancy_enabled": None,
                            "data_endpoint_enabled": None,
                            "network_rule_bypass_option": None,
                            "identity": [],
                        },
                        unknown_values={
                            "sku": True,
                            "public_network_access_enabled": True,
                            "admin_enabled": True,
                            "anonymous_pull_enabled": True,
                            "network_rule_set": [{"default_action": True, "ip_rule": True}],
                            "encryption": [{"key_vault_key_id": True, "identity_client_id": True}],
                            "retention_policy_in_days": True,
                            "export_policy_enabled": True,
                            "quarantine_policy_enabled": True,
                            "trust_policy_enabled": True,
                            "zone_redundancy_enabled": True,
                            "data_endpoint_enabled": True,
                            "network_rule_bypass_option": True,
                            "identity": True,
                        },
                    )
                ]
            )
            .resources[0]
        )

        self.assertEqual(facts.container_registry_premium_tier_state, "unknown")
        self.assertEqual(facts.public_network_fallback_state, "unknown")
        self.assertIsNone(facts.public_network_access_enabled)
        self.assertEqual(facts.container_registry_admin_state, "unknown")
        self.assertEqual(facts.container_registry_anonymous_pull_state, "unknown")
        self.assertIsNone(facts.network_default_action)
        self.assertEqual(facts.container_registry_customer_managed_key_state, "unknown")
        self.assertEqual(facts.container_registry_retention_state, "unknown")
        self.assertEqual(facts.container_registry_export_policy_state, "unknown")
        self.assertEqual(facts.container_registry_quarantine_policy_state, "unknown")
        self.assertEqual(facts.container_registry_trust_policy_state, "unknown")
        self.assertEqual(facts.container_registry_zone_redundancy_state, "unknown")
        self.assertEqual(facts.container_registry_data_endpoint_state, "unknown")
        self.assertIn("sku is unknown after planning", facts.container_registry_posture_uncertainties)
        self.assertIn(
            "network_rule_set.default_action is unknown after planning",
            facts.container_registry_posture_uncertainties,
        )
        self.assertIn(
            "network_rule_set.ip_rule is unknown after planning", facts.container_registry_posture_uncertainties
        )
        self.assertIn(
            "encryption.key_vault_key_id is unknown after planning", facts.container_registry_posture_uncertainties
        )
        self.assertIn(
            "retention_policy_in_days is unknown after planning", facts.container_registry_posture_uncertainties
        )
        self.assertEqual(facts.managed_identity_uncertainties, ["identity is unknown after planning"])

    def test_container_registry_is_registered_as_supported(self) -> None:
        inventory = AzureNormalizer().normalize([_registry(values={"sku": "Basic"})])

        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual([resource.address for resource in inventory.resources], ["azurerm_container_registry.images"])


if __name__ == "__main__":
    unittest.main()
