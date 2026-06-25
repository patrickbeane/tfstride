from __future__ import annotations

import unittest

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.azure.data_normalizers import (
    normalize_storage_account,
    normalize_storage_account_network_rules,
    normalize_storage_container,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType


def _resource(
    resource_type: str,
    values: dict[str, object],
    *,
    name: str = "example",
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
    )


class AzureStorageNormalizerTests(unittest.TestCase):
    def test_storage_account_normalizes_explicit_posture_and_inline_network_rules(self) -> None:
        normalized = normalize_storage_account(
            _resource(
                AzureResourceType.STORAGE_ACCOUNT,
                {
                    "id": "/subscriptions/example/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs",
                    "name": "tfstridelogs",
                    "allow_nested_items_to_be_public": False,
                    "shared_access_key_enabled": False,
                    "min_tls_version": "TLS1_2",
                    "public_network_access_enabled": True,
                    "network_rules": [{"default_action": "Deny"}],
                },
                name="logs",
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.DATA)
        self.assertEqual(
            normalized.identifier,
            "/subscriptions/example/resourceGroups/app/providers/Microsoft.Storage/storageAccounts/logs",
        )
        self.assertEqual(normalized.data_sensitivity, "sensitive")
        self.assertTrue(normalized.storage_encrypted)
        self.assertEqual(facts.bucket_name, "tfstridelogs")
        self.assertFalse(facts.allow_nested_items_to_be_public)
        self.assertFalse(facts.shared_access_key_enabled)
        self.assertEqual(facts.min_tls_version, "TLS1_2")
        self.assertTrue(facts.public_network_access_enabled)
        self.assertEqual(facts.network_default_action, "Deny")
        self.assertEqual(facts.network_rule_source_address, "azurerm_storage_account.logs")

    def test_storage_account_applies_documented_azurerm_defaults(self) -> None:
        normalized = normalize_storage_account(_resource(AzureResourceType.STORAGE_ACCOUNT, {"name": "tfstridelogs"}))
        facts = azure_facts(normalized)

        self.assertTrue(facts.allow_nested_items_to_be_public)
        self.assertTrue(facts.shared_access_key_enabled)
        self.assertEqual(facts.min_tls_version, "TLS1_2")
        self.assertTrue(facts.public_network_access_enabled)
        self.assertEqual(facts.network_default_action, "Allow")
        self.assertIsNone(facts.network_rule_source_address)

    def test_storage_container_normalizes_account_reference_and_private_default(self) -> None:
        normalized = normalize_storage_container(
            _resource(
                AzureResourceType.STORAGE_CONTAINER,
                {
                    "name": "private",
                    "storage_account_id": "azurerm_storage_account.logs.id",
                },
                name="private",
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.DATA)
        self.assertEqual(facts.bucket_name, "private")
        self.assertEqual(facts.storage_account_reference, "azurerm_storage_account.logs.id")
        self.assertEqual(facts.container_access_type, "private")
        self.assertTrue(normalized.storage_encrypted)

    def test_storage_container_accepts_deprecated_account_name_reference(self) -> None:
        normalized = normalize_storage_container(
            _resource(
                AzureResourceType.STORAGE_CONTAINER,
                {
                    "name": "public",
                    "storage_account_name": "tfstridelogs",
                    "container_access_type": "blob",
                },
            )
        )

        self.assertEqual(azure_facts(normalized).storage_account_reference, "tfstridelogs")

    def test_standalone_network_rules_normalize_account_reference(self) -> None:
        normalized = normalize_storage_account_network_rules(
            _resource(
                AzureResourceType.STORAGE_ACCOUNT_NETWORK_RULES,
                {
                    "storage_account_id": "azurerm_storage_account.logs.id",
                    "default_action": "Deny",
                },
                name="logs",
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(facts.storage_account_reference, "azurerm_storage_account.logs.id")
        self.assertEqual(facts.network_default_action, "Deny")
        self.assertEqual(
            facts.network_rule_source_address,
            "azurerm_storage_account_network_rules.logs",
        )


if __name__ == "__main__":
    unittest.main()
