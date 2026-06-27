from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.key_vault_normalizers import (
    normalize_key_vault,
    normalize_key_vault_access_policy,
    normalize_key_vault_secret,
    normalize_role_assignment,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType


def _resource(
    resource_type: str,
    values: dict[str, object],
    *,
    name: str = "example",
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


class AzureKeyVaultNormalizerTests(unittest.TestCase):
    def test_key_vault_normalizes_public_network_and_recovery_posture(self) -> None:
        normalized = normalize_key_vault(
            _resource(
                AzureResourceType.KEY_VAULT,
                {
                    "id": "/subscriptions/example/providers/Microsoft.KeyVault/vaults/application",
                    "name": "application",
                    "tenant_id": "tenant-id",
                    "public_network_access_enabled": True,
                    "purge_protection_enabled": False,
                    "enable_rbac_authorization": True,
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(facts.key_vault_id, normalized.identifier)
        self.assertTrue(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "enabled")
        self.assertEqual(facts.network_default_action, "Allow")
        self.assertFalse(facts.purge_protection_enabled)
        self.assertTrue(facts.rbac_authorization_enabled)
        self.assertTrue(normalized.storage_encrypted)
        self.assertEqual(normalized.data_sensitivity, "sensitive")

    def test_key_vault_normalizes_restricted_network_acls(self) -> None:
        normalized = normalize_key_vault(
            _resource(
                AzureResourceType.KEY_VAULT,
                {
                    "name": "restricted",
                    "public_network_access_enabled": True,
                    "purge_protection_enabled": True,
                    "network_acls": [
                        {
                            "default_action": "Deny",
                            "ip_rules": ["198.51.100.10"],
                            "virtual_network_subnet_ids": ["azurerm_subnet.app.id"],
                        }
                    ],
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(facts.public_network_fallback_state, "enabled")
        self.assertEqual(facts.network_default_action, "Deny")
        self.assertEqual(facts.key_vault_network_ip_rules, ["198.51.100.10"])
        self.assertEqual(facts.key_vault_network_subnet_ids, ["azurerm_subnet.app.id"])
        self.assertTrue(facts.purge_protection_enabled)

    def test_key_vault_normalizes_disabled_public_network_fallback(self) -> None:
        normalized = normalize_key_vault(
            _resource(
                AzureResourceType.KEY_VAULT,
                {
                    "name": "private",
                    "public_network_access_enabled": False,
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertFalse(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "disabled")

    def test_key_vault_missing_public_network_fallback_is_unknown(self) -> None:
        normalized = normalize_key_vault(
            _resource(
                AzureResourceType.KEY_VAULT,
                {
                    "name": "unset",
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertIsNone(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "unknown")
        self.assertEqual(facts.network_default_action, "Allow")

    def test_key_vault_preserves_computed_network_and_authorization_values_as_unknown(self) -> None:
        normalized = normalize_key_vault(
            _resource(
                AzureResourceType.KEY_VAULT,
                {
                    "name": "pending",
                    "public_network_access_enabled": None,
                    "purge_protection_enabled": None,
                    "enable_rbac_authorization": None,
                    "network_acls": [{"default_action": None}],
                    "access_policy": None,
                },
                unknown_values={
                    "public_network_access_enabled": True,
                    "purge_protection_enabled": True,
                    "enable_rbac_authorization": True,
                    "network_acls": [{"default_action": True}],
                    "access_policy": True,
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertIsNone(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "unknown")
        self.assertIsNone(facts.network_default_action)
        self.assertIsNone(facts.purge_protection_enabled)
        self.assertIsNone(facts.rbac_authorization_enabled)
        self.assertEqual(
            facts.key_vault_network_uncertainties,
            [
                "public_network_access_enabled is unknown after planning",
                "network_acls.default_action is unknown after planning",
            ],
        )
        self.assertEqual(
            facts.key_vault_authorization_uncertainties,
            [
                "enable_rbac_authorization is unknown after planning",
                "access_policy is unknown after planning",
            ],
        )
        self.assertEqual(
            facts.key_vault_recovery_uncertainties,
            ["purge_protection_enabled is unknown after planning"],
        )

    def test_access_policy_and_role_assignment_preserve_authorization_context(self) -> None:
        policy = normalize_key_vault_access_policy(
            _resource(
                AzureResourceType.KEY_VAULT_ACCESS_POLICY,
                {
                    "key_vault_id": "azurerm_key_vault.application.id",
                    "tenant_id": "tenant-id",
                    "object_id": "operator-id",
                    "secret_permissions": ["Set", "Get", "Purge"],
                },
            )
        )
        assignment = normalize_role_assignment(
            _resource(
                AzureResourceType.ROLE_ASSIGNMENT,
                {
                    "scope": "azurerm_key_vault.application.id",
                    "role_definition_name": "Key Vault Administrator",
                    "principal_id": "principal-id",
                    "principal_type": "ServicePrincipal",
                },
            )
        )

        policy_facts = azure_facts(policy)
        assignment_facts = azure_facts(assignment)
        self.assertEqual(policy_facts.key_vault_reference, "azurerm_key_vault.application.id")
        self.assertEqual(
            policy_facts.key_vault_access_policies[0]["secret_permissions"],
            ["get", "purge", "set"],
        )
        self.assertEqual(assignment_facts.role_assignment_scope, "azurerm_key_vault.application.id")
        self.assertEqual(assignment_facts.role_definition_name, "Key Vault Administrator")
        self.assertEqual(assignment_facts.principal_id, "principal-id")

    def test_key_vault_child_preserves_vault_reference(self) -> None:
        secret = normalize_key_vault_secret(
            _resource(
                AzureResourceType.KEY_VAULT_SECRET,
                {"name": "api-key", "key_vault_id": "azurerm_key_vault.application.id"},
            )
        )

        self.assertEqual(azure_facts(secret).key_vault_reference, "azurerm_key_vault.application.id")
        self.assertTrue(secret.storage_encrypted)
        self.assertEqual(secret.data_sensitivity, "sensitive")


if __name__ == "__main__":
    unittest.main()
