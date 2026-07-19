from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.identity_normalizers import normalize_role_assignment
from tfstride.providers.azure.key_vault_normalizers import (
    normalize_key_vault,
    normalize_key_vault_access_policy,
    normalize_key_vault_certificate,
    normalize_key_vault_key,
    normalize_key_vault_secret,
)
from tfstride.providers.azure.normalizer import AzureNormalizer
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
        self.assertIsNone(facts.key_vault_uri)
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

    def test_key_vault_and_secret_capture_exact_data_plane_identifiers(self) -> None:
        secret = normalize_key_vault_secret(
            _resource(
                AzureResourceType.KEY_VAULT_SECRET,
                {
                    "id": "https://application.vault.azure.net/secrets/api-key/secret-version",
                    "versionless_id": "https://application.vault.azure.net/secrets/api-key",
                    "resource_id": (
                        "/subscriptions/example/resourceGroups/app/providers/"
                        "Microsoft.KeyVault/vaults/application/secrets/api-key"
                    ),
                    "name": "api-key",
                    "version": "secret-version",
                    "key_vault_id": "azurerm_key_vault.application.id",
                },
            )
        )
        facts = azure_facts(secret)

        self.assertEqual(facts.key_vault_secret_name, "api-key")
        self.assertEqual(
            facts.key_vault_secret_uri,
            "https://application.vault.azure.net/secrets/api-key/secret-version",
        )
        self.assertEqual(
            facts.key_vault_secret_versionless_uri,
            "https://application.vault.azure.net/secrets/api-key",
        )
        self.assertEqual(facts.key_vault_secret_version, "secret-version")
        self.assertEqual(
            facts.key_vault_secret_resource_id,
            "/subscriptions/example/resourceGroups/app/providers/Microsoft.KeyVault/vaults/application/secrets/api-key",
        )
        self.assertEqual(facts.key_vault_identity_uncertainties, [])

    def test_key_vault_relationship_derives_secret_identifiers_from_exact_vault_uri(self) -> None:
        vault = _resource(
            AzureResourceType.KEY_VAULT,
            {
                "id": "/subscriptions/example/resourceGroups/app/providers/Microsoft.KeyVault/vaults/application",
                "name": "application",
                "vault_uri": "https://application.vault.azure.net/",
            },
        )
        secret = _resource(
            AzureResourceType.KEY_VAULT_SECRET,
            {
                "name": "api-key",
                "version": "secret-version",
                "key_vault_id": "azurerm_key_vault.example.id",
            },
        )

        inventory = AzureNormalizer().normalize([vault, secret])
        normalized_secret = inventory.get_by_address("azurerm_key_vault_secret.example")
        assert normalized_secret is not None
        facts = azure_facts(normalized_secret)

        self.assertEqual(facts.resolved_key_vault_address, "azurerm_key_vault.example")
        self.assertEqual(facts.key_vault_uri, "https://application.vault.azure.net")
        self.assertEqual(
            facts.key_vault_secret_versionless_uri,
            "https://application.vault.azure.net/secrets/api-key",
        )
        self.assertEqual(
            facts.key_vault_secret_uri,
            "https://application.vault.azure.net/secrets/api-key/secret-version",
        )

    def test_key_vault_secret_does_not_derive_identity_from_name_only(self) -> None:
        secret = normalize_key_vault_secret(
            _resource(
                AzureResourceType.KEY_VAULT_SECRET,
                {"name": "api-key", "key_vault_id": "azurerm_key_vault.application.id"},
            )
        )
        facts = azure_facts(secret)

        self.assertIsNone(facts.key_vault_uri)
        self.assertIsNone(facts.key_vault_secret_uri)
        self.assertIsNone(facts.key_vault_secret_versionless_uri)
        self.assertEqual(facts.key_vault_identity_uncertainties, [])

    def test_key_vault_secret_preserves_unresolved_identity_fields(self) -> None:
        secret = normalize_key_vault_secret(
            _resource(
                AzureResourceType.KEY_VAULT_SECRET,
                {
                    "name": "api-key",
                    "key_vault_id": "azurerm_key_vault.application.id",
                    "id": "${azurerm_key_vault_secret.api_key.id}",
                    "version": None,
                },
                unknown_values={"version": True},
            )
        )
        facts = azure_facts(secret)

        self.assertIsNone(facts.key_vault_secret_uri)
        self.assertIsNone(facts.key_vault_secret_versionless_uri)
        self.assertEqual(
            facts.key_vault_identity_uncertainties,
            ["version is unknown after planning", "id is unresolved after planning"],
        )

    def test_key_vault_secret_preserves_lifecycle_posture(self) -> None:
        secret = normalize_key_vault_secret(
            _resource(
                AzureResourceType.KEY_VAULT_SECRET,
                {
                    "name": "api-key",
                    "key_vault_id": "azurerm_key_vault.application.id",
                    "expiration_date": "2027-01-01T00:00:00Z",
                    "not_before_date": "2026-01-01T00:00:00Z",
                },
            )
        )
        facts = azure_facts(secret)

        self.assertEqual(facts.key_vault_expiration_date, "2027-01-01T00:00:00Z")
        self.assertEqual(facts.key_vault_not_before_date, "2026-01-01T00:00:00Z")
        self.assertIsNone(facts.key_vault_certificate_validity_months)
        self.assertEqual(facts.key_vault_lifecycle_uncertainties, [])

    def test_key_vault_key_preserves_rotation_policy_and_key_shape(self) -> None:
        key = normalize_key_vault_key(
            _resource(
                AzureResourceType.KEY_VAULT_KEY,
                {
                    "id": "azurerm_key_vault_key.signing.id",
                    "name": "signing",
                    "key_vault_id": "azurerm_key_vault.application.id",
                    "key_type": "RSA",
                    "key_size": 2048,
                    "key_opts": ["decrypt", "encrypt", "sign", "verify"],
                    "not_before_date": "2026-01-01T00:00:00Z",
                    "expiration_date": "2027-01-01T00:00:00Z",
                    "rotation_policy": [
                        {
                            "expire_after": "P90D",
                            "notify_before_expiry": "P30D",
                            "automatic": [
                                {
                                    "time_after_creation": "P30D",
                                    "time_before_expiry": "P15D",
                                }
                            ],
                        }
                    ],
                },
            )
        )
        facts = azure_facts(key)

        self.assertEqual(key.identifier, "azurerm_key_vault_key.signing.id")
        self.assertEqual(facts.key_vault_reference, "azurerm_key_vault.application.id")
        self.assertEqual(facts.key_vault_expiration_date, "2027-01-01T00:00:00Z")
        self.assertEqual(facts.key_vault_not_before_date, "2026-01-01T00:00:00Z")
        self.assertEqual(facts.key_vault_key_type, "RSA")
        self.assertEqual(facts.key_vault_key_size, 2048)
        self.assertIsNone(facts.key_vault_key_curve)
        self.assertEqual(facts.key_vault_key_ops, ["decrypt", "encrypt", "sign", "verify"])
        self.assertEqual(facts.key_vault_rotation_policy_expire_after, "P90D")
        self.assertEqual(facts.key_vault_rotation_policy_notify_before_expiry, "P30D")
        self.assertEqual(facts.key_vault_rotation_policy_automatic_time_after_creation, "P30D")
        self.assertEqual(facts.key_vault_rotation_policy_automatic_time_before_expiry, "P15D")
        self.assertEqual(
            facts.key_vault_rotation_policy,
            {
                "expire_after": "P90D",
                "notify_before_expiry": "P30D",
                "automatic": {
                    "time_after_creation": "P30D",
                    "time_before_expiry": "P15D",
                },
            },
        )
        self.assertEqual(facts.key_vault_key_posture_uncertainties, [])
        self.assertTrue(key.storage_encrypted)
        self.assertEqual(key.data_sensitivity, "sensitive")

    def test_key_vault_key_preserves_unknown_rotation_policy_and_key_shape(self) -> None:
        key = normalize_key_vault_key(
            _resource(
                AzureResourceType.KEY_VAULT_KEY,
                {
                    "name": "pending",
                    "key_vault_id": "azurerm_key_vault.application.id",
                    "rotation_policy": [{"automatic": [{}]}],
                },
                unknown_values={
                    "key_type": True,
                    "key_size": True,
                    "key_opts": True,
                    "rotation_policy": [
                        {
                            "expire_after": True,
                            "notify_before_expiry": True,
                            "automatic": [
                                {
                                    "time_after_creation": True,
                                    "time_before_expiry": True,
                                }
                            ],
                        }
                    ],
                },
            )
        )
        facts = azure_facts(key)

        self.assertIsNone(facts.key_vault_key_type)
        self.assertIsNone(facts.key_vault_key_size)
        self.assertEqual(facts.key_vault_key_ops, [])
        self.assertEqual(facts.key_vault_rotation_policy, {})
        self.assertIsNone(facts.key_vault_rotation_policy_expire_after)
        self.assertIsNone(facts.key_vault_rotation_policy_notify_before_expiry)
        self.assertIsNone(facts.key_vault_rotation_policy_automatic_time_after_creation)
        self.assertIsNone(facts.key_vault_rotation_policy_automatic_time_before_expiry)
        self.assertEqual(
            facts.key_vault_key_posture_uncertainties,
            [
                "key_type is unknown after planning",
                "key_size is unknown after planning",
                "key_opts is unknown after planning",
                "rotation_policy.expire_after is unknown after planning",
                "rotation_policy.notify_before_expiry is unknown after planning",
                "rotation_policy.automatic.time_after_creation is unknown after planning",
                "rotation_policy.automatic.time_before_expiry is unknown after planning",
            ],
        )

    def test_key_vault_certificate_preserves_lifecycle_posture(self) -> None:
        certificate = normalize_key_vault_certificate(
            _resource(
                AzureResourceType.KEY_VAULT_CERTIFICATE,
                {
                    "name": "tls",
                    "key_vault_id": "azurerm_key_vault.application.id",
                    "certificate_policy": [{"validity_in_months": 12}],
                },
            )
        )
        facts = azure_facts(certificate)

        self.assertEqual(facts.key_vault_certificate_validity_months, 12)
        self.assertEqual(facts.key_vault_lifecycle_uncertainties, [])

    def test_key_vault_child_preserves_unknown_lifecycle_posture(self) -> None:
        certificate = normalize_key_vault_certificate(
            _resource(
                AzureResourceType.KEY_VAULT_CERTIFICATE,
                {"name": "tls", "key_vault_id": "azurerm_key_vault.application.id"},
                unknown_values={
                    "expiration_date": True,
                    "not_before_date": True,
                    "certificate_policy": [{"validity_in_months": True}],
                },
            )
        )
        facts = azure_facts(certificate)

        self.assertIsNone(facts.key_vault_expiration_date)
        self.assertIsNone(facts.key_vault_not_before_date)
        self.assertIsNone(facts.key_vault_certificate_validity_months)
        self.assertEqual(
            facts.key_vault_lifecycle_uncertainties,
            [
                "expiration_date is unknown after planning",
                "not_before_date is unknown after planning",
                "certificate_policy.validity_in_months is unknown after planning",
            ],
        )


if __name__ == "__main__":
    unittest.main()
