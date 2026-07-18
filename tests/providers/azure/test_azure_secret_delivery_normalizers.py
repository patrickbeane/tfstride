from __future__ import annotations

import unittest
from collections.abc import Callable

from tfstride.models import NormalizedResource, TerraformResource
from tfstride.providers.azure.app_service_normalizers import (
    normalize_function_app,
    normalize_linux_function_app,
    normalize_linux_web_app,
    normalize_windows_function_app,
    normalize_windows_web_app,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType


def _resource(
    resource_type: str,
    values: dict[str, object],
    *,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.app",
        mode="managed",
        resource_type=resource_type,
        name="app",
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values=unknown_values or {},
    )


class AzureAppServiceSecretDeliveryNormalizerTests(unittest.TestCase):
    def test_versioned_key_vault_secret_uri_preserves_exact_identities(self) -> None:
        normalized = normalize_linux_web_app(
            _resource(
                AzureResourceType.LINUX_WEB_APP,
                {
                    "name": "api",
                    "app_settings": {
                        "DB_PASSWORD": (
                            "@Microsoft.KeyVault(SecretUri="
                            "https://Orders-Vault.vault.azure.net/secrets/database-password/abc123)"
                        )
                    },
                    "key_vault_reference_identity_id": (
                        "/subscriptions/sub/resourceGroups/app/providers/"
                        "Microsoft.ManagedIdentity/userAssignedIdentities/app"
                    ),
                },
            )
        )

        facts = azure_facts(normalized)
        self.assertEqual(len(facts.app_service_secret_references), 1)
        reference = facts.app_service_secret_references[0]
        self.assertEqual(reference["source"], AzureResourceType.LINUX_WEB_APP)
        self.assertEqual(reference["path"], "app_settings['DB_PASSWORD']")
        self.assertEqual(reference["state"], "reference")
        self.assertTrue(reference["is_resolved"])
        self.assertEqual(reference["reference_kind"], "key_vault_secret_uri")
        self.assertEqual(reference["target_resolution"], "resolved")
        self.assertEqual(reference["key_vault_uri"], "https://orders-vault.vault.azure.net")
        self.assertEqual(
            reference["key_vault_secret_versionless_uri"],
            "https://orders-vault.vault.azure.net/secrets/database-password",
        )
        self.assertEqual(
            reference["key_vault_secret_uri"],
            "https://orders-vault.vault.azure.net/secrets/database-password/abc123",
        )
        self.assertEqual(reference["key_vault_secret_name"], "database-password")
        self.assertEqual(reference["key_vault_secret_version"], "abc123")
        self.assertEqual(reference["secret_version_state"], "configured")
        self.assertEqual(reference["normalized_setting_name"], "db_password")
        self.assertEqual(reference["sensitive_category"], "password")
        self.assertEqual(
            facts.app_service_key_vault_reference_identity_id,
            "/subscriptions/sub/resourceGroups/app/providers/Microsoft.ManagedIdentity/userAssignedIdentities/app",
        )
        self.assertEqual(facts.app_service_secret_posture_uncertainties, [])

    def test_versionless_key_vault_reference_is_normalized_for_all_app_variants(self) -> None:
        cases: tuple[tuple[str, Callable[[TerraformResource], NormalizedResource]], ...] = (
            (AzureResourceType.LINUX_WEB_APP, normalize_linux_web_app),
            (AzureResourceType.WINDOWS_WEB_APP, normalize_windows_web_app),
            (AzureResourceType.FUNCTION_APP, normalize_function_app),
            (AzureResourceType.LINUX_FUNCTION_APP, normalize_linux_function_app),
            (AzureResourceType.WINDOWS_FUNCTION_APP, normalize_windows_function_app),
        )
        for resource_type, normalize in cases:
            with self.subTest(resource_type=resource_type):
                normalized = normalize(
                    _resource(
                        resource_type,
                        {
                            "name": "app",
                            "app_settings": {
                                "SERVICE_ENDPOINT": (
                                    "@Microsoft.KeyVault(SecretUri="
                                    "https://app-vault.vault.azure.net/secrets/service-token)"
                                )
                            },
                        },
                    )
                )

                reference = azure_facts(normalized).app_service_secret_references[0]
                self.assertEqual(reference["source"], resource_type)
                self.assertEqual(reference["key_vault_secret_name"], "service-token")
                self.assertIsNone(reference["key_vault_secret_version"])
                self.assertEqual(reference["secret_version_state"], "not_configured")

    def test_sensitive_literal_is_recorded_without_retaining_its_value(self) -> None:
        literal = "never-store-this-password"
        normalized = normalize_windows_web_app(
            _resource(
                AzureResourceType.WINDOWS_WEB_APP,
                {
                    "name": "admin",
                    "app_settings": {
                        "DB_PASSWORD": literal,
                        "LOG_LEVEL": "info",
                    },
                },
            )
        )

        references = azure_facts(normalized).app_service_secret_references
        self.assertEqual(len(references), 1)
        self.assertEqual(references[0]["setting_name"], "DB_PASSWORD")
        self.assertEqual(references[0]["state"], "literal")
        self.assertTrue(references[0]["is_resolved"])
        self.assertNotIn("value", references[0])
        self.assertNotIn(literal, repr(references))
        self.assertNotIn("LOG_LEVEL", repr(references))

    def test_unknown_settings_are_explicit_without_becoming_literal_claims(self) -> None:
        normalized = normalize_linux_function_app(
            _resource(
                AzureResourceType.LINUX_FUNCTION_APP,
                {
                    "name": "worker",
                    "app_settings": {
                        "API_KEY": None,
                        "DB_PASSWORD": "${azurerm_key_vault_secret.database.value}",
                        "LOG_LEVEL": None,
                    },
                    "key_vault_reference_identity_id": None,
                },
                unknown_values={
                    "app_settings": {"API_KEY": True},
                    "key_vault_reference_identity_id": True,
                },
            )
        )

        facts = azure_facts(normalized)
        records = facts.app_service_secret_references
        self.assertEqual([record["setting_name"] for record in records], ["API_KEY", "DB_PASSWORD"])
        self.assertTrue(all(record["state"] == "unknown" for record in records))
        self.assertTrue(all(record["is_resolved"] is False for record in records))
        self.assertIsNone(facts.app_service_key_vault_reference_identity_id)
        self.assertEqual(
            facts.app_service_secret_posture_uncertainties,
            [
                "app_settings['API_KEY'] is unknown after planning",
                "app_settings['DB_PASSWORD'] is unknown after planning",
                "key_vault_reference_identity_id is unknown after planning",
            ],
        )

    def test_entire_unknown_app_settings_map_is_preserved_as_uncertainty(self) -> None:
        normalized = normalize_function_app(
            _resource(
                AzureResourceType.FUNCTION_APP,
                {"name": "jobs", "app_settings": None},
                unknown_values={"app_settings": True},
            )
        )

        facts = azure_facts(normalized)
        self.assertEqual(
            facts.app_service_secret_references,
            [
                {
                    "source": AzureResourceType.FUNCTION_APP,
                    "path": "app_settings",
                    "setting_name": None,
                    "state": "unknown",
                    "is_resolved": False,
                    "unresolved_reason": "app_settings is unknown after planning",
                }
            ],
        )
        self.assertEqual(
            facts.app_service_secret_posture_uncertainties,
            ["app_settings is unknown after planning"],
        )

    def test_malformed_or_non_exact_key_vault_references_do_not_resolve(self) -> None:
        normalized = normalize_linux_web_app(
            _resource(
                AzureResourceType.LINUX_WEB_APP,
                {
                    "name": "api",
                    "app_settings": {
                        "BAD_HOST": (
                            "@Microsoft.KeyVault(SecretUri=https://app-vault.vault.azure.net.example/secrets/api-key)"
                        ),
                        "NAME_ONLY": ("@Microsoft.KeyVault(VaultName=app-vault;SecretName=api-key)"),
                        "MALFORMED_SECRET": "@Microsoft.KeyVault(SecretUri=never-store-this-secret)",
                    },
                },
            )
        )

        records = azure_facts(normalized).app_service_secret_references
        self.assertEqual(
            [record["setting_name"] for record in records],
            ["BAD_HOST", "MALFORMED_SECRET", "NAME_ONLY"],
        )
        self.assertTrue(all(record["state"] == "reference" for record in records))
        self.assertTrue(all(record["target_resolution"] == "unresolved" for record in records))
        self.assertTrue(all(record["is_resolved"] is False for record in records))
        self.assertTrue(all("key_vault_uri" not in record for record in records))
        self.assertNotIn("never-store-this-secret", repr(records))
        self.assertEqual(
            azure_facts(normalized).app_service_secret_posture_uncertainties,
            [
                "app_settings['BAD_HOST'] contains an unsupported Key Vault reference",
                "app_settings['MALFORMED_SECRET'] contains an unsupported Key Vault reference",
                "app_settings['NAME_ONLY'] contains an unsupported Key Vault reference",
            ],
        )


if __name__ == "__main__":
    unittest.main()
