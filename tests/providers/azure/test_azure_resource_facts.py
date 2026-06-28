from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_facts import AzureResourceFacts, azure_fact_domains, azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.metadata_ownership import ProviderMetadataOwnershipError


def _resource(metadata: dict[object, object] | None = None) -> NormalizedResource:
    return NormalizedResource(
        address="azurerm_storage_account.logs",
        provider="azure",
        resource_type=AzureResourceType.STORAGE_ACCOUNT,
        name="logs",
        category=ResourceCategory.DATA,
        metadata=metadata,
    )


class AzureResourceFactsTests(unittest.TestCase):
    def test_reads_storage_posture_from_provider_metadata(self) -> None:
        resource = _resource(
            {
                AzureResourceMetadata.NAME: "tfstridelogs",
                AzureResourceMetadata.STORAGE_ACCOUNT_ID: "/subscriptions/example/storageAccounts/tfstridelogs",
                AzureResourceMetadata.ALLOW_NESTED_ITEMS_TO_BE_PUBLIC: False,
                AzureResourceMetadata.SHARED_ACCESS_KEY_ENABLED: False,
                AzureResourceMetadata.STORAGE_INFRASTRUCTURE_ENCRYPTION_ENABLED: True,
                AzureResourceMetadata.STORAGE_CUSTOMER_MANAGED_KEY_ID: "azurerm_key_vault_key.storage.id",
                AzureResourceMetadata.STORAGE_CUSTOMER_MANAGED_KEY_IDENTITY_ID: (
                    "azurerm_user_assigned_identity.storage.id"
                ),
                AzureResourceMetadata.STORAGE_BLOB_VERSIONING_ENABLED: True,
                AzureResourceMetadata.STORAGE_BLOB_DELETE_RETENTION_DAYS: 30,
                AzureResourceMetadata.STORAGE_CONTAINER_DELETE_RETENTION_DAYS: 14,
                AzureResourceMetadata.STORAGE_BLOB_RESTORE_POLICY_DAYS: 7,
                AzureResourceMetadata.MIN_TLS_VERSION: "TLS1_2",
                AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED: True,
                AzureResourceMetadata.PUBLIC_NETWORK_FALLBACK_STATE: "enabled",
                AzureResourceMetadata.NETWORK_DEFAULT_ACTION: "Deny",
            }
        )

        facts = azure_facts(resource)

        self.assertEqual(facts.bucket_name, "tfstridelogs")
        self.assertEqual(facts.storage_account_id, "/subscriptions/example/storageAccounts/tfstridelogs")
        self.assertFalse(facts.allow_nested_items_to_be_public)
        self.assertFalse(facts.shared_access_key_enabled)
        self.assertTrue(facts.storage_infrastructure_encryption_enabled)
        self.assertEqual(facts.storage_customer_managed_key_id, "azurerm_key_vault_key.storage.id")
        self.assertEqual(
            facts.storage_customer_managed_key_identity_id,
            "azurerm_user_assigned_identity.storage.id",
        )
        self.assertTrue(facts.storage_blob_versioning_enabled)
        self.assertEqual(facts.storage_blob_delete_retention_days, 30)
        self.assertEqual(facts.storage_container_delete_retention_days, 14)
        self.assertEqual(facts.storage_blob_restore_policy_days, 7)
        self.assertEqual(facts.min_tls_version, "TLS1_2")
        self.assertTrue(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "enabled")
        self.assertEqual(facts.network_default_action, "Deny")

    def test_fact_domains_share_provider_owned_facade(self) -> None:
        domains = azure_fact_domains(_resource())

        self.assertIsInstance(domains.storage, AzureResourceFacts)
        self.assertIs(domains.iam, domains.storage)
        self.assertIs(domains.sql, domains.storage)
        self.assertIs(domains.compute, domains.storage)
        self.assertIs(domains.workload, domains.storage)

    def test_mutations_update_metadata_and_public_posture(self) -> None:
        resource = _resource()
        facts = azure_facts(resource)

        facts.set_effective_network_rule("Allow", "azurerm_storage_account_network_rules.logs")
        facts.add_public_container_address("azurerm_storage_container.public")
        facts.add_storage_posture_uncertainty("default_action is unknown after planning")
        facts.extend_storage_posture_uncertainties(
            [
                "public_network_access_enabled is unknown after planning",
                "default_action is unknown after planning",
            ]
        )
        facts.set_public_endpoint_posture(reachable=True, reasons=["public network"])

        self.assertEqual(facts.network_default_action, "Allow")
        self.assertEqual(
            facts.network_rule_source_address,
            "azurerm_storage_account_network_rules.logs",
        )
        self.assertEqual(facts.public_container_addresses, ["azurerm_storage_container.public"])
        self.assertEqual(
            facts.storage_posture_uncertainties,
            [
                "default_action is unknown after planning",
                "public_network_access_enabled is unknown after planning",
            ],
        )
        self.assertTrue(resource.direct_internet_reachable)
        self.assertEqual(resource.public_access_reasons, ["public network"])

    def test_network_relationship_mutations_use_provider_facade(self) -> None:
        resource = _resource()
        related = NormalizedResource(
            address="azurerm_network_interface.web",
            provider="azure",
            resource_type=AzureResourceType.NETWORK_INTERFACE,
            name="web",
            category=ResourceCategory.NETWORK,
            vpc_id="azurerm_virtual_network.main",
            subnet_ids=("azurerm_subnet.app",),
            security_group_ids=("azurerm_network_security_group.web",),
        )
        facts = azure_facts(resource)

        facts.inherit_network_relationships(related)
        facts.add_resolved_network_interface_address(related.address)
        facts.set_public_ip_attachment(configured=True, reasons=["attached public IP"])

        self.assertEqual(resource.vpc_id, "azurerm_virtual_network.main")
        self.assertEqual(resource.subnet_ids, ("azurerm_subnet.app",))
        self.assertEqual(resource.security_group_ids, ("azurerm_network_security_group.web",))
        self.assertEqual(facts.resolved_network_interface_addresses, [related.address])
        self.assertTrue(resource.public_access_configured)
        self.assertFalse(resource.public_exposure)

    def test_rejects_foreign_provider_metadata_writes(self) -> None:
        facts = azure_facts(_resource())

        with self.assertRaisesRegex(
            ProviderMetadataOwnershipError,
            "use a field from AzureResourceMetadata",
        ):
            facts.set(GcpResourceMetadata.PROJECT, "foreign-project")


if __name__ == "__main__":
    unittest.main()
