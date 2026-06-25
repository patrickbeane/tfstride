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
                AzureResourceMetadata.MIN_TLS_VERSION: "TLS1_2",
                AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED: True,
                AzureResourceMetadata.NETWORK_DEFAULT_ACTION: "Deny",
            }
        )

        facts = azure_facts(resource)

        self.assertEqual(facts.bucket_name, "tfstridelogs")
        self.assertEqual(facts.storage_account_id, "/subscriptions/example/storageAccounts/tfstridelogs")
        self.assertFalse(facts.allow_nested_items_to_be_public)
        self.assertFalse(facts.shared_access_key_enabled)
        self.assertEqual(facts.min_tls_version, "TLS1_2")
        self.assertTrue(facts.public_network_access_enabled)
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
        facts.set_public_endpoint_posture(reachable=True, reasons=["public network"])

        self.assertEqual(facts.network_default_action, "Allow")
        self.assertEqual(
            facts.network_rule_source_address,
            "azurerm_storage_account_network_rules.logs",
        )
        self.assertEqual(facts.public_container_addresses, ["azurerm_storage_container.public"])
        self.assertTrue(resource.direct_internet_reachable)
        self.assertEqual(resource.public_access_reasons, ["public network"])

    def test_rejects_foreign_provider_metadata_writes(self) -> None:
        facts = azure_facts(_resource())

        with self.assertRaisesRegex(
            ProviderMetadataOwnershipError,
            "use a field from AzureResourceMetadata",
        ):
            facts.set(GcpResourceMetadata.PROJECT, "foreign-project")


if __name__ == "__main__":
    unittest.main()
