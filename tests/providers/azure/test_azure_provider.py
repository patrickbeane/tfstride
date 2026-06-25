from __future__ import annotations

import unittest

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.rule_registry import RuleRegistry
from tfstride.models import NormalizedResource, ResourceCategory, ResourceInventory, TerraformResource
from tfstride.providers.azure.limitations import AZURE_LIMITATIONS
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import SUPPORTED_AZURE_TYPES, AzureNormalizer
from tfstride.providers.azure.plugin import azure_provider_plugin
from tfstride.providers.azure.resource_capabilities import AZURE_RESOURCE_CAPABILITIES
from tfstride.providers.resource_capabilities import ResourceCapability
from tfstride.providers.resource_facts import NeutralProviderResourceFacts
from tfstride.resource_metadata import InventoryMetadata


def _terraform_resource(
    resource_type: str,
    *,
    name: str = "example",
    provider_name: str = "registry.terraform.io/hashicorp/azurerm",
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name=provider_name,
        values={},
    )


class AzureProviderTests(unittest.TestCase):
    def test_plugin_describes_empty_azure_provider_contract(self) -> None:
        plugin = azure_provider_plugin()

        self.assertEqual(plugin.provider, "azure")
        self.assertIs(plugin.metadata_namespace, AzureResourceMetadata)
        self.assertEqual(plugin.supported_resource_types, SUPPORTED_AZURE_TYPES)
        self.assertEqual(dict(plugin.resource_capabilities), dict(AZURE_RESOURCE_CAPABILITIES))
        self.assertEqual(plugin.limitations, AZURE_LIMITATIONS)
        self.assertIsInstance(plugin.create_normalizer(), AzureNormalizer)
        self.assertIsNone(plugin.create_resource_decorator())
        self.assertEqual(plugin.create_rule_metadata(), ())
        self.assertIsNone(plugin.create_rule_contribution(FindingFactory(RuleRegistry([]))))
        self.assertIsNone(plugin.create_boundary_contributor())
        self.assertIsNone(plugin.create_analysis_index_extension(ResourceInventory(provider="azure", resources=[])))
        self.assertFalse(plugin.supports_resource_type("azurerm_storage_account"))
        self.assertEqual(
            plugin.resource_types_for_capability(ResourceCapability.OBJECT_STORAGE),
            frozenset(),
        )

    def test_plugin_uses_shared_neutral_resource_facts(self) -> None:
        resource = NormalizedResource(
            address="azurerm_storage_account.logs",
            provider="azure",
            resource_type="azurerm_storage_account",
            name="logs",
            category=ResourceCategory.DATA,
        )

        facts = azure_provider_plugin().resource_facts_factory(resource)

        self.assertIsInstance(facts.storage, NeutralProviderResourceFacts)
        self.assertIs(facts.iam, facts.storage)
        self.assertIs(facts.sql, facts.storage)
        self.assertIs(facts.compute, facts.storage)
        self.assertIs(facts.workload, facts.storage)

    def test_normalizer_detects_azurerm_source_and_resource_prefix(self) -> None:
        normalizer = AzureNormalizer()

        self.assertTrue(
            normalizer.owns_resource(
                _terraform_resource(
                    "custom_resource",
                    provider_name="registry.terraform.io/hashicorp/azurerm",
                )
            )
        )
        self.assertTrue(
            normalizer.owns_resource(
                _terraform_resource(
                    "azurerm_storage_account",
                    provider_name="registry.example.com/custom/provider",
                )
            )
        )

    def test_normalizer_does_not_claim_adjacent_azure_providers(self) -> None:
        normalizer = AzureNormalizer()
        resources = (
            _terraform_resource(
                "azapi_resource",
                provider_name="registry.terraform.io/azure/azapi",
            ),
            _terraform_resource(
                "azuread_user",
                provider_name="registry.terraform.io/hashicorp/azuread",
            ),
            _terraform_resource(
                "azuredevops_project",
                provider_name="registry.terraform.io/microsoft/azuredevops",
            ),
        )

        self.assertTrue(all(not normalizer.owns_resource(resource) for resource in resources))

    def test_normalizer_reports_owned_resources_as_unsupported(self) -> None:
        resources = [
            _terraform_resource("azurerm_storage_account"),
            _terraform_resource("azurerm_resource_group"),
            _terraform_resource(
                "azurerm_storage_account",
                name="secondary",
                provider_name="registry.example.com/custom/provider",
            ),
            _terraform_resource(
                "azapi_resource",
                provider_name="registry.terraform.io/azure/azapi",
            ),
            _terraform_resource(
                "azuread_user",
                provider_name="registry.terraform.io/hashicorp/azuread",
            ),
            _terraform_resource(
                "aws_instance",
                provider_name="registry.terraform.io/hashicorp/aws",
            ),
        ]

        inventory = AzureNormalizer().normalize(resources)

        self.assertEqual(inventory.provider, "azure")
        self.assertEqual(inventory.resources, ())
        self.assertEqual(
            inventory.unsupported_resources,
            [
                "azurerm_resource_group.example",
                "azurerm_storage_account.example",
                "azurerm_storage_account.secondary",
            ],
        )
        self.assertEqual(InventoryMetadata.SUPPORTED_RESOURCE_TYPES.get(inventory.metadata), [])
        self.assertEqual(InventoryMetadata.TOTAL_INPUT_RESOURCES.get(inventory.metadata), 6)
        self.assertEqual(InventoryMetadata.PROVIDER_RESOURCE_COUNT.get(inventory.metadata), 3)
        self.assertEqual(InventoryMetadata.NORMALIZED_RESOURCE_COUNT.get(inventory.metadata), 0)
        self.assertEqual(
            InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.get(inventory.metadata),
            {
                "azurerm_resource_group": 1,
                "azurerm_storage_account": 2,
            },
        )


if __name__ == "__main__":
    unittest.main()
