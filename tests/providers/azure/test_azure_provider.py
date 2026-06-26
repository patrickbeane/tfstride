from __future__ import annotations

import unittest

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.rule_registry import default_rule_registry
from tfstride.models import NormalizedResource, ResourceCategory, ResourceInventory, TerraformResource
from tfstride.providers.azure.boundaries import AzureBoundaryContributor
from tfstride.providers.azure.limitations import AZURE_LIMITATIONS
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import SUPPORTED_AZURE_TYPES, AzureNormalizer
from tfstride.providers.azure.plugin import azure_provider_plugin
from tfstride.providers.azure.resource_capabilities import AZURE_RESOURCE_CAPABILITIES
from tfstride.providers.azure.resource_decorator import AzureResourceDecorator
from tfstride.providers.azure.resource_facts import AzureResourceFacts
from tfstride.providers.azure.resource_types import AZURE_SUPPORTED_RESOURCE_TYPES, AzureResourceType
from tfstride.providers.resource_capabilities import ResourceCapability
from tfstride.resource_metadata import InventoryMetadata


def _terraform_resource(
    resource_type: str,
    *,
    name: str = "example",
    provider_name: str = "registry.terraform.io/hashicorp/azurerm",
    values: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name=provider_name,
        values=values or {},
    )


class AzureProviderTests(unittest.TestCase):
    def test_plugin_describes_azure_storage_network_and_compute_contract(self) -> None:
        plugin = azure_provider_plugin()
        registry = default_rule_registry()
        contribution = plugin.create_rule_contribution(FindingFactory(registry))

        self.assertEqual(plugin.provider, "azure")
        self.assertIs(plugin.metadata_namespace, AzureResourceMetadata)
        self.assertEqual(plugin.supported_resource_types, AZURE_SUPPORTED_RESOURCE_TYPES)
        self.assertEqual(plugin.supported_resource_types, SUPPORTED_AZURE_TYPES)
        self.assertEqual(dict(plugin.resource_capabilities), dict(AZURE_RESOURCE_CAPABILITIES))
        self.assertEqual(plugin.limitations, AZURE_LIMITATIONS)
        self.assertIsInstance(plugin.create_normalizer(), AzureNormalizer)
        self.assertIsInstance(plugin.create_resource_decorator(), AzureResourceDecorator)
        self.assertEqual(len(plugin.create_rule_metadata()), 6)
        self.assertIsNotNone(contribution)
        assert contribution is not None
        self.assertEqual(tuple(len(group) for group in contribution.rule_groups), (6, 0, 0, 0, 0, 0))
        self.assertIsInstance(plugin.create_boundary_contributor(), AzureBoundaryContributor)
        self.assertEqual(
            plugin.create_observations(ResourceInventory(provider="azure", resources=[])),
            [],
        )
        self.assertIsNone(plugin.create_analysis_index_extension(ResourceInventory(provider="azure", resources=[])))
        self.assertTrue(plugin.supports_resource_type(AzureResourceType.STORAGE_ACCOUNT))
        self.assertEqual(
            plugin.resource_types_for_capability(ResourceCapability.OBJECT_STORAGE),
            frozenset({AzureResourceType.STORAGE_ACCOUNT}),
        )
        self.assertEqual(
            plugin.resource_types_for_capability(ResourceCapability.WORKLOAD),
            frozenset(
                {
                    AzureResourceType.LINUX_VIRTUAL_MACHINE,
                    AzureResourceType.WINDOWS_VIRTUAL_MACHINE,
                }
            ),
        )
        self.assertEqual(
            plugin.resource_types_for_capability(ResourceCapability.NETWORK_SECURITY_GROUP),
            frozenset({AzureResourceType.NETWORK_SECURITY_GROUP}),
        )

    def test_plugin_uses_azure_resource_facts(self) -> None:
        resource = NormalizedResource(
            address="azurerm_storage_account.logs",
            provider="azure",
            resource_type=AzureResourceType.STORAGE_ACCOUNT,
            name="logs",
            category=ResourceCategory.DATA,
        )

        facts = azure_provider_plugin().resource_facts_factory(resource)

        self.assertIsInstance(facts.storage, AzureResourceFacts)
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
                    AzureResourceType.STORAGE_ACCOUNT,
                    provider_name="registry.example.com/custom/provider",
                )
            )
        )

    def test_normalizer_does_not_claim_adjacent_azure_providers(self) -> None:
        normalizer = AzureNormalizer()
        resources = (
            _terraform_resource("azapi_resource", provider_name="registry.terraform.io/azure/azapi"),
            _terraform_resource("azuread_user", provider_name="registry.terraform.io/hashicorp/azuread"),
            _terraform_resource(
                "azuredevops_project",
                provider_name="registry.terraform.io/microsoft/azuredevops",
            ),
        )

        self.assertTrue(all(not normalizer.owns_resource(resource) for resource in resources))

    def test_normalizer_tracks_supported_and_unsupported_azure_resources(self) -> None:
        resources = [
            _terraform_resource(
                AzureResourceType.STORAGE_ACCOUNT,
                values={"name": "tfstridelogs"},
            ),
            _terraform_resource("azurerm_key_vault"),
            _terraform_resource("azapi_resource", provider_name="registry.terraform.io/azure/azapi"),
        ]

        inventory = AzureNormalizer().normalize(resources)

        self.assertEqual(inventory.provider, "azure")
        self.assertEqual([resource.address for resource in inventory.resources], ["azurerm_storage_account.example"])
        self.assertEqual(inventory.unsupported_resources, ["azurerm_key_vault.example"])
        self.assertEqual(
            InventoryMetadata.SUPPORTED_RESOURCE_TYPES.get(inventory.metadata),
            sorted(AZURE_SUPPORTED_RESOURCE_TYPES),
        )
        self.assertEqual(InventoryMetadata.TOTAL_INPUT_RESOURCES.get(inventory.metadata), 3)
        self.assertEqual(InventoryMetadata.PROVIDER_RESOURCE_COUNT.get(inventory.metadata), 2)
        self.assertEqual(InventoryMetadata.NORMALIZED_RESOURCE_COUNT.get(inventory.metadata), 1)
        self.assertEqual(
            InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.get(inventory.metadata),
            {"azurerm_key_vault": 1},
        )


if __name__ == "__main__":
    unittest.main()
