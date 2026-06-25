from __future__ import annotations

import unittest

from tests.integration.analysis_support import AZURE_FIXTURE_PATH
from tfstride.app import TfStride
from tfstride.providers.azure.resource_types import AzureResourceType


class AzureCoverageExpansionIntegrationTests(unittest.TestCase):
    def test_mixed_fixture_reports_supported_and_unsupported_resources_honestly(self) -> None:
        result = TfStride().analyze_plan(AZURE_FIXTURE_PATH)
        coverage = result.analysis_coverage.resources

        self.assertEqual(result.inventory.provider, "azure")
        self.assertEqual(coverage.total_resources, 15)
        self.assertEqual(coverage.provider_resources, 15)
        self.assertEqual(coverage.normalized_resources, 13)
        self.assertEqual(coverage.unsupported_resources, 2)
        self.assertEqual(
            result.inventory.unsupported_resources,
            [
                "azurerm_key_vault.application",
                "azurerm_kubernetes_cluster.platform",
            ],
        )
        self.assertEqual(
            coverage.unsupported_resource_types,
            {
                "azurerm_key_vault": 1,
                "azurerm_kubernetes_cluster": 1,
            },
        )

    def test_mixed_fixture_normalizes_only_existing_storage_compute_and_network_domains(self) -> None:
        result = TfStride().analyze_plan(AZURE_FIXTURE_PATH)
        normalized_types = {resource.resource_type for resource in result.inventory.resources}

        self.assertEqual(
            normalized_types,
            {
                AzureResourceType.STORAGE_ACCOUNT,
                AzureResourceType.STORAGE_ACCOUNT_NETWORK_RULES,
                AzureResourceType.STORAGE_CONTAINER,
                AzureResourceType.VIRTUAL_NETWORK,
                AzureResourceType.SUBNET,
                AzureResourceType.NETWORK_SECURITY_GROUP,
                AzureResourceType.NETWORK_SECURITY_RULE,
                AzureResourceType.SUBNET_NETWORK_SECURITY_GROUP_ASSOCIATION,
                AzureResourceType.NETWORK_INTERFACE,
                AzureResourceType.NETWORK_INTERFACE_SECURITY_GROUP_ASSOCIATION,
                AzureResourceType.PUBLIC_IP,
                AzureResourceType.LINUX_VIRTUAL_MACHINE,
            },
        )
        self.assertNotIn("azurerm_key_vault", normalized_types)
        self.assertNotIn("azurerm_kubernetes_cluster", normalized_types)


if __name__ == "__main__":
    unittest.main()
