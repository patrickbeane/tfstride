from __future__ import annotations

from collections import Counter
from typing import Any

from tfstride.models import ResourceInventory, TerraformResource
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.base import ProviderNormalizer
from tfstride.resource_metadata import InventoryMetadata

SUPPORTED_AZURE_TYPES: frozenset[str] = frozenset()


class AzureNormalizer(ProviderNormalizer):
    """Recognize AzureRM resources until concrete normalization support lands."""

    provider = "azure"

    def owns_resource(self, resource: TerraformResource) -> bool:
        return _is_azure_resource(resource)

    def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
        azure_resources = [resource for resource in resources if self.owns_resource(resource)]
        unsupported_resource_types = Counter(resource.resource_type for resource in azure_resources)
        unsupported = sorted(resource.address for resource in azure_resources)

        metadata: dict[str, Any] = {}
        InventoryMetadata.SUPPORTED_RESOURCE_TYPES.set(metadata, sorted(SUPPORTED_AZURE_TYPES))
        InventoryMetadata.TOTAL_INPUT_RESOURCES.set(metadata, len(resources))
        InventoryMetadata.PROVIDER_RESOURCE_COUNT.set(metadata, len(azure_resources))
        InventoryMetadata.NORMALIZED_RESOURCE_COUNT.set(metadata, 0)
        InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.set(
            metadata,
            dict(sorted(unsupported_resource_types.items())),
        )

        return ResourceInventory(
            provider=self.provider,
            resources=[],
            unsupported_resources=unsupported,
            metadata=metadata,
        )


def _is_azure_resource(resource: TerraformResource) -> bool:
    provider_name = str(resource.provider_name).strip().lower()
    return provider_name.endswith("/azurerm") or resource.resource_type.startswith(AzureResourceType.PREFIX)
