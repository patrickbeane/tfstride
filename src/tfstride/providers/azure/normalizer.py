from __future__ import annotations

from collections import Counter
from typing import Any

from tfstride.models import ResourceInventory, TerraformResource
from tfstride.providers.azure.data_normalizers import (
    normalize_storage_account,
    normalize_storage_account_network_rules,
    normalize_storage_container,
)
from tfstride.providers.azure.resource_decorator import AzureResourceDecorator
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.base import ProviderNormalizer
from tfstride.resource_metadata import InventoryMetadata

_AZURE_RESOURCE_NORMALIZERS = {
    AzureResourceType.STORAGE_ACCOUNT: normalize_storage_account,
    AzureResourceType.STORAGE_ACCOUNT_NETWORK_RULES: normalize_storage_account_network_rules,
    AzureResourceType.STORAGE_CONTAINER: normalize_storage_container,
}
SUPPORTED_AZURE_TYPES = frozenset(_AZURE_RESOURCE_NORMALIZERS)


class AzureNormalizer(ProviderNormalizer):
    """Normalize the initial AzureRM storage resource set."""

    provider = "azure"

    def __init__(self, resource_decorator: AzureResourceDecorator | None = None) -> None:
        self._resource_decorator = resource_decorator or AzureResourceDecorator()
        self._resource_normalizers = dict(_AZURE_RESOURCE_NORMALIZERS)

    def owns_resource(self, resource: TerraformResource) -> bool:
        return _is_azure_resource(resource)

    def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
        azure_resources = [resource for resource in resources if self.owns_resource(resource)]
        unsupported_resource_types = Counter(
            resource.resource_type
            for resource in azure_resources
            if resource.resource_type not in SUPPORTED_AZURE_TYPES
        )
        unsupported = sorted(
            resource.address for resource in azure_resources if resource.resource_type not in SUPPORTED_AZURE_TYPES
        )
        normalized = [
            self._resource_normalizers[resource.resource_type](resource)
            for resource in azure_resources
            if resource.resource_type in SUPPORTED_AZURE_TYPES
        ]
        self._resource_decorator.decorate(normalized)

        metadata: dict[str, Any] = {}
        InventoryMetadata.SUPPORTED_RESOURCE_TYPES.set(metadata, sorted(SUPPORTED_AZURE_TYPES))
        InventoryMetadata.TOTAL_INPUT_RESOURCES.set(metadata, len(resources))
        InventoryMetadata.PROVIDER_RESOURCE_COUNT.set(metadata, len(azure_resources))
        InventoryMetadata.NORMALIZED_RESOURCE_COUNT.set(metadata, len(normalized))
        InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.set(
            metadata,
            dict(sorted(unsupported_resource_types.items())),
        )

        return ResourceInventory(
            provider=self.provider,
            resources=normalized,
            unsupported_resources=unsupported,
            metadata=metadata,
        )


def _is_azure_resource(resource: TerraformResource) -> bool:
    provider_name = str(resource.provider_name).strip().lower()
    return provider_name.endswith("/azurerm") or resource.resource_type.startswith(AzureResourceType.PREFIX)
