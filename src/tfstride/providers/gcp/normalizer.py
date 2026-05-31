from __future__ import annotations

from collections import Counter
from typing import Any

from tfstride.models import ResourceInventory, TerraformResource
from tfstride.providers.base import ProviderNormalizer
from tfstride.resource_metadata import InventoryMetadata


GCP_PROVIDER = "gcp"
SUPPORTED_GCP_TYPES: frozenset[str] = frozenset()


class GcpNormalizer(ProviderNormalizer):
    """GCP normalizer scaffold that records recognized but unsupported GCP resources."""

    provider = GCP_PROVIDER

    def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
        gcp_resources = [resource for resource in resources if _is_gcp_resource(resource)]
        unsupported_resource_types = Counter(resource.resource_type for resource in gcp_resources)
        unsupported = sorted(resource.address for resource in gcp_resources)

        metadata: dict[str, Any] = {}
        InventoryMetadata.SUPPORTED_RESOURCE_TYPES.set(metadata, sorted(SUPPORTED_GCP_TYPES))
        InventoryMetadata.TOTAL_INPUT_RESOURCES.set(metadata, len(resources))
        InventoryMetadata.PROVIDER_RESOURCE_COUNT.set(metadata, len(gcp_resources))
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


def _is_gcp_resource(resource: TerraformResource) -> bool:
    provider_name = str(resource.provider_name).strip().lower()
    return (
        provider_name.endswith("/google")
        or provider_name.endswith("/google-beta")
        or resource.resource_type.startswith("google_")
    )