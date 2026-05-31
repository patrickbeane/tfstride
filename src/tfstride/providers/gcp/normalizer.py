from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from typing import Any

from tfstride.models import NormalizedResource, ResourceInventory, TerraformResource
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.compute_normalizers import normalize_compute_instance
from tfstride.providers.gcp.data_normalizers import normalize_storage_bucket
from tfstride.providers.gcp.iam_normalizers import normalize_project_iam_member
from tfstride.providers.gcp.network_normalizers import (
    GCP_PROVIDER,
    normalize_compute_firewall,
    normalize_compute_network,
    normalize_compute_subnetwork,
)
from tfstride.resource_metadata import InventoryMetadata


ResourceNormalizer = Callable[[TerraformResource], NormalizedResource]

_GCP_RESOURCE_NORMALIZERS: dict[str, ResourceNormalizer] = {
    "google_compute_firewall": normalize_compute_firewall,
    "google_compute_instance": normalize_compute_instance,
    "google_compute_network": normalize_compute_network,
    "google_compute_subnetwork": normalize_compute_subnetwork,
    "google_project_iam_member": normalize_project_iam_member,
    "google_storage_bucket": normalize_storage_bucket,
}
SUPPORTED_GCP_TYPES = frozenset(_GCP_RESOURCE_NORMALIZERS)


class GcpNormalizer(ProviderNormalizer):
    """Normalize the initial supported Terraform Google provider resource set."""

    provider = GCP_PROVIDER

    def __init__(self) -> None:
        self._resource_normalizers = dict(_GCP_RESOURCE_NORMALIZERS)

    def owns_resource(self, resource: TerraformResource) -> bool:
        return _is_gcp_resource(resource)

    def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
        gcp_resources = [resource for resource in resources if self.owns_resource(resource)]
        unsupported_resource_types = Counter(
            resource.resource_type
            for resource in gcp_resources
            if resource.resource_type not in SUPPORTED_GCP_TYPES
        )
        unsupported = sorted(
            resource.address for resource in gcp_resources if resource.resource_type not in SUPPORTED_GCP_TYPES
        )
        normalized = [
            self._normalize_resource(resource)
            for resource in gcp_resources
            if resource.resource_type in SUPPORTED_GCP_TYPES
        ]

        metadata: dict[str, Any] = {}
        InventoryMetadata.SUPPORTED_RESOURCE_TYPES.set(metadata, sorted(SUPPORTED_GCP_TYPES))
        InventoryMetadata.TOTAL_INPUT_RESOURCES.set(metadata, len(resources))
        InventoryMetadata.PROVIDER_RESOURCE_COUNT.set(metadata, len(gcp_resources))
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

    def _normalize_resource(self, resource: TerraformResource) -> NormalizedResource:
        try:
            normalizer = self._resource_normalizers[resource.resource_type]
        except KeyError as exc:
            raise ValueError(f"Unsupported resource type reached normalizer: {resource.resource_type}") from exc
        return normalizer(resource)


def _is_gcp_resource(resource: TerraformResource) -> bool:
    provider_name = str(resource.provider_name).strip().lower()
    return (
        provider_name.endswith("/google")
        or provider_name.endswith("/google-beta")
        or resource.resource_type.startswith("google_")
    )