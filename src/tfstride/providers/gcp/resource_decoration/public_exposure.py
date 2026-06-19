from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.resource_decoration.bucket_exposure import (
    derive_public_bucket_exposure,
)
from tfstride.providers.gcp.resource_decoration.compute_firewall_exposure import (
    derive_public_compute_exposure,
)
from tfstride.providers.gcp.resource_decoration.serverless_exposure import (
    derive_public_serverless_exposure,
)
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import (
    GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES,
    GcpResourceType,
)


class DerivePublicExposureStage:
    name = "derive_public_exposure"

    def apply(self, resources: list[NormalizedResource], context: GcpDecorationContext) -> None:
        index = context.index
        for resource in resources:
            if resource.resource_type == GcpResourceType.COMPUTE_INSTANCE:
                derive_public_compute_exposure(resource, index)
            elif resource.resource_type in GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES:
                derive_public_serverless_exposure(resource, index)
            elif resource.resource_type == GcpResourceType.STORAGE_BUCKET:
                derive_public_bucket_exposure(resource, index)
