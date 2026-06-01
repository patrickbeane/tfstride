from __future__ import annotations

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.coercion import as_bool
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import resource_identifier, resource_name


def normalize_storage_bucket(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=resource_identifier(resource),
        data_sensitivity="sensitive",
        metadata={
            GcpResourceMetadata.NAME.key: resource_name(resource),
            GcpResourceMetadata.BUCKET_NAME.key: resource_name(resource),
            GcpResourceMetadata.SELF_LINK.key: values.get("self_link"),
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.LABELS.key: values.get("labels") or {},
            GcpResourceMetadata.UNIFORM_BUCKET_LEVEL_ACCESS.key: as_bool(values.get("uniform_bucket_level_access")),
            GcpResourceMetadata.PUBLIC_ACCESS_PREVENTION.key: values.get("public_access_prevention"),
            "location": values.get("location"),
            "storage_class": values.get("storage_class"),
            "force_destroy": as_bool(values.get("force_destroy")),
        },
    )