from __future__ import annotations

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.coercion import as_list, compact
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import (
    has_external_access_config,
    network_interface_subnetworks,
    resource_identifier,
    resource_name,
)


def normalize_compute_instance(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    public_access_configured = has_external_access_config(values)
    public_access_reasons = (
        ["compute instance has an external access config"]
        if public_access_configured
        else []
    )
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=resource_identifier(resource),
        subnet_ids=tuple(network_interface_subnetworks(values)),
        public_access_configured=public_access_configured,
        metadata={
            GcpResourceMetadata.NAME.key: resource_name(resource),
            GcpResourceMetadata.SELF_LINK.key: values.get("self_link"),
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.ZONE.key: values.get("zone"),
            GcpResourceMetadata.MACHINE_TYPE.key: values.get("machine_type"),
            GcpResourceMetadata.NETWORK_TAGS.key: compact(as_list(values.get("tags"))),
            GcpResourceMetadata.NETWORK_INTERFACES.key: as_list(values.get("network_interface")),
            GcpResourceMetadata.SERVICE_ACCOUNTS.key: as_list(values.get("service_account")),
            GcpResourceMetadata.LABELS.key: values.get("labels") or {},
            "can_ip_forward": bool(values.get("can_ip_forward", False)),
            "public_access_reasons": public_access_reasons,
            "public_exposure_reasons": [],
        },
    )