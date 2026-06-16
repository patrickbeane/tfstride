from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.attributes import GcpAttr, GcpValues
from tfstride.providers.gcp.coercion import as_bool
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_utils import (
    has_external_access_config,
    network_interface_subnetworks,
    resource_identifier,
    resource_name,
)


def normalize_compute_instance(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    instance_metadata = values.get(GcpAttr.METADATA)
    os_login_enabled = _os_login_enabled(instance_metadata)
    public_access_configured = has_external_access_config(resource.values)
    public_access_reasons = (
        ["compute instance has an external access config"]
        if public_access_configured
        else []
    )
    metadata = {
        GcpResourceMetadata.NAME: resource_name(resource),
        GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
        GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
        GcpResourceMetadata.ZONE: values.get(GcpAttr.ZONE),
        GcpResourceMetadata.MACHINE_TYPE: values.get(GcpAttr.MACHINE_TYPE),
        GcpResourceMetadata.NETWORK_TAGS: values.get(GcpAttr.TAGS),
        GcpResourceMetadata.NETWORK_INTERFACES: values.get(GcpAttr.NETWORK_INTERFACE),
        GcpResourceMetadata.SERVICE_ACCOUNTS: values.get(GcpAttr.SERVICE_ACCOUNT_BLOCKS),
        GcpResourceMetadata.LABELS: values.get(GcpAttr.LABELS),
        "metadata": instance_metadata,
        "can_ip_forward": bool(values.raw(GcpAttr.CAN_IP_FORWARD)),
    }
    if os_login_enabled is not None:
        metadata[GcpResourceMetadata.OS_LOGIN_ENABLED] = os_login_enabled
    normalized = NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=resource_identifier(resource),
        subnet_ids=tuple(network_interface_subnetworks(resource.values)),
        public_access_configured=public_access_configured,
        metadata=metadata,
    )
    gcp_mutations(normalized).set_public_access(
        configured=public_access_configured,
        reasons=public_access_reasons,
    )
    return normalized


def _os_login_enabled(metadata: dict[str, Any]) -> bool | None:
    values = GcpValues(metadata)
    if not values.has(GcpAttr.ENABLE_OSLOGIN):
        return None
    return as_bool(values.raw(GcpAttr.ENABLE_OSLOGIN))