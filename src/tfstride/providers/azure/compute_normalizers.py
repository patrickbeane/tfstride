from __future__ import annotations

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_utils import as_list, compact_strings, first_non_empty

AZURE_PROVIDER = "azure"


def normalize_linux_virtual_machine(resource: TerraformResource) -> NormalizedResource:
    return _normalize_virtual_machine(resource, os_type="linux")


def normalize_windows_virtual_machine(resource: TerraformResource) -> NormalizedResource:
    return _normalize_virtual_machine(resource, os_type="windows")


def _normalize_virtual_machine(resource: TerraformResource, *, os_type: str) -> NormalizedResource:
    values = resource.values
    network_interface_references = compact_strings(as_list(values.get("network_interface_ids")))
    public_ip_address = first_non_empty(values.get("public_ip_address"))
    public_access_configured = bool(public_ip_address)
    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=first_non_empty(values.get("id"), values.get("name"), resource.address),
        public_access_configured=public_access_configured,
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
            AzureResourceMetadata.VM_SIZE: first_non_empty(values.get("size")),
            AzureResourceMetadata.OS_TYPE: os_type,
            AzureResourceMetadata.NETWORK_INTERFACE_REFERENCES: network_interface_references,
            AzureResourceMetadata.PUBLIC_IP_ADDRESS: public_ip_address,
        },
    )
