from __future__ import annotations

from types import MappingProxyType

from tfstride.providers.azure.resource_types import AZURE_COMPUTE_RESOURCE_TYPES, AzureResourceType
from tfstride.providers.resource_capabilities import ResourceCapability, ResourceCapabilityMap

_STORAGE_ACCOUNTS = frozenset({AzureResourceType.STORAGE_ACCOUNT})
_VIRTUAL_MACHINES = AZURE_COMPUTE_RESOURCE_TYPES

AZURE_RESOURCE_CAPABILITIES: ResourceCapabilityMap = MappingProxyType(
    {
        ResourceCapability.WORKLOAD: _VIRTUAL_MACHINES,
        ResourceCapability.SECURITY_GROUP_BACKED_WORKLOAD: _VIRTUAL_MACHINES,
        ResourceCapability.PUBLIC_COMPUTE: _VIRTUAL_MACHINES,
        ResourceCapability.DATA_STORE: _STORAGE_ACCOUNTS,
        ResourceCapability.PUBLIC_EDGE: _STORAGE_ACCOUNTS | _VIRTUAL_MACHINES,
        ResourceCapability.NETWORK_SECURITY_GROUP: frozenset({AzureResourceType.NETWORK_SECURITY_GROUP}),
        ResourceCapability.SUBNET: frozenset({AzureResourceType.SUBNET}),
        ResourceCapability.OBJECT_STORAGE: _STORAGE_ACCOUNTS,
    }
)
