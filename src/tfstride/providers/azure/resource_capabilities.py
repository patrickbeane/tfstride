from __future__ import annotations

from types import MappingProxyType

from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.resource_capabilities import ResourceCapability, ResourceCapabilityMap

_STORAGE_ACCOUNTS = frozenset({AzureResourceType.STORAGE_ACCOUNT})

AZURE_RESOURCE_CAPABILITIES: ResourceCapabilityMap = MappingProxyType(
    {
        ResourceCapability.DATA_STORE: _STORAGE_ACCOUNTS,
        ResourceCapability.PUBLIC_EDGE: _STORAGE_ACCOUNTS,
        ResourceCapability.OBJECT_STORAGE: _STORAGE_ACCOUNTS,
    }
)
