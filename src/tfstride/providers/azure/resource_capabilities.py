from __future__ import annotations

from types import MappingProxyType

from tfstride.providers.azure.resource_types import AZURE_COMPUTE_RESOURCE_TYPES, AzureResourceType
from tfstride.providers.resource_capabilities import ResourceCapability, ResourceCapabilityMap

_STORAGE_ACCOUNTS = frozenset({AzureResourceType.STORAGE_ACCOUNT})
_VIRTUAL_MACHINES = AZURE_COMPUTE_RESOURCE_TYPES
_KEY_VAULTS = frozenset({AzureResourceType.KEY_VAULT})
_KEY_VAULT_DATA = frozenset(
    {
        AzureResourceType.KEY_VAULT,
        AzureResourceType.KEY_VAULT_SECRET,
        AzureResourceType.KEY_VAULT_KEY,
        AzureResourceType.KEY_VAULT_CERTIFICATE,
    }
)
_SQL_SERVERS = frozenset({AzureResourceType.MSSQL_SERVER})
_SQL_DATA = frozenset({AzureResourceType.MSSQL_SERVER, AzureResourceType.MSSQL_DATABASE})

AZURE_RESOURCE_CAPABILITIES: ResourceCapabilityMap = MappingProxyType(
    {
        ResourceCapability.WORKLOAD: _VIRTUAL_MACHINES,
        ResourceCapability.SECURITY_GROUP_BACKED_WORKLOAD: _VIRTUAL_MACHINES,
        ResourceCapability.PUBLIC_COMPUTE: _VIRTUAL_MACHINES,
        ResourceCapability.DATA_STORE: _STORAGE_ACCOUNTS | _KEY_VAULT_DATA | _SQL_DATA,
        ResourceCapability.PUBLIC_EDGE: _STORAGE_ACCOUNTS | _KEY_VAULTS | _VIRTUAL_MACHINES | _SQL_SERVERS,
        ResourceCapability.IDENTITY_ROLE: frozenset({AzureResourceType.USER_ASSIGNED_IDENTITY}),
        ResourceCapability.IAM_POLICY: frozenset(
            {AzureResourceType.KEY_VAULT_ACCESS_POLICY, AzureResourceType.ROLE_ASSIGNMENT}
        ),
        ResourceCapability.NETWORK_SECURITY_GROUP: frozenset({AzureResourceType.NETWORK_SECURITY_GROUP}),
        ResourceCapability.SUBNET: frozenset({AzureResourceType.SUBNET}),
        ResourceCapability.OBJECT_STORAGE: _STORAGE_ACCOUNTS,
        ResourceCapability.SECRET_STORE: frozenset({AzureResourceType.KEY_VAULT, AzureResourceType.KEY_VAULT_SECRET}),
        ResourceCapability.CONTROL_PLANE_SENSITIVE_DATA_STORE: _KEY_VAULT_DATA,
        ResourceCapability.KEY_MANAGEMENT: frozenset({AzureResourceType.KEY_VAULT, AzureResourceType.KEY_VAULT_KEY}),
        ResourceCapability.SENSITIVE_RESOURCE_POLICY: _KEY_VAULTS,
    }
)
