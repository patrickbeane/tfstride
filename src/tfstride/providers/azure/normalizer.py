from __future__ import annotations

from collections import Counter
from typing import Any

from tfstride.models import ResourceInventory, TerraformResource
from tfstride.providers.azure.app_service_normalizers import (
    normalize_function_app,
    normalize_linux_function_app,
    normalize_linux_web_app,
    normalize_windows_function_app,
    normalize_windows_web_app,
)
from tfstride.providers.azure.compute_normalizers import (
    normalize_linux_virtual_machine,
    normalize_windows_virtual_machine,
)
from tfstride.providers.azure.data_normalizers import (
    normalize_storage_account,
    normalize_storage_account_network_rules,
    normalize_storage_container,
)
from tfstride.providers.azure.identity_normalizers import (
    normalize_role_assignment,
    normalize_role_definition,
    normalize_user_assigned_identity,
)
from tfstride.providers.azure.key_vault_normalizers import (
    normalize_key_vault,
    normalize_key_vault_access_policy,
    normalize_key_vault_certificate,
    normalize_key_vault_key,
    normalize_key_vault_secret,
)
from tfstride.providers.azure.mssql_normalizers import (
    normalize_mssql_database,
    normalize_mssql_firewall_rule,
    normalize_mssql_server,
    normalize_mssql_server_security_alert_policy,
    normalize_mssql_virtual_network_rule,
)
from tfstride.providers.azure.network_normalizers import (
    normalize_network_interface,
    normalize_network_interface_security_group_association,
    normalize_network_security_group,
    normalize_network_security_rule,
    normalize_private_endpoint,
    normalize_public_ip,
    normalize_subnet,
    normalize_subnet_network_security_group_association,
    normalize_virtual_network,
)
from tfstride.providers.azure.postgresql_normalizers import (
    normalize_postgresql_flexible_server,
    normalize_postgresql_flexible_server_configuration,
    normalize_postgresql_flexible_server_database,
    normalize_postgresql_flexible_server_firewall_rule,
)
from tfstride.providers.azure.resource_decorator import AzureResourceDecorator
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.base import ProviderNormalizer
from tfstride.resource_metadata import InventoryMetadata

_AZURE_RESOURCE_NORMALIZERS = {
    AzureResourceType.STORAGE_ACCOUNT: normalize_storage_account,
    AzureResourceType.STORAGE_ACCOUNT_NETWORK_RULES: normalize_storage_account_network_rules,
    AzureResourceType.STORAGE_CONTAINER: normalize_storage_container,
    AzureResourceType.KEY_VAULT: normalize_key_vault,
    AzureResourceType.KEY_VAULT_ACCESS_POLICY: normalize_key_vault_access_policy,
    AzureResourceType.KEY_VAULT_SECRET: normalize_key_vault_secret,
    AzureResourceType.KEY_VAULT_KEY: normalize_key_vault_key,
    AzureResourceType.KEY_VAULT_CERTIFICATE: normalize_key_vault_certificate,
    AzureResourceType.ROLE_ASSIGNMENT: normalize_role_assignment,
    AzureResourceType.ROLE_DEFINITION: normalize_role_definition,
    AzureResourceType.USER_ASSIGNED_IDENTITY: normalize_user_assigned_identity,
    AzureResourceType.VIRTUAL_NETWORK: normalize_virtual_network,
    AzureResourceType.SUBNET: normalize_subnet,
    AzureResourceType.NETWORK_SECURITY_GROUP: normalize_network_security_group,
    AzureResourceType.NETWORK_SECURITY_RULE: normalize_network_security_rule,
    AzureResourceType.SUBNET_NETWORK_SECURITY_GROUP_ASSOCIATION: normalize_subnet_network_security_group_association,
    AzureResourceType.NETWORK_INTERFACE: normalize_network_interface,
    AzureResourceType.NETWORK_INTERFACE_SECURITY_GROUP_ASSOCIATION: (
        normalize_network_interface_security_group_association
    ),
    AzureResourceType.PUBLIC_IP: normalize_public_ip,
    AzureResourceType.PRIVATE_ENDPOINT: normalize_private_endpoint,
    AzureResourceType.LINUX_WEB_APP: normalize_linux_web_app,
    AzureResourceType.WINDOWS_WEB_APP: normalize_windows_web_app,
    AzureResourceType.FUNCTION_APP: normalize_function_app,
    AzureResourceType.LINUX_FUNCTION_APP: normalize_linux_function_app,
    AzureResourceType.WINDOWS_FUNCTION_APP: normalize_windows_function_app,
    AzureResourceType.LINUX_VIRTUAL_MACHINE: normalize_linux_virtual_machine,
    AzureResourceType.WINDOWS_VIRTUAL_MACHINE: normalize_windows_virtual_machine,
    AzureResourceType.MSSQL_SERVER: normalize_mssql_server,
    AzureResourceType.MSSQL_DATABASE: normalize_mssql_database,
    AzureResourceType.MSSQL_FIREWALL_RULE: normalize_mssql_firewall_rule,
    AzureResourceType.MSSQL_VIRTUAL_NETWORK_RULE: normalize_mssql_virtual_network_rule,
    AzureResourceType.MSSQL_SERVER_SECURITY_ALERT_POLICY: normalize_mssql_server_security_alert_policy,
    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER: normalize_postgresql_flexible_server,
    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_DATABASE: normalize_postgresql_flexible_server_database,
    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_FIREWALL_RULE: normalize_postgresql_flexible_server_firewall_rule,
    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_CONFIGURATION: normalize_postgresql_flexible_server_configuration,
}
SUPPORTED_AZURE_TYPES = frozenset(_AZURE_RESOURCE_NORMALIZERS)


class AzureNormalizer(ProviderNormalizer):
    """Normalize supported AzureRM storage, identity, Key Vault, network, compute, and app resources."""

    provider = "azure"

    def __init__(self, resource_decorator: AzureResourceDecorator | None = None) -> None:
        self._resource_decorator = resource_decorator or AzureResourceDecorator()
        self._resource_normalizers = dict(_AZURE_RESOURCE_NORMALIZERS)

    def owns_resource(self, resource: TerraformResource) -> bool:
        return _is_azure_resource(resource)

    def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
        azure_resources = [resource for resource in resources if self.owns_resource(resource)]
        unsupported_resource_types = Counter(
            resource.resource_type
            for resource in azure_resources
            if resource.resource_type not in SUPPORTED_AZURE_TYPES
        )
        unsupported = sorted(
            resource.address for resource in azure_resources if resource.resource_type not in SUPPORTED_AZURE_TYPES
        )
        normalized = [
            self._resource_normalizers[resource.resource_type](resource)
            for resource in azure_resources
            if resource.resource_type in SUPPORTED_AZURE_TYPES
        ]
        self._resource_decorator.decorate(normalized)

        metadata: dict[str, Any] = {}
        InventoryMetadata.SUPPORTED_RESOURCE_TYPES.set(metadata, sorted(SUPPORTED_AZURE_TYPES))
        InventoryMetadata.TOTAL_INPUT_RESOURCES.set(metadata, len(resources))
        InventoryMetadata.PROVIDER_RESOURCE_COUNT.set(metadata, len(azure_resources))
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


def _is_azure_resource(resource: TerraformResource) -> bool:
    provider_name = str(resource.provider_name).strip().lower()
    return provider_name.endswith("/azurerm") or resource.resource_type.startswith(AzureResourceType.PREFIX)
