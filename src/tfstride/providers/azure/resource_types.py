from __future__ import annotations


class AzureResourceType:
    """Terraform AzureRM provider resource type identifiers."""

    PREFIX = "azurerm_"

    STORAGE_ACCOUNT = "azurerm_storage_account"
    STORAGE_ACCOUNT_NETWORK_RULES = "azurerm_storage_account_network_rules"
    STORAGE_CONTAINER = "azurerm_storage_container"
    VIRTUAL_NETWORK = "azurerm_virtual_network"
    SUBNET = "azurerm_subnet"
    NETWORK_SECURITY_GROUP = "azurerm_network_security_group"
    NETWORK_SECURITY_RULE = "azurerm_network_security_rule"
    SUBNET_NETWORK_SECURITY_GROUP_ASSOCIATION = "azurerm_subnet_network_security_group_association"
    NETWORK_INTERFACE = "azurerm_network_interface"
    NETWORK_INTERFACE_SECURITY_GROUP_ASSOCIATION = "azurerm_network_interface_security_group_association"
    PUBLIC_IP = "azurerm_public_ip"
    LINUX_VIRTUAL_MACHINE = "azurerm_linux_virtual_machine"
    WINDOWS_VIRTUAL_MACHINE = "azurerm_windows_virtual_machine"


AZURE_STORAGE_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.STORAGE_ACCOUNT,
        AzureResourceType.STORAGE_ACCOUNT_NETWORK_RULES,
        AzureResourceType.STORAGE_CONTAINER,
    }
)

AZURE_NETWORK_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.VIRTUAL_NETWORK,
        AzureResourceType.SUBNET,
        AzureResourceType.NETWORK_SECURITY_GROUP,
        AzureResourceType.NETWORK_SECURITY_RULE,
        AzureResourceType.SUBNET_NETWORK_SECURITY_GROUP_ASSOCIATION,
        AzureResourceType.NETWORK_INTERFACE,
        AzureResourceType.NETWORK_INTERFACE_SECURITY_GROUP_ASSOCIATION,
        AzureResourceType.PUBLIC_IP,
    }
)

AZURE_COMPUTE_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.LINUX_VIRTUAL_MACHINE,
        AzureResourceType.WINDOWS_VIRTUAL_MACHINE,
    }
)

AZURE_SUPPORTED_RESOURCE_TYPES = (
    AZURE_STORAGE_RESOURCE_TYPES | AZURE_NETWORK_RESOURCE_TYPES | AZURE_COMPUTE_RESOURCE_TYPES
)
