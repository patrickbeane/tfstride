from __future__ import annotations


class AzureResourceType:
    """Terraform AzureRM provider resource type identifiers."""

    PREFIX = "azurerm_"

    STORAGE_ACCOUNT = "azurerm_storage_account"
    STORAGE_ACCOUNT_NETWORK_RULES = "azurerm_storage_account_network_rules"
    STORAGE_CONTAINER = "azurerm_storage_container"


AZURE_STORAGE_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.STORAGE_ACCOUNT,
        AzureResourceType.STORAGE_ACCOUNT_NETWORK_RULES,
        AzureResourceType.STORAGE_CONTAINER,
    }
)
