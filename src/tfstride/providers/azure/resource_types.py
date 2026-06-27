from __future__ import annotations


class AzureResourceType:
    """Terraform AzureRM provider resource type identifiers."""

    PREFIX = "azurerm_"

    STORAGE_ACCOUNT = "azurerm_storage_account"
    STORAGE_ACCOUNT_NETWORK_RULES = "azurerm_storage_account_network_rules"
    STORAGE_CONTAINER = "azurerm_storage_container"
    KEY_VAULT = "azurerm_key_vault"
    KEY_VAULT_ACCESS_POLICY = "azurerm_key_vault_access_policy"
    KEY_VAULT_SECRET = "azurerm_key_vault_secret"
    KEY_VAULT_KEY = "azurerm_key_vault_key"
    KEY_VAULT_CERTIFICATE = "azurerm_key_vault_certificate"
    ROLE_ASSIGNMENT = "azurerm_role_assignment"
    USER_ASSIGNED_IDENTITY = "azurerm_user_assigned_identity"
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
    MSSQL_SERVER = "azurerm_mssql_server"
    MSSQL_DATABASE = "azurerm_mssql_database"
    MSSQL_FIREWALL_RULE = "azurerm_mssql_firewall_rule"
    MSSQL_VIRTUAL_NETWORK_RULE = "azurerm_mssql_virtual_network_rule"
    MSSQL_SERVER_SECURITY_ALERT_POLICY = "azurerm_mssql_server_security_alert_policy"
    POSTGRESQL_FLEXIBLE_SERVER = "azurerm_postgresql_flexible_server"
    POSTGRESQL_FLEXIBLE_SERVER_DATABASE = "azurerm_postgresql_flexible_server_database"
    POSTGRESQL_FLEXIBLE_SERVER_FIREWALL_RULE = "azurerm_postgresql_flexible_server_firewall_rule"
    POSTGRESQL_FLEXIBLE_SERVER_CONFIGURATION = "azurerm_postgresql_flexible_server_configuration"


AZURE_STORAGE_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.STORAGE_ACCOUNT,
        AzureResourceType.STORAGE_ACCOUNT_NETWORK_RULES,
        AzureResourceType.STORAGE_CONTAINER,
    }
)

AZURE_KEY_VAULT_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.KEY_VAULT,
        AzureResourceType.KEY_VAULT_ACCESS_POLICY,
        AzureResourceType.KEY_VAULT_SECRET,
        AzureResourceType.KEY_VAULT_KEY,
        AzureResourceType.KEY_VAULT_CERTIFICATE,
        AzureResourceType.ROLE_ASSIGNMENT,
    }
)

AZURE_IDENTITY_RESOURCE_TYPES = frozenset({AzureResourceType.USER_ASSIGNED_IDENTITY})

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

AZURE_SQL_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.MSSQL_SERVER,
        AzureResourceType.MSSQL_DATABASE,
        AzureResourceType.MSSQL_FIREWALL_RULE,
        AzureResourceType.MSSQL_VIRTUAL_NETWORK_RULE,
        AzureResourceType.MSSQL_SERVER_SECURITY_ALERT_POLICY,
    }
)

AZURE_POSTGRESQL_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
        AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_DATABASE,
        AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_FIREWALL_RULE,
        AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_CONFIGURATION,
    }
)

AZURE_SUPPORTED_RESOURCE_TYPES = (
    AZURE_STORAGE_RESOURCE_TYPES
    | AZURE_KEY_VAULT_RESOURCE_TYPES
    | AZURE_IDENTITY_RESOURCE_TYPES
    | AZURE_NETWORK_RESOURCE_TYPES
    | AZURE_COMPUTE_RESOURCE_TYPES
    | AZURE_SQL_RESOURCE_TYPES
    | AZURE_POSTGRESQL_RESOURCE_TYPES
)
