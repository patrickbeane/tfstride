from __future__ import annotations


class AzureResourceType:
    """Terraform AzureRM provider resource type identifiers."""

    PREFIX = "azurerm_"

    STORAGE_ACCOUNT = "azurerm_storage_account"
    STORAGE_ACCOUNT_NETWORK_RULES = "azurerm_storage_account_network_rules"
    STORAGE_CONTAINER = "azurerm_storage_container"
    SERVICE_BUS_NAMESPACE = "azurerm_servicebus_namespace"
    SERVICE_BUS_NAMESPACE_NETWORK_RULE_SET = "azurerm_servicebus_namespace_network_rule_set"
    SERVICE_BUS_NAMESPACE_CUSTOMER_MANAGED_KEY = "azurerm_servicebus_namespace_customer_managed_key"
    SERVICE_BUS_QUEUE = "azurerm_servicebus_queue"
    SERVICE_BUS_TOPIC = "azurerm_servicebus_topic"
    SERVICE_BUS_SUBSCRIPTION = "azurerm_servicebus_subscription"
    CONTAINER_REGISTRY = "azurerm_container_registry"
    KEY_VAULT = "azurerm_key_vault"
    KEY_VAULT_ACCESS_POLICY = "azurerm_key_vault_access_policy"
    KEY_VAULT_SECRET = "azurerm_key_vault_secret"
    KEY_VAULT_KEY = "azurerm_key_vault_key"
    KEY_VAULT_CERTIFICATE = "azurerm_key_vault_certificate"
    ROLE_ASSIGNMENT = "azurerm_role_assignment"
    ROLE_DEFINITION = "azurerm_role_definition"
    USER_ASSIGNED_IDENTITY = "azurerm_user_assigned_identity"
    FEDERATED_IDENTITY_CREDENTIAL = "azurerm_federated_identity_credential"
    VIRTUAL_NETWORK = "azurerm_virtual_network"
    SUBNET = "azurerm_subnet"
    NETWORK_SECURITY_GROUP = "azurerm_network_security_group"
    NETWORK_SECURITY_RULE = "azurerm_network_security_rule"
    NETWORK_WATCHER_FLOW_LOG = "azurerm_network_watcher_flow_log"
    SUBNET_NETWORK_SECURITY_GROUP_ASSOCIATION = "azurerm_subnet_network_security_group_association"
    NETWORK_INTERFACE = "azurerm_network_interface"
    NETWORK_INTERFACE_SECURITY_GROUP_ASSOCIATION = "azurerm_network_interface_security_group_association"
    PUBLIC_IP = "azurerm_public_ip"
    LOAD_BALANCER = "azurerm_lb"
    APPLICATION_GATEWAY = "azurerm_application_gateway"
    PRIVATE_ENDPOINT = "azurerm_private_endpoint"
    PRIVATE_DNS_ZONE = "azurerm_private_dns_zone"
    PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_LINK = "azurerm_private_dns_zone_virtual_network_link"
    LINUX_WEB_APP = "azurerm_linux_web_app"
    WINDOWS_WEB_APP = "azurerm_windows_web_app"
    FUNCTION_APP = "azurerm_function_app"
    LINUX_FUNCTION_APP = "azurerm_linux_function_app"
    WINDOWS_FUNCTION_APP = "azurerm_windows_function_app"
    KUBERNETES_CLUSTER = "azurerm_kubernetes_cluster"
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
    MONITOR_DIAGNOSTIC_SETTING = "azurerm_monitor_diagnostic_setting"
    SECURITY_CENTER_SUBSCRIPTION_PRICING = "azurerm_security_center_subscription_pricing"
    SECURITY_CENTER_AUTO_PROVISIONING = "azurerm_security_center_auto_provisioning"
    SECURITY_CENTER_CONTACT = "azurerm_security_center_contact"
    SECURITY_CENTER_WORKSPACE = "azurerm_security_center_workspace"
    SECURITY_CENTER_SETTING = "azurerm_security_center_setting"
    ADVANCED_THREAT_PROTECTION = "azurerm_advanced_threat_protection"


AZURE_STORAGE_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.STORAGE_ACCOUNT,
        AzureResourceType.STORAGE_ACCOUNT_NETWORK_RULES,
        AzureResourceType.STORAGE_CONTAINER,
    }
)

AZURE_SERVICE_BUS_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.SERVICE_BUS_NAMESPACE,
        AzureResourceType.SERVICE_BUS_NAMESPACE_NETWORK_RULE_SET,
        AzureResourceType.SERVICE_BUS_NAMESPACE_CUSTOMER_MANAGED_KEY,
        AzureResourceType.SERVICE_BUS_QUEUE,
        AzureResourceType.SERVICE_BUS_TOPIC,
        AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
    }
)

AZURE_CONTAINER_REGISTRY_RESOURCE_TYPES = frozenset({AzureResourceType.CONTAINER_REGISTRY})

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
AZURE_FEDERATED_IDENTITY_RESOURCE_TYPES = frozenset({AzureResourceType.FEDERATED_IDENTITY_CREDENTIAL})
AZURE_RBAC_RESOURCE_TYPES = frozenset({AzureResourceType.ROLE_ASSIGNMENT, AzureResourceType.ROLE_DEFINITION})

AZURE_NETWORK_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.VIRTUAL_NETWORK,
        AzureResourceType.SUBNET,
        AzureResourceType.NETWORK_SECURITY_GROUP,
        AzureResourceType.NETWORK_SECURITY_RULE,
        AzureResourceType.NETWORK_WATCHER_FLOW_LOG,
        AzureResourceType.SUBNET_NETWORK_SECURITY_GROUP_ASSOCIATION,
        AzureResourceType.NETWORK_INTERFACE,
        AzureResourceType.NETWORK_INTERFACE_SECURITY_GROUP_ASSOCIATION,
        AzureResourceType.PUBLIC_IP,
        AzureResourceType.LOAD_BALANCER,
        AzureResourceType.APPLICATION_GATEWAY,
        AzureResourceType.PRIVATE_ENDPOINT,
        AzureResourceType.PRIVATE_DNS_ZONE,
        AzureResourceType.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_LINK,
    }
)

AZURE_COMPUTE_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.LINUX_VIRTUAL_MACHINE,
        AzureResourceType.WINDOWS_VIRTUAL_MACHINE,
    }
)

AZURE_AKS_RESOURCE_TYPES = frozenset({AzureResourceType.KUBERNETES_CLUSTER})

AZURE_APP_SERVICE_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.LINUX_WEB_APP,
        AzureResourceType.WINDOWS_WEB_APP,
        AzureResourceType.FUNCTION_APP,
        AzureResourceType.LINUX_FUNCTION_APP,
        AzureResourceType.WINDOWS_FUNCTION_APP,
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

AZURE_AUDIT_SECURITY_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.MONITOR_DIAGNOSTIC_SETTING,
        AzureResourceType.SECURITY_CENTER_SUBSCRIPTION_PRICING,
        AzureResourceType.SECURITY_CENTER_AUTO_PROVISIONING,
        AzureResourceType.SECURITY_CENTER_CONTACT,
        AzureResourceType.SECURITY_CENTER_WORKSPACE,
        AzureResourceType.SECURITY_CENTER_SETTING,
        AzureResourceType.ADVANCED_THREAT_PROTECTION,
    }
)

AZURE_SUPPORTED_RESOURCE_TYPES = (
    AZURE_STORAGE_RESOURCE_TYPES
    | AZURE_SERVICE_BUS_RESOURCE_TYPES
    | AZURE_CONTAINER_REGISTRY_RESOURCE_TYPES
    | AZURE_KEY_VAULT_RESOURCE_TYPES
    | AZURE_IDENTITY_RESOURCE_TYPES
    | AZURE_FEDERATED_IDENTITY_RESOURCE_TYPES
    | AZURE_RBAC_RESOURCE_TYPES
    | AZURE_NETWORK_RESOURCE_TYPES
    | AZURE_COMPUTE_RESOURCE_TYPES
    | AZURE_AKS_RESOURCE_TYPES
    | AZURE_APP_SERVICE_RESOURCE_TYPES
    | AZURE_SQL_RESOURCE_TYPES
    | AZURE_POSTGRESQL_RESOURCE_TYPES
    | AZURE_AUDIT_SECURITY_RESOURCE_TYPES
)
