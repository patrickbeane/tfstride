from __future__ import annotations

from tfstride.analysis.rule_registry import RuleMetadata
from tfstride.models import StrideCategory

AZURE_RULE_METADATA = (
    RuleMetadata(
        rule_id="azure-public-compute-broad-ingress",
        title="Internet-exposed Azure virtual machine permits broad ingress",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Remove the public IP where possible, restrict subnet and NIC NSG rules to expected client "
            "CIDRs and service ports, and use Azure Bastion, VPN, or Just-In-Time VM access for administration."
        ),
        tags=("azure", "network", "compute", "nsg", "public-access"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-storage-container-public-access",
        title="Azure Storage container is publicly accessible",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Set the container access type to `private`, disable nested public access on the storage account, "
            "and use scoped identities or time-limited access mechanisms for intentional object sharing."
        ),
        tags=("azure", "storage", "container", "public-access"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-storage-account-nested-public-access-enabled",
        title="Azure Storage account permits nested public blob access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Set `allow_nested_items_to_be_public` to `false` so containers and blobs cannot opt into "
            "anonymous public access."
        ),
        tags=("azure", "storage", "public-access"),
        severity_factors=("privilege_breadth", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-storage-account-shared-key-enabled",
        title="Azure Storage account permits Shared Key authorization",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Disable Shared Key authorization where supported, use Microsoft Entra ID and managed identities, "
            "and configure the AzureRM provider to use Azure AD for storage operations."
        ),
        tags=("azure", "storage", "identity", "shared-key"),
        severity_factors=("privilege_breadth", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-storage-account-minimum-tls-below-1-2",
        title="Azure Storage account allows TLS below 1.2",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Set `min_tls_version` to `TLS1_2` and remove clients that require deprecated TLS versions."
        ),
        tags=("azure", "storage", "tls"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-storage-account-public-network-unrestricted",
        title="Azure Storage account allows unrestricted public network access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Disable public network access where possible, or set the effective storage network default action "
            "to `Deny` and allow only reviewed subnets, IP ranges, or private endpoints."
        ),
        tags=("azure", "storage", "network", "public-access"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-storage-account-missing-private-endpoint",
        title="Azure Storage account lacks resolved private endpoint coverage",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Add a Private Endpoint for the required storage subresources, verify clients use private paths, "
            "and explicitly disable public network access where possible."
        ),
        tags=("azure", "storage", "private-endpoint", "public-fallback"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-key-vault-public-network-access",
        title="Azure Key Vault allows unrestricted public network access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Disable public network access where possible, or configure Key Vault network ACLs with a "
            "default action of `Deny` and use reviewed subnets, IP ranges, or private endpoints."
        ),
        tags=("azure", "key-vault", "network", "public-access"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-key-vault-missing-private-endpoint",
        title="Azure Key Vault lacks resolved private endpoint coverage",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Add a Private Endpoint for the vault, verify data-plane clients use the private path, and "
            "explicitly disable public network access where possible."
        ),
        tags=("azure", "key-vault", "private-endpoint", "public-fallback"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-key-vault-privileged-access",
        title="Azure Key Vault grants privileged identity access",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Replace broad Key Vault access policies and privileged vault-scoped roles with least-privilege "
            "RBAC assignments, narrow principals, and separate administrative from data-plane duties."
        ),
        tags=("azure", "key-vault", "identity", "authorization", "least-privilege"),
        severity_factors=("privilege_breadth", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-key-vault-purge-protection-disabled",
        title="Azure Key Vault purge protection is disabled",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Enable purge protection and retain soft-deleted vault objects long enough to recover from "
            "accidental or malicious deletion."
        ),
        tags=("azure", "key-vault", "recovery", "purge-protection"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-managed-identity-broad-rbac",
        title="Azure managed identity has broad RBAC authority",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Replace broad managed identity role assignments with least-privilege resource-scoped roles, "
            "split deployment and runtime identities, and avoid subscription or resource-group scope unless required."
        ),
        tags=("azure", "managed-identity", "rbac", "least-privilege"),
        severity_factors=("privilege_breadth", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-public-workload-sensitive-resource-access",
        title="Internet-exposed Azure workload can access sensitive resources",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Remove direct internet exposure from the workload, restrict NSG ingress to trusted paths, and narrow "
            "the managed identity role assignment to the minimum sensitive resource operations required."
        ),
        tags=("azure", "managed-identity", "sensitive-data", "public-access"),
        severity_factors=("internet_exposure", "privilege_breadth", "data_sensitivity", "lateral_movement"),
    ),
    RuleMetadata(
        rule_id="azure-app-service-public-network-access-not-disabled",
        title="Azure App Service public network access is not disabled",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Set `public_network_access_enabled` to `false` for private apps, or document the required public "
            "entry path and pair it with authentication, access restrictions, and monitored ingress controls."
        ),
        tags=("azure", "app-service", "function-app", "network", "public-access"),
        severity_factors=("internet_exposure", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-app-service-minimum-tls-below-1-2",
        title="Azure App Service allows TLS below 1.2",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Set the App Service or Function App `minimum_tls_version` to `1.2` or newer and retire clients "
            "that require deprecated TLS versions."
        ),
        tags=("azure", "app-service", "function-app", "tls"),
        severity_factors=("internet_exposure", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-app-service-minimum-tls-unknown",
        title="Azure App Service minimum TLS version is not deterministic",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Set the App Service or Function App `minimum_tls_version` explicitly to `1.2` or newer so the "
            "planned endpoint posture is reviewable before deployment."
        ),
        tags=("azure", "app-service", "function-app", "tls", "analysis-uncertainty"),
        severity_factors=("internet_exposure", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-app-service-managed-identity-missing",
        title="Azure App Service does not configure managed identity",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Enable a system-assigned or user-assigned managed identity for Azure resource access and remove "
            "static credentials from app settings, deployment variables, and connection strings where possible."
        ),
        tags=("azure", "app-service", "function-app", "managed-identity", "least-privilege"),
        severity_factors=("internet_exposure", "privilege_breadth", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-app-service-vnet-integration-missing",
        title="Azure App Service does not configure VNet integration",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Configure regional VNet integration for App Service workloads that call private Azure resources, "
            "then prefer private endpoints, service endpoints, or tightly scoped service firewalls for outbound "
            "dependencies."
        ),
        tags=("azure", "app-service", "function-app", "network", "vnet-integration"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-sql-public-network-access-enabled",
        title="Azure SQL Database has public network access enabled",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Disable public network access on the Azure SQL server and use Private Link or VNet service endpoints "
            "for all client connections."
        ),
        tags=("azure", "sql", "network", "public-access"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-sql-missing-private-endpoint",
        title="Azure SQL server lacks resolved private endpoint coverage",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Add a Private Endpoint for the SQL server, verify clients use private connectivity, and explicitly "
            "disable public network access where possible."
        ),
        tags=("azure", "sql", "private-endpoint", "public-fallback"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-sql-firewall-broad-public-access",
        title="Azure SQL firewall rule allows broad public IP access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Replace broad IP ranges (0.0.0.0 to 255.255.255.255) with specific trusted client CIDRs, use "
            "Private Link, or rely on VNet service endpoints instead of IP-based firewall rules."
        ),
        tags=("azure", "sql", "firewall", "public-access"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-sql-minimum-tls-below-1-2",
        title="Azure SQL Database allows TLS below 1.2",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Set `minimum_tls_version` to `1.2` and remove clients that require deprecated TLS versions."
        ),
        tags=("azure", "sql", "tls"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-sql-security-alert-policy-disabled",
        title="Azure SQL Database security alert policy is disabled",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Enable the security alert policy and configure email notifications for the DBA or security team."
        ),
        tags=("azure", "sql", "security-alerting"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-private-endpoint-public-fallback",
        title="Azure resource has private endpoint coverage with public fallback",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Keep the Private Endpoint, verify clients use the private path, and explicitly disable public "
            "network access when public data-plane fallback is not required."
        ),
        tags=("azure", "private-endpoint", "public-fallback", "network"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-postgresql-public-network-access-enabled",
        title="Azure PostgreSQL Flexible Server has public network access enabled",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Disable public network access on the PostgreSQL Flexible Server and use Private Link or "
            "VNet integration for all client connections."
        ),
        tags=("azure", "postgresql", "network", "public-access"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-postgresql-firewall-broad-public-access",
        title="Azure PostgreSQL Flexible Server firewall rule allows broad public IP access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Replace broad IP ranges (0.0.0.0 to 255.255.255.255) with specific trusted client CIDRs, use "
            "Private Link, or rely on VNet integration instead of IP-based firewall rules."
        ),
        tags=("azure", "postgresql", "firewall", "public-access"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-postgresql-weak-tls-or-ssl",
        title="Azure PostgreSQL Flexible Server has weak TLS or SSL posture",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=("Set a minimum TLS version of 1.2 and ensure `require_secure_transport` is enabled."),
        tags=("azure", "postgresql", "tls", "ssl"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-postgresql-geo-backup-disabled",
        title="Azure PostgreSQL Flexible Server geo-redundant backup is disabled",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=("Enable geo-redundant backup to protect against regional data loss."),
        tags=("azure", "postgresql", "backup", "recovery"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
)
