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
)
