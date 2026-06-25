from __future__ import annotations

from tfstride.analysis.rule_registry import RuleMetadata
from tfstride.models import StrideCategory

AZURE_RULE_METADATA = (
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
)
