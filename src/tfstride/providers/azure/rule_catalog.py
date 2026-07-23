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
        rule_id="azure-load-balancer-public-frontend",
        title="Azure Load Balancer has a public frontend",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Remove the public frontend when the load balancer is intended to be internal, or verify the "
            "public edge is paired with narrow load-balancing/NAT rules, backend membership, and NSG controls."
        ),
        tags=("azure", "network", "load-balancer", "public-access"),
        severity_factors=("internet_exposure", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-application-gateway-public-listener",
        title="Azure Application Gateway has a public listener",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Use a private frontend for internal applications, or ensure public Application Gateway listeners are "
            "intentional and protected with WAF policy, reviewed routing, authentication, and backend controls."
        ),
        tags=("azure", "network", "application-gateway", "load-balancer", "public-access"),
        severity_factors=("internet_exposure", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-public-application-gateway-waf-missing",
        title="Public Azure Application Gateway listener lacks modeled WAF protection",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Attach an Application Gateway WAF policy or enable Application Gateway WAF configuration for public "
            "listeners, keep the policy reference deterministic in Terraform, and review WAF mode and exclusions "
            "separately for policy depth."
        ),
        tags=("azure", "network", "application-gateway", "waf", "public-edge"),
        severity_factors=("internet_exposure", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-nsg-flow-logs-not-configured",
        title="Azure Network Security Group lacks flow-log coverage",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Configure an `azurerm_network_watcher_flow_log` for the NSG, route logs to durable storage, and keep "
            "retention long enough for incident response and network investigation workflows."
        ),
        tags=("azure", "network", "nsg", "flow-logs", "monitoring"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-nsg-flow-log-disabled",
        title="Azure Network Watcher flow log is disabled or unknown",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Set the Network Watcher flow log `enabled` value to `true` and keep Terraform plan values "
            "deterministic so NSG flow telemetry collection can be reviewed before deployment."
        ),
        tags=("azure", "network", "nsg", "flow-logs", "monitoring"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-nsg-flow-log-destination-missing",
        title="Azure Network Watcher flow log has no deterministic storage destination",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Configure a `storage_account_id` destination for Network Watcher flow logs and retain the storage "
            "account with access controls appropriate for security telemetry."
        ),
        tags=("azure", "network", "nsg", "flow-logs", "logging-destination"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-nsg-flow-log-retention-insufficient",
        title="Azure Network Watcher flow-log retention is insufficient",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Enable Network Watcher flow-log retention and configure a retention period that meets incident "
            "response, threat hunting, and compliance review requirements."
        ),
        tags=("azure", "network", "nsg", "flow-logs", "retention"),
        severity_factors=("lateral_movement", "blast_radius"),
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
        rule_id="azure-storage-account-customer-managed-key-missing",
        title="Azure Storage account does not use customer-managed key control",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Configure a customer-managed Key Vault key for storage encryption where regulatory, rotation, "
            "or separation-of-duties requirements call for customer key ownership."
        ),
        tags=("azure", "storage", "encryption", "cmk", "key-management"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-storage-account-infrastructure-encryption-not-enabled",
        title="Azure Storage account does not explicitly enable infrastructure encryption",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Enable infrastructure encryption for storage accounts that require additional encryption-at-rest "
            "depth beyond Azure Storage default encryption."
        ),
        tags=("azure", "storage", "encryption", "defense-in-depth"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-storage-account-blob-versioning-disabled",
        title="Azure Storage account blob versioning is not enabled",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Enable blob versioning for sensitive storage accounts and pair it with lifecycle policies that "
            "match recovery objectives and storage cost constraints."
        ),
        tags=("azure", "storage", "blob", "recovery", "versioning"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-storage-account-blob-soft-delete-insufficient",
        title="Azure Storage account blob soft delete retention is insufficient",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Enable blob soft delete and configure a retention period that meets recovery objectives for "
            "accidental or malicious blob deletion."
        ),
        tags=("azure", "storage", "blob", "recovery", "soft-delete"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-storage-account-container-soft-delete-insufficient",
        title="Azure Storage account container soft delete retention is insufficient",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Enable container soft delete and configure a retention period that meets recovery objectives for "
            "container-level deletion events."
        ),
        tags=("azure", "storage", "container", "recovery", "soft-delete"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-storage-account-point-in-time-restore-missing",
        title="Azure Storage account point-in-time restore is not configured",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Configure point-in-time restore for supported blob workloads where recovery from destructive "
            "changes is required, and align restore days with recovery objectives."
        ),
        tags=("azure", "storage", "blob", "recovery", "point-in-time-restore"),
        severity_factors=("data_sensitivity", "blast_radius"),
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
        rule_id="azure-service-bus-public-network-access-not-disabled",
        title="Azure Service Bus namespace does not disable public network access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Disable public network access for Service Bus where possible. If public connectivity is required, "
            "use an effective default-deny network rule with narrow reviewed exceptions and do not treat it as "
            "equivalent to private-only access."
        ),
        tags=("azure", "service-bus", "network", "public-access"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-service-bus-minimum-tls-below-1-2",
        title="Azure Service Bus namespace allows TLS below 1.2",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Set `minimum_tls_version` to `1.2` and remove Service Bus clients that require deprecated TLS versions."
        ),
        tags=("azure", "service-bus", "tls"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-service-bus-minimum-tls-unknown",
        title="Azure Service Bus namespace minimum TLS posture is unknown",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Set `minimum_tls_version` explicitly to `1.2` or newer so Terraform plan analysis can verify "
            "Service Bus transport protection."
        ),
        tags=("azure", "service-bus", "tls", "configuration-uncertainty"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-service-bus-local-auth-enabled",
        title="Azure Service Bus namespace permits local or SAS authorization",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Disable local authorization where application compatibility permits it, use Microsoft Entra ID with "
            "least-privilege roles, and rotate or retire existing shared access policies and connection strings."
        ),
        tags=("azure", "service-bus", "identity", "sas", "local-auth"),
        severity_factors=("internet_exposure", "privilege_breadth", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-service-bus-customer-managed-key-missing",
        title="Azure Service Bus namespace lacks customer-managed key control",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "For Premium namespaces that require customer key ownership, configure a customer-managed Key Vault "
            "key and retain deterministic Terraform references for key review and rotation governance."
        ),
        tags=("azure", "service-bus", "encryption", "cmk", "key-management"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-service-bus-missing-private-endpoint",
        title="Azure Service Bus namespace lacks resolved private endpoint coverage",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "For Premium namespaces, add a Private Endpoint for the namespace, configure Private DNS, verify "
            "clients use the private path, and explicitly disable public network access where possible."
        ),
        tags=("azure", "service-bus", "private-endpoint", "public-fallback"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-container-registry-public-network-access-not-disabled",
        title="Azure Container Registry does not disable public network access",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Disable public network access for Container Registry where possible. If public connectivity is "
            "required, use default-deny network rules with narrow reviewed exceptions and do not treat firewall "
            "rules as equivalent to private-only access."
        ),
        tags=("azure", "container-registry", "network", "public-access"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-container-registry-admin-account-enabled",
        title="Azure Container Registry admin account is enabled",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Disable the Container Registry admin account and use Microsoft Entra ID, managed identities, and "
            "least-privilege Azure RBAC roles for image push and pull operations."
        ),
        tags=("azure", "container-registry", "identity", "local-auth", "admin-account"),
        severity_factors=("internet_exposure", "privilege_breadth", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-container-registry-anonymous-pull-enabled",
        title="Azure Container Registry permits anonymous image pulls",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Disable anonymous pull access and require Microsoft Entra ID or scoped registry authentication for "
            "all image retrieval."
        ),
        tags=("azure", "container-registry", "anonymous-access", "public-access"),
        severity_factors=("internet_exposure", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-container-registry-customer-managed-key-missing",
        title="Premium Azure Container Registry lacks customer-managed key control",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "For Premium registries that require customer key ownership, configure a customer-managed Key Vault "
            "key and managed identity, and retain deterministic Terraform references for key governance."
        ),
        tags=("azure", "container-registry", "encryption", "cmk", "key-management"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-container-registry-missing-private-endpoint",
        title="Premium Azure Container Registry lacks resolved private endpoint coverage",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Add a Private Endpoint for the Premium registry, configure Private DNS, verify clients use the "
            "private path, and explicitly disable public network access where possible."
        ),
        tags=("azure", "container-registry", "private-endpoint", "public-fallback"),
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
        rule_id="azure-key-vault-secret-certificate-lifecycle-incomplete",
        title="Azure Key Vault secret or certificate lifecycle posture is incomplete",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Configure explicit expiry for Key Vault secrets and certificates, keep validity windows bounded, "
            "and pair lifecycle settings with rotation automation appropriate for the secret or certificate type."
        ),
        tags=("azure", "key-vault", "secrets", "certificates", "lifecycle", "expiry"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-key-vault-key-strength-weak",
        title="Azure Key Vault key strength is weak",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Use RSA Key Vault keys of at least 2048 bits, or stronger approved key types and curves where "
            "appropriate for the workload and compliance baseline."
        ),
        tags=("azure", "key-vault", "keys", "cryptography", "key-strength"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-key-vault-key-rotation-policy-incomplete",
        title="Azure Key Vault key rotation posture is incomplete",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Configure Key Vault key rotation policies with bounded expiry and automatic rotation intervals, "
            "and keep key validity windows aligned with cryptographic lifecycle and compliance requirements."
        ),
        tags=("azure", "key-vault", "keys", "rotation", "lifecycle"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-custom-role-wildcard-management-plane",
        title="Custom Azure role grants wildcard management-plane permissions",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            'Replace `actions = ["*"]` with the smallest Azure control-plane actions required, keep '
            "NotActions as defense-in-depth only, and constrain assignable scopes to the narrowest resource group "
            "or resource scope possible."
        ),
        tags=("azure", "rbac", "custom-role", "least-privilege", "wildcard"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-custom-role-authorization-management",
        title="Custom Azure role grants broad authorization-management permissions",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Remove authorization-management wildcard or role-assignment capabilities unless the custom role is "
            "strictly for delegated RBAC administration, then restrict assignable scopes and monitor assignments."
        ),
        tags=("azure", "rbac", "custom-role", "authorization", "least-privilege"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-custom-role-broad-management-plane",
        title="Custom Azure role grants broad management-plane wildcard permissions",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Replace service-level wildcard actions with specific create, update, read, or delete permissions, and "
            "split deployment duties by service area where practical."
        ),
        tags=("azure", "rbac", "custom-role", "management-plane", "least-privilege"),
        severity_factors=("privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-custom-role-broad-data-plane",
        title="Custom Azure role grants broad data-plane permissions",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Replace broad storage or Key Vault data-plane wildcards with task-specific data actions, separate "
            "read/write/delete duties, and keep assignable scopes close to the target resource."
        ),
        tags=("azure", "rbac", "custom-role", "data-plane", "least-privilege"),
        severity_factors=("privilege_breadth", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-custom-role-subscription-assignable-scope",
        title="Custom Azure role is assignable at subscription scope",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Avoid subscription-wide assignable scopes for custom roles unless required; prefer resource-group or "
            "resource scopes and review existing role assignments before broadening assignable scopes."
        ),
        tags=("azure", "rbac", "custom-role", "assignable-scope", "blast-radius"),
        severity_factors=("privilege_breadth", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-custom-role-assignment-blast-radius",
        title="Azure principal is assigned broad custom RBAC role",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Remove or narrow broad custom-role assignments, prefer built-in least-privilege roles where possible, "
            "scope assignments to the target resource or smallest resource group, and reserve authorization-management "
            "or wildcard roles for tightly controlled deployment identities."
        ),
        tags=("azure", "rbac", "custom-role", "role-assignment", "blast-radius"),
        severity_factors=("privilege_breadth", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-rbac-privileged-assignment",
        title="Azure principal has privileged RBAC assignment posture",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Replace broad built-in Azure RBAC assignments with least-privilege roles, scope assignments to the "
            "smallest resource group or resource, and reserve subscription-wide administrative grants for tightly "
            "controlled break-glass or deployment principals."
        ),
        tags=("azure", "rbac", "privileged-access", "role-assignment"),
        severity_factors=("privilege_breadth", "data_sensitivity", "lateral_movement", "blast_radius"),
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
        rule_id="azure-federated-identity-privileged-access",
        title="Federated identity can reach privileged Azure managed identity access",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Narrow federated credential subjects and audiences to exact workloads, remove broad managed-identity "
            "RBAC assignments, scope roles to the smallest required resource, and separate deployment identities "
            "from runtime identities."
        ),
        tags=(
            "azure",
            "managed-identity",
            "federated-identity",
            "rbac",
            "privileged-access",
            "transitive-path",
        ),
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
        rule_id="azure-app-service-platform-authentication-disabled",
        title="Public Azure App Service has platform authentication disabled",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Enable App Service authentication through `auth_settings` or `auth_settings_v2` for public apps, "
            "configure a reviewed identity provider and unauthenticated-request action, and document any "
            "application-level authentication controls that are intentionally enforced outside Terraform."
        ),
        tags=("azure", "app-service", "function-app", "authentication", "public-access"),
        severity_factors=("internet_exposure", "privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-app-service-anonymous-platform-access-allowed",
        title="Public Azure App Service permits anonymous platform access",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Set the App Service unauthenticated-request action to require a reviewed identity provider or "
            "return an authentication failure, unless anonymous access is an explicit product requirement; "
            "document any application-level authentication enforced outside Terraform."
        ),
        tags=("azure", "app-service", "function-app", "authentication", "anonymous-access", "public-access"),
        severity_factors=("internet_exposure", "privilege_breadth", "lateral_movement", "blast_radius"),
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
        rule_id="azure-app-service-access-restrictions-not-default-deny",
        title="Azure App Service access restrictions are not default deny",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Set the App Service `ip_restriction_default_action` to `Deny` and allow only reviewed client "
            "CIDRs, service tags, or subnet-based paths when the app intentionally keeps public network access."
        ),
        tags=("azure", "app-service", "function-app", "access-restrictions", "public-access"),
        severity_factors=("internet_exposure", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-app-service-broad-access-restriction-allow",
        title="Azure App Service access restriction allows broad public sources",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Replace broad App Service allow rules with narrow trusted CIDRs, service tags, or subnet-backed "
            "access paths, and keep the default action set to `Deny`."
        ),
        tags=("azure", "app-service", "function-app", "access-restrictions", "public-access"),
        severity_factors=("internet_exposure", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-app-service-scm-access-unrestricted",
        title="Azure App Service SCM endpoint access is unrestricted",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Restrict SCM/Kudu access with explicit SCM access restrictions or inherit a default-deny main-site "
            "restriction set, and keep deployment operations behind trusted networks or private build agents."
        ),
        tags=("azure", "app-service", "function-app", "scm", "kudu", "access-restrictions"),
        severity_factors=("internet_exposure", "privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-app-service-image-not-digest-pinned",
        title="Azure App Service container image is not digest-pinned",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Pin App Service and Function App container images to an immutable `sha256` digest, and update the "
            "digest through a reviewed build and deployment process when releasing a new artifact."
        ),
        tags=("azure", "app-service", "function-app", "container", "supply-chain", "image-integrity"),
        severity_factors=("blast_radius",),
    ),
    RuleMetadata(
        rule_id="azure-app-service-can-modify-image-repository",
        title="Azure App Service runtime identity can modify its deployed image repository",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Remove ACR push and equivalent custom-role data permissions from the App Service runtime identity, "
            "use a separate deployment identity, and deploy digest-pinned container images."
        ),
        tags=("azure", "app-service", "function-app", "acr", "managed-identity", "supply-chain", "persistence"),
        severity_factors=("privilege_breadth", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-public-app-service-storage-mutation-access",
        title="Public Azure App Service identity can mutate Blob Storage",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Remove Storage Blob Data Contributor, Storage Blob Data Owner, and equivalent custom-role mutation "
            "permissions from public App Service runtime identities; scope required access to the exact account or "
            "container, separate privileged storage mutation from public runtimes, and restrict public ingress."
        ),
        tags=(
            "azure",
            "app-service",
            "function-app",
            "storage",
            "managed-identity",
            "public-access",
            "tampering",
        ),
        severity_factors=(
            "internet_exposure",
            "privilege_breadth",
            "data_sensitivity",
            "lateral_movement",
            "blast_radius",
        ),
    ),
    RuleMetadata(
        rule_id="azure-public-app-service-service-bus-mutation-access",
        title="Public Azure App Service identity can mutate Service Bus messaging",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Remove Azure Service Bus Data Sender, unnecessary Azure Service Bus Data Owner, and equivalent "
            "custom-role mutation permissions from public App Service runtime identities; scope required access "
            "to the exact namespace or entity, separate message publishing from public runtimes where possible, "
            "and restrict public ingress."
        ),
        tags=(
            "azure",
            "app-service",
            "function-app",
            "service-bus",
            "managed-identity",
            "public-access",
            "tampering",
        ),
        severity_factors=(
            "internet_exposure",
            "privilege_breadth",
            "data_sensitivity",
            "lateral_movement",
            "blast_radius",
        ),
    ),
    RuleMetadata(
        rule_id="azure-app-service-sensitive-app-setting-inline",
        title="Azure App Service materializes a sensitive setting as a literal value",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Move credential material from App Service application settings to Key Vault references or "
            "managed-identity-backed secret retrieval, and keep literal values out of Terraform configuration, "
            "plans, state, and App Service configuration."
        ),
        tags=("azure", "app-service", "function-app", "secrets", "app-settings", "credential-delivery"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-app-service-key-vault-reference-identity-not-configured",
        title="Azure App Service Key Vault reference identity is not configured",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Configure key_vault_reference_identity_id with the exact attached user-assigned managed identity, "
            "or enable a system-assigned identity for Key Vault reference resolution."
        ),
        tags=("azure", "app-service", "function-app", "key-vault", "managed-identity"),
        severity_factors=("privilege_breadth", "data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-app-service-key-vault-secret-access-overprivileged",
        title="Azure App Service Key Vault secret access is overprivileged",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Replace Key Vault administration, write, deletion, or recovery permissions with Key Vault Secrets "
            "User or an equivalent read-only secret access policy scoped to the required vault or secret."
        ),
        tags=("azure", "app-service", "function-app", "key-vault", "managed-identity", "least-privilege"),
        severity_factors=("privilege_breadth", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-diagnostic-settings-missing",
        title="Azure resource lacks diagnostic settings",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Add an Azure Monitor diagnostic setting for the resource and route security-relevant logs and metrics "
            "to a retained Log Analytics workspace, storage account, Event Hub, or approved partner destination."
        ),
        tags=("azure", "diagnostic-settings", "logging", "monitoring"),
        severity_factors=("internet_exposure", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-diagnostic-setting-no-log-destination",
        title="Azure diagnostic setting has no log destination",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Configure the diagnostic setting with a Log Analytics workspace, storage account, Event Hub "
            "authorization rule, or marketplace partner destination so emitted logs and metrics are retained."
        ),
        tags=("azure", "diagnostic-settings", "logging", "monitoring"),
        severity_factors=("data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-diagnostic-setting-audit-logs-incomplete",
        title="Azure diagnostic setting does not enable audit logs",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Enable high-confidence audit or security log categories, or an audit/allLogs category group, for "
            "diagnostic settings on sensitive Azure resources and route them to a retained logging destination."
        ),
        tags=("azure", "diagnostic-settings", "audit-logs", "logging", "monitoring"),
        severity_factors=("internet_exposure", "data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-defender-pricing-tier-not-standard",
        title="Microsoft Defender for Cloud pricing tier is not Standard",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Set the modeled Defender for Cloud subscription pricing tier to Standard for service plans that "
            "need threat detection and security posture recommendations."
        ),
        tags=("azure", "defender", "security-center", "monitoring"),
        severity_factors=("data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-security-center-auto-provisioning-disabled",
        title="Security Center auto-provisioning is disabled",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Enable Security Center auto-provisioning where monitored workloads should receive supported security "
            "agents automatically, or document the external deployment mechanism that replaces it."
        ),
        tags=("azure", "security-center", "defender", "monitoring", "auto-provisioning"),
        severity_factors=("data_sensitivity", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-aks-api-server-public-unrestricted",
        title="AKS control plane is public without narrow authorized IP ranges",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Enable private cluster mode where possible, or configure `api_server_access_profile.authorized_ip_ranges` "
            "with narrow trusted CIDRs and avoid internet-wide source ranges."
        ),
        tags=("azure", "aks", "kubernetes", "control-plane", "public-access"),
        severity_factors=("internet_exposure", "privilege_breadth", "lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-aks-private-cluster-not-enabled",
        title="AKS private cluster mode is not enabled",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Enable AKS private cluster mode for private workloads, or document why public API server access is "
            "required and pair it with narrow authorized IP ranges."
        ),
        tags=("azure", "aks", "kubernetes", "control-plane", "private-cluster"),
        severity_factors=("internet_exposure", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-aks-local-accounts-not-disabled",
        title="AKS local accounts are not disabled",
        category=StrideCategory.SPOOFING,
        recommended_mitigation=(
            "Set `local_account_disabled` to `true`, use Microsoft Entra ID-backed authentication, and review any "
            "break-glass access paths separately."
        ),
        tags=("azure", "aks", "kubernetes", "identity", "local-accounts"),
        severity_factors=("privilege_breadth", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-aks-rbac-posture-weak",
        title="AKS RBAC posture is weak or not deterministic",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Enable Kubernetes RBAC explicitly, use Microsoft Entra ID integration for administrative access, and "
            "avoid disabling Azure RBAC integration when the cluster relies on Azure authorization controls."
        ),
        tags=("azure", "aks", "kubernetes", "rbac", "least-privilege"),
        severity_factors=("privilege_breadth", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-aks-network-policy-missing",
        title="AKS network policy is not configured",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Configure an AKS network policy provider such as Azure, Cilium, or Calico, then define pod-level "
            "network policies for sensitive namespaces and workloads."
        ),
        tags=("azure", "aks", "kubernetes", "network-policy", "segmentation"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-aks-workload-identity-not-enabled",
        title="AKS workload identity is not fully enabled",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        recommended_mitigation=(
            "Enable the AKS OIDC issuer and workload identity, bind Kubernetes service accounts to narrow "
            "managed identities, and avoid relying on node credentials or static secrets for Azure API access."
        ),
        tags=("azure", "aks", "kubernetes", "identity", "workload-identity"),
        severity_factors=("privilege_breadth", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-aks-key-management-service-not-configured",
        title="AKS Key Management Service is not configured",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Configure AKS Key Management Service with a customer-managed Key Vault key for Kubernetes secrets "
            "where customer key ownership or stronger secrets encryption posture is required."
        ),
        tags=("azure", "aks", "kubernetes", "secrets", "encryption", "kms"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-aks-monitoring-agent-not-enabled",
        title="AKS monitoring agent is not enabled",
        category=StrideCategory.REPUDIATION,
        recommended_mitigation=(
            "Enable the OMS agent or the current Azure Monitor integration for AKS and route cluster telemetry to "
            "a retained Log Analytics workspace or centralized logging pipeline."
        ),
        tags=("azure", "aks", "kubernetes", "monitoring", "logging"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-aks-defender-not-enabled",
        title="AKS Defender coverage is not enabled",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Enable Microsoft Defender for Containers for AKS clusters that need runtime threat detection, "
            "vulnerability recommendations, and security posture monitoring."
        ),
        tags=("azure", "aks", "kubernetes", "defender", "monitoring"),
        severity_factors=("lateral_movement", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-aks-azure-policy-not-enabled",
        title="AKS Azure Policy add-on is not enabled",
        category=StrideCategory.TAMPERING,
        recommended_mitigation=(
            "Enable the Azure Policy add-on for AKS where policy-as-code enforcement, guardrails, or compliance "
            "reporting are expected for Kubernetes resources."
        ),
        tags=("azure", "aks", "kubernetes", "azure-policy", "governance"),
        severity_factors=("lateral_movement", "blast_radius"),
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
        rule_id="azure-sql-short-term-backup-retention-insufficient",
        title="Azure SQL Database short-term backup retention is insufficient",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Configure `short_term_retention_policy.retention_days` for Azure SQL databases to meet recovery "
            "objectives, and keep retention long enough for delayed detection of destructive changes."
        ),
        tags=("azure", "sql", "backup", "recovery", "retention"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-sql-long-term-backup-retention-not-configured",
        title="Azure SQL Database long-term backup retention is not configured",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Configure `long_term_retention_policy` for Azure SQL databases that require recovery beyond the "
            "short-term backup window or need compliance retention evidence."
        ),
        tags=("azure", "sql", "backup", "recovery", "long-term-retention"),
        severity_factors=("data_sensitivity", "blast_radius"),
    ),
    RuleMetadata(
        rule_id="azure-sql-backup-geo-redundancy-not-enabled",
        title="Azure SQL Database backup geo-redundancy is not enabled",
        category=StrideCategory.DENIAL_OF_SERVICE,
        recommended_mitigation=(
            "Use geo-redundant or geo-zone-redundant backup storage where regional recovery is required, and "
            "avoid local-only backup redundancy for critical SQL databases."
        ),
        tags=("azure", "sql", "backup", "recovery", "geo-redundancy"),
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
        rule_id="azure-private-endpoint-dns-posture-incomplete",
        title="Azure Private Endpoint DNS posture is incomplete",
        category=StrideCategory.INFORMATION_DISCLOSURE,
        recommended_mitigation=(
            "Configure a Private DNS zone group for each Private Endpoint, link the Private DNS zone to the "
            "endpoint VNet where Terraform manages the link, and validate private DNS resolution outside tfSTRIDE "
            "for live environments."
        ),
        tags=("azure", "private-endpoint", "private-dns", "private-link", "network"),
        severity_factors=("data_sensitivity", "blast_radius"),
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
