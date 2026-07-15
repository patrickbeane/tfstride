from __future__ import annotations

from collections.abc import Mapping

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.rule_definitions import (
    RuleContribution,
    RuleDetector,
    build_rule_contribution,
)
from tfstride.analysis.rule_registry import RuleRegistry, default_rule_registry
from tfstride.providers.azure.aks_rules import AzureAksRuleDetectors
from tfstride.providers.azure.app_service_rules import AzureAppServiceRuleDetectors
from tfstride.providers.azure.audit_rules import AzureAuditRuleDetectors
from tfstride.providers.azure.compute_rules import AzureComputeRuleDetectors
from tfstride.providers.azure.container_registry_rules import AzureContainerRegistryRuleDetectors
from tfstride.providers.azure.iam_assignment_rules import AzureIamAssignmentRuleDetectors
from tfstride.providers.azure.key_vault_rules import AzureKeyVaultRuleDetectors
from tfstride.providers.azure.load_balancer_rules import AzureLoadBalancerRuleDetectors
from tfstride.providers.azure.managed_identity_rules import AzureManagedIdentityRuleDetectors
from tfstride.providers.azure.mssql_rules import AzureMssqlRuleDetectors
from tfstride.providers.azure.network_telemetry_rules import AzureNetworkTelemetryRuleDetectors
from tfstride.providers.azure.postgresql_rules import AzurePostgresqlRuleDetectors
from tfstride.providers.azure.private_endpoint_rules import AzurePrivateEndpointPostureRuleDetectors
from tfstride.providers.azure.rbac_rules import AzureCustomRoleRuleDetectors
from tfstride.providers.azure.service_bus_rules import AzureServiceBusRuleDetectors
from tfstride.providers.azure.storage_rules import AzureStorageRuleDetectors

AZURE_RULE_GROUP_IDS: tuple[tuple[str, ...], ...] = (
    (
        "azure-public-compute-broad-ingress",
        "azure-load-balancer-public-frontend",
        "azure-application-gateway-public-listener",
        "azure-public-application-gateway-waf-missing",
        "azure-nsg-flow-logs-not-configured",
        "azure-nsg-flow-log-disabled",
        "azure-nsg-flow-log-destination-missing",
        "azure-nsg-flow-log-retention-insufficient",
        "azure-storage-container-public-access",
        "azure-storage-account-nested-public-access-enabled",
        "azure-storage-account-shared-key-enabled",
        "azure-storage-account-minimum-tls-below-1-2",
        "azure-storage-account-public-network-unrestricted",
        "azure-storage-account-customer-managed-key-missing",
        "azure-storage-account-infrastructure-encryption-not-enabled",
        "azure-storage-account-blob-versioning-disabled",
        "azure-storage-account-blob-soft-delete-insufficient",
        "azure-storage-account-container-soft-delete-insufficient",
        "azure-storage-account-point-in-time-restore-missing",
        "azure-storage-account-missing-private-endpoint",
        "azure-service-bus-public-network-access-not-disabled",
        "azure-service-bus-minimum-tls-below-1-2",
        "azure-service-bus-minimum-tls-unknown",
        "azure-service-bus-local-auth-enabled",
        "azure-service-bus-customer-managed-key-missing",
        "azure-service-bus-missing-private-endpoint",
        "azure-container-registry-public-network-access-not-disabled",
        "azure-container-registry-admin-account-enabled",
        "azure-container-registry-anonymous-pull-enabled",
        "azure-container-registry-customer-managed-key-missing",
        "azure-container-registry-missing-private-endpoint",
        "azure-key-vault-public-network-access",
        "azure-key-vault-missing-private-endpoint",
        "azure-key-vault-privileged-access",
        "azure-key-vault-purge-protection-disabled",
        "azure-key-vault-secret-certificate-lifecycle-incomplete",
        "azure-key-vault-key-strength-weak",
        "azure-key-vault-key-rotation-policy-incomplete",
        "azure-custom-role-wildcard-management-plane",
        "azure-custom-role-authorization-management",
        "azure-custom-role-broad-management-plane",
        "azure-custom-role-broad-data-plane",
        "azure-custom-role-subscription-assignable-scope",
        "azure-custom-role-assignment-blast-radius",
        "azure-rbac-privileged-assignment",
        "azure-managed-identity-broad-rbac",
        "azure-public-workload-sensitive-resource-access",
        "azure-app-service-public-network-access-not-disabled",
        "azure-app-service-platform-authentication-disabled",
        "azure-app-service-anonymous-platform-access-allowed",
        "azure-app-service-minimum-tls-below-1-2",
        "azure-app-service-minimum-tls-unknown",
        "azure-app-service-managed-identity-missing",
        "azure-app-service-vnet-integration-missing",
        "azure-app-service-access-restrictions-not-default-deny",
        "azure-app-service-broad-access-restriction-allow",
        "azure-app-service-scm-access-unrestricted",
        "azure-diagnostic-settings-missing",
        "azure-diagnostic-setting-no-log-destination",
        "azure-diagnostic-setting-audit-logs-incomplete",
        "azure-defender-pricing-tier-not-standard",
        "azure-security-center-auto-provisioning-disabled",
        "azure-aks-api-server-public-unrestricted",
        "azure-aks-private-cluster-not-enabled",
        "azure-aks-local-accounts-not-disabled",
        "azure-aks-rbac-posture-weak",
        "azure-aks-network-policy-missing",
        "azure-aks-workload-identity-not-enabled",
        "azure-aks-key-management-service-not-configured",
        "azure-aks-monitoring-agent-not-enabled",
        "azure-aks-defender-not-enabled",
        "azure-aks-azure-policy-not-enabled",
        "azure-sql-public-network-access-enabled",
        "azure-sql-missing-private-endpoint",
        "azure-sql-firewall-broad-public-access",
        "azure-sql-minimum-tls-below-1-2",
        "azure-sql-security-alert-policy-disabled",
        "azure-sql-short-term-backup-retention-insufficient",
        "azure-sql-long-term-backup-retention-not-configured",
        "azure-sql-backup-geo-redundancy-not-enabled",
        "azure-private-endpoint-public-fallback",
        "azure-private-endpoint-dns-posture-incomplete",
        "azure-postgresql-public-network-access-enabled",
        "azure-postgresql-firewall-broad-public-access",
        "azure-postgresql-weak-tls-or-ssl",
        "azure-postgresql-geo-backup-disabled",
    ),
    (),
    (),
    (),
    (),
    (),
)


def build_azure_rule_contribution(
    finding_factory: FindingFactory,
    metadata_registry: RuleRegistry | None = None,
) -> RuleContribution:
    compute_detectors = AzureComputeRuleDetectors(finding_factory)
    load_balancer_detectors = AzureLoadBalancerRuleDetectors(finding_factory)
    network_telemetry_detectors = AzureNetworkTelemetryRuleDetectors(finding_factory)
    app_service_detectors = AzureAppServiceRuleDetectors(finding_factory)
    audit_detectors = AzureAuditRuleDetectors(finding_factory)
    aks_detectors = AzureAksRuleDetectors(finding_factory)
    storage_detectors = AzureStorageRuleDetectors(finding_factory)
    service_bus_detectors = AzureServiceBusRuleDetectors(finding_factory)
    container_registry_detectors = AzureContainerRegistryRuleDetectors(finding_factory)
    key_vault_detectors = AzureKeyVaultRuleDetectors(finding_factory)
    custom_role_detectors = AzureCustomRoleRuleDetectors(finding_factory)
    iam_assignment_detectors = AzureIamAssignmentRuleDetectors(finding_factory)
    managed_identity_detectors = AzureManagedIdentityRuleDetectors(finding_factory)
    mssql_detectors = AzureMssqlRuleDetectors(finding_factory)
    postgresql_detectors = AzurePostgresqlRuleDetectors(finding_factory)
    private_endpoint_detectors = AzurePrivateEndpointPostureRuleDetectors(finding_factory)
    detectors_by_rule_id: Mapping[str, RuleDetector] = {
        "azure-public-compute-broad-ingress": compute_detectors.detect_public_compute_broad_ingress,
        "azure-load-balancer-public-frontend": (load_balancer_detectors.detect_public_load_balancer_frontend),
        "azure-application-gateway-public-listener": (
            load_balancer_detectors.detect_public_application_gateway_listener
        ),
        "azure-public-application-gateway-waf-missing": (
            load_balancer_detectors.detect_public_application_gateway_waf_missing
        ),
        "azure-nsg-flow-logs-not-configured": network_telemetry_detectors.detect_nsg_flow_logs_not_configured,
        "azure-nsg-flow-log-disabled": network_telemetry_detectors.detect_flow_log_disabled,
        "azure-nsg-flow-log-destination-missing": (network_telemetry_detectors.detect_flow_log_destination_missing),
        "azure-nsg-flow-log-retention-insufficient": (
            network_telemetry_detectors.detect_flow_log_retention_insufficient
        ),
        "azure-storage-container-public-access": storage_detectors.detect_public_container_access,
        "azure-storage-account-nested-public-access-enabled": (storage_detectors.detect_nested_public_access_enabled),
        "azure-storage-account-shared-key-enabled": storage_detectors.detect_shared_key_enabled,
        "azure-storage-account-minimum-tls-below-1-2": storage_detectors.detect_minimum_tls_below_1_2,
        "azure-storage-account-public-network-unrestricted": (storage_detectors.detect_unrestricted_public_network),
        "azure-storage-account-customer-managed-key-missing": (storage_detectors.detect_customer_managed_key_missing),
        "azure-storage-account-infrastructure-encryption-not-enabled": (
            storage_detectors.detect_infrastructure_encryption_not_enabled
        ),
        "azure-storage-account-blob-versioning-disabled": storage_detectors.detect_blob_versioning_disabled,
        "azure-storage-account-blob-soft-delete-insufficient": (storage_detectors.detect_blob_soft_delete_insufficient),
        "azure-storage-account-container-soft-delete-insufficient": (
            storage_detectors.detect_container_soft_delete_insufficient
        ),
        "azure-storage-account-point-in-time-restore-missing": (storage_detectors.detect_point_in_time_restore_missing),
        "azure-storage-account-missing-private-endpoint": (
            private_endpoint_detectors.detect_storage_account_missing_private_endpoint
        ),
        "azure-service-bus-public-network-access-not-disabled": (
            service_bus_detectors.detect_public_network_access_not_disabled
        ),
        "azure-service-bus-minimum-tls-below-1-2": (service_bus_detectors.detect_minimum_tls_below_1_2),
        "azure-service-bus-minimum-tls-unknown": service_bus_detectors.detect_minimum_tls_unknown,
        "azure-service-bus-local-auth-enabled": service_bus_detectors.detect_local_auth_enabled,
        "azure-service-bus-customer-managed-key-missing": (service_bus_detectors.detect_customer_managed_key_missing),
        "azure-service-bus-missing-private-endpoint": (
            private_endpoint_detectors.detect_service_bus_namespace_missing_private_endpoint
        ),
        "azure-container-registry-public-network-access-not-disabled": (
            container_registry_detectors.detect_public_network_access_not_disabled
        ),
        "azure-container-registry-admin-account-enabled": (container_registry_detectors.detect_admin_account_enabled),
        "azure-container-registry-anonymous-pull-enabled": (container_registry_detectors.detect_anonymous_pull_enabled),
        "azure-container-registry-customer-managed-key-missing": (
            container_registry_detectors.detect_customer_managed_key_missing
        ),
        "azure-container-registry-missing-private-endpoint": (
            private_endpoint_detectors.detect_container_registry_missing_private_endpoint
        ),
        "azure-key-vault-public-network-access": key_vault_detectors.detect_public_network_access,
        "azure-key-vault-missing-private-endpoint": (
            private_endpoint_detectors.detect_key_vault_missing_private_endpoint
        ),
        "azure-key-vault-privileged-access": key_vault_detectors.detect_privileged_access,
        "azure-key-vault-purge-protection-disabled": (key_vault_detectors.detect_purge_protection_disabled),
        "azure-key-vault-secret-certificate-lifecycle-incomplete": (
            key_vault_detectors.detect_secret_certificate_lifecycle_incomplete
        ),
        "azure-key-vault-key-strength-weak": key_vault_detectors.detect_key_strength_weak,
        "azure-key-vault-key-rotation-policy-incomplete": (key_vault_detectors.detect_key_rotation_policy_incomplete),
        "azure-custom-role-wildcard-management-plane": (custom_role_detectors.detect_wildcard_management_plane),
        "azure-custom-role-authorization-management": custom_role_detectors.detect_authorization_management,
        "azure-custom-role-broad-management-plane": custom_role_detectors.detect_broad_management_plane,
        "azure-custom-role-broad-data-plane": custom_role_detectors.detect_broad_data_plane,
        "azure-custom-role-subscription-assignable-scope": (custom_role_detectors.detect_subscription_assignable_scope),
        "azure-custom-role-assignment-blast-radius": (custom_role_detectors.detect_assigned_custom_role_blast_radius),
        "azure-rbac-privileged-assignment": iam_assignment_detectors.detect_privileged_assignment,
        "azure-managed-identity-broad-rbac": managed_identity_detectors.detect_broad_rbac,
        "azure-public-workload-sensitive-resource-access": (
            managed_identity_detectors.detect_public_workload_sensitive_resource_access
        ),
        "azure-app-service-public-network-access-not-disabled": (
            app_service_detectors.detect_public_network_access_not_disabled
        ),
        "azure-app-service-platform-authentication-disabled": (
            app_service_detectors.detect_platform_authentication_disabled
        ),
        "azure-app-service-anonymous-platform-access-allowed": (
            app_service_detectors.detect_anonymous_platform_access_allowed
        ),
        "azure-app-service-minimum-tls-below-1-2": app_service_detectors.detect_minimum_tls_below_1_2,
        "azure-app-service-minimum-tls-unknown": app_service_detectors.detect_minimum_tls_unknown,
        "azure-app-service-managed-identity-missing": app_service_detectors.detect_managed_identity_missing,
        "azure-app-service-vnet-integration-missing": app_service_detectors.detect_vnet_integration_missing,
        "azure-app-service-access-restrictions-not-default-deny": (
            app_service_detectors.detect_access_restrictions_not_default_deny
        ),
        "azure-app-service-broad-access-restriction-allow": (
            app_service_detectors.detect_broad_access_restriction_allow
        ),
        "azure-app-service-scm-access-unrestricted": app_service_detectors.detect_scm_access_unrestricted,
        "azure-diagnostic-settings-missing": audit_detectors.detect_missing_diagnostic_settings,
        "azure-diagnostic-setting-no-log-destination": audit_detectors.detect_diagnostic_setting_no_log_destination,
        "azure-diagnostic-setting-audit-logs-incomplete": (
            audit_detectors.detect_diagnostic_setting_audit_logs_incomplete
        ),
        "azure-defender-pricing-tier-not-standard": audit_detectors.detect_defender_pricing_tier_not_standard,
        "azure-security-center-auto-provisioning-disabled": (
            audit_detectors.detect_security_center_auto_provisioning_disabled
        ),
        "azure-aks-api-server-public-unrestricted": aks_detectors.detect_public_api_server_unrestricted,
        "azure-aks-private-cluster-not-enabled": aks_detectors.detect_private_cluster_not_enabled,
        "azure-aks-local-accounts-not-disabled": aks_detectors.detect_local_accounts_not_disabled,
        "azure-aks-rbac-posture-weak": aks_detectors.detect_rbac_posture_weak,
        "azure-aks-network-policy-missing": aks_detectors.detect_network_policy_missing,
        "azure-aks-workload-identity-not-enabled": aks_detectors.detect_workload_identity_not_enabled,
        "azure-aks-key-management-service-not-configured": (aks_detectors.detect_key_management_service_not_configured),
        "azure-aks-monitoring-agent-not-enabled": aks_detectors.detect_monitoring_agent_not_enabled,
        "azure-aks-defender-not-enabled": aks_detectors.detect_defender_not_enabled,
        "azure-aks-azure-policy-not-enabled": aks_detectors.detect_azure_policy_not_enabled,
        "azure-sql-public-network-access-enabled": mssql_detectors.detect_public_network_access_enabled,
        "azure-sql-missing-private-endpoint": (private_endpoint_detectors.detect_sql_server_missing_private_endpoint),
        "azure-sql-firewall-broad-public-access": mssql_detectors.detect_broad_firewall_access,
        "azure-sql-minimum-tls-below-1-2": mssql_detectors.detect_minimum_tls_below_1_2,
        "azure-sql-security-alert-policy-disabled": mssql_detectors.detect_security_alert_policy_disabled,
        "azure-sql-short-term-backup-retention-insufficient": (
            mssql_detectors.detect_short_term_backup_retention_insufficient
        ),
        "azure-sql-long-term-backup-retention-not-configured": (
            mssql_detectors.detect_long_term_backup_retention_not_configured
        ),
        "azure-sql-backup-geo-redundancy-not-enabled": (mssql_detectors.detect_backup_geo_redundancy_not_enabled),
        "azure-private-endpoint-public-fallback": (private_endpoint_detectors.detect_private_endpoint_public_fallback),
        "azure-private-endpoint-dns-posture-incomplete": (
            private_endpoint_detectors.detect_private_endpoint_dns_posture_incomplete
        ),
        "azure-postgresql-public-network-access-enabled": postgresql_detectors.detect_public_network_access_enabled,
        "azure-postgresql-firewall-broad-public-access": postgresql_detectors.detect_broad_firewall_access,
        "azure-postgresql-weak-tls-or-ssl": postgresql_detectors.detect_weak_tls_or_ssl,
        "azure-postgresql-geo-backup-disabled": postgresql_detectors.detect_geo_backup_disabled,
    }
    resolved_metadata_registry = metadata_registry if metadata_registry is not None else default_rule_registry()
    return build_rule_contribution(
        (
            tuple((rule_id, detectors_by_rule_id[rule_id]) for rule_id in rule_group)
            for rule_group in AZURE_RULE_GROUP_IDS
        ),
        resolved_metadata_registry,
    )
