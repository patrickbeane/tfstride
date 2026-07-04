from __future__ import annotations

from collections.abc import Mapping

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.gcp.rules import GcpRuleDetectors
from tfstride.analysis.rule_definitions import RuleContribution, RuleDetector, build_rule_contribution
from tfstride.analysis.rule_registry import RuleRegistry, default_rule_registry
from tfstride.providers.gcp.audit_rules import GcpAuditRuleDetectors
from tfstride.providers.gcp.path_chain_rules import GcpPathChainRuleDetectors
from tfstride.providers.gcp.private_connectivity_rules import GcpPrivateConnectivityRuleDetectors

GCP_RULE_GROUP_IDS: tuple[tuple[str, ...], ...] = (
    (
        "gcp-sensitive-resource-iam-external-access",
        "gcp-pubsub-public-access",
        "gcp-bigquery-public-access",
        "gcp-cloud-sql-public-authorized-network",
        "gcp-cloud-sql-backup-disabled",
        "gcp-cloud-sql-public-ip-without-private-network",
        "gcp-cloud-sql-ssl-not-required",
        "gcp-cloud-sql-point-in-time-recovery-disabled",
        "gcp-cloud-sql-deletion-protection-disabled",
        "gcp-cloud-sql-private-connectivity-not-modeled",
        "gcp-private-workload-private-google-access-disabled",
        "gcp-gcs-public-access",
        "gcp-gcs-uniform-bucket-level-access-disabled",
        "gcp-gcs-public-access-prevention-not-enforced",
        "gcp-gcs-versioning-disabled",
        "gcp-gcs-customer-managed-encryption-missing",
        "gcp-gcs-retention-policy-insufficient",
        "gcp-secret-manager-customer-managed-encryption-missing",
        "gcp-secret-manager-lifecycle-posture-incomplete",
        "gcp-kms-key-rotation-not-configured-or-too-long",
        "gcp-kms-key-destroy-scheduled-duration-too-short",
        "gcp-public-compute-broad-ingress",
        "gcp-public-load-balanced-workload",
        "gcp-load-balancer-http-public-proxy",
        "gcp-load-balancer-ssl-policy-missing-or-weak",
        "gcp-compute-os-login-disabled",
        "gcp-gke-public-control-plane",
        "gcp-gke-broad-authorized-networks",
        "gcp-gke-workload-identity-disabled",
        "gcp-gke-legacy-metadata-endpoints-enabled",
        "gcp-gke-broad-node-service-account",
        "gcp-gke-control-plane-logging-incomplete",
        "gcp-scc-asset-discovery-disabled",
        "gcp-logging-exclusion-drops-audit-security-logs",
        "gcp-central-audit-sink-not-modeled",
        "gcp-gke-network-policy-disabled",
        "gcp-gke-secrets-encryption-not-configured",
        "gcp-gke-legacy-abac-enabled-or-unknown",
        "gcp-gke-client-certificate-auth-enabled-or-unknown",
        "gcp-gke-shielded-nodes-disabled-or-unknown",
        "gcp-gke-binary-authorization-not-enabled",
        "gcp-cloud-run-public-invoker",
        "gcp-cloud-functions-public-invoker",
    ),
    (),
    (),
    (
        "gcp-service-account-iam-broad-principal",
        "gcp-service-account-iam-privileged-role",
        "gcp-service-account-key-hygiene",
        "gcp-service-account-key-effective-access",
        "gcp-org-folder-iam-broad-principal",
        "gcp-org-folder-iam-privileged-role",
        "gcp-project-iam-broad-principal",
        "gcp-project-iam-privileged-role",
        "gcp-inherited-iam-sensitive-resource-access",
        "gcp-inherited-iam-blast-radius",
    ),
    ("gcp-public-workload-sensitive-data-access",),
    (),
)


def build_gcp_rule_contribution(
    finding_factory: FindingFactory,
    metadata_registry: RuleRegistry | None = None,
) -> RuleContribution:
    gcp_detectors = GcpRuleDetectors(finding_factory)
    audit_detectors = GcpAuditRuleDetectors(finding_factory)
    private_connectivity_detectors = GcpPrivateConnectivityRuleDetectors(finding_factory)
    path_chain_detectors = GcpPathChainRuleDetectors(finding_factory)
    detectors_by_rule_id: Mapping[str, RuleDetector] = {
        "gcp-sensitive-resource-iam-external-access": gcp_detectors.detect_sensitive_iam_external_access,
        "gcp-pubsub-public-access": gcp_detectors.detect_pubsub_public_access,
        "gcp-bigquery-public-access": gcp_detectors.detect_bigquery_public_access,
        "gcp-cloud-sql-public-authorized-network": gcp_detectors.detect_cloud_sql_public_authorized_network,
        "gcp-cloud-sql-backup-disabled": gcp_detectors.detect_cloud_sql_backup_disabled,
        "gcp-cloud-sql-public-ip-without-private-network": (
            gcp_detectors.detect_cloud_sql_public_ip_without_private_network
        ),
        "gcp-cloud-sql-ssl-not-required": gcp_detectors.detect_cloud_sql_ssl_not_required,
        "gcp-cloud-sql-point-in-time-recovery-disabled": (
            gcp_detectors.detect_cloud_sql_point_in_time_recovery_disabled
        ),
        "gcp-cloud-sql-deletion-protection-disabled": gcp_detectors.detect_cloud_sql_deletion_protection_disabled,
        "gcp-cloud-sql-private-connectivity-not-modeled": (
            private_connectivity_detectors.detect_cloud_sql_private_connectivity_not_modeled
        ),
        "gcp-private-workload-private-google-access-disabled": (
            private_connectivity_detectors.detect_private_workload_private_google_access_disabled
        ),
        "gcp-gcs-public-access": gcp_detectors.detect_gcs_public_access,
        "gcp-gcs-uniform-bucket-level-access-disabled": gcp_detectors.detect_gcs_uniform_bucket_level_access_disabled,
        "gcp-gcs-public-access-prevention-not-enforced": (
            gcp_detectors.detect_gcs_public_access_prevention_not_enforced
        ),
        "gcp-gcs-versioning-disabled": gcp_detectors.detect_gcs_versioning_disabled,
        "gcp-gcs-customer-managed-encryption-missing": gcp_detectors.detect_gcs_customer_managed_encryption_missing,
        "gcp-gcs-retention-policy-insufficient": gcp_detectors.detect_gcs_retention_policy_insufficient,
        "gcp-secret-manager-customer-managed-encryption-missing": (
            gcp_detectors.detect_secret_manager_customer_managed_encryption_missing
        ),
        "gcp-secret-manager-lifecycle-posture-incomplete": (
            gcp_detectors.detect_secret_manager_lifecycle_posture_incomplete
        ),
        "gcp-kms-key-rotation-not-configured-or-too-long": (
            gcp_detectors.detect_kms_key_rotation_not_configured_or_too_long
        ),
        "gcp-kms-key-destroy-scheduled-duration-too-short": (
            gcp_detectors.detect_kms_key_destroy_scheduled_duration_too_short
        ),
        "gcp-public-compute-broad-ingress": gcp_detectors.detect_public_compute_broad_ingress,
        "gcp-public-load-balanced-workload": gcp_detectors.detect_public_load_balanced_workload,
        "gcp-load-balancer-http-public-proxy": gcp_detectors.detect_public_load_balancer_http_frontend,
        "gcp-load-balancer-ssl-policy-missing-or-weak": (
            gcp_detectors.detect_public_load_balancer_ssl_policy_missing_or_weak
        ),
        "gcp-compute-os-login-disabled": gcp_detectors.detect_compute_os_login_disabled,
        "gcp-gke-public-control-plane": gcp_detectors.detect_gke_public_control_plane,
        "gcp-gke-broad-authorized-networks": gcp_detectors.detect_gke_broad_authorized_networks,
        "gcp-gke-workload-identity-disabled": gcp_detectors.detect_gke_workload_identity_disabled,
        "gcp-gke-legacy-metadata-endpoints-enabled": gcp_detectors.detect_gke_legacy_metadata_endpoints_enabled,
        "gcp-gke-broad-node-service-account": gcp_detectors.detect_gke_broad_node_service_account,
        "gcp-gke-control-plane-logging-incomplete": gcp_detectors.detect_gke_control_plane_logging_incomplete,
        "gcp-scc-asset-discovery-disabled": audit_detectors.detect_scc_asset_discovery_disabled,
        "gcp-logging-exclusion-drops-audit-security-logs": (
            audit_detectors.detect_logging_exclusion_drops_audit_security_logs
        ),
        "gcp-central-audit-sink-not-modeled": audit_detectors.detect_central_audit_sink_not_modeled,
        "gcp-gke-network-policy-disabled": gcp_detectors.detect_gke_network_policy_disabled,
        "gcp-gke-secrets-encryption-not-configured": gcp_detectors.detect_gke_secrets_encryption_not_configured,
        "gcp-gke-legacy-abac-enabled-or-unknown": gcp_detectors.detect_gke_legacy_abac_enabled_or_unknown,
        "gcp-gke-client-certificate-auth-enabled-or-unknown": (
            gcp_detectors.detect_gke_client_certificate_auth_enabled_or_unknown
        ),
        "gcp-gke-shielded-nodes-disabled-or-unknown": gcp_detectors.detect_gke_shielded_nodes_disabled_or_unknown,
        "gcp-gke-binary-authorization-not-enabled": gcp_detectors.detect_gke_binary_authorization_not_enabled,
        "gcp-cloud-run-public-invoker": gcp_detectors.detect_cloud_run_public_invoker,
        "gcp-cloud-functions-public-invoker": gcp_detectors.detect_cloud_function_public_invoker,
        "gcp-service-account-iam-broad-principal": gcp_detectors.detect_service_account_iam_broad_principal,
        "gcp-service-account-iam-privileged-role": gcp_detectors.detect_service_account_iam_privileged_role,
        "gcp-service-account-key-hygiene": gcp_detectors.detect_service_account_key_hygiene,
        "gcp-service-account-key-effective-access": gcp_detectors.detect_service_account_key_effective_access,
        "gcp-org-folder-iam-broad-principal": gcp_detectors.detect_org_folder_iam_broad_principal,
        "gcp-org-folder-iam-privileged-role": gcp_detectors.detect_org_folder_iam_privileged_role,
        "gcp-project-iam-broad-principal": gcp_detectors.detect_project_iam_broad_principal,
        "gcp-project-iam-privileged-role": gcp_detectors.detect_project_iam_privileged_role,
        "gcp-inherited-iam-sensitive-resource-access": gcp_detectors.detect_inherited_iam_sensitive_resource_access,
        "gcp-inherited-iam-blast-radius": gcp_detectors.detect_inherited_iam_blast_radius,
        "gcp-public-workload-sensitive-data-access": (
            path_chain_detectors.detect_public_workload_sensitive_data_access
        ),
    }
    resolved_metadata_registry = metadata_registry if metadata_registry is not None else default_rule_registry()
    return build_rule_contribution(
        (
            tuple((rule_id, detectors_by_rule_id[rule_id]) for rule_id in rule_group)
            for rule_group in GCP_RULE_GROUP_IDS
        ),
        resolved_metadata_registry,
    )
