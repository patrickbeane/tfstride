from __future__ import annotations

from types import MappingProxyType

from tfstride.providers.resource_capabilities import ResourceCapability


GCP_RESOURCE_CAPABILITIES = MappingProxyType(
    {
        ResourceCapability.WORKLOAD: frozenset({"google_compute_instance"}),
        ResourceCapability.PUBLIC_COMPUTE: frozenset({"google_compute_instance"}),
        ResourceCapability.DATA_STORE: frozenset({"google_secret_manager_secret", "google_sql_database_instance", "google_storage_bucket"}),
        ResourceCapability.PUBLIC_EDGE: frozenset(
            {
                "google_compute_forwarding_rule",
                "google_compute_global_forwarding_rule",
                "google_compute_instance",
                "google_sql_database_instance",
                "google_storage_bucket",
            }
        ),
        ResourceCapability.IDENTITY_ROLE: frozenset({"google_service_account"}),
        ResourceCapability.IAM_POLICY: frozenset(
            {
                "google_kms_crypto_key_iam_binding",
                "google_kms_crypto_key_iam_member",
                "google_kms_crypto_key_iam_policy",
                "google_project_iam_member",
                "google_secret_manager_secret_iam_binding",
                "google_secret_manager_secret_iam_member",
                "google_secret_manager_secret_iam_policy",
                "google_service_account_iam_binding",
                "google_service_account_iam_member",
                "google_service_account_iam_policy",
                "google_storage_bucket_iam_binding",
                "google_storage_bucket_iam_member",
                "google_storage_bucket_iam_policy",
            }
        ),
        ResourceCapability.NETWORK_SECURITY_GROUP: frozenset({"google_compute_firewall"}),
        ResourceCapability.SUBNET: frozenset({"google_compute_subnetwork"}),
        ResourceCapability.DATABASE: frozenset({"google_sql_database_instance"}),
        ResourceCapability.OBJECT_STORAGE: frozenset({"google_storage_bucket"}),
        ResourceCapability.SECRET_STORE: frozenset({"google_secret_manager_secret"}),
        ResourceCapability.CONTROL_PLANE_SENSITIVE_DATA_STORE: frozenset({"google_secret_manager_secret"}),
        ResourceCapability.KEY_MANAGEMENT: frozenset({"google_kms_crypto_key"}),
        ResourceCapability.SENSITIVE_RESOURCE_POLICY: frozenset(
            {
                "google_kms_crypto_key",
                "google_secret_manager_secret",
                "google_storage_bucket",
            }
        ),
    }
)