from __future__ import annotations

from types import MappingProxyType

from tfstride.providers.resource_capabilities import ResourceCapability


GCP_RESOURCE_CAPABILITIES = MappingProxyType(
    {
        ResourceCapability.WORKLOAD: frozenset({"google_compute_instance"}),
        ResourceCapability.PUBLIC_COMPUTE: frozenset({"google_compute_instance"}),
        ResourceCapability.DATA_STORE: frozenset({"google_sql_database_instance", "google_storage_bucket"}),
        ResourceCapability.PUBLIC_EDGE: frozenset(
            {
                "google_compute_instance",
                "google_sql_database_instance",
                "google_storage_bucket",
            }
        ),
        ResourceCapability.IDENTITY_ROLE: frozenset({"google_service_account"}),
        ResourceCapability.IAM_POLICY: frozenset(
            {
                "google_project_iam_member",
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
    }
)