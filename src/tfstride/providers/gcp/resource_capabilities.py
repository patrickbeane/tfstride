from __future__ import annotations

from types import MappingProxyType

from tfstride.providers.gcp.constants import (
    GCP_IAM_POLICY_RESOURCE_TYPES,
    GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES,
)
from tfstride.providers.resource_capabilities import ResourceCapability


GCP_RESOURCE_CAPABILITIES = MappingProxyType(
    {
        ResourceCapability.WORKLOAD: GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES
        | frozenset({"google_compute_instance"}),
        ResourceCapability.PUBLIC_COMPUTE: GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES
        | frozenset({"google_compute_instance"}),
        ResourceCapability.DATA_STORE: frozenset(
            {
                "google_bigquery_dataset",
                "google_bigquery_table",
                "google_pubsub_subscription",
                "google_pubsub_topic",
                "google_secret_manager_secret",
                "google_sql_database_instance",
                "google_storage_bucket",
            }
        ),
        ResourceCapability.PUBLIC_EDGE: GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES
        | frozenset(
            {
                "google_compute_forwarding_rule",
                "google_compute_global_forwarding_rule",
                "google_compute_instance",
                "google_container_cluster",
                "google_sql_database_instance",
                "google_storage_bucket",
            }
        ),
        ResourceCapability.IDENTITY_ROLE: frozenset({"google_service_account"}),
        ResourceCapability.IAM_POLICY: GCP_IAM_POLICY_RESOURCE_TYPES,
        ResourceCapability.NETWORK_SECURITY_GROUP: frozenset({"google_compute_firewall"}),
        ResourceCapability.SUBNET: frozenset({"google_compute_subnetwork"}),
        ResourceCapability.DATABASE: frozenset({"google_sql_database_instance"}),
        ResourceCapability.OBJECT_STORAGE: frozenset({"google_storage_bucket"}),
        ResourceCapability.SECRET_STORE: frozenset({"google_secret_manager_secret"}),
        ResourceCapability.CONTROL_PLANE_SENSITIVE_DATA_STORE: frozenset({"google_secret_manager_secret"}),
        ResourceCapability.KEY_MANAGEMENT: frozenset({"google_kms_crypto_key"}),
        ResourceCapability.PROVIDER_MANAGED_EGRESS_WITHOUT_VPC: GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES,
        ResourceCapability.SENSITIVE_RESOURCE_POLICY: frozenset(
            {
                "google_bigquery_dataset",
                "google_bigquery_table",
                "google_kms_crypto_key",
                "google_pubsub_subscription",
                "google_pubsub_topic",
                "google_secret_manager_secret",
                "google_storage_bucket",
            }
        ),
    }
)