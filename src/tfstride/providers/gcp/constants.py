from __future__ import annotations


PUBLIC_GCP_IAM_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})

GCP_CLOUD_RUN_RESOURCE_TYPES = frozenset(
    {
        "google_cloud_run_service",
        "google_cloud_run_v2_service",
    }
)
GCP_CLOUD_FUNCTION_RESOURCE_TYPES = frozenset(
    {
        "google_cloudfunctions_function",
        "google_cloudfunctions2_function",
    }
)
GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES = (
    GCP_CLOUD_RUN_RESOURCE_TYPES | GCP_CLOUD_FUNCTION_RESOURCE_TYPES
)
GCP_GKE_RESOURCE_TYPES = frozenset({"google_container_cluster", "google_container_node_pool"})

GCP_PROJECT_IAM_RESOURCE_TYPES = frozenset(
    {"google_project_iam_binding", "google_project_iam_member", "google_project_iam_policy"}
)
GCP_ORGANIZATION_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_organization_iam_binding",
        "google_organization_iam_member",
        "google_organization_iam_policy",
    }
)
GCP_FOLDER_IAM_RESOURCE_TYPES = frozenset(
    {"google_folder_iam_binding", "google_folder_iam_member", "google_folder_iam_policy"}
)
GCP_ORG_FOLDER_IAM_RESOURCE_TYPES = (
    GCP_ORGANIZATION_IAM_RESOURCE_TYPES | GCP_FOLDER_IAM_RESOURCE_TYPES
)
GCP_ORGANIZATION_POLICY_RESOURCE_TYPES = frozenset(
    {
        "google_org_policy_policy",
        "google_organization_policy",
        "google_folder_organization_policy",
        "google_project_organization_policy",
    }
)
GCP_CUSTOM_ROLE_RESOURCE_TYPES = frozenset(
    {
        "google_organization_iam_custom_role",
        "google_project_iam_custom_role",
    }
)
GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_service_account_iam_binding",
        "google_service_account_iam_member",
        "google_service_account_iam_policy",
    }
)
GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_storage_bucket_iam_binding",
        "google_storage_bucket_iam_member",
        "google_storage_bucket_iam_policy",
    }
)
GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_secret_manager_secret_iam_binding",
        "google_secret_manager_secret_iam_member",
        "google_secret_manager_secret_iam_policy",
    }
)
GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_pubsub_topic_iam_binding",
        "google_pubsub_topic_iam_member",
        "google_pubsub_topic_iam_policy",
    }
)
GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_pubsub_subscription_iam_binding",
        "google_pubsub_subscription_iam_member",
        "google_pubsub_subscription_iam_policy",
    }
)
GCP_BIGQUERY_DATASET_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_bigquery_dataset_iam_binding",
        "google_bigquery_dataset_iam_member",
        "google_bigquery_dataset_iam_policy",
    }
)
GCP_BIGQUERY_TABLE_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_bigquery_table_iam_binding",
        "google_bigquery_table_iam_member",
        "google_bigquery_table_iam_policy",
    }
)
GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_kms_crypto_key_iam_binding",
        "google_kms_crypto_key_iam_member",
        "google_kms_crypto_key_iam_policy",
    }
)
GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_kms_key_ring_iam_binding",
        "google_kms_key_ring_iam_member",
        "google_kms_key_ring_iam_policy",
    }
)
GCP_CLOUD_RUN_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_cloud_run_service_iam_binding",
        "google_cloud_run_service_iam_member",
        "google_cloud_run_service_iam_policy",
        "google_cloud_run_v2_service_iam_binding",
        "google_cloud_run_v2_service_iam_member",
        "google_cloud_run_v2_service_iam_policy",
    }
)
GCP_CLOUD_FUNCTION_IAM_RESOURCE_TYPES = frozenset(
    {
        "google_cloudfunctions_function_iam_binding",
        "google_cloudfunctions_function_iam_member",
        "google_cloudfunctions_function_iam_policy",
        "google_cloudfunctions2_function_iam_binding",
        "google_cloudfunctions2_function_iam_member",
        "google_cloudfunctions2_function_iam_policy",
    }
)
GCP_RESOURCE_IAM_RESOURCE_TYPES = (
    GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES
    | GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES
    | GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES
    | GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES
    | GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES
    | GCP_BIGQUERY_DATASET_IAM_RESOURCE_TYPES
    | GCP_BIGQUERY_TABLE_IAM_RESOURCE_TYPES
    | GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES
    | GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES
    | GCP_CLOUD_RUN_IAM_RESOURCE_TYPES
    | GCP_CLOUD_FUNCTION_IAM_RESOURCE_TYPES
)
GCP_IAM_GRANT_RESOURCE_TYPES = (
    GCP_PROJECT_IAM_RESOURCE_TYPES
    | GCP_ORGANIZATION_IAM_RESOURCE_TYPES
    | GCP_FOLDER_IAM_RESOURCE_TYPES
    | GCP_RESOURCE_IAM_RESOURCE_TYPES
)
GCP_IAM_POLICY_RESOURCE_TYPES = GCP_IAM_GRANT_RESOURCE_TYPES | GCP_CUSTOM_ROLE_RESOURCE_TYPES