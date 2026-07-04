from __future__ import annotations


class GcpResourceType:
    """Terraform Google provider resource type identifiers."""

    PREFIX = "google_"

    BIGQUERY_DATASET = "google_bigquery_dataset"
    BIGQUERY_DATASET_IAM_BINDING = "google_bigquery_dataset_iam_binding"
    BIGQUERY_DATASET_IAM_MEMBER = "google_bigquery_dataset_iam_member"
    BIGQUERY_DATASET_IAM_POLICY = "google_bigquery_dataset_iam_policy"
    BIGQUERY_TABLE = "google_bigquery_table"
    BIGQUERY_TABLE_IAM_BINDING = "google_bigquery_table_iam_binding"
    BIGQUERY_TABLE_IAM_MEMBER = "google_bigquery_table_iam_member"
    BIGQUERY_TABLE_IAM_POLICY = "google_bigquery_table_iam_policy"
    CLOUD_RUN_SERVICE = "google_cloud_run_service"
    CLOUD_RUN_SERVICE_IAM_BINDING = "google_cloud_run_service_iam_binding"
    CLOUD_RUN_SERVICE_IAM_MEMBER = "google_cloud_run_service_iam_member"
    CLOUD_RUN_SERVICE_IAM_POLICY = "google_cloud_run_service_iam_policy"
    CLOUD_RUN_V2_SERVICE = "google_cloud_run_v2_service"
    CLOUD_RUN_V2_SERVICE_IAM_BINDING = "google_cloud_run_v2_service_iam_binding"
    CLOUD_RUN_V2_SERVICE_IAM_MEMBER = "google_cloud_run_v2_service_iam_member"
    CLOUD_RUN_V2_SERVICE_IAM_POLICY = "google_cloud_run_v2_service_iam_policy"
    CLOUDFUNCTIONS_FUNCTION = "google_cloudfunctions_function"
    CLOUDFUNCTIONS_FUNCTION_IAM_BINDING = "google_cloudfunctions_function_iam_binding"
    CLOUDFUNCTIONS_FUNCTION_IAM_MEMBER = "google_cloudfunctions_function_iam_member"
    CLOUDFUNCTIONS_FUNCTION_IAM_POLICY = "google_cloudfunctions_function_iam_policy"
    CLOUDFUNCTIONS2_FUNCTION = "google_cloudfunctions2_function"
    CLOUDFUNCTIONS2_FUNCTION_IAM_BINDING = "google_cloudfunctions2_function_iam_binding"
    CLOUDFUNCTIONS2_FUNCTION_IAM_MEMBER = "google_cloudfunctions2_function_iam_member"
    CLOUDFUNCTIONS2_FUNCTION_IAM_POLICY = "google_cloudfunctions2_function_iam_policy"
    COMPUTE_BACKEND_BUCKET = "google_compute_backend_bucket"
    COMPUTE_BACKEND_SERVICE = "google_compute_backend_service"
    COMPUTE_FIREWALL = "google_compute_firewall"
    COMPUTE_FIREWALL_POLICY = "google_compute_firewall_policy"
    COMPUTE_FIREWALL_POLICY_ASSOCIATION = "google_compute_firewall_policy_association"
    COMPUTE_FIREWALL_POLICY_RULE = "google_compute_firewall_policy_rule"
    COMPUTE_FORWARDING_RULE = "google_compute_forwarding_rule"
    COMPUTE_GLOBAL_ADDRESS = "google_compute_global_address"
    COMPUTE_GLOBAL_FORWARDING_RULE = "google_compute_global_forwarding_rule"
    COMPUTE_MANAGED_SSL_CERTIFICATE = "google_compute_managed_ssl_certificate"
    COMPUTE_INSTANCE = "google_compute_instance"
    COMPUTE_NETWORK = "google_compute_network"
    COMPUTE_NETWORK_ENDPOINT_GROUP = "google_compute_network_endpoint_group"
    COMPUTE_REGION_BACKEND_SERVICE = "google_compute_region_backend_service"
    COMPUTE_REGION_NETWORK_ENDPOINT_GROUP = "google_compute_region_network_endpoint_group"
    COMPUTE_REGION_TARGET_HTTP_PROXY = "google_compute_region_target_http_proxy"
    COMPUTE_REGION_TARGET_HTTPS_PROXY = "google_compute_region_target_https_proxy"
    COMPUTE_REGION_URL_MAP = "google_compute_region_url_map"
    COMPUTE_SERVICE_ATTACHMENT = "google_compute_service_attachment"
    COMPUTE_ROUTE = "google_compute_route"
    COMPUTE_ROUTER = "google_compute_router"
    COMPUTE_ROUTER_NAT = "google_compute_router_nat"
    COMPUTE_SUBNETWORK = "google_compute_subnetwork"
    COMPUTE_SSL_POLICY = "google_compute_ssl_policy"
    COMPUTE_TARGET_HTTP_PROXY = "google_compute_target_http_proxy"
    COMPUTE_TARGET_HTTPS_PROXY = "google_compute_target_https_proxy"
    COMPUTE_URL_MAP = "google_compute_url_map"
    CONTAINER_CLUSTER = "google_container_cluster"
    CONTAINER_NODE_POOL = "google_container_node_pool"
    FOLDER_IAM_BINDING = "google_folder_iam_binding"
    FOLDER_IAM_MEMBER = "google_folder_iam_member"
    FOLDER_IAM_POLICY = "google_folder_iam_policy"
    FOLDER_ORGANIZATION_POLICY = "google_folder_organization_policy"
    KMS_CRYPTO_KEY = "google_kms_crypto_key"
    KMS_CRYPTO_KEY_IAM_BINDING = "google_kms_crypto_key_iam_binding"
    KMS_CRYPTO_KEY_IAM_MEMBER = "google_kms_crypto_key_iam_member"
    KMS_CRYPTO_KEY_IAM_POLICY = "google_kms_crypto_key_iam_policy"
    KMS_KEY_RING_IAM_BINDING = "google_kms_key_ring_iam_binding"
    KMS_KEY_RING_IAM_MEMBER = "google_kms_key_ring_iam_member"
    KMS_KEY_RING_IAM_POLICY = "google_kms_key_ring_iam_policy"
    LOGGING_ORGANIZATION_EXCLUSION = "google_logging_organization_exclusion"
    LOGGING_ORGANIZATION_SINK = "google_logging_organization_sink"
    LOGGING_PROJECT_EXCLUSION = "google_logging_project_exclusion"
    LOGGING_PROJECT_SINK = "google_logging_project_sink"
    ORGANIZATION_IAM_BINDING = "google_organization_iam_binding"
    ORGANIZATION_IAM_CUSTOM_ROLE = "google_organization_iam_custom_role"
    ORGANIZATION_IAM_MEMBER = "google_organization_iam_member"
    ORGANIZATION_IAM_POLICY = "google_organization_iam_policy"
    ORGANIZATION_POLICY = "google_organization_policy"
    ORG_POLICY_POLICY = "google_org_policy_policy"
    PROJECT_IAM_BINDING = "google_project_iam_binding"
    PROJECT_IAM_CUSTOM_ROLE = "google_project_iam_custom_role"
    PROJECT_IAM_MEMBER = "google_project_iam_member"
    PROJECT_IAM_POLICY = "google_project_iam_policy"
    PROJECT_ORGANIZATION_POLICY = "google_project_organization_policy"
    NETWORK_CONNECTIVITY_SERVICE_CONNECTION_POLICY = "google_network_connectivity_service_connection_policy"
    PUBSUB_SUBSCRIPTION = "google_pubsub_subscription"
    PUBSUB_SUBSCRIPTION_IAM_BINDING = "google_pubsub_subscription_iam_binding"
    PUBSUB_SUBSCRIPTION_IAM_MEMBER = "google_pubsub_subscription_iam_member"
    PUBSUB_SUBSCRIPTION_IAM_POLICY = "google_pubsub_subscription_iam_policy"
    PUBSUB_TOPIC = "google_pubsub_topic"
    PUBSUB_TOPIC_IAM_BINDING = "google_pubsub_topic_iam_binding"
    PUBSUB_TOPIC_IAM_MEMBER = "google_pubsub_topic_iam_member"
    PUBSUB_TOPIC_IAM_POLICY = "google_pubsub_topic_iam_policy"
    SECRET_MANAGER_SECRET = "google_secret_manager_secret"
    SECRET_MANAGER_SECRET_IAM_BINDING = "google_secret_manager_secret_iam_binding"
    SECRET_MANAGER_SECRET_IAM_MEMBER = "google_secret_manager_secret_iam_member"
    SECRET_MANAGER_SECRET_IAM_POLICY = "google_secret_manager_secret_iam_policy"
    SERVICE_NETWORKING_CONNECTION = "google_service_networking_connection"
    SERVICE_ACCOUNT = "google_service_account"
    SERVICE_ACCOUNT_IAM_BINDING = "google_service_account_iam_binding"
    SERVICE_ACCOUNT_IAM_MEMBER = "google_service_account_iam_member"
    SERVICE_ACCOUNT_IAM_POLICY = "google_service_account_iam_policy"
    SERVICE_ACCOUNT_KEY = "google_service_account_key"
    SCC_ORGANIZATION_SETTINGS = "google_scc_organization_settings"
    SQL_DATABASE_INSTANCE = "google_sql_database_instance"
    STORAGE_BUCKET = "google_storage_bucket"
    STORAGE_BUCKET_IAM_BINDING = "google_storage_bucket_iam_binding"
    STORAGE_BUCKET_IAM_MEMBER = "google_storage_bucket_iam_member"
    STORAGE_BUCKET_IAM_POLICY = "google_storage_bucket_iam_policy"


GCP_CLOUD_RUN_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.CLOUD_RUN_SERVICE,
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
    }
)
GCP_CLOUD_FUNCTION_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.CLOUDFUNCTIONS_FUNCTION,
        GcpResourceType.CLOUDFUNCTIONS2_FUNCTION,
    }
)
GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES = GCP_CLOUD_RUN_RESOURCE_TYPES | GCP_CLOUD_FUNCTION_RESOURCE_TYPES
GCP_GKE_RESOURCE_TYPES = frozenset({GcpResourceType.CONTAINER_CLUSTER, GcpResourceType.CONTAINER_NODE_POOL})
GCP_WORKLOAD_RESOURCE_TYPES = GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES | frozenset({GcpResourceType.COMPUTE_INSTANCE})

GCP_PROJECT_IAM_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.PROJECT_IAM_BINDING,
        GcpResourceType.PROJECT_IAM_MEMBER,
        GcpResourceType.PROJECT_IAM_POLICY,
    }
)
GCP_ORGANIZATION_IAM_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.ORGANIZATION_IAM_BINDING,
        GcpResourceType.ORGANIZATION_IAM_MEMBER,
        GcpResourceType.ORGANIZATION_IAM_POLICY,
    }
)
GCP_FOLDER_IAM_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.FOLDER_IAM_BINDING,
        GcpResourceType.FOLDER_IAM_MEMBER,
        GcpResourceType.FOLDER_IAM_POLICY,
    }
)
GCP_ORG_FOLDER_IAM_RESOURCE_TYPES = GCP_ORGANIZATION_IAM_RESOURCE_TYPES | GCP_FOLDER_IAM_RESOURCE_TYPES
GCP_ORGANIZATION_POLICY_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.ORG_POLICY_POLICY,
        GcpResourceType.ORGANIZATION_POLICY,
        GcpResourceType.FOLDER_ORGANIZATION_POLICY,
        GcpResourceType.PROJECT_ORGANIZATION_POLICY,
    }
)
GCP_CUSTOM_ROLE_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.ORGANIZATION_IAM_CUSTOM_ROLE,
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
    }
)
GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.SERVICE_ACCOUNT_IAM_BINDING,
        GcpResourceType.SERVICE_ACCOUNT_IAM_MEMBER,
        GcpResourceType.SERVICE_ACCOUNT_IAM_POLICY,
    }
)
GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.STORAGE_BUCKET_IAM_BINDING,
        GcpResourceType.STORAGE_BUCKET_IAM_MEMBER,
        GcpResourceType.STORAGE_BUCKET_IAM_POLICY,
    }
)
GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.SECRET_MANAGER_SECRET_IAM_BINDING,
        GcpResourceType.SECRET_MANAGER_SECRET_IAM_MEMBER,
        GcpResourceType.SECRET_MANAGER_SECRET_IAM_POLICY,
    }
)
GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.PUBSUB_TOPIC_IAM_BINDING,
        GcpResourceType.PUBSUB_TOPIC_IAM_MEMBER,
        GcpResourceType.PUBSUB_TOPIC_IAM_POLICY,
    }
)
GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.PUBSUB_SUBSCRIPTION_IAM_BINDING,
        GcpResourceType.PUBSUB_SUBSCRIPTION_IAM_MEMBER,
        GcpResourceType.PUBSUB_SUBSCRIPTION_IAM_POLICY,
    }
)
GCP_BIGQUERY_DATASET_IAM_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.BIGQUERY_DATASET_IAM_BINDING,
        GcpResourceType.BIGQUERY_DATASET_IAM_MEMBER,
        GcpResourceType.BIGQUERY_DATASET_IAM_POLICY,
    }
)
GCP_BIGQUERY_TABLE_IAM_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.BIGQUERY_TABLE_IAM_BINDING,
        GcpResourceType.BIGQUERY_TABLE_IAM_MEMBER,
        GcpResourceType.BIGQUERY_TABLE_IAM_POLICY,
    }
)
GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.KMS_CRYPTO_KEY_IAM_BINDING,
        GcpResourceType.KMS_CRYPTO_KEY_IAM_MEMBER,
        GcpResourceType.KMS_CRYPTO_KEY_IAM_POLICY,
    }
)
GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.KMS_KEY_RING_IAM_BINDING,
        GcpResourceType.KMS_KEY_RING_IAM_MEMBER,
        GcpResourceType.KMS_KEY_RING_IAM_POLICY,
    }
)
GCP_CLOUD_RUN_IAM_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.CLOUD_RUN_SERVICE_IAM_BINDING,
        GcpResourceType.CLOUD_RUN_SERVICE_IAM_MEMBER,
        GcpResourceType.CLOUD_RUN_SERVICE_IAM_POLICY,
        GcpResourceType.CLOUD_RUN_V2_SERVICE_IAM_BINDING,
        GcpResourceType.CLOUD_RUN_V2_SERVICE_IAM_MEMBER,
        GcpResourceType.CLOUD_RUN_V2_SERVICE_IAM_POLICY,
    }
)
GCP_CLOUD_FUNCTION_IAM_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.CLOUDFUNCTIONS_FUNCTION_IAM_BINDING,
        GcpResourceType.CLOUDFUNCTIONS_FUNCTION_IAM_MEMBER,
        GcpResourceType.CLOUDFUNCTIONS_FUNCTION_IAM_POLICY,
        GcpResourceType.CLOUDFUNCTIONS2_FUNCTION_IAM_BINDING,
        GcpResourceType.CLOUDFUNCTIONS2_FUNCTION_IAM_MEMBER,
        GcpResourceType.CLOUDFUNCTIONS2_FUNCTION_IAM_POLICY,
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

GCP_FORWARDING_RULE_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.COMPUTE_FORWARDING_RULE,
        GcpResourceType.COMPUTE_GLOBAL_FORWARDING_RULE,
    }
)
GCP_LOAD_BALANCER_BACKEND_SERVICE_TYPES = frozenset(
    {
        GcpResourceType.COMPUTE_BACKEND_SERVICE,
        GcpResourceType.COMPUTE_REGION_BACKEND_SERVICE,
    }
)
GCP_LOAD_BALANCER_BACKEND_BUCKET_TYPES = frozenset({GcpResourceType.COMPUTE_BACKEND_BUCKET})
GCP_LOAD_BALANCER_NEG_TYPES = frozenset(
    {
        GcpResourceType.COMPUTE_NETWORK_ENDPOINT_GROUP,
        GcpResourceType.COMPUTE_REGION_NETWORK_ENDPOINT_GROUP,
    }
)
GCP_LOAD_BALANCER_TARGET_PROXY_TYPES = frozenset(
    {
        GcpResourceType.COMPUTE_TARGET_HTTP_PROXY,
        GcpResourceType.COMPUTE_TARGET_HTTPS_PROXY,
        GcpResourceType.COMPUTE_REGION_TARGET_HTTP_PROXY,
        GcpResourceType.COMPUTE_REGION_TARGET_HTTPS_PROXY,
    }
)
GCP_LOAD_BALANCER_URL_MAP_TYPES = frozenset(
    {
        GcpResourceType.COMPUTE_URL_MAP,
        GcpResourceType.COMPUTE_REGION_URL_MAP,
    }
)

GCP_DATA_STORE_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.BIGQUERY_DATASET,
        GcpResourceType.BIGQUERY_TABLE,
        GcpResourceType.PUBSUB_SUBSCRIPTION,
        GcpResourceType.PUBSUB_TOPIC,
        GcpResourceType.SECRET_MANAGER_SECRET,
        GcpResourceType.SQL_DATABASE_INSTANCE,
        GcpResourceType.STORAGE_BUCKET,
    }
)
GCP_PUBLIC_EDGE_RESOURCE_TYPES = GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES | frozenset(
    {
        GcpResourceType.COMPUTE_FORWARDING_RULE,
        GcpResourceType.COMPUTE_GLOBAL_FORWARDING_RULE,
        GcpResourceType.COMPUTE_INSTANCE,
        GcpResourceType.CONTAINER_CLUSTER,
        GcpResourceType.SQL_DATABASE_INSTANCE,
        GcpResourceType.STORAGE_BUCKET,
    }
)
GCP_NETWORK_SECURITY_GROUP_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.COMPUTE_FIREWALL,
        GcpResourceType.COMPUTE_FIREWALL_POLICY,
        GcpResourceType.COMPUTE_FIREWALL_POLICY_RULE,
    }
)
GCP_SENSITIVE_RESOURCE_POLICY_TYPES = frozenset(
    {
        GcpResourceType.BIGQUERY_DATASET,
        GcpResourceType.BIGQUERY_TABLE,
        GcpResourceType.KMS_CRYPTO_KEY,
        GcpResourceType.PUBSUB_SUBSCRIPTION,
        GcpResourceType.PUBSUB_TOPIC,
        GcpResourceType.SECRET_MANAGER_SECRET,
        GcpResourceType.STORAGE_BUCKET,
    }
)

GCP_NORMALIZED_RESOURCE_TYPES = frozenset(
    {
        GcpResourceType.COMPUTE_BACKEND_BUCKET,
        GcpResourceType.COMPUTE_BACKEND_SERVICE,
        GcpResourceType.COMPUTE_FIREWALL,
        GcpResourceType.COMPUTE_FIREWALL_POLICY,
        GcpResourceType.COMPUTE_FIREWALL_POLICY_ASSOCIATION,
        GcpResourceType.COMPUTE_FIREWALL_POLICY_RULE,
        GcpResourceType.COMPUTE_FORWARDING_RULE,
        GcpResourceType.COMPUTE_GLOBAL_ADDRESS,
        GcpResourceType.COMPUTE_GLOBAL_FORWARDING_RULE,
        GcpResourceType.COMPUTE_MANAGED_SSL_CERTIFICATE,
        GcpResourceType.COMPUTE_INSTANCE,
        GcpResourceType.COMPUTE_NETWORK,
        GcpResourceType.COMPUTE_NETWORK_ENDPOINT_GROUP,
        GcpResourceType.COMPUTE_REGION_BACKEND_SERVICE,
        GcpResourceType.COMPUTE_REGION_NETWORK_ENDPOINT_GROUP,
        GcpResourceType.COMPUTE_REGION_TARGET_HTTP_PROXY,
        GcpResourceType.COMPUTE_REGION_TARGET_HTTPS_PROXY,
        GcpResourceType.COMPUTE_REGION_URL_MAP,
        GcpResourceType.COMPUTE_SERVICE_ATTACHMENT,
        GcpResourceType.COMPUTE_ROUTE,
        GcpResourceType.COMPUTE_ROUTER,
        GcpResourceType.COMPUTE_ROUTER_NAT,
        GcpResourceType.COMPUTE_SUBNETWORK,
        GcpResourceType.COMPUTE_SSL_POLICY,
        GcpResourceType.COMPUTE_TARGET_HTTP_PROXY,
        GcpResourceType.COMPUTE_TARGET_HTTPS_PROXY,
        GcpResourceType.COMPUTE_URL_MAP,
        GcpResourceType.BIGQUERY_DATASET,
        GcpResourceType.BIGQUERY_DATASET_IAM_BINDING,
        GcpResourceType.BIGQUERY_DATASET_IAM_MEMBER,
        GcpResourceType.BIGQUERY_DATASET_IAM_POLICY,
        GcpResourceType.BIGQUERY_TABLE,
        GcpResourceType.BIGQUERY_TABLE_IAM_BINDING,
        GcpResourceType.BIGQUERY_TABLE_IAM_MEMBER,
        GcpResourceType.BIGQUERY_TABLE_IAM_POLICY,
        GcpResourceType.CLOUD_RUN_SERVICE,
        GcpResourceType.CLOUD_RUN_SERVICE_IAM_BINDING,
        GcpResourceType.CLOUD_RUN_SERVICE_IAM_MEMBER,
        GcpResourceType.CLOUD_RUN_SERVICE_IAM_POLICY,
        GcpResourceType.CLOUD_RUN_V2_SERVICE,
        GcpResourceType.CLOUD_RUN_V2_SERVICE_IAM_BINDING,
        GcpResourceType.CLOUD_RUN_V2_SERVICE_IAM_MEMBER,
        GcpResourceType.CLOUD_RUN_V2_SERVICE_IAM_POLICY,
        GcpResourceType.CLOUDFUNCTIONS_FUNCTION,
        GcpResourceType.CLOUDFUNCTIONS_FUNCTION_IAM_BINDING,
        GcpResourceType.CLOUDFUNCTIONS_FUNCTION_IAM_MEMBER,
        GcpResourceType.CLOUDFUNCTIONS_FUNCTION_IAM_POLICY,
        GcpResourceType.CLOUDFUNCTIONS2_FUNCTION,
        GcpResourceType.CLOUDFUNCTIONS2_FUNCTION_IAM_BINDING,
        GcpResourceType.CLOUDFUNCTIONS2_FUNCTION_IAM_MEMBER,
        GcpResourceType.CLOUDFUNCTIONS2_FUNCTION_IAM_POLICY,
        GcpResourceType.CONTAINER_CLUSTER,
        GcpResourceType.CONTAINER_NODE_POOL,
        GcpResourceType.KMS_CRYPTO_KEY,
        GcpResourceType.KMS_CRYPTO_KEY_IAM_BINDING,
        GcpResourceType.KMS_CRYPTO_KEY_IAM_MEMBER,
        GcpResourceType.KMS_CRYPTO_KEY_IAM_POLICY,
        GcpResourceType.KMS_KEY_RING_IAM_BINDING,
        GcpResourceType.KMS_KEY_RING_IAM_MEMBER,
        GcpResourceType.KMS_KEY_RING_IAM_POLICY,
        GcpResourceType.LOGGING_ORGANIZATION_EXCLUSION,
        GcpResourceType.LOGGING_ORGANIZATION_SINK,
        GcpResourceType.LOGGING_PROJECT_EXCLUSION,
        GcpResourceType.LOGGING_PROJECT_SINK,
        GcpResourceType.FOLDER_IAM_BINDING,
        GcpResourceType.FOLDER_IAM_MEMBER,
        GcpResourceType.FOLDER_IAM_POLICY,
        GcpResourceType.ORGANIZATION_IAM_BINDING,
        GcpResourceType.ORGANIZATION_IAM_CUSTOM_ROLE,
        GcpResourceType.ORGANIZATION_IAM_MEMBER,
        GcpResourceType.ORGANIZATION_IAM_POLICY,
        GcpResourceType.FOLDER_ORGANIZATION_POLICY,
        GcpResourceType.NETWORK_CONNECTIVITY_SERVICE_CONNECTION_POLICY,
        GcpResourceType.ORG_POLICY_POLICY,
        GcpResourceType.ORGANIZATION_POLICY,
        GcpResourceType.PROJECT_ORGANIZATION_POLICY,
        GcpResourceType.PROJECT_IAM_BINDING,
        GcpResourceType.PROJECT_IAM_CUSTOM_ROLE,
        GcpResourceType.PROJECT_IAM_MEMBER,
        GcpResourceType.PROJECT_IAM_POLICY,
        GcpResourceType.PUBSUB_SUBSCRIPTION,
        GcpResourceType.PUBSUB_SUBSCRIPTION_IAM_BINDING,
        GcpResourceType.PUBSUB_SUBSCRIPTION_IAM_MEMBER,
        GcpResourceType.PUBSUB_SUBSCRIPTION_IAM_POLICY,
        GcpResourceType.PUBSUB_TOPIC,
        GcpResourceType.PUBSUB_TOPIC_IAM_BINDING,
        GcpResourceType.PUBSUB_TOPIC_IAM_MEMBER,
        GcpResourceType.PUBSUB_TOPIC_IAM_POLICY,
        GcpResourceType.SECRET_MANAGER_SECRET,
        GcpResourceType.SECRET_MANAGER_SECRET_IAM_BINDING,
        GcpResourceType.SECRET_MANAGER_SECRET_IAM_MEMBER,
        GcpResourceType.SECRET_MANAGER_SECRET_IAM_POLICY,
        GcpResourceType.SERVICE_NETWORKING_CONNECTION,
        GcpResourceType.SERVICE_ACCOUNT,
        GcpResourceType.SERVICE_ACCOUNT_IAM_BINDING,
        GcpResourceType.SERVICE_ACCOUNT_IAM_MEMBER,
        GcpResourceType.SERVICE_ACCOUNT_IAM_POLICY,
        GcpResourceType.SERVICE_ACCOUNT_KEY,
        GcpResourceType.SCC_ORGANIZATION_SETTINGS,
        GcpResourceType.SQL_DATABASE_INSTANCE,
        GcpResourceType.STORAGE_BUCKET,
        GcpResourceType.STORAGE_BUCKET_IAM_BINDING,
        GcpResourceType.STORAGE_BUCKET_IAM_MEMBER,
        GcpResourceType.STORAGE_BUCKET_IAM_POLICY,
    }
)
