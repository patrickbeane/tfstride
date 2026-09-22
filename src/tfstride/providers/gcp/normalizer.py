from __future__ import annotations

from tfstride.models import ResourceInventory, TerraformResource
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.artifact_registry_normalizers import normalize_artifact_registry_repository
from tfstride.providers.gcp.audit_normalizers import (
    normalize_logging_organization_exclusion,
    normalize_logging_organization_sink,
    normalize_logging_project_exclusion,
    normalize_logging_project_sink,
    normalize_scc_organization_settings,
)
from tfstride.providers.gcp.compute_normalizers import normalize_compute_instance
from tfstride.providers.gcp.container_normalizers import (
    normalize_container_cluster,
    normalize_container_node_pool,
)
from tfstride.providers.gcp.data_normalizers import (
    normalize_bigquery_dataset,
    normalize_bigquery_table,
    normalize_pubsub_subscription,
    normalize_pubsub_topic,
    normalize_secret_manager_secret,
    normalize_sql_database_instance,
)
from tfstride.providers.gcp.firestore_normalizers import normalize_firestore_database
from tfstride.providers.gcp.iam_normalizers import (
    normalize_artifact_registry_repository_iam_binding,
    normalize_artifact_registry_repository_iam_member,
    normalize_artifact_registry_repository_iam_policy,
    normalize_bigquery_dataset_iam_binding,
    normalize_bigquery_dataset_iam_member,
    normalize_bigquery_dataset_iam_policy,
    normalize_bigquery_table_iam_binding,
    normalize_bigquery_table_iam_member,
    normalize_bigquery_table_iam_policy,
    normalize_folder_iam_binding,
    normalize_folder_iam_member,
    normalize_folder_iam_policy,
    normalize_iam_deny_policy,
    normalize_kms_crypto_key_iam_binding,
    normalize_kms_crypto_key_iam_member,
    normalize_kms_crypto_key_iam_policy,
    normalize_kms_key_ring_iam_binding,
    normalize_kms_key_ring_iam_member,
    normalize_kms_key_ring_iam_policy,
    normalize_organization_iam_binding,
    normalize_organization_iam_custom_role,
    normalize_organization_iam_member,
    normalize_organization_iam_policy,
    normalize_project_iam_binding,
    normalize_project_iam_custom_role,
    normalize_project_iam_member,
    normalize_project_iam_policy,
    normalize_pubsub_subscription_iam_binding,
    normalize_pubsub_subscription_iam_member,
    normalize_pubsub_subscription_iam_policy,
    normalize_pubsub_topic_iam_binding,
    normalize_pubsub_topic_iam_member,
    normalize_pubsub_topic_iam_policy,
    normalize_secret_manager_secret_iam_binding,
    normalize_secret_manager_secret_iam_member,
    normalize_secret_manager_secret_iam_policy,
    normalize_service_account,
    normalize_service_account_iam_binding,
    normalize_service_account_iam_member,
    normalize_service_account_iam_policy,
    normalize_service_account_key,
    normalize_storage_bucket_iam_binding,
    normalize_storage_bucket_iam_member,
    normalize_storage_bucket_iam_policy,
    normalize_workload_identity_pool,
    normalize_workload_identity_pool_provider,
)
from tfstride.providers.gcp.identity_normalizers import normalize_folder, normalize_kms_key_ring, normalize_project
from tfstride.providers.gcp.kms_normalizers import normalize_kms_crypto_key, normalize_kms_crypto_key_version
from tfstride.providers.gcp.network_normalizers import (
    GCP_PROVIDER,
    normalize_compute_backend_bucket,
    normalize_compute_backend_service,
    normalize_compute_firewall,
    normalize_compute_firewall_policy,
    normalize_compute_firewall_policy_association,
    normalize_compute_firewall_policy_rule,
    normalize_compute_forwarding_rule,
    normalize_compute_global_address,
    normalize_compute_global_forwarding_rule,
    normalize_compute_managed_ssl_certificate,
    normalize_compute_network,
    normalize_compute_network_endpoint_group,
    normalize_compute_region_backend_service,
    normalize_compute_region_network_endpoint_group,
    normalize_compute_region_security_policy,
    normalize_compute_region_target_http_proxy,
    normalize_compute_region_target_https_proxy,
    normalize_compute_region_url_map,
    normalize_compute_route,
    normalize_compute_router,
    normalize_compute_router_nat,
    normalize_compute_security_policy,
    normalize_compute_service_attachment,
    normalize_compute_ssl_policy,
    normalize_compute_subnetwork,
    normalize_compute_target_http_proxy,
    normalize_compute_target_https_proxy,
    normalize_compute_url_map,
    normalize_network_connectivity_service_connection_policy,
    normalize_service_networking_connection,
)
from tfstride.providers.gcp.org_policy_normalizers import (
    normalize_folder_organization_policy,
    normalize_org_policy_policy,
    normalize_organization_policy,
    normalize_project_organization_policy,
)
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.secret_manager_normalizers import (
    normalize_secret_manager_secret_version,
)
from tfstride.providers.gcp.serverless_normalizers import (
    normalize_cloud_run_service,
    normalize_cloud_run_service_iam_binding,
    normalize_cloud_run_service_iam_member,
    normalize_cloud_run_service_iam_policy,
    normalize_cloud_run_v2_service,
    normalize_cloud_run_v2_service_iam_binding,
    normalize_cloud_run_v2_service_iam_member,
    normalize_cloud_run_v2_service_iam_policy,
    normalize_cloudfunctions2_function,
    normalize_cloudfunctions2_function_iam_binding,
    normalize_cloudfunctions2_function_iam_member,
    normalize_cloudfunctions2_function_iam_policy,
    normalize_cloudfunctions_function,
    normalize_cloudfunctions_function_iam_binding,
    normalize_cloudfunctions_function_iam_member,
    normalize_cloudfunctions_function_iam_policy,
)
from tfstride.providers.gcp.storage_normalizers import normalize_storage_bucket
from tfstride.providers.normalization import ResourceNormalizer, normalize_provider_inventory

_GCP_RESOURCE_NORMALIZERS: dict[str, ResourceNormalizer] = {
    GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY: normalize_artifact_registry_repository,
    GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY_IAM_BINDING: normalize_artifact_registry_repository_iam_binding,
    GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY_IAM_MEMBER: normalize_artifact_registry_repository_iam_member,
    GcpResourceType.ARTIFACT_REGISTRY_REPOSITORY_IAM_POLICY: normalize_artifact_registry_repository_iam_policy,
    GcpResourceType.COMPUTE_BACKEND_BUCKET: normalize_compute_backend_bucket,
    GcpResourceType.COMPUTE_BACKEND_SERVICE: normalize_compute_backend_service,
    GcpResourceType.COMPUTE_FIREWALL: normalize_compute_firewall,
    GcpResourceType.COMPUTE_FIREWALL_POLICY: normalize_compute_firewall_policy,
    GcpResourceType.COMPUTE_FIREWALL_POLICY_ASSOCIATION: normalize_compute_firewall_policy_association,
    GcpResourceType.COMPUTE_FIREWALL_POLICY_RULE: normalize_compute_firewall_policy_rule,
    GcpResourceType.COMPUTE_FORWARDING_RULE: normalize_compute_forwarding_rule,
    GcpResourceType.COMPUTE_GLOBAL_ADDRESS: normalize_compute_global_address,
    GcpResourceType.COMPUTE_GLOBAL_FORWARDING_RULE: normalize_compute_global_forwarding_rule,
    GcpResourceType.COMPUTE_MANAGED_SSL_CERTIFICATE: normalize_compute_managed_ssl_certificate,
    GcpResourceType.COMPUTE_INSTANCE: normalize_compute_instance,
    GcpResourceType.COMPUTE_NETWORK: normalize_compute_network,
    GcpResourceType.COMPUTE_NETWORK_ENDPOINT_GROUP: normalize_compute_network_endpoint_group,
    GcpResourceType.COMPUTE_REGION_BACKEND_SERVICE: normalize_compute_region_backend_service,
    GcpResourceType.COMPUTE_REGION_NETWORK_ENDPOINT_GROUP: normalize_compute_region_network_endpoint_group,
    GcpResourceType.COMPUTE_REGION_SECURITY_POLICY: normalize_compute_region_security_policy,
    GcpResourceType.COMPUTE_REGION_TARGET_HTTP_PROXY: normalize_compute_region_target_http_proxy,
    GcpResourceType.COMPUTE_REGION_TARGET_HTTPS_PROXY: normalize_compute_region_target_https_proxy,
    GcpResourceType.COMPUTE_REGION_URL_MAP: normalize_compute_region_url_map,
    GcpResourceType.COMPUTE_SERVICE_ATTACHMENT: normalize_compute_service_attachment,
    GcpResourceType.COMPUTE_SECURITY_POLICY: normalize_compute_security_policy,
    GcpResourceType.COMPUTE_SSL_POLICY: normalize_compute_ssl_policy,
    GcpResourceType.COMPUTE_ROUTE: normalize_compute_route,
    GcpResourceType.COMPUTE_ROUTER: normalize_compute_router,
    GcpResourceType.COMPUTE_ROUTER_NAT: normalize_compute_router_nat,
    GcpResourceType.COMPUTE_SUBNETWORK: normalize_compute_subnetwork,
    GcpResourceType.COMPUTE_TARGET_HTTP_PROXY: normalize_compute_target_http_proxy,
    GcpResourceType.COMPUTE_TARGET_HTTPS_PROXY: normalize_compute_target_https_proxy,
    GcpResourceType.COMPUTE_URL_MAP: normalize_compute_url_map,
    GcpResourceType.BIGQUERY_DATASET: normalize_bigquery_dataset,
    GcpResourceType.BIGQUERY_DATASET_IAM_BINDING: normalize_bigquery_dataset_iam_binding,
    GcpResourceType.BIGQUERY_DATASET_IAM_MEMBER: normalize_bigquery_dataset_iam_member,
    GcpResourceType.BIGQUERY_DATASET_IAM_POLICY: normalize_bigquery_dataset_iam_policy,
    GcpResourceType.BIGQUERY_TABLE: normalize_bigquery_table,
    GcpResourceType.BIGQUERY_TABLE_IAM_BINDING: normalize_bigquery_table_iam_binding,
    GcpResourceType.BIGQUERY_TABLE_IAM_MEMBER: normalize_bigquery_table_iam_member,
    GcpResourceType.BIGQUERY_TABLE_IAM_POLICY: normalize_bigquery_table_iam_policy,
    GcpResourceType.CLOUD_RUN_SERVICE: normalize_cloud_run_service,
    GcpResourceType.CLOUD_RUN_SERVICE_IAM_BINDING: normalize_cloud_run_service_iam_binding,
    GcpResourceType.CLOUD_RUN_SERVICE_IAM_MEMBER: normalize_cloud_run_service_iam_member,
    GcpResourceType.CLOUD_RUN_SERVICE_IAM_POLICY: normalize_cloud_run_service_iam_policy,
    GcpResourceType.CLOUD_RUN_V2_SERVICE: normalize_cloud_run_v2_service,
    GcpResourceType.CLOUD_RUN_V2_SERVICE_IAM_BINDING: normalize_cloud_run_v2_service_iam_binding,
    GcpResourceType.CLOUD_RUN_V2_SERVICE_IAM_MEMBER: normalize_cloud_run_v2_service_iam_member,
    GcpResourceType.CLOUD_RUN_V2_SERVICE_IAM_POLICY: normalize_cloud_run_v2_service_iam_policy,
    GcpResourceType.CLOUDFUNCTIONS_FUNCTION: normalize_cloudfunctions_function,
    GcpResourceType.CLOUDFUNCTIONS_FUNCTION_IAM_BINDING: normalize_cloudfunctions_function_iam_binding,
    GcpResourceType.CLOUDFUNCTIONS_FUNCTION_IAM_MEMBER: normalize_cloudfunctions_function_iam_member,
    GcpResourceType.CLOUDFUNCTIONS_FUNCTION_IAM_POLICY: normalize_cloudfunctions_function_iam_policy,
    GcpResourceType.CLOUDFUNCTIONS2_FUNCTION: normalize_cloudfunctions2_function,
    GcpResourceType.CLOUDFUNCTIONS2_FUNCTION_IAM_BINDING: normalize_cloudfunctions2_function_iam_binding,
    GcpResourceType.CLOUDFUNCTIONS2_FUNCTION_IAM_MEMBER: normalize_cloudfunctions2_function_iam_member,
    GcpResourceType.CLOUDFUNCTIONS2_FUNCTION_IAM_POLICY: normalize_cloudfunctions2_function_iam_policy,
    GcpResourceType.CONTAINER_CLUSTER: normalize_container_cluster,
    GcpResourceType.CONTAINER_NODE_POOL: normalize_container_node_pool,
    GcpResourceType.KMS_CRYPTO_KEY: normalize_kms_crypto_key,
    GcpResourceType.KMS_KEY_RING: normalize_kms_key_ring,
    GcpResourceType.KMS_CRYPTO_KEY_VERSION: normalize_kms_crypto_key_version,
    GcpResourceType.KMS_CRYPTO_KEY_IAM_BINDING: normalize_kms_crypto_key_iam_binding,
    GcpResourceType.KMS_CRYPTO_KEY_IAM_MEMBER: normalize_kms_crypto_key_iam_member,
    GcpResourceType.KMS_CRYPTO_KEY_IAM_POLICY: normalize_kms_crypto_key_iam_policy,
    GcpResourceType.KMS_KEY_RING_IAM_BINDING: normalize_kms_key_ring_iam_binding,
    GcpResourceType.KMS_KEY_RING_IAM_MEMBER: normalize_kms_key_ring_iam_member,
    GcpResourceType.KMS_KEY_RING_IAM_POLICY: normalize_kms_key_ring_iam_policy,
    GcpResourceType.IAM_DENY_POLICY: normalize_iam_deny_policy,
    GcpResourceType.LOGGING_ORGANIZATION_EXCLUSION: normalize_logging_organization_exclusion,
    GcpResourceType.LOGGING_ORGANIZATION_SINK: normalize_logging_organization_sink,
    GcpResourceType.LOGGING_PROJECT_EXCLUSION: normalize_logging_project_exclusion,
    GcpResourceType.LOGGING_PROJECT_SINK: normalize_logging_project_sink,
    GcpResourceType.FOLDER_IAM_BINDING: normalize_folder_iam_binding,
    GcpResourceType.FOLDER_IAM_MEMBER: normalize_folder_iam_member,
    GcpResourceType.FOLDER_IAM_POLICY: normalize_folder_iam_policy,
    GcpResourceType.ORGANIZATION_IAM_BINDING: normalize_organization_iam_binding,
    GcpResourceType.ORGANIZATION_IAM_CUSTOM_ROLE: normalize_organization_iam_custom_role,
    GcpResourceType.ORGANIZATION_IAM_MEMBER: normalize_organization_iam_member,
    GcpResourceType.ORGANIZATION_IAM_POLICY: normalize_organization_iam_policy,
    GcpResourceType.FOLDER_ORGANIZATION_POLICY: normalize_folder_organization_policy,
    GcpResourceType.FIRESTORE_DATABASE: normalize_firestore_database,
    GcpResourceType.NETWORK_CONNECTIVITY_SERVICE_CONNECTION_POLICY: (
        normalize_network_connectivity_service_connection_policy
    ),
    GcpResourceType.ORG_POLICY_POLICY: normalize_org_policy_policy,
    GcpResourceType.ORGANIZATION_POLICY: normalize_organization_policy,
    GcpResourceType.FOLDER: normalize_folder,
    GcpResourceType.PROJECT: normalize_project,
    GcpResourceType.PROJECT_ORGANIZATION_POLICY: normalize_project_organization_policy,
    GcpResourceType.PROJECT_IAM_BINDING: normalize_project_iam_binding,
    GcpResourceType.PROJECT_IAM_CUSTOM_ROLE: normalize_project_iam_custom_role,
    GcpResourceType.PROJECT_IAM_MEMBER: normalize_project_iam_member,
    GcpResourceType.PROJECT_IAM_POLICY: normalize_project_iam_policy,
    GcpResourceType.PUBSUB_SUBSCRIPTION: normalize_pubsub_subscription,
    GcpResourceType.PUBSUB_SUBSCRIPTION_IAM_BINDING: normalize_pubsub_subscription_iam_binding,
    GcpResourceType.PUBSUB_SUBSCRIPTION_IAM_MEMBER: normalize_pubsub_subscription_iam_member,
    GcpResourceType.PUBSUB_SUBSCRIPTION_IAM_POLICY: normalize_pubsub_subscription_iam_policy,
    GcpResourceType.PUBSUB_TOPIC: normalize_pubsub_topic,
    GcpResourceType.PUBSUB_TOPIC_IAM_BINDING: normalize_pubsub_topic_iam_binding,
    GcpResourceType.PUBSUB_TOPIC_IAM_MEMBER: normalize_pubsub_topic_iam_member,
    GcpResourceType.PUBSUB_TOPIC_IAM_POLICY: normalize_pubsub_topic_iam_policy,
    GcpResourceType.SECRET_MANAGER_SECRET: normalize_secret_manager_secret,
    GcpResourceType.SECRET_MANAGER_SECRET_VERSION: normalize_secret_manager_secret_version,
    GcpResourceType.SECRET_MANAGER_SECRET_IAM_BINDING: normalize_secret_manager_secret_iam_binding,
    GcpResourceType.SECRET_MANAGER_SECRET_IAM_MEMBER: normalize_secret_manager_secret_iam_member,
    GcpResourceType.SECRET_MANAGER_SECRET_IAM_POLICY: normalize_secret_manager_secret_iam_policy,
    GcpResourceType.SERVICE_NETWORKING_CONNECTION: normalize_service_networking_connection,
    GcpResourceType.SERVICE_ACCOUNT: normalize_service_account,
    GcpResourceType.SERVICE_ACCOUNT_IAM_BINDING: normalize_service_account_iam_binding,
    GcpResourceType.SERVICE_ACCOUNT_IAM_MEMBER: normalize_service_account_iam_member,
    GcpResourceType.SERVICE_ACCOUNT_IAM_POLICY: normalize_service_account_iam_policy,
    GcpResourceType.SERVICE_ACCOUNT_KEY: normalize_service_account_key,
    GcpResourceType.WORKLOAD_IDENTITY_POOL: normalize_workload_identity_pool,
    GcpResourceType.WORKLOAD_IDENTITY_POOL_PROVIDER: normalize_workload_identity_pool_provider,
    GcpResourceType.SCC_ORGANIZATION_SETTINGS: normalize_scc_organization_settings,
    GcpResourceType.SQL_DATABASE_INSTANCE: normalize_sql_database_instance,
    GcpResourceType.STORAGE_BUCKET: normalize_storage_bucket,
    GcpResourceType.STORAGE_BUCKET_IAM_BINDING: normalize_storage_bucket_iam_binding,
    GcpResourceType.STORAGE_BUCKET_IAM_MEMBER: normalize_storage_bucket_iam_member,
    GcpResourceType.STORAGE_BUCKET_IAM_POLICY: normalize_storage_bucket_iam_policy,
}
SUPPORTED_GCP_TYPES = frozenset(_GCP_RESOURCE_NORMALIZERS)


class GcpNormalizer(ProviderNormalizer):
    """Normalize the initial supported Terraform Google provider resource set."""

    provider = GCP_PROVIDER

    def __init__(self, resource_decorator: GcpResourceDecorator | None = None) -> None:
        self._resource_decorator = resource_decorator or GcpResourceDecorator()
        self._resource_normalizers = dict(_GCP_RESOURCE_NORMALIZERS)

    def owns_resource(self, resource: TerraformResource) -> bool:
        return _is_gcp_resource(resource)

    def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
        return normalize_provider_inventory(
            resources,
            provider=self.provider,
            owns_resource=self.owns_resource,
            resource_normalizers=self._resource_normalizers,
            decorate_resources=self._resource_decorator.decorate,
        )


def _is_gcp_resource(resource: TerraformResource) -> bool:
    provider_name = str(resource.provider_name).strip().lower()
    return (
        provider_name.endswith("/google")
        or provider_name.endswith("/google-beta")
        or resource.resource_type.startswith(GcpResourceType.PREFIX)
    )
