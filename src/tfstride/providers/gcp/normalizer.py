from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from typing import Any

from tfstride.models import NormalizedResource, ResourceInventory, TerraformResource
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.compute_normalizers import normalize_compute_instance
from tfstride.providers.gcp.container_normalizers import (
    normalize_container_cluster,
    normalize_container_node_pool,
)
from tfstride.providers.gcp.data_normalizers import (
    normalize_bigquery_dataset,
    normalize_bigquery_table,
    normalize_kms_crypto_key,
    normalize_pubsub_subscription,
    normalize_pubsub_topic,
    normalize_secret_manager_secret,
    normalize_sql_database_instance,
    normalize_storage_bucket,
)
from tfstride.providers.gcp.iam_normalizers import (
    normalize_bigquery_dataset_iam_binding,
    normalize_bigquery_dataset_iam_member,
    normalize_bigquery_dataset_iam_policy,
    normalize_bigquery_table_iam_binding,
    normalize_bigquery_table_iam_member,
    normalize_bigquery_table_iam_policy,
    normalize_kms_crypto_key_iam_binding,
    normalize_kms_crypto_key_iam_member,
    normalize_kms_crypto_key_iam_policy,
    normalize_kms_key_ring_iam_binding,
    normalize_kms_key_ring_iam_member,
    normalize_kms_key_ring_iam_policy,
    normalize_folder_iam_binding,
    normalize_folder_iam_member,
    normalize_folder_iam_policy,
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
from tfstride.providers.gcp.network_normalizers import (
    GCP_PROVIDER,
    normalize_compute_backend_bucket,
    normalize_compute_backend_service,
    normalize_compute_firewall,
    normalize_compute_forwarding_rule,
    normalize_compute_global_forwarding_rule,
    normalize_compute_network,
    normalize_compute_network_endpoint_group,
    normalize_compute_region_backend_service,
    normalize_compute_region_network_endpoint_group,
    normalize_compute_region_target_http_proxy,
    normalize_compute_region_target_https_proxy,
    normalize_compute_region_url_map,
    normalize_compute_route,
    normalize_compute_router,
    normalize_compute_router_nat,
    normalize_compute_subnetwork,
    normalize_compute_target_http_proxy,
    normalize_compute_target_https_proxy,
    normalize_compute_url_map,
)
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator
from tfstride.resource_metadata import InventoryMetadata


ResourceNormalizer = Callable[[TerraformResource], NormalizedResource]

_GCP_RESOURCE_NORMALIZERS: dict[str, ResourceNormalizer] = {
    "google_compute_backend_bucket": normalize_compute_backend_bucket,
    "google_compute_backend_service": normalize_compute_backend_service,
    "google_compute_firewall": normalize_compute_firewall,
    "google_compute_forwarding_rule": normalize_compute_forwarding_rule,
    "google_compute_global_forwarding_rule": normalize_compute_global_forwarding_rule,
    "google_compute_instance": normalize_compute_instance,
    "google_compute_network": normalize_compute_network,
    "google_compute_network_endpoint_group": normalize_compute_network_endpoint_group,
    "google_compute_region_backend_service": normalize_compute_region_backend_service,
    "google_compute_region_network_endpoint_group": normalize_compute_region_network_endpoint_group,
    "google_compute_region_target_http_proxy": normalize_compute_region_target_http_proxy,
    "google_compute_region_target_https_proxy": normalize_compute_region_target_https_proxy,
    "google_compute_region_url_map": normalize_compute_region_url_map,
    "google_compute_route": normalize_compute_route,
    "google_compute_router": normalize_compute_router,
    "google_compute_router_nat": normalize_compute_router_nat,
    "google_compute_subnetwork": normalize_compute_subnetwork,
    "google_compute_target_http_proxy": normalize_compute_target_http_proxy,
    "google_compute_target_https_proxy": normalize_compute_target_https_proxy,
    "google_compute_url_map": normalize_compute_url_map,
    "google_bigquery_dataset": normalize_bigquery_dataset,
    "google_bigquery_dataset_iam_binding": normalize_bigquery_dataset_iam_binding,
    "google_bigquery_dataset_iam_member": normalize_bigquery_dataset_iam_member,
    "google_bigquery_dataset_iam_policy": normalize_bigquery_dataset_iam_policy,
    "google_bigquery_table": normalize_bigquery_table,
    "google_bigquery_table_iam_binding": normalize_bigquery_table_iam_binding,
    "google_bigquery_table_iam_member": normalize_bigquery_table_iam_member,
    "google_bigquery_table_iam_policy": normalize_bigquery_table_iam_policy,
    "google_cloud_run_service": normalize_cloud_run_service,
    "google_cloud_run_service_iam_binding": normalize_cloud_run_service_iam_binding,
    "google_cloud_run_service_iam_member": normalize_cloud_run_service_iam_member,
    "google_cloud_run_service_iam_policy": normalize_cloud_run_service_iam_policy,
    "google_cloud_run_v2_service": normalize_cloud_run_v2_service,
    "google_cloud_run_v2_service_iam_binding": normalize_cloud_run_v2_service_iam_binding,
    "google_cloud_run_v2_service_iam_member": normalize_cloud_run_v2_service_iam_member,
    "google_cloud_run_v2_service_iam_policy": normalize_cloud_run_v2_service_iam_policy,
    "google_cloudfunctions_function": normalize_cloudfunctions_function,
    "google_cloudfunctions_function_iam_binding": normalize_cloudfunctions_function_iam_binding,
    "google_cloudfunctions_function_iam_member": normalize_cloudfunctions_function_iam_member,
    "google_cloudfunctions_function_iam_policy": normalize_cloudfunctions_function_iam_policy,
    "google_cloudfunctions2_function": normalize_cloudfunctions2_function,
    "google_cloudfunctions2_function_iam_binding": normalize_cloudfunctions2_function_iam_binding,
    "google_cloudfunctions2_function_iam_member": normalize_cloudfunctions2_function_iam_member,
    "google_cloudfunctions2_function_iam_policy": normalize_cloudfunctions2_function_iam_policy,
    "google_container_cluster": normalize_container_cluster,
    "google_container_node_pool": normalize_container_node_pool,
    "google_kms_crypto_key": normalize_kms_crypto_key,
    "google_kms_crypto_key_iam_binding": normalize_kms_crypto_key_iam_binding,
    "google_kms_crypto_key_iam_member": normalize_kms_crypto_key_iam_member,
    "google_kms_crypto_key_iam_policy": normalize_kms_crypto_key_iam_policy,
    "google_kms_key_ring_iam_binding": normalize_kms_key_ring_iam_binding,
    "google_kms_key_ring_iam_member": normalize_kms_key_ring_iam_member,
    "google_kms_key_ring_iam_policy": normalize_kms_key_ring_iam_policy,
    "google_folder_iam_binding": normalize_folder_iam_binding,
    "google_folder_iam_member": normalize_folder_iam_member,
    "google_folder_iam_policy": normalize_folder_iam_policy,
    "google_organization_iam_binding": normalize_organization_iam_binding,
    "google_organization_iam_custom_role": normalize_organization_iam_custom_role,
    "google_organization_iam_member": normalize_organization_iam_member,
    "google_organization_iam_policy": normalize_organization_iam_policy,
    "google_project_iam_binding": normalize_project_iam_binding,
    "google_project_iam_custom_role": normalize_project_iam_custom_role,
    "google_project_iam_member": normalize_project_iam_member,
    "google_project_iam_policy": normalize_project_iam_policy,
    "google_pubsub_subscription": normalize_pubsub_subscription,
    "google_pubsub_subscription_iam_binding": normalize_pubsub_subscription_iam_binding,
    "google_pubsub_subscription_iam_member": normalize_pubsub_subscription_iam_member,
    "google_pubsub_subscription_iam_policy": normalize_pubsub_subscription_iam_policy,
    "google_pubsub_topic": normalize_pubsub_topic,
    "google_pubsub_topic_iam_binding": normalize_pubsub_topic_iam_binding,
    "google_pubsub_topic_iam_member": normalize_pubsub_topic_iam_member,
    "google_pubsub_topic_iam_policy": normalize_pubsub_topic_iam_policy,
    "google_secret_manager_secret": normalize_secret_manager_secret,
    "google_secret_manager_secret_iam_binding": normalize_secret_manager_secret_iam_binding,
    "google_secret_manager_secret_iam_member": normalize_secret_manager_secret_iam_member,
    "google_secret_manager_secret_iam_policy": normalize_secret_manager_secret_iam_policy,
    "google_service_account": normalize_service_account,
    "google_service_account_iam_binding": normalize_service_account_iam_binding,
    "google_service_account_iam_member": normalize_service_account_iam_member,
    "google_service_account_iam_policy": normalize_service_account_iam_policy,
    "google_service_account_key": normalize_service_account_key,
    "google_sql_database_instance": normalize_sql_database_instance,
    "google_storage_bucket": normalize_storage_bucket,
    "google_storage_bucket_iam_binding": normalize_storage_bucket_iam_binding,
    "google_storage_bucket_iam_member": normalize_storage_bucket_iam_member,
    "google_storage_bucket_iam_policy": normalize_storage_bucket_iam_policy,
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
        gcp_resources = [resource for resource in resources if self.owns_resource(resource)]
        unsupported_resource_types = Counter(
            resource.resource_type
            for resource in gcp_resources
            if resource.resource_type not in SUPPORTED_GCP_TYPES
        )
        unsupported = sorted(
            resource.address for resource in gcp_resources if resource.resource_type not in SUPPORTED_GCP_TYPES
        )
        normalized = [
            self._normalize_resource(resource)
            for resource in gcp_resources
            if resource.resource_type in SUPPORTED_GCP_TYPES
        ]
        self._resource_decorator.decorate(normalized)

        metadata: dict[str, Any] = {}
        InventoryMetadata.SUPPORTED_RESOURCE_TYPES.set(metadata, sorted(SUPPORTED_GCP_TYPES))
        InventoryMetadata.TOTAL_INPUT_RESOURCES.set(metadata, len(resources))
        InventoryMetadata.PROVIDER_RESOURCE_COUNT.set(metadata, len(gcp_resources))
        InventoryMetadata.NORMALIZED_RESOURCE_COUNT.set(metadata, len(normalized))
        InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.set(
            metadata,
            dict(sorted(unsupported_resource_types.items())),
        )

        return ResourceInventory(
            provider=self.provider,
            resources=normalized,
            unsupported_resources=unsupported,
            metadata=metadata,
        )

    def _normalize_resource(self, resource: TerraformResource) -> NormalizedResource:
        try:
            normalizer = self._resource_normalizers[resource.resource_type]
        except KeyError as exc:
            raise ValueError(f"Unsupported resource type reached normalizer: {resource.resource_type}") from exc
        return normalizer(resource)


def _is_gcp_resource(resource: TerraformResource) -> bool:
    provider_name = str(resource.provider_name).strip().lower()
    return (
        provider_name.endswith("/google")
        or provider_name.endswith("/google-beta")
        or resource.resource_type.startswith("google_")
    )