from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_types import (
    GCP_ARTIFACT_REGISTRY_REPOSITORY_IAM_RESOURCE_TYPES,
    GCP_BIGQUERY_DATASET_IAM_RESOURCE_TYPES,
    GCP_BIGQUERY_TABLE_IAM_RESOURCE_TYPES,
    GCP_CLOUD_FUNCTION_IAM_RESOURCE_TYPES,
    GCP_CLOUD_RUN_IAM_RESOURCE_TYPES,
    GCP_FORWARDING_RULE_RESOURCE_TYPES,
    GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES,
    GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES,
    GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES,
    GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES,
    GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES,
    GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES,
    GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import GCP_NETWORK_REFERENCE_SUFFIXES, gcp_reference_key


@dataclass(frozen=True, slots=True)
class GcpResourceIndex:
    resources_by_reference: Mapping[str, NormalizedResource]
    network_references: Mapping[str, str]
    subnetworks_by_reference: Mapping[str, NormalizedResource]
    routers_by_reference: Mapping[str, NormalizedResource]
    forwarding_rules: tuple[NormalizedResource, ...]
    routes: tuple[NormalizedResource, ...]
    router_nats: tuple[NormalizedResource, ...]
    firewalls: tuple[NormalizedResource, ...]
    firewall_policy_rules: tuple[NormalizedResource, ...]
    firewall_policy_associations: tuple[NormalizedResource, ...]
    bucket_iam_resources: tuple[NormalizedResource, ...]
    secret_iam_resources: tuple[NormalizedResource, ...]
    pubsub_topic_iam_resources: tuple[NormalizedResource, ...]
    pubsub_subscription_iam_resources: tuple[NormalizedResource, ...]
    bigquery_dataset_iam_resources: tuple[NormalizedResource, ...]
    bigquery_table_iam_resources: tuple[NormalizedResource, ...]
    kms_crypto_key_iam_resources: tuple[NormalizedResource, ...]
    kms_key_ring_iam_resources: tuple[NormalizedResource, ...]
    cloud_run_iam_resources: tuple[NormalizedResource, ...]
    cloud_function_iam_resources: tuple[NormalizedResource, ...]
    artifact_registry_iam_resources: tuple[NormalizedResource, ...]
    service_accounts: tuple[NormalizedResource, ...]
    service_account_iam_resources: tuple[NormalizedResource, ...]
    workload_identity_pools: tuple[NormalizedResource, ...]
    workload_identity_pool_providers: tuple[NormalizedResource, ...]


@dataclass(slots=True)
class GcpDecorationContext:
    index: GcpResourceIndex


class GcpResourceIndexBuilder:
    def build(self, resources: list[NormalizedResource]) -> GcpResourceIndex:
        resources_by_reference: dict[str, NormalizedResource] = {}
        network_references: dict[str, str] = {}
        subnetworks_by_reference: dict[str, NormalizedResource] = {}
        routers_by_reference: dict[str, NormalizedResource] = {}
        forwarding_rules: list[NormalizedResource] = []
        routes: list[NormalizedResource] = []
        router_nats: list[NormalizedResource] = []
        firewalls: list[NormalizedResource] = []
        firewall_policy_rules: list[NormalizedResource] = []
        firewall_policy_associations: list[NormalizedResource] = []
        bucket_iam_resources: list[NormalizedResource] = []
        secret_iam_resources: list[NormalizedResource] = []
        pubsub_topic_iam_resources: list[NormalizedResource] = []
        pubsub_subscription_iam_resources: list[NormalizedResource] = []
        bigquery_dataset_iam_resources: list[NormalizedResource] = []
        bigquery_table_iam_resources: list[NormalizedResource] = []
        kms_crypto_key_iam_resources: list[NormalizedResource] = []
        kms_key_ring_iam_resources: list[NormalizedResource] = []
        cloud_run_iam_resources: list[NormalizedResource] = []
        cloud_function_iam_resources: list[NormalizedResource] = []
        artifact_registry_iam_resources: list[NormalizedResource] = []
        service_accounts: list[NormalizedResource] = []
        service_account_iam_resources: list[NormalizedResource] = []
        workload_identity_pools: list[NormalizedResource] = []
        workload_identity_pool_providers: list[NormalizedResource] = []
        for resource in resources:
            resource_references = gcp_resource_references(resource)
            for reference in resource_references:
                resources_by_reference.setdefault(reference, resource)
            if resource.resource_type == GcpResourceType.COMPUTE_NETWORK:
                for reference in resource_references:
                    network_references.setdefault(reference, resource.address)
                    network_references.setdefault(
                        gcp_network_reference_key(reference),
                        resource.address,
                    )
            elif resource.resource_type == GcpResourceType.COMPUTE_SUBNETWORK:
                for reference in resource_references:
                    subnetworks_by_reference.setdefault(reference, resource)
            elif resource.resource_type == GcpResourceType.COMPUTE_ROUTER:
                for reference in resource_references:
                    routers_by_reference.setdefault(reference, resource)
            elif resource.resource_type == GcpResourceType.COMPUTE_ROUTE:
                routes.append(resource)
            elif resource.resource_type == GcpResourceType.COMPUTE_ROUTER_NAT:
                router_nats.append(resource)
            elif resource.resource_type in GCP_FORWARDING_RULE_RESOURCE_TYPES:
                forwarding_rules.append(resource)
            elif resource.resource_type == GcpResourceType.COMPUTE_FIREWALL:
                firewalls.append(resource)
            elif resource.resource_type == GcpResourceType.COMPUTE_FIREWALL_POLICY_RULE:
                firewall_policy_rules.append(resource)
            elif resource.resource_type == GcpResourceType.COMPUTE_FIREWALL_POLICY_ASSOCIATION:
                firewall_policy_associations.append(resource)
            elif resource.resource_type == GcpResourceType.SERVICE_ACCOUNT:
                service_accounts.append(resource)
            elif resource.resource_type in GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES:
                service_account_iam_resources.append(resource)
            elif resource.resource_type == GcpResourceType.WORKLOAD_IDENTITY_POOL:
                workload_identity_pools.append(resource)
            elif resource.resource_type == GcpResourceType.WORKLOAD_IDENTITY_POOL_PROVIDER:
                workload_identity_pool_providers.append(resource)
            elif resource.resource_type in GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES:
                bucket_iam_resources.append(resource)
            elif resource.resource_type in GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES:
                secret_iam_resources.append(resource)
            elif resource.resource_type in GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES:
                pubsub_topic_iam_resources.append(resource)
            elif resource.resource_type in GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES:
                pubsub_subscription_iam_resources.append(resource)
            elif resource.resource_type in GCP_BIGQUERY_DATASET_IAM_RESOURCE_TYPES:
                bigquery_dataset_iam_resources.append(resource)
            elif resource.resource_type in GCP_BIGQUERY_TABLE_IAM_RESOURCE_TYPES:
                bigquery_table_iam_resources.append(resource)
            elif resource.resource_type in GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES:
                kms_crypto_key_iam_resources.append(resource)
            elif resource.resource_type in GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES:
                kms_key_ring_iam_resources.append(resource)
            elif resource.resource_type in GCP_CLOUD_RUN_IAM_RESOURCE_TYPES:
                cloud_run_iam_resources.append(resource)
            elif resource.resource_type in GCP_CLOUD_FUNCTION_IAM_RESOURCE_TYPES:
                cloud_function_iam_resources.append(resource)
            elif resource.resource_type in GCP_ARTIFACT_REGISTRY_REPOSITORY_IAM_RESOURCE_TYPES:
                artifact_registry_iam_resources.append(resource)
        return GcpResourceIndex(
            resources_by_reference=MappingProxyType(resources_by_reference),
            network_references=MappingProxyType(network_references),
            subnetworks_by_reference=MappingProxyType(subnetworks_by_reference),
            routers_by_reference=MappingProxyType(routers_by_reference),
            forwarding_rules=tuple(forwarding_rules),
            routes=tuple(routes),
            router_nats=tuple(router_nats),
            firewalls=tuple(firewalls),
            firewall_policy_rules=tuple(firewall_policy_rules),
            firewall_policy_associations=tuple(firewall_policy_associations),
            bucket_iam_resources=tuple(bucket_iam_resources),
            secret_iam_resources=tuple(secret_iam_resources),
            pubsub_topic_iam_resources=tuple(pubsub_topic_iam_resources),
            pubsub_subscription_iam_resources=tuple(pubsub_subscription_iam_resources),
            bigquery_dataset_iam_resources=tuple(bigquery_dataset_iam_resources),
            bigquery_table_iam_resources=tuple(bigquery_table_iam_resources),
            kms_crypto_key_iam_resources=tuple(kms_crypto_key_iam_resources),
            kms_key_ring_iam_resources=tuple(kms_key_ring_iam_resources),
            cloud_run_iam_resources=tuple(cloud_run_iam_resources),
            cloud_function_iam_resources=tuple(cloud_function_iam_resources),
            artifact_registry_iam_resources=tuple(artifact_registry_iam_resources),
            service_accounts=tuple(service_accounts),
            service_account_iam_resources=tuple(service_account_iam_resources),
            workload_identity_pools=tuple(workload_identity_pools),
            workload_identity_pool_providers=tuple(workload_identity_pool_providers),
        )


def gcp_resource_references(resource: NormalizedResource) -> tuple[str, ...]:
    references = {
        resource.address,
        f"{resource.address}.id",
        f"{resource.address}.name",
    }
    for reference in (
        resource.identifier,
        resource.get_metadata_field(GcpResourceMetadata.NAME),
        resource.get_metadata_field(GcpResourceMetadata.BUCKET_NAME),
        resource.get_metadata_field(GcpResourceMetadata.SECRET_ID),
        resource.get_metadata_field(GcpResourceMetadata.SECRET_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.BIGQUERY_DATASET_ID),
        resource.get_metadata_field(GcpResourceMetadata.BIGQUERY_DATASET_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.BIGQUERY_TABLE_ID),
        resource.get_metadata_field(GcpResourceMetadata.BIGQUERY_TABLE_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.KMS_KEY_RING),
        resource.get_metadata_field(GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE),
        resource.get_metadata_field(GcpResourceMetadata.SELF_LINK),
        resource.get_metadata_field(GcpResourceMetadata.ARTIFACT_REGISTRY_REPOSITORY_PATH),
    ):
        if reference:
            references.add(reference)
    return tuple(
        sorted(gcp_reference_key(reference, GCP_NETWORK_REFERENCE_SUFFIXES) for reference in references if reference)
    )


def gcp_network_reference_key(value: str) -> str:
    text = gcp_reference_key(value, GCP_NETWORK_REFERENCE_SUFFIXES)
    for marker in ("/global/networks/", "/networks/"):
        if marker in text:
            return text.rsplit(marker, 1)[-1]
    return text
