from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_index import GcpResourceIndex
from tfstride.providers.gcp.resource_types import GCP_CLOUD_RUN_RESOURCE_TYPES


def serverless_iam_resources(
    resource: NormalizedResource,
    index: GcpResourceIndex,
) -> tuple[NormalizedResource, ...]:
    return (
        index.cloud_run_iam_resources
        if resource.resource_type in GCP_CLOUD_RUN_RESOURCE_TYPES
        else index.cloud_function_iam_resources
    )


def resource_iam_target_reference(resource: NormalizedResource) -> str | None:
    bucket_name = resource.get_metadata_field(GcpResourceMetadata.BUCKET_NAME)
    if bucket_name:
        return bucket_name
    secret_reference = resource.get_metadata_field(GcpResourceMetadata.SECRET_REFERENCE)
    if secret_reference:
        return secret_reference
    pubsub_topic_reference = resource.get_metadata_field(GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE)
    if pubsub_topic_reference:
        return pubsub_topic_reference
    pubsub_subscription_reference = resource.get_metadata_field(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_REFERENCE)
    if pubsub_subscription_reference:
        return pubsub_subscription_reference
    bigquery_table_reference = resource.get_metadata_field(GcpResourceMetadata.BIGQUERY_TABLE_REFERENCE)
    if bigquery_table_reference:
        return bigquery_table_reference
    bigquery_dataset_reference = resource.get_metadata_field(GcpResourceMetadata.BIGQUERY_DATASET_REFERENCE)
    if bigquery_dataset_reference:
        return bigquery_dataset_reference
    cloud_run_reference = resource.get_metadata_field(GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE)
    if cloud_run_reference:
        return cloud_run_reference
    cloud_function_reference = resource.get_metadata_field(GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE)
    if cloud_function_reference:
        return cloud_function_reference
    crypto_key_reference = resource.get_metadata_field(GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE)
    if crypto_key_reference:
        return crypto_key_reference
    return resource.get_metadata_field(GcpResourceMetadata.KMS_KEY_RING)


def iam_bindings(resource: NormalizedResource) -> list[dict[str, Any]]:
    bindings = resource.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS)
    if bindings:
        return bindings
    role = resource.get_metadata_field(GcpResourceMetadata.IAM_ROLE)
    member = resource.get_metadata_field(GcpResourceMetadata.IAM_MEMBER)
    if role and member:
        binding: dict[str, Any] = {"role": role, "members": [member]}
        condition = resource.get_metadata_field(GcpResourceMetadata.IAM_CONDITION)
        if condition:
            binding["condition"] = condition
        return [binding]
    return []
