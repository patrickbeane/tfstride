from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.resource_decoration.iam import (
    iam_bindings,
    resource_iam_target_reference,
    serverless_iam_resources,
)
from tfstride.providers.gcp.resource_index import (
    GcpDecorationContext,
    gcp_resource_references,
)
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_types import (
    GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import (
    GCP_NETWORK_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
)


class DecorateSensitiveIamBindingsStage:
    name = "decorate_sensitive_iam_bindings"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        index = context.index
        for resource in resources:
            if resource.resource_type in GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES:
                _derive_sensitive_resource_iam_bindings(
                    resource,
                    serverless_iam_resources(resource, index),
                )
            elif resource.resource_type == GcpResourceType.SECRET_MANAGER_SECRET:
                _derive_sensitive_resource_iam_bindings(
                    resource,
                    index.secret_iam_resources,
                )
            elif resource.resource_type == GcpResourceType.PUBSUB_TOPIC:
                _derive_sensitive_resource_iam_bindings(
                    resource,
                    index.pubsub_topic_iam_resources,
                )
            elif resource.resource_type == GcpResourceType.PUBSUB_SUBSCRIPTION:
                _derive_sensitive_resource_iam_bindings(
                    resource,
                    index.pubsub_subscription_iam_resources,
                )
            elif resource.resource_type == GcpResourceType.BIGQUERY_DATASET:
                _derive_sensitive_resource_iam_bindings(
                    resource,
                    index.bigquery_dataset_iam_resources,
                )
            elif resource.resource_type == GcpResourceType.BIGQUERY_TABLE:
                _derive_sensitive_resource_iam_bindings(
                    resource,
                    index.bigquery_table_iam_resources,
                )
            elif resource.resource_type == GcpResourceType.KMS_CRYPTO_KEY:
                _derive_sensitive_resource_iam_bindings(
                    resource,
                    index.kms_crypto_key_iam_resources + index.kms_key_ring_iam_resources,
                )
            elif resource.resource_type == GcpResourceType.STORAGE_BUCKET:
                _derive_sensitive_resource_iam_bindings(
                    resource,
                    index.bucket_iam_resources,
                )


def _derive_sensitive_resource_iam_bindings(
    resource: NormalizedResource,
    iam_resources: tuple[NormalizedResource, ...],
) -> None:
    resource_references = set(gcp_resource_references(resource))
    bindings: list[dict[str, Any]] = []
    source_addresses: list[str] = []
    for iam_resource in iam_resources:
        target_reference = resource_iam_target_reference(iam_resource)
        if (
            not target_reference
            or gcp_reference_key(target_reference, GCP_NETWORK_REFERENCE_SUFFIXES) not in resource_references
        ):
            continue
        for binding in iam_bindings(iam_resource):
            decorated_binding = {
                "role": str(binding.get("role") or "unknown role"),
                "members": binding_members(binding),
                "source": iam_resource.address,
            }
            condition = binding.get("condition")
            if condition:
                decorated_binding["condition"] = condition
            bindings.append(decorated_binding)
            source_addresses.append(iam_resource.address)

    gcp_mutations(resource).set_sensitive_resource_iam_bindings(
        bindings=bindings,
        source_addresses=source_addresses,
    )
