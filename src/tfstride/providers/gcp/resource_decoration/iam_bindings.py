from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.resource_decoration.iam import (
    iam_bindings,
    resolve_resource_iam_target,
    serverless_iam_resources,
)
from tfstride.providers.gcp.resource_decoration.kms_iam import kms_key_ring_iam_target_applies_to_key
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import (
    GcpDecorationContext,
    GcpResourceIndex,
)
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_types import (
    GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES,
    GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import binding_members


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
                    index,
                )
            elif resource.resource_type == GcpResourceType.SECRET_MANAGER_SECRET:
                _derive_sensitive_resource_iam_bindings(
                    resource,
                    index.secret_iam_resources,
                    index,
                )
            elif resource.resource_type == GcpResourceType.PUBSUB_TOPIC:
                _derive_sensitive_resource_iam_bindings(
                    resource,
                    index.pubsub_topic_iam_resources,
                    index,
                )
            elif resource.resource_type == GcpResourceType.PUBSUB_SUBSCRIPTION:
                _derive_sensitive_resource_iam_bindings(
                    resource,
                    index.pubsub_subscription_iam_resources,
                    index,
                )
            elif resource.resource_type == GcpResourceType.BIGQUERY_DATASET:
                _derive_sensitive_resource_iam_bindings(
                    resource,
                    index.bigquery_dataset_iam_resources,
                    index,
                )
            elif resource.resource_type == GcpResourceType.BIGQUERY_TABLE:
                _derive_sensitive_resource_iam_bindings(
                    resource,
                    index.bigquery_table_iam_resources,
                    index,
                )
            elif resource.resource_type == GcpResourceType.KMS_CRYPTO_KEY:
                _derive_sensitive_resource_iam_bindings(
                    resource,
                    index.kms_crypto_key_iam_resources + index.kms_key_ring_iam_resources,
                    index,
                )
            elif resource.resource_type == GcpResourceType.STORAGE_BUCKET:
                _derive_sensitive_resource_iam_bindings(
                    resource,
                    index.bucket_iam_resources,
                    index,
                )


def _derive_sensitive_resource_iam_bindings(
    resource: NormalizedResource,
    iam_resources: tuple[NormalizedResource, ...],
    index: GcpResourceIndex,
) -> None:
    bindings: list[dict[str, Any]] = []
    source_addresses: list[str] = []
    for iam_resource in iam_resources:
        iam_facts = gcp_facts(iam_resource)
        policy_state = iam_facts.iam_policy_data_state
        if (
            iam_resource.resource_type.endswith("_iam_policy")
            and policy_state is not None
            and policy_state != "configured"
        ):
            continue
        if iam_resource.resource_type in GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES:
            target_matches = (
                resource.resource_type == GcpResourceType.KMS_CRYPTO_KEY
                and kms_key_ring_iam_target_applies_to_key(iam_resource, resource, index)
            )
        else:
            if not iam_resource.resource_type.startswith(f"{resource.resource_type}_iam_"):
                continue
            target_matches = (
                resolve_resource_iam_target(
                    iam_resource,
                    index,
                    resource_types={resource.resource_type},
                ).selected_candidate
                is resource
            )
        if not target_matches:
            continue
        for binding in iam_bindings(iam_resource):
            if binding.get("role_state") == "unknown" or binding.get("members_state") == "unknown":
                continue
            decorated_binding = {
                "role": str(binding.get("role") or "unknown role"),
                "members": binding_members(binding),
                "source": iam_resource.address,
            }
            condition = binding.get("condition")
            if condition:
                decorated_binding["condition"] = condition
            condition_state = binding.get("condition_state")
            if isinstance(condition_state, str) and condition_state:
                decorated_binding["condition_state"] = condition_state
            bindings.append(decorated_binding)
            source_addresses.append(iam_resource.address)

    gcp_mutations(resource).set_sensitive_resource_iam_bindings(
        bindings=bindings,
        source_addresses=source_addresses,
    )
