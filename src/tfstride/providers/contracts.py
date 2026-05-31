from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProviderEncapsulationContract:
    """Declarative boundary between core models and provider-owned details."""

    provider_neutral_resource_fields: frozenset[str]
    provider_neutral_resource_accessors: frozenset[str]
    legacy_provider_metadata_accessors: frozenset[str]
    guidelines: tuple[str, ...]


PROVIDER_ENCAPSULATION_GUIDELINES = (
    "Core models expose normalized, provider-neutral facts used by shared analysis and reporting.",
    "Provider packages own provider-specific facts, metadata keys, indexes, decorators, and relationship resolution.",
    "Shared analysis should prefer normalized fields or capability helpers over raw provider metadata keys.",
    "Do not add new provider-specific convenience accessors to NormalizedResource; put them behind a provider facts facade.",
)

PROVIDER_NEUTRAL_NORMALIZED_RESOURCE_FIELDS = frozenset(
    {
        "address",
        "provider",
        "resource_type",
        "name",
        "category",
        "identifier",
        "arn",
        "vpc_id",
        "subnet_ids",
        "security_group_ids",
        "attached_role_arns",
        "network_rules",
        "policy_statements",
        "public_access_configured",
        "public_exposure",
        "data_sensitivity",
    }
)

PROVIDER_NEUTRAL_NORMALIZED_RESOURCE_ACCESSORS = frozenset(
    {
        "display_name",
        "metadata",
        "direct_internet_reachable",
        "internet_ingress_capable",
        "in_public_subnet",
        "has_nat_gateway_egress",
        "is_public_subnet",
        "has_public_route",
        "vpc_enabled",
        "storage_encrypted",
        "publicly_accessible",
        "public_access_reasons",
        "public_exposure_reasons",
        "internet_ingress_reasons",
    }
)

# These accessors are kept as an explicit legacy surface while AWS facts are moved
# out of the core model. This list should shrink over time, not grow.
LEGACY_NORMALIZED_RESOURCE_PROVIDER_METADATA_ACCESSORS = frozenset(
    {
        "security_group_id",
        "role_reference",
        "role_references",
        "resolved_role_references",
        "iam_instance_profile",
        "policy_arn",
        "policy_name",
        "cluster_reference",
        "cluster_name",
        "task_definition_reference",
        "task_definition_family",
        "task_definition_revision",
        "network_mode",
        "requires_compatibilities",
        "task_role_arn",
        "execution_role_arn",
        "secret_arn",
        "function_name",
        "secret_name",
        "route_table_id",
        "subnet_id",
        "routes",
        "map_public_ip_on_launch",
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets",
        "trust_principals",
        "trust_statements",
        "resource_policy_source_addresses",
        "policy_document",
        "public_access_block",
        "bucket_name",
        "bucket_acl",
        "engine",
    }
)

DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT = ProviderEncapsulationContract(
    provider_neutral_resource_fields=PROVIDER_NEUTRAL_NORMALIZED_RESOURCE_FIELDS,
    provider_neutral_resource_accessors=PROVIDER_NEUTRAL_NORMALIZED_RESOURCE_ACCESSORS,
    legacy_provider_metadata_accessors=LEGACY_NORMALIZED_RESOURCE_PROVIDER_METADATA_ACCESSORS,
    guidelines=PROVIDER_ENCAPSULATION_GUIDELINES,
)