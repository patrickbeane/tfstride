from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.resource_metadata import MetadataField, ResourceMetadata


@dataclass(frozen=True, slots=True)
class ProviderEncapsulationContract:
    """Declarative boundary between core models and provider-owned details."""

    provider_neutral_resource_fields: frozenset[str]
    provider_neutral_resource_accessors: frozenset[str]
    legacy_provider_metadata_accessors: frozenset[str]
    guidelines: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ResourceMetadataOwnershipContract:
    """Ownership map for shared and provider-owned metadata namespaces."""

    shared_core_fields: frozenset[str]
    provider_owned_fields: Mapping[str, frozenset[str]]
    guidelines: tuple[str, ...]


PROVIDER_ENCAPSULATION_GUIDELINES = (
    "Core models expose normalized, provider-neutral facts used by shared analysis and reporting.",
    "Provider packages own provider-specific facts, metadata keys, indexes, decorators, boundary contributors, and relationship resolution.",
    "Shared boundary orchestration should accept provider contributors through the provider plugin contract rather than importing provider packages directly.",
    "Shared analysis should prefer normalized fields or capability helpers over raw provider metadata keys.",
    "Do not add new provider-specific convenience accessors to NormalizedResource; put them behind a provider facts facade.",
)

RESOURCE_METADATA_OWNERSHIP_GUIDELINES = (
    "Shared-core metadata backs provider-neutral NormalizedResource posture and reporting fields.",
    "Provider-owned metadata belongs behind provider facts, mutation facades, or provider metadata namespaces.",
    "Provider-shaped data used by shared analysis must be exposed through provider facts before adding another provider.",
    "ResourceMetadata fields are shared-core; provider metadata namespace fields are provider-owned unless they intentionally alias shared-core fields.",
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

# Provider-specific convenience accessors have moved out of the core model.
LEGACY_NORMALIZED_RESOURCE_PROVIDER_METADATA_ACCESSORS = frozenset()


def _metadata_fields_by_name(namespace: type[Any]) -> dict[str, MetadataField[Any]]:
    return {name: value for name, value in vars(namespace).items() if isinstance(value, MetadataField)}


def _metadata_field_names(namespace: type[Any]) -> frozenset[str]:
    return frozenset(_metadata_fields_by_name(namespace))


SHARED_CORE_RESOURCE_METADATA_FIELDS = _metadata_field_names(ResourceMetadata)


def _provider_owned_metadata_field_names(namespace: type[Any]) -> frozenset[str]:
    namespace_fields = _metadata_fields_by_name(namespace)
    shared_fields = _metadata_fields_by_name(ResourceMetadata)
    invalid_shared_aliases = {
        field_name
        for field_name in namespace_fields.keys() & shared_fields.keys()
        if namespace_fields[field_name] is not shared_fields[field_name]
    }
    if invalid_shared_aliases:
        formatted = ", ".join(sorted(invalid_shared_aliases))
        raise ValueError(f"Provider metadata namespace has non-shared fields using shared-core names: {formatted}.")
    return frozenset(namespace_fields) - SHARED_CORE_RESOURCE_METADATA_FIELDS


AWS_OWNED_RESOURCE_METADATA_FIELDS = _provider_owned_metadata_field_names(AwsResourceMetadata)
GCP_OWNED_RESOURCE_METADATA_FIELDS = _provider_owned_metadata_field_names(GcpResourceMetadata)
AZURE_OWNED_RESOURCE_METADATA_FIELDS = _provider_owned_metadata_field_names(AzureResourceMetadata)


PROVIDER_OWNED_RESOURCE_METADATA_FIELDS = MappingProxyType(
    {
        "aws": AWS_OWNED_RESOURCE_METADATA_FIELDS,
        "gcp": GCP_OWNED_RESOURCE_METADATA_FIELDS,
        "azure": AZURE_OWNED_RESOURCE_METADATA_FIELDS,
    }
)


DEFAULT_PROVIDER_ENCAPSULATION_CONTRACT = ProviderEncapsulationContract(
    provider_neutral_resource_fields=PROVIDER_NEUTRAL_NORMALIZED_RESOURCE_FIELDS,
    provider_neutral_resource_accessors=PROVIDER_NEUTRAL_NORMALIZED_RESOURCE_ACCESSORS,
    legacy_provider_metadata_accessors=LEGACY_NORMALIZED_RESOURCE_PROVIDER_METADATA_ACCESSORS,
    guidelines=PROVIDER_ENCAPSULATION_GUIDELINES,
)

DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT = ResourceMetadataOwnershipContract(
    shared_core_fields=SHARED_CORE_RESOURCE_METADATA_FIELDS,
    provider_owned_fields=PROVIDER_OWNED_RESOURCE_METADATA_FIELDS,
    guidelines=RESOURCE_METADATA_OWNERSHIP_GUIDELINES,
)
