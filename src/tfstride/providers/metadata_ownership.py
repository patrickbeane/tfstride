from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from types import MappingProxyType
from typing import Any

from tfstride.providers.contracts import (
    DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT,
    ResourceMetadataOwnershipContract,
)
from tfstride.providers.names import normalize_provider_name
from tfstride.resource_metadata import MetadataField, ResourceMetadata


class ProviderMetadataOwnershipError(ValueError):
    """Raised when provider facts try to write metadata outside their namespace."""


_SHARED_METADATA_OWNER = "shared-core"


@dataclass(frozen=True, slots=True)
class NormalizedResourceMetadataWriteValidator:
    """Validate direct NormalizedResource metadata writes against provider ownership."""

    _field_owners_by_identity: Mapping[int, str]
    _namespace_names_by_provider: Mapping[str, str]

    @classmethod
    def build(
        cls,
        *,
        contract: ResourceMetadataOwnershipContract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT,
    ) -> NormalizedResourceMetadataWriteValidator:
        from tfstride.providers.aws.metadata import AwsResourceMetadata
        from tfstride.providers.azure.metadata import AzureResourceMetadata
        from tfstride.providers.gcp.metadata import GcpResourceMetadata

        field_owners: dict[int, str] = {}
        shared_fields = _metadata_fields_by_name(ResourceMetadata)
        for field_name in contract.shared_core_fields:
            field = shared_fields.get(field_name)
            if field is None:
                raise ProviderMetadataOwnershipError(
                    f"Shared metadata field {field_name} is missing from ResourceMetadata."
                )
            field_owners[id(field)] = _SHARED_METADATA_OWNER

        provider_namespaces = {
            "aws": AwsResourceMetadata,
            "gcp": GcpResourceMetadata,
            "azure": AzureResourceMetadata,
        }
        for provider, namespace in provider_namespaces.items():
            fields_by_name = _metadata_fields_by_name(namespace)
            for field_name in contract.provider_owned_fields[provider]:
                field = fields_by_name.get(field_name)
                if field is None:
                    raise ProviderMetadataOwnershipError(
                        f"{namespace.__name__} is missing owned metadata field {field_name}."
                    )
                field_owners[id(field)] = provider

        return cls(
            _field_owners_by_identity=MappingProxyType(field_owners),
            _namespace_names_by_provider=MappingProxyType(
                {provider: namespace.__name__ for provider, namespace in provider_namespaces.items()}
            ),
        )

    def validate(self, *, resource_provider: str, field: MetadataField[Any]) -> None:
        owner = self._field_owners_by_identity.get(id(field))
        if owner is None or owner == _SHARED_METADATA_OWNER:
            return

        provider = normalize_provider_name(resource_provider)
        if provider == owner:
            return

        namespace_name = self._namespace_names_by_provider.get(provider, f"{provider} provider metadata")
        target_provider = provider or "unknown"
        raise ProviderMetadataOwnershipError(
            f"Metadata field {field.key} is owned by {owner} and cannot be written directly to "
            f"{target_provider} resource metadata; use a field from {namespace_name} or the "
            f"{owner} provider facts facade."
        )


@lru_cache(maxsize=1)
def default_normalized_resource_metadata_write_validator() -> NormalizedResourceMetadataWriteValidator:
    return NormalizedResourceMetadataWriteValidator.build()


def validate_normalized_resource_metadata_write(*, resource_provider: str, field: MetadataField[Any]) -> None:
    default_normalized_resource_metadata_write_validator().validate(
        resource_provider=resource_provider,
        field=field,
    )


@dataclass(frozen=True, slots=True)
class ProviderMetadataWriteValidator:
    """Validate provider metadata writes against the ownership contract."""

    provider: str
    namespace_name: str
    _field_names_by_identity: Mapping[int, str]

    @classmethod
    def build(
        cls,
        *,
        provider: str,
        namespace: type,
        contract: ResourceMetadataOwnershipContract = DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT,
    ) -> ProviderMetadataWriteValidator:
        provider_key = normalize_provider_name(provider)
        if provider_key not in contract.provider_owned_fields:
            raise ProviderMetadataOwnershipError(f"Unknown provider `{provider}` in metadata ownership contract.")

        fields_by_name = _metadata_fields_by_name(namespace)
        allowed_names = contract.shared_core_fields | contract.provider_owned_fields[provider_key]
        unclassified_names = frozenset(fields_by_name) - allowed_names
        if unclassified_names:
            formatted = ", ".join(sorted(unclassified_names))
            raise ProviderMetadataOwnershipError(
                f"{namespace.__name__} exposes unclassified metadata fields: {formatted}."
            )

        return cls(
            provider=provider_key,
            namespace_name=namespace.__name__,
            _field_names_by_identity=MappingProxyType({id(field): name for name, field in fields_by_name.items()}),
        )

    def validate(self, field: MetadataField[Any]) -> None:
        if id(field) in self._field_names_by_identity:
            return
        raise ProviderMetadataOwnershipError(
            f"Metadata field `{field.key}` is not writable through {self.provider} resource facts; "
            f"use a field from {self.namespace_name}."
        )


def _metadata_fields_by_name(namespace: type) -> dict[str, MetadataField[Any]]:
    return {name: value for name, value in vars(namespace).items() if isinstance(value, MetadataField)}
