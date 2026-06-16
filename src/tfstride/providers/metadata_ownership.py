from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from tfstride.providers.contracts import (
    DEFAULT_RESOURCE_METADATA_OWNERSHIP_CONTRACT,
    ResourceMetadataOwnershipContract,
)
from tfstride.resource_metadata import MetadataField


class ProviderMetadataOwnershipError(ValueError):
    """Raised when provider facts try to write metadata outside their namespace."""


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
        provider_key = provider.strip().lower()
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
            _field_names_by_identity=MappingProxyType(
                {id(field): name for name, field in fields_by_name.items()}
            ),
        )

    def validate(self, field: MetadataField[Any]) -> None:
        if id(field) in self._field_names_by_identity:
            return
        raise ProviderMetadataOwnershipError(
            f"Metadata field `{field.key}` is not writable through {self.provider} resource facts; "
            f"use a field from {self.namespace_name}."
        )


def _metadata_fields_by_name(namespace: type) -> dict[str, MetadataField[Any]]:
    return {
        name: value
        for name, value in vars(namespace).items()
        if isinstance(value, MetadataField)
    }