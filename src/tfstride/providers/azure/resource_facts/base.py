from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TypeVar

from tfstride.models import NormalizedResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.public_network import PUBLIC_NETWORK_FALLBACK_UNKNOWN
from tfstride.providers.metadata_ownership import ProviderMetadataWriteValidator
from tfstride.resource_metadata import MetadataField, StringListMetadataField

_MetadataValue = TypeVar("_MetadataValue")
_AZURE_METADATA_WRITE_VALIDATOR = ProviderMetadataWriteValidator.build(
    provider="azure",
    namespace=AzureResourceMetadata,
)


@dataclass(frozen=True, slots=True)
class AzureBaseFacts:
    """Azure-owned view over normalized metadata and relationship posture."""

    resource: NormalizedResource

    def get(self, field: MetadataField[_MetadataValue]) -> _MetadataValue:
        return self.resource.get_metadata_field(field)

    def set(self, field: MetadataField[_MetadataValue], value: _MetadataValue) -> None:
        _AZURE_METADATA_WRITE_VALIDATOR.validate(field)
        self.resource.set_metadata_field(field, value)

    def optional_bool(self, field: MetadataField[bool]) -> bool | None:
        if not self.resource.has_metadata_value(field):
            return None
        return self.get(field)

    def append(self, field: StringListMetadataField, value: str | None) -> None:
        _AZURE_METADATA_WRITE_VALIDATOR.validate(field)
        self.resource.append_metadata_field(field, value)

    def extend(self, field: StringListMetadataField, values: Sequence[str | None]) -> None:
        _AZURE_METADATA_WRITE_VALIDATOR.validate(field)
        self.resource.extend_metadata_field(field, values)

    @property
    def name(self) -> str | None:
        return self.get(AzureResourceMetadata.NAME)

    @property
    def min_tls_version(self) -> str | None:
        return self.get(AzureResourceMetadata.MIN_TLS_VERSION)

    @property
    def public_network_access_enabled(self) -> bool | None:
        return self.optional_bool(AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED)

    @property
    def public_network_fallback_state(self) -> str:
        return self.get(AzureResourceMetadata.PUBLIC_NETWORK_FALLBACK_STATE) or PUBLIC_NETWORK_FALLBACK_UNKNOWN

    @property
    def network_default_action(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_DEFAULT_ACTION)

    @property
    def network_rule_source_address(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_RULE_SOURCE_ADDRESS)

    def set_storage_encrypted(self, value: bool) -> None:
        self.resource.storage_encrypted = value

    def add_unresolved_resource_reference(self, kind: str, reference: str | None) -> None:
        self.append(
            AzureResourceMetadata.UNRESOLVED_RESOURCE_REFERENCES,
            f"{kind}:{reference}" if reference else kind,
        )

    def set_public_endpoint_posture(self, *, reachable: bool, reasons: Sequence[str]) -> None:
        self.resource.public_access_configured = reachable
        self.resource.direct_internet_reachable = reachable
        self.resource.internet_ingress_capable = reachable
        self.resource.public_access_reasons = list(reasons)
        self.resource.internet_ingress_reasons = list(reasons)
