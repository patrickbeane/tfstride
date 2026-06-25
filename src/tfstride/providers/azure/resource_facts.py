from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TypeVar

from tfstride.models import NormalizedResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.metadata_ownership import ProviderMetadataWriteValidator
from tfstride.providers.resource_facts import NeutralProviderResourceFacts, ProviderResourceFactDomains
from tfstride.resource_metadata import MetadataField, StringListMetadataField

_MetadataValue = TypeVar("_MetadataValue")
_AZURE_METADATA_WRITE_VALIDATOR = ProviderMetadataWriteValidator.build(
    provider="azure",
    namespace=AzureResourceMetadata,
)


@dataclass(frozen=True, slots=True)
class AzureResourceFacts(NeutralProviderResourceFacts):
    """Azure-owned view over storage metadata and normalized posture."""

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

    @property
    def bucket_name(self) -> str | None:
        return self.get(AzureResourceMetadata.NAME)

    @property
    def storage_account_id(self) -> str | None:
        return self.get(AzureResourceMetadata.STORAGE_ACCOUNT_ID)

    @property
    def storage_account_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.STORAGE_ACCOUNT_REFERENCE)

    @property
    def resolved_storage_account_address(self) -> str | None:
        return self.get(AzureResourceMetadata.RESOLVED_STORAGE_ACCOUNT_ADDRESS)

    @property
    def container_access_type(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_ACCESS_TYPE)

    @property
    def allow_nested_items_to_be_public(self) -> bool | None:
        return self.optional_bool(AzureResourceMetadata.ALLOW_NESTED_ITEMS_TO_BE_PUBLIC)

    @property
    def shared_access_key_enabled(self) -> bool | None:
        return self.optional_bool(AzureResourceMetadata.SHARED_ACCESS_KEY_ENABLED)

    @property
    def min_tls_version(self) -> str | None:
        return self.get(AzureResourceMetadata.MIN_TLS_VERSION)

    @property
    def public_network_access_enabled(self) -> bool | None:
        return self.optional_bool(AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED)

    @property
    def network_default_action(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_DEFAULT_ACTION)

    @property
    def network_rule_source_address(self) -> str | None:
        return self.get(AzureResourceMetadata.NETWORK_RULE_SOURCE_ADDRESS)

    @property
    def public_container_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.PUBLIC_CONTAINER_ADDRESSES)

    def set_resolved_storage_account_address(self, address: str) -> None:
        self.set(AzureResourceMetadata.RESOLVED_STORAGE_ACCOUNT_ADDRESS, address)

    def set_effective_network_rule(self, default_action: str, source_address: str | None) -> None:
        self.set(AzureResourceMetadata.NETWORK_DEFAULT_ACTION, default_action)
        self.set(AzureResourceMetadata.NETWORK_RULE_SOURCE_ADDRESS, source_address)

    def add_public_container_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.PUBLIC_CONTAINER_ADDRESSES, address)

    def add_unresolved_storage_account_reference(self, reference: str | None) -> None:
        self.append(AzureResourceMetadata.UNRESOLVED_STORAGE_ACCOUNT_REFERENCES, reference)

    def set_public_endpoint_posture(
        self,
        *,
        reachable: bool,
        reasons: Sequence[str],
    ) -> None:
        self.resource.public_access_configured = reachable
        self.resource.direct_internet_reachable = reachable
        self.resource.internet_ingress_capable = reachable
        self.resource.public_access_reasons = list(reasons)
        self.resource.internet_ingress_reasons = list(reasons)

    def set_public_container_posture(
        self,
        *,
        configured: bool,
        exposed: bool,
        reasons: Sequence[str],
    ) -> None:
        self.resource.public_access_configured = configured
        self.resource.public_exposure = exposed
        self.resource.publicly_accessible = exposed
        self.resource.direct_internet_reachable = exposed
        self.resource.public_access_reasons = list(reasons)
        self.resource.public_exposure_reasons = list(reasons) if exposed else []

    def set_public_container_exposure(self, reasons: Sequence[str]) -> None:
        self.resource.public_exposure = True
        self.resource.publicly_accessible = True
        self.resource.public_exposure_reasons = list(reasons)


def azure_facts(resource: NormalizedResource) -> AzureResourceFacts:
    return AzureResourceFacts(resource)


def azure_fact_domains(resource: NormalizedResource) -> ProviderResourceFactDomains:
    facts = azure_facts(resource)
    return ProviderResourceFactDomains(
        storage=facts,
        iam=facts,
        sql=facts,
        compute=facts,
        workload=facts,
    )
