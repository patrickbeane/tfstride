from __future__ import annotations

from collections.abc import Sequence

from tfstride.providers.azure.metadata import AzureResourceMetadata


class AzureStorageFacts:
    __slots__ = ()

    @property
    def bucket_name(self) -> str | None:
        return self.name

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
    def public_container_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.PUBLIC_CONTAINER_ADDRESSES)

    @property
    def storage_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.STORAGE_POSTURE_UNCERTAINTIES)

    def set_resolved_storage_account_address(self, address: str) -> None:
        self.set(AzureResourceMetadata.RESOLVED_STORAGE_ACCOUNT_ADDRESS, address)

    def set_effective_network_rule(self, default_action: str | None, source_address: str | None) -> None:
        self.set(AzureResourceMetadata.NETWORK_DEFAULT_ACTION, default_action)
        self.set(AzureResourceMetadata.NETWORK_RULE_SOURCE_ADDRESS, source_address)

    def add_storage_posture_uncertainty(self, uncertainty: str | None) -> None:
        self.append(AzureResourceMetadata.STORAGE_POSTURE_UNCERTAINTIES, uncertainty)

    def extend_storage_posture_uncertainties(self, uncertainties: Sequence[str | None]) -> None:
        self.extend(AzureResourceMetadata.STORAGE_POSTURE_UNCERTAINTIES, uncertainties)

    def add_public_container_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.PUBLIC_CONTAINER_ADDRESSES, address)

    def add_unresolved_storage_account_reference(self, reference: str | None) -> None:
        self.append(AzureResourceMetadata.UNRESOLVED_STORAGE_ACCOUNT_REFERENCES, reference)

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
