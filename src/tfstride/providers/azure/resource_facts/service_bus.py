from __future__ import annotations

from collections.abc import Sequence

from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.public_network import public_network_fallback_state
from tfstride.providers.azure.resource_facts.base import AzureBaseFacts
from tfstride.providers.coercion import STATE_DISABLED, STATE_ENABLED


class AzureServiceBusFacts(AzureBaseFacts):
    __slots__ = ()

    @property
    def service_bus_namespace_id(self) -> str | None:
        return self.get(AzureResourceMetadata.SERVICE_BUS_NAMESPACE_ID)

    @property
    def service_bus_namespace_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.SERVICE_BUS_NAMESPACE_REFERENCE)

    @property
    def resolved_service_bus_namespace_address(self) -> str | None:
        return self.get(AzureResourceMetadata.RESOLVED_SERVICE_BUS_NAMESPACE_ADDRESS)

    @property
    def service_bus_sku(self) -> str | None:
        return self.get(AzureResourceMetadata.SERVICE_BUS_SKU)

    @property
    def service_bus_tier(self) -> str | None:
        return self.get(AzureResourceMetadata.SERVICE_BUS_TIER)

    @property
    def service_bus_local_auth_state(self) -> str | None:
        return self.get(AzureResourceMetadata.SERVICE_BUS_LOCAL_AUTH_STATE)

    @property
    def service_bus_local_auth_enabled(self) -> bool | None:
        if self.service_bus_local_auth_state == STATE_ENABLED:
            return True
        if self.service_bus_local_auth_state == STATE_DISABLED:
            return False
        return None

    @property
    def service_bus_customer_managed_key_state(self) -> str | None:
        return self.get(AzureResourceMetadata.SERVICE_BUS_CUSTOMER_MANAGED_KEY_STATE)

    @property
    def service_bus_key_vault_key_id(self) -> str | None:
        return self.get(AzureResourceMetadata.SERVICE_BUS_KEY_VAULT_KEY_ID)

    @property
    def service_bus_network_rule_source_address(self) -> str | None:
        return self.get(AzureResourceMetadata.SERVICE_BUS_NETWORK_RULE_SOURCE_ADDRESS)

    @property
    def service_bus_customer_managed_key_source_address(self) -> str | None:
        return self.get(AzureResourceMetadata.SERVICE_BUS_CUSTOMER_MANAGED_KEY_SOURCE_ADDRESS)

    @property
    def service_bus_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.SERVICE_BUS_POSTURE_UNCERTAINTIES)

    @property
    def unresolved_service_bus_namespace_references(self) -> list[str]:
        return self.get(AzureResourceMetadata.UNRESOLVED_SERVICE_BUS_NAMESPACE_REFERENCES)

    def set_resolved_service_bus_namespace_address(self, address: str) -> None:
        self.set(AzureResourceMetadata.RESOLVED_SERVICE_BUS_NAMESPACE_ADDRESS, address)

    def set_effective_service_bus_network_rule(
        self,
        *,
        default_action: str | None,
        source_address: str,
        public_network_access_enabled: bool | None,
    ) -> None:
        self.set(AzureResourceMetadata.NETWORK_DEFAULT_ACTION, default_action)
        self.set(AzureResourceMetadata.SERVICE_BUS_NETWORK_RULE_SOURCE_ADDRESS, source_address)
        if public_network_access_enabled is not None:
            self.set(AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED, public_network_access_enabled)
            self.set(
                AzureResourceMetadata.PUBLIC_NETWORK_FALLBACK_STATE,
                public_network_fallback_state(public_network_access_enabled),
            )

    def set_service_bus_customer_managed_key(
        self,
        *,
        state: str,
        key_vault_key_id: str | None,
        source_address: str,
    ) -> None:
        self.set(AzureResourceMetadata.SERVICE_BUS_CUSTOMER_MANAGED_KEY_STATE, state)
        self.set(AzureResourceMetadata.SERVICE_BUS_KEY_VAULT_KEY_ID, key_vault_key_id)
        self.set(AzureResourceMetadata.SERVICE_BUS_CUSTOMER_MANAGED_KEY_SOURCE_ADDRESS, source_address)

    def extend_service_bus_posture_uncertainties(self, uncertainties: Sequence[str | None]) -> None:
        self.extend(AzureResourceMetadata.SERVICE_BUS_POSTURE_UNCERTAINTIES, uncertainties)

    def add_unresolved_service_bus_namespace_reference(self, reference: str | None) -> None:
        self.append(AzureResourceMetadata.UNRESOLVED_SERVICE_BUS_NAMESPACE_REFERENCES, reference)
