from __future__ import annotations

from typing import Any

from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_facts.base import AzureBaseFacts
from tfstride.providers.coercion import STATE_DISABLED, STATE_ENABLED


class AzureContainerRegistryFacts(AzureBaseFacts):
    __slots__ = ()

    @property
    def container_registry_id(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_ID)

    @property
    def container_registry_sku(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_SKU)

    @property
    def container_registry_login_server(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_LOGIN_SERVER)

    @property
    def container_registry_premium_tier_state(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_PREMIUM_TIER_STATE)

    @property
    def container_registry_is_premium(self) -> bool | None:
        return _bool_from_state(self.container_registry_premium_tier_state)

    @property
    def container_registry_admin_state(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_ADMIN_STATE)

    @property
    def container_registry_admin_enabled(self) -> bool | None:
        return _bool_from_state(self.container_registry_admin_state)

    @property
    def container_registry_anonymous_pull_state(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_ANONYMOUS_PULL_STATE)

    @property
    def container_registry_anonymous_pull_enabled(self) -> bool | None:
        return _bool_from_state(self.container_registry_anonymous_pull_state)

    @property
    def container_registry_customer_managed_key_state(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_CUSTOMER_MANAGED_KEY_STATE)

    @property
    def container_registry_key_vault_key_id(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_KEY_VAULT_KEY_ID)

    @property
    def container_registry_encryption_identity_client_id(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_ENCRYPTION_IDENTITY_CLIENT_ID)

    @property
    def container_registry_retention_state(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_RETENTION_STATE)

    @property
    def container_registry_retention_days(self) -> int | None:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_RETENTION_DAYS)

    @property
    def container_registry_export_policy_state(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_EXPORT_POLICY_STATE)

    @property
    def container_registry_export_policy_enabled(self) -> bool | None:
        return _bool_from_state(self.container_registry_export_policy_state)

    @property
    def container_registry_quarantine_policy_state(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_QUARANTINE_POLICY_STATE)

    @property
    def container_registry_quarantine_policy_enabled(self) -> bool | None:
        return _bool_from_state(self.container_registry_quarantine_policy_state)

    @property
    def container_registry_trust_policy_state(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_TRUST_POLICY_STATE)

    @property
    def container_registry_trust_policy_enabled(self) -> bool | None:
        return _bool_from_state(self.container_registry_trust_policy_state)

    @property
    def container_registry_zone_redundancy_state(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_ZONE_REDUNDANCY_STATE)

    @property
    def container_registry_zone_redundancy_enabled(self) -> bool | None:
        return _bool_from_state(self.container_registry_zone_redundancy_state)

    @property
    def container_registry_data_endpoint_state(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_DATA_ENDPOINT_STATE)

    @property
    def container_registry_data_endpoint_enabled(self) -> bool | None:
        return _bool_from_state(self.container_registry_data_endpoint_state)

    @property
    def container_registry_network_rule_bypass_option(self) -> str | None:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_NETWORK_RULE_BYPASS_OPTION)

    @property
    def container_registry_network_rule_set(self) -> dict[str, Any]:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_NETWORK_RULE_SET)

    @property
    def container_registry_encryption_configuration(self) -> dict[str, Any]:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_ENCRYPTION_CONFIGURATION)

    @property
    def container_registry_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.CONTAINER_REGISTRY_POSTURE_UNCERTAINTIES)


def _bool_from_state(state: str | None) -> bool | None:
    if state == STATE_ENABLED:
        return True
    if state == STATE_DISABLED:
        return False
    return None
