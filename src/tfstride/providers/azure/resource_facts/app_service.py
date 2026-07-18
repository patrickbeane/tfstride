from __future__ import annotations

from typing import Any

from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_facts.base import AzureBaseFacts


class AzureAppServiceFacts(AzureBaseFacts):
    __slots__ = ()

    @property
    def app_service_id(self) -> str | None:
        return self.get(AzureResourceMetadata.APP_SERVICE_ID)

    @property
    def app_service_plan_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.APP_SERVICE_PLAN_REFERENCE)

    @property
    def app_service_key_vault_reference_identity_id(self) -> str | None:
        return self.get(AzureResourceMetadata.APP_SERVICE_KEY_VAULT_REFERENCE_IDENTITY_ID)

    @property
    def app_service_secret_references(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.APP_SERVICE_SECRET_REFERENCES)

    @property
    def app_service_secret_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_SECRET_POSTURE_UNCERTAINTIES)

    @property
    def app_service_vnet_integration_subnet_id(self) -> str | None:
        return self.get(AzureResourceMetadata.APP_SERVICE_VNET_INTEGRATION_SUBNET_ID)

    @property
    def app_service_ip_restriction_default_action(self) -> str | None:
        return self.get(AzureResourceMetadata.APP_SERVICE_IP_RESTRICTION_DEFAULT_ACTION)

    @property
    def app_service_scm_ip_restriction_default_action(self) -> str | None:
        return self.get(AzureResourceMetadata.APP_SERVICE_SCM_IP_RESTRICTION_DEFAULT_ACTION)

    @property
    def app_service_scm_use_main_ip_restriction(self) -> bool | None:
        return self.optional_bool(AzureResourceMetadata.APP_SERVICE_SCM_USE_MAIN_IP_RESTRICTION)

    @property
    def app_service_access_restrictions(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.APP_SERVICE_ACCESS_RESTRICTIONS)

    @property
    def app_service_scm_access_restrictions(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.APP_SERVICE_SCM_ACCESS_RESTRICTIONS)

    @property
    def ftps_state(self) -> str | None:
        return self.get(AzureResourceMetadata.FTPS_STATE)

    @property
    def app_service_auth_settings(self) -> dict[str, Any]:
        return self.get(AzureResourceMetadata.APP_SERVICE_AUTH_SETTINGS)

    @property
    def app_service_auth_settings_v2(self) -> dict[str, Any]:
        return self.get(AzureResourceMetadata.APP_SERVICE_AUTH_SETTINGS_V2)

    @property
    def app_service_legacy_auth_enabled_state(self) -> str | None:
        return _auth_string(self.app_service_auth_settings, "enabled_state")

    @property
    def app_service_legacy_unauthenticated_action(self) -> str | None:
        return _auth_string(self.app_service_auth_settings, "unauthenticated_action")

    @property
    def app_service_legacy_default_provider(self) -> str | None:
        return _auth_string(self.app_service_auth_settings, "default_provider")

    @property
    def app_service_legacy_token_store_state(self) -> str | None:
        return _auth_string(self.app_service_auth_settings, "token_store_state")

    @property
    def app_service_auth_v2_enabled_state(self) -> str | None:
        return _auth_string(self.app_service_auth_settings_v2, "auth_enabled_state")

    @property
    def app_service_auth_v2_require_authentication_state(self) -> str | None:
        return _auth_string(self.app_service_auth_settings_v2, "require_authentication_state")

    @property
    def app_service_auth_v2_unauthenticated_action(self) -> str | None:
        return _auth_string(self.app_service_auth_settings_v2, "unauthenticated_action")

    @property
    def app_service_auth_v2_default_provider(self) -> str | None:
        return _auth_string(self.app_service_auth_settings_v2, "default_provider")

    @property
    def app_service_auth_v2_token_store_state(self) -> str | None:
        return _auth_string(self.app_service_auth_settings_v2, "token_store_state")

    @property
    def app_service_auth_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_AUTH_POSTURE_UNCERTAINTIES)

    @property
    def container_image_references(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.CONTAINER_IMAGE_REFERENCES)

    @property
    def container_image_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.CONTAINER_IMAGE_POSTURE_UNCERTAINTIES)

    @property
    def acr_write_paths(self) -> list[dict[str, Any]]:
        return self.get(AzureResourceMetadata.ACR_WRITE_PATHS)

    @property
    def acr_write_path_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.ACR_WRITE_PATH_UNCERTAINTIES)

    def set_acr_write_paths(self, values: list[dict[str, Any]]) -> None:
        self.set(AzureResourceMetadata.ACR_WRITE_PATHS, values)

    def extend_acr_write_path_uncertainties(self, values: list[str]) -> None:
        self.extend(AzureResourceMetadata.ACR_WRITE_PATH_UNCERTAINTIES, values)

    @property
    def app_service_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_POSTURE_UNCERTAINTIES)


def _auth_string(values: dict[str, Any], key: str) -> str | None:
    value = values.get(key)
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None
