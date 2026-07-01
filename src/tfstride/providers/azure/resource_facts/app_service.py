from __future__ import annotations

from typing import Any

from tfstride.providers.azure.metadata import AzureResourceMetadata


class AzureAppServiceFacts:
    __slots__ = ()

    @property
    def app_service_id(self) -> str | None:
        return self.get(AzureResourceMetadata.APP_SERVICE_ID)

    @property
    def app_service_plan_reference(self) -> str | None:
        return self.get(AzureResourceMetadata.APP_SERVICE_PLAN_REFERENCE)

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
    def app_service_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_POSTURE_UNCERTAINTIES)
