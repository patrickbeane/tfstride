from __future__ import annotations

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
    def ftps_state(self) -> str | None:
        return self.get(AzureResourceMetadata.FTPS_STATE)

    @property
    def app_service_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.APP_SERVICE_POSTURE_UNCERTAINTIES)
