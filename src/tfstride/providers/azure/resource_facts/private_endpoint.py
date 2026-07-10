from __future__ import annotations

from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_facts.base import AzureBaseFacts


class AzurePrivateEndpointFacts(AzureBaseFacts):
    __slots__ = ()

    @property
    def private_endpoint_id(self) -> str | None:
        return self.get(AzureResourceMetadata.PRIVATE_ENDPOINT_ID)

    @property
    def private_service_connections(self) -> list[dict]:
        return self.get(AzureResourceMetadata.PRIVATE_SERVICE_CONNECTIONS)

    @property
    def private_connection_resource_ids(self) -> list[str]:
        return self.get(AzureResourceMetadata.PRIVATE_CONNECTION_RESOURCE_IDS)

    @property
    def private_endpoint_subresource_names(self) -> list[str]:
        return self.get(AzureResourceMetadata.PRIVATE_ENDPOINT_SUBRESOURCE_NAMES)

    @property
    def private_dns_zone_group_names(self) -> list[str]:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_GROUP_NAMES)

    @property
    def private_dns_zone_ids(self) -> list[str]:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_IDS)

    @property
    def private_dns_zone_groups(self) -> list[dict]:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_GROUPS)

    @property
    def private_dns_zone_group_state(self) -> str | None:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_GROUP_STATE)

    @property
    def private_dns_zone_ids_state(self) -> str | None:
        return self.get(AzureResourceMetadata.PRIVATE_DNS_ZONE_IDS_STATE)

    @property
    def private_endpoint_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.PRIVATE_ENDPOINT_UNCERTAINTIES)
