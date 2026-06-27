from __future__ import annotations

from collections.abc import Sequence

from tfstride.providers.azure.metadata import AzureResourceMetadata


class AzureSqlFacts:
    __slots__ = ()

    @property
    def mssql_server_id(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_SERVER_ID)

    @property
    def mssql_firewall_start_ip(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_FIREWALL_START_IP)

    @property
    def mssql_firewall_end_ip(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_FIREWALL_END_IP)

    @property
    def mssql_vnet_subnet_id(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_VNET_SUBNET_ID)

    @property
    def mssql_security_alert_state(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_SECURITY_ALERT_STATE)

    @property
    def mssql_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.MSSQL_POSTURE_UNCERTAINTIES)

    @property
    def mssql_firewall_rule_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.MSSQL_FIREWALL_RULE_ADDRESSES)

    @property
    def mssql_vnet_rule_addresses(self) -> list[str]:
        return self.get(AzureResourceMetadata.MSSQL_VNET_RULE_ADDRESSES)

    def add_mssql_firewall_rule_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.MSSQL_FIREWALL_RULE_ADDRESSES, address)

    def add_mssql_vnet_rule_address(self, address: str) -> None:
        self.append(AzureResourceMetadata.MSSQL_VNET_RULE_ADDRESSES, address)

    def extend_mssql_posture_uncertainties(self, uncertainties: Sequence[str | None]) -> None:
        self.extend(AzureResourceMetadata.MSSQL_POSTURE_UNCERTAINTIES, uncertainties)
