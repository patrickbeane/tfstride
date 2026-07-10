from __future__ import annotations

from collections.abc import Sequence

from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_facts.base import AzureBaseFacts


class AzureSqlFacts(AzureBaseFacts):
    __slots__ = ()

    @property
    def mssql_database_id(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_DATABASE_ID)

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
    def mssql_short_term_retention_state(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_SHORT_TERM_RETENTION_STATE)

    @property
    def mssql_short_term_retention_days(self) -> int | None:
        return self.get(AzureResourceMetadata.MSSQL_SHORT_TERM_RETENTION_DAYS)

    @property
    def mssql_backup_interval_hours(self) -> int | None:
        return self.get(AzureResourceMetadata.MSSQL_BACKUP_INTERVAL_HOURS)

    @property
    def mssql_long_term_retention_state(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_LONG_TERM_RETENTION_STATE)

    @property
    def mssql_long_term_weekly_retention(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_LONG_TERM_WEEKLY_RETENTION)

    @property
    def mssql_long_term_monthly_retention(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_LONG_TERM_MONTHLY_RETENTION)

    @property
    def mssql_long_term_yearly_retention(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_LONG_TERM_YEARLY_RETENTION)

    @property
    def mssql_long_term_week_of_year(self) -> int | None:
        return self.get(AzureResourceMetadata.MSSQL_LONG_TERM_WEEK_OF_YEAR)

    @property
    def mssql_geo_backup_state(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_GEO_BACKUP_STATE)

    @property
    def mssql_backup_storage_redundancy(self) -> str | None:
        return self.get(AzureResourceMetadata.MSSQL_BACKUP_STORAGE_REDUNDANCY)

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
