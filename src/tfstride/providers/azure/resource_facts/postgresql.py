from __future__ import annotations

from tfstride.providers.azure.metadata import AzureResourceMetadata


class AzurePostgresqlFacts:
    __slots__ = ()

    @property
    def postgresql_server_id(self) -> str | None:
        return self.get(AzureResourceMetadata.POSTGRESQL_SERVER_ID)

    @property
    def postgresql_firewall_start_ip(self) -> str | None:
        return self.get(AzureResourceMetadata.POSTGRESQL_FIREWALL_START_IP)

    @property
    def postgresql_firewall_end_ip(self) -> str | None:
        return self.get(AzureResourceMetadata.POSTGRESQL_FIREWALL_END_IP)

    @property
    def postgresql_ssl_min_protocol_version(self) -> str | None:
        return self.get(AzureResourceMetadata.POSTGRESQL_SSL_MIN_PROTOCOL_VERSION)

    @property
    def postgresql_geo_redundant_backup_enabled(self) -> bool | None:
        return self.optional_bool(AzureResourceMetadata.POSTGRESQL_GEO_REDUNDANT_BACKUP_ENABLED)

    @property
    def postgresql_delegated_subnet_id(self) -> str | None:
        return self.get(AzureResourceMetadata.POSTGRESQL_DELEGATED_SUBNET_ID)

    @property
    def postgresql_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.POSTGRESQL_POSTURE_UNCERTAINTIES)

    @property
    def postgresql_config_name(self) -> str | None:
        return self.get(AzureResourceMetadata.POSTGRESQL_CONFIG_NAME)

    @property
    def postgresql_config_value(self) -> str | None:
        return self.get(AzureResourceMetadata.POSTGRESQL_CONFIG_VALUE)

    @property
    def postgresql_config_server_id(self) -> str | None:
        return self.get(AzureResourceMetadata.POSTGRESQL_CONFIG_SERVER_ID)
