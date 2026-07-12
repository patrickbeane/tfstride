from __future__ import annotations

from typing import Any

from tfstride.providers.gcp.metadata import GcpResourceMetadata


class GcpCloudSqlFacts:
    __slots__ = ()

    @property
    def engine(self) -> str | None:
        return self.get(GcpResourceMetadata.DATABASE_VERSION)

    @property
    def authorized_networks(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.CLOUD_SQL_AUTHORIZED_NETWORKS)

    @property
    def backup_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.CLOUD_SQL_BACKUP_ENABLED)

    @property
    def point_in_time_recovery_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED)

    @property
    def ipv4_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.CLOUD_SQL_IPV4_ENABLED)

    @property
    def private_network(self) -> str | None:
        return self.get(GcpResourceMetadata.CLOUD_SQL_PRIVATE_NETWORK)

    @property
    def require_ssl(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.CLOUD_SQL_REQUIRE_SSL)

    @property
    def ssl_mode(self) -> str | None:
        return self.get(GcpResourceMetadata.CLOUD_SQL_SSL_MODE)

    @property
    def deletion_protection(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.DELETION_PROTECTION)
