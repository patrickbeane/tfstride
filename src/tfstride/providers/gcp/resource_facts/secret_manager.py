from __future__ import annotations

from typing import Any

from tfstride.providers.gcp.metadata import GcpResourceMetadata


class GcpSecretManagerFacts:
    __slots__ = ()

    @property
    def secret_manager_replication_mode(self) -> str | None:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_REPLICATION_MODE)

    @property
    def secret_manager_kms_key_names(self) -> list[str]:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_KMS_KEY_NAMES)

    @property
    def secret_manager_replication(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_REPLICATION)

    @property
    def secret_manager_ttl(self) -> str | None:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_TTL)

    @property
    def secret_manager_expire_time(self) -> str | None:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_EXPIRE_TIME)

    @property
    def secret_manager_version_destroy_ttl(self) -> str | None:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_VERSION_DESTROY_TTL)

    @property
    def secret_manager_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.SECRET_MANAGER_POSTURE_UNCERTAINTIES)
