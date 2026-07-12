from __future__ import annotations

from typing import Any

from tfstride.providers.gcp.metadata import GcpResourceMetadata


class GcpStorageFacts:
    __slots__ = ()

    @property
    def bucket_name(self) -> str | None:
        return self.get(GcpResourceMetadata.BUCKET_NAME)

    @property
    def uniform_bucket_level_access(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.UNIFORM_BUCKET_LEVEL_ACCESS)

    @property
    def public_access_prevention(self) -> str | None:
        return self.get(GcpResourceMetadata.PUBLIC_ACCESS_PREVENTION)

    @property
    def versioning_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GCS_VERSIONING_ENABLED)

    @property
    def gcs_retention_period_seconds(self) -> int | None:
        return self.get(GcpResourceMetadata.GCS_RETENTION_PERIOD_SECONDS)

    @property
    def gcs_retention_policy_locked(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GCS_RETENTION_POLICY_LOCKED)

    @property
    def gcs_retention_policy_configuration(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GCS_RETENTION_POLICY_CONFIGURATION)

    @property
    def gcs_retention_policy_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.GCS_RETENTION_POLICY_UNCERTAINTIES)

    @property
    def default_kms_key_name(self) -> str | None:
        return self.get(GcpResourceMetadata.GCS_DEFAULT_KMS_KEY_NAME)

    @property
    def customer_managed_encryption(self) -> bool | None:
        value = self.optional_bool(GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION)
        if value is not None:
            return value
        if self.default_kms_key_name:
            return True
        return None
