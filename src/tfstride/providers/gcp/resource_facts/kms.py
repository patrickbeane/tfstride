from __future__ import annotations

from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts.base import GcpBaseFacts


class GcpKmsFacts(GcpBaseFacts):
    __slots__ = ()

    @property
    def kms_purpose(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_PURPOSE)

    @property
    def kms_rotation_period(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_ROTATION_PERIOD)

    @property
    def kms_destroy_scheduled_duration(self) -> str | None:
        return self.get(GcpResourceMetadata.KMS_DESTROY_SCHEDULED_DURATION)

    @property
    def kms_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.KMS_POSTURE_UNCERTAINTIES)
