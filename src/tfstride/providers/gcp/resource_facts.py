from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TypeVar

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.resource_facts import NeutralProviderResourceFacts
from tfstride.resource_metadata import MetadataField, StringListMetadataField


_MetadataValue = TypeVar("_MetadataValue")


@dataclass(frozen=True, slots=True)
class GcpResourceFacts(NeutralProviderResourceFacts):
    """GCP-owned view over provider-specific resource metadata."""

    def get(self, field: MetadataField[_MetadataValue]) -> _MetadataValue:
        return self.resource.get_metadata_field(field)

    def set(self, field: MetadataField[_MetadataValue], value: _MetadataValue) -> None:
        self.resource.set_metadata_field(field, value)

    def append(self, field: StringListMetadataField, value: str | None) -> None:
        self.resource.append_metadata_field(field, value)

    def extend(self, field: StringListMetadataField, values: Sequence[str | None]) -> None:
        self.resource.extend_metadata_field(field, values)

    @property
    def bucket_name(self) -> str | None:
        return self.get(GcpResourceMetadata.BUCKET_NAME)

    @property
    def network_tags(self) -> list[str]:
        return self.get(GcpResourceMetadata.NETWORK_TAGS)

    @property
    def internet_ingress_firewalls(self) -> list[str]:
        return self.get(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS)

    @property
    def iam_role(self) -> str | None:
        return self.get(GcpResourceMetadata.IAM_ROLE)

    @property
    def iam_member(self) -> str | None:
        return self.get(GcpResourceMetadata.IAM_MEMBER)


def gcp_facts(resource: NormalizedResource) -> GcpResourceFacts:
    return GcpResourceFacts(resource)