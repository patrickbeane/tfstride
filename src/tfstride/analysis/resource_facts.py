from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.resource_metadata import ResourceMetadata


@dataclass(frozen=True, slots=True)
class AnalysisResourceFacts:
    """Read facade for metadata-backed facts used by shared analysis."""

    resource: NormalizedResource

    @property
    def bucket_name(self) -> str | None:
        return self.resource.get_metadata_field(ResourceMetadata.BUCKET_NAME)

    @property
    def bucket_acl(self) -> str:
        return self.resource.get_metadata_field(ResourceMetadata.BUCKET_ACL) or ""

    @property
    def public_access_block(self) -> dict[str, bool] | None:
        return self.resource.get_metadata_field(ResourceMetadata.PUBLIC_ACCESS_BLOCK)

    @property
    def policy_document(self) -> dict[str, Any]:
        return self.resource.get_metadata_field(ResourceMetadata.POLICY_DOCUMENT)

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        return self.resource.get_metadata_field(ResourceMetadata.TRUST_STATEMENTS)

    @property
    def database_engine(self) -> str | None:
        return self.resource.get_metadata_field(ResourceMetadata.ENGINE)

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return self.resource.get_metadata_field(ResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES)


def analysis_facts(resource: NormalizedResource) -> AnalysisResourceFacts:
    return AnalysisResourceFacts(resource)