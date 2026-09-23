from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata


def firewall_field_is_uncertain(resource: NormalizedResource, field: str) -> bool:
    return any(
        field in match["unknown_fields"] or field in match["unsupported_fields"]
        for match in resource.get_metadata_field(GcpResourceMetadata.FIREWALL_MATCHES)
    )
