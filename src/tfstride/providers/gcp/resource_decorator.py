from __future__ import annotations

from collections.abc import Sequence

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.resource_decoration_stages import (
    GcpDecorationStage,
    default_gcp_decoration_stages,
)
from tfstride.providers.gcp.resource_index import GcpDecorationContext, GcpResourceIndexBuilder


class GcpResourceDecorator:
    """Run ordered GCP resource decoration stages."""

    def __init__(
        self,
        *,
        index_builder: GcpResourceIndexBuilder | None = None,
        stages: Sequence[GcpDecorationStage] | None = None,
    ) -> None:
        self._index_builder = index_builder or GcpResourceIndexBuilder()
        self._stages = tuple(stages) if stages is not None else default_gcp_decoration_stages()

    def decorate(self, resources: list[NormalizedResource]) -> None:
        context = GcpDecorationContext(index=self._index_builder.build(resources))
        for stage in self._stages:
            stage.apply(resources, context)
