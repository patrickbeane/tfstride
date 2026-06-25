from __future__ import annotations

from collections.abc import Sequence

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_decoration_stages import (
    AzureDecorationStage,
    default_azure_decoration_stages,
)
from tfstride.providers.azure.resource_index import AzureDecorationContext, AzureResourceIndexBuilder


class AzureResourceDecorator:
    """Run ordered Azure storage, network, and compute relationship stages."""

    def __init__(
        self,
        *,
        index_builder: AzureResourceIndexBuilder | None = None,
        stages: Sequence[AzureDecorationStage] | None = None,
    ) -> None:
        self._index_builder = index_builder or AzureResourceIndexBuilder()
        self._stages = tuple(stages) if stages is not None else default_azure_decoration_stages()

    def decorate(self, resources: list[NormalizedResource]) -> None:
        context = AzureDecorationContext(index=self._index_builder.build(resources))
        for stage in self._stages:
            stage.apply(resources, context)
