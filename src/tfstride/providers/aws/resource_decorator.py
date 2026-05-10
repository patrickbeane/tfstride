from __future__ import annotations

from collections.abc import Sequence

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_decoration_stages import (
    AwsDecorationStage,
    default_aws_decoration_stages,
)
from tfstride.providers.aws.resource_index import AwsDecorationContext, AwsResourceIndexBuilder


class AwsResourceDecorator:
    def __init__(
        self,
        *,
        index_builder: AwsResourceIndexBuilder | None = None,
        stages: Sequence[AwsDecorationStage] | None = None,
    ) -> None:
        self._index_builder = index_builder or AwsResourceIndexBuilder()
        self._stages = tuple(stages) if stages is not None else default_aws_decoration_stages()

    def decorate(self, resources: list[NormalizedResource]) -> None:
        context = AwsDecorationContext(index=self._index_builder.build(resources))
        for stage in self._stages:
            stage.apply(resources, context)
