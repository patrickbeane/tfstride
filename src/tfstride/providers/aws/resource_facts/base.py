from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TypeVar

from tfstride.models import NormalizedResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.coercion import STATE_DISABLED, STATE_ENABLED
from tfstride.providers.metadata_ownership import ProviderMetadataWriteValidator
from tfstride.resource_metadata import MetadataField, StringListMetadataField

_MetadataValue = TypeVar("_MetadataValue")
_AWS_METADATA_WRITE_VALIDATOR = ProviderMetadataWriteValidator.build(
    provider="aws",
    namespace=AwsResourceMetadata,
)


@dataclass(frozen=True, slots=True)
class AwsBaseFacts:
    """AWS-owned view over normalized metadata and relationship posture."""

    resource: NormalizedResource

    def get(self, field: MetadataField[_MetadataValue]) -> _MetadataValue:
        return self.resource.get_metadata_field(field)

    def set(self, field: MetadataField[_MetadataValue], value: _MetadataValue) -> None:
        _AWS_METADATA_WRITE_VALIDATOR.validate(field)
        self.resource.set_metadata_field(field, value)

    def append(self, field: StringListMetadataField, value: str | None) -> None:
        _AWS_METADATA_WRITE_VALIDATOR.validate(field)
        self.resource.append_metadata_field(field, value)

    def extend(self, field: StringListMetadataField, values: Sequence[str | None]) -> None:
        _AWS_METADATA_WRITE_VALIDATOR.validate(field)
        self.resource.extend_metadata_field(field, values)

    @property
    def name(self) -> str | None:
        return self.get(AwsResourceMetadata.NAME)

    @property
    def resource_name(self) -> str | None:
        return self.name

    @property
    def engine(self) -> str | None:
        return self.get(AwsResourceMetadata.ENGINE)


def _bool_from_state(state: str | None) -> bool | None:
    if state == STATE_ENABLED:
        return True
    if state == STATE_DISABLED:
        return False
    return None
