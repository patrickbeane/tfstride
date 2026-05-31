from __future__ import annotations

from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES, AwsNormalizer
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.plugin import ProviderPlugin


def aws_provider_plugin() -> ProviderPlugin:
    return ProviderPlugin(
        provider="aws",
        normalizer_factory=AwsNormalizer,
        resource_facts_factory=aws_facts,
        metadata_namespace=AwsResourceMetadata,
        supported_resource_types=frozenset(SUPPORTED_AWS_TYPES),
        resource_decorator_factory=AwsResourceDecorator,
    )