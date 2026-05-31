from __future__ import annotations

from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.registry import ProviderRegistry
from tfstride.providers.resource_facts import ProviderResourceFactsRegistry


DEFAULT_PROVIDER = "aws"


def default_provider_registry() -> ProviderRegistry:
    return ProviderRegistry([AwsNormalizer()])


def default_resource_facts_registry() -> ProviderResourceFactsRegistry:
    return ProviderResourceFactsRegistry([(DEFAULT_PROVIDER, aws_facts)])