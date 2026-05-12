from __future__ import annotations

from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.registry import ProviderRegistry


DEFAULT_PROVIDER = "aws"


def default_provider_registry() -> ProviderRegistry:
    return ProviderRegistry([AwsNormalizer()])