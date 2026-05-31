from __future__ import annotations

from tfstride.providers.aws.plugin import aws_provider_plugin
from tfstride.providers.gcp.plugin import gcp_provider_plugin
from tfstride.providers.plugin import (
    ProviderPlugin,
    provider_limitations_from_plugins,
    provider_registry_from_plugins,
    resource_capability_registry_from_plugins,
    resource_facts_registry_from_plugins,
)
from tfstride.providers.registry import ProviderRegistry
from tfstride.providers.resource_capabilities import ProviderResourceCapabilityRegistry
from tfstride.providers.resource_facts import ProviderResourceFactsRegistry


DEFAULT_PROVIDER = "aws"


def default_provider_plugins() -> tuple[ProviderPlugin, ...]:
    return (aws_provider_plugin(), gcp_provider_plugin())


def default_provider_registry() -> ProviderRegistry:
    return provider_registry_from_plugins(default_provider_plugins())


def default_resource_facts_registry() -> ProviderResourceFactsRegistry:
    return resource_facts_registry_from_plugins(default_provider_plugins())


def default_resource_capability_registry() -> ProviderResourceCapabilityRegistry:
    return resource_capability_registry_from_plugins(default_provider_plugins())


def default_provider_limitations() -> dict[str, tuple[str, ...]]:
    return provider_limitations_from_plugins(default_provider_plugins())