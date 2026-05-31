"""Provider adapters for tfstride."""

from tfstride.providers.plugin import (
    ProviderPlugin,
    ProviderPluginError,
    ProviderResourceDecorator,
    provider_limitations_from_plugins,
    provider_registry_from_plugins,
    resource_capability_registry_from_plugins,
    resource_facts_registry_from_plugins,
)
from tfstride.providers.registry import (
    ProviderNotRegisteredError,
    ProviderRegistry,
    ProviderRegistryError,
    ProviderSelectionError,
)
from tfstride.providers.resource_capabilities import (
    ProviderResourceCapabilityRegistry,
    ProviderResourceCapabilityRegistryError,
    ResourceCapability,
)
from tfstride.providers.resource_facts import (
    NeutralProviderResourceFacts,
    ProviderResourceFacts,
    ProviderResourceFactsNotRegisteredError,
    ProviderResourceFactsRegistry,
    ProviderResourceFactsRegistryError,
)

__all__ = [
    "NeutralProviderResourceFacts",
    "ProviderNotRegisteredError",
    "ProviderPlugin",
    "ProviderPluginError",
    "ProviderRegistry",
    "ProviderRegistryError",
    "ProviderResourceCapabilityRegistry",
    "ProviderResourceCapabilityRegistryError",
    "ProviderResourceDecorator",
    "ProviderResourceFacts",
    "ProviderSelectionError",
    "ProviderResourceFactsNotRegisteredError",
    "ProviderResourceFactsRegistry",
    "ProviderResourceFactsRegistryError",
    "ResourceCapability",
    "provider_limitations_from_plugins",
    "provider_registry_from_plugins",
    "resource_capability_registry_from_plugins",
    "resource_facts_registry_from_plugins",
]