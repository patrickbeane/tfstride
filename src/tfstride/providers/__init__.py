"""Provider adapters for tfstride."""

from tfstride.providers.plugin import (
    ProviderPlugin,
    ProviderPluginError,
    ProviderResourceDecorator,
    provider_registry_from_plugins,
    resource_facts_registry_from_plugins,
)
from tfstride.providers.registry import ProviderNotRegisteredError, ProviderRegistry, ProviderRegistryError
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
    "ProviderResourceDecorator",
    "ProviderResourceFacts",
    "ProviderResourceFactsNotRegisteredError",
    "ProviderResourceFactsRegistry",
    "ProviderResourceFactsRegistryError",
    "provider_registry_from_plugins",
    "resource_facts_registry_from_plugins",
]