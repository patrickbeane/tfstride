"""Provider adapters for tfstride."""

from tfstride.providers.plugin import (
    ProviderBoundaryContributorFactory,
    ProviderPlugin,
    ProviderPluginError,
    ProviderResourceDecorator,
    ProviderRuleContributionFactory,
    boundary_contributor_factories_by_provider_from_plugins,
    boundary_contributors_by_provider_from_plugins,
    boundary_contributors_from_plugins,
    provider_limitations_from_plugins,
    provider_registry_from_plugins,
    resource_capability_registry_from_plugins,
    resource_facts_registry_from_plugins,
    rule_contribution_from_plugins,
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
    ProviderResourceFactDomains,
    ProviderResourceFactsNotRegisteredError,
    ProviderResourceFactsRegistry,
    ProviderResourceFactsRegistryError,
)

__all__ = [
    "NeutralProviderResourceFacts",
    "ProviderBoundaryContributorFactory",
    "ProviderNotRegisteredError",
    "ProviderPlugin",
    "ProviderPluginError",
    "ProviderRegistry",
    "ProviderRegistryError",
    "ProviderResourceCapabilityRegistry",
    "ProviderResourceCapabilityRegistryError",
    "ProviderResourceDecorator",
    "ProviderRuleContributionFactory",
    "ProviderResourceFactDomains",
    "ProviderSelectionError",
    "ProviderResourceFactsNotRegisteredError",
    "ProviderResourceFactsRegistry",
    "ProviderResourceFactsRegistryError",
    "ResourceCapability",
    "boundary_contributor_factories_by_provider_from_plugins",
    "boundary_contributors_by_provider_from_plugins",
    "boundary_contributors_from_plugins",
    "provider_limitations_from_plugins",
    "provider_registry_from_plugins",
    "resource_capability_registry_from_plugins",
    "resource_facts_registry_from_plugins",
    "rule_contribution_from_plugins",
]
