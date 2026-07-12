"""Provider adapters for tfstride."""

from tfstride.providers.plugin import (
    ProviderBoundaryContributorFactory,
    ProviderPlugin,
    ProviderPluginError,
    ProviderResourceDecorator,
    ProviderRuleContributionFactory,
    ProviderRuleMetadataFactory,
    boundary_contributor_factories_by_provider_from_plugins,
    boundary_contributors_by_provider_from_plugins,
    boundary_contributors_from_plugins,
    provider_limitations_from_plugins,
    provider_registry_from_plugins,
    resource_capability_registry_from_plugins,
    rule_contribution_from_plugins,
    rule_metadata_from_plugins,
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

__all__ = [
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
    "ProviderRuleMetadataFactory",
    "ProviderSelectionError",
    "ResourceCapability",
    "boundary_contributor_factories_by_provider_from_plugins",
    "boundary_contributors_by_provider_from_plugins",
    "boundary_contributors_from_plugins",
    "provider_limitations_from_plugins",
    "provider_registry_from_plugins",
    "resource_capability_registry_from_plugins",
    "rule_contribution_from_plugins",
    "rule_metadata_from_plugins",
]
