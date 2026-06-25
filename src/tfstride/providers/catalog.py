from __future__ import annotations

from functools import cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tfstride.analysis.boundaries.types import BoundaryContributor
    from tfstride.analysis.finding_factory import FindingFactory
    from tfstride.analysis.indexes import AnalysisIndexExtensionFactory
    from tfstride.analysis.rule_definitions import RuleContribution
    from tfstride.analysis.rule_registry import RuleMetadata

from tfstride.providers.aws.plugin import aws_provider_plugin
from tfstride.providers.azure.plugin import azure_provider_plugin
from tfstride.providers.gcp.plugin import gcp_provider_plugin
from tfstride.providers.names import normalize_provider_name
from tfstride.providers.plugin import (
    ProviderBoundaryContributorFactory,
    ProviderPlugin,
    analysis_index_factories_by_provider_from_plugins,
    boundary_contributor_factories_by_provider_from_plugins,
    boundary_contributors_by_provider_from_plugins,
    boundary_contributors_from_plugins,
    provider_limitations_from_plugins,
    provider_registry_from_plugins,
    resource_capability_registry_from_plugins,
    resource_facts_registry_from_plugins,
    rule_contribution_from_plugins,
    rule_metadata_from_plugins,
)
from tfstride.providers.registry import ProviderRegistry
from tfstride.providers.resource_capabilities import ProviderResourceCapabilityRegistry
from tfstride.providers.resource_facts import ProviderResourceFactsRegistry

DEFAULT_PROVIDER = "aws"


@cache
def default_provider_plugins() -> tuple[ProviderPlugin, ...]:
    return (aws_provider_plugin(), gcp_provider_plugin(), azure_provider_plugin())


def default_provider_registry() -> ProviderRegistry:
    return provider_registry_from_plugins(default_provider_plugins())


def default_resource_facts_registry() -> ProviderResourceFactsRegistry:
    return resource_facts_registry_from_plugins(default_provider_plugins())


def default_resource_capability_registry() -> ProviderResourceCapabilityRegistry:
    return resource_capability_registry_from_plugins(default_provider_plugins())


def default_provider_limitations() -> dict[str, tuple[str, ...]]:
    return provider_limitations_from_plugins(default_provider_plugins())


def default_provider_rule_metadata() -> tuple[RuleMetadata, ...]:
    return rule_metadata_from_plugins(default_provider_plugins())


def default_provider_analysis_index_factories_by_provider() -> dict[str, AnalysisIndexExtensionFactory]:
    return analysis_index_factories_by_provider_from_plugins(default_provider_plugins())


def default_provider_analysis_index_factory(provider: str) -> AnalysisIndexExtensionFactory | None:
    return default_provider_analysis_index_factories_by_provider().get(normalize_provider_name(provider))


def default_provider_boundary_contributors(provider: str | None = None) -> tuple[BoundaryContributor, ...]:
    return boundary_contributors_from_plugins(default_provider_plugins(), provider=provider)


def default_provider_boundary_contributors_by_provider() -> dict[str, tuple[BoundaryContributor, ...]]:
    return boundary_contributors_by_provider_from_plugins(default_provider_plugins())


def default_provider_boundary_contributor_factories_by_provider() -> dict[
    str, tuple[ProviderBoundaryContributorFactory, ...]
]:
    return boundary_contributor_factories_by_provider_from_plugins(default_provider_plugins())


def default_rule_contribution(finding_factory: FindingFactory) -> RuleContribution:
    return rule_contribution_from_plugins(default_provider_plugins(), finding_factory)
