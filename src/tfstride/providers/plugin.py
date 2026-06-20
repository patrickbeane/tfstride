from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol

from tfstride.models import NormalizedResource
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.registry import ProviderRegistry
from tfstride.providers.resource_capabilities import (
    ProviderResourceCapabilityRegistry,
    ProviderResourceCapabilityRegistryError,
    ResourceCapability,
    ResourceCapabilityMap,
)
from tfstride.providers.resource_facts import (
    ProviderResourceFactsFactory,
    ProviderResourceFactsRegistry,
)

if TYPE_CHECKING:
    from tfstride.analysis.boundaries.types import BoundaryContributor
    from tfstride.analysis.finding_factory import FindingFactory
    from tfstride.analysis.rule_definitions import RuleContribution

ProviderBoundaryContributorFactory = Callable[[], "BoundaryContributor"]
ProviderRuleContributionFactory = Callable[["FindingFactory"], "RuleContribution"]


class ProviderPluginError(ValueError):
    """Raised when a provider plugin descriptor is incomplete or inconsistent."""


class ProviderResourceDecorator(Protocol):
    """Provider-owned post-normalization resource decoration hook."""

    def decorate(self, resources: list[NormalizedResource]) -> None:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class ProviderPlugin:
    """Contract every provider package exposes to the shared application layer."""

    provider: str
    normalizer_factory: Callable[[], ProviderNormalizer]
    resource_facts_factory: ProviderResourceFactsFactory
    metadata_namespace: type
    supported_resource_types: frozenset[str]
    resource_capabilities: ResourceCapabilityMap = field(default_factory=dict)
    limitations: tuple[str, ...] = ()
    resource_decorator_factory: Callable[[], ProviderResourceDecorator] | None = None
    rule_contribution_factory: ProviderRuleContributionFactory | None = None
    boundary_contributor_factory: ProviderBoundaryContributorFactory | None = None

    def __post_init__(self) -> None:
        provider = _normalize_provider_name(self.provider)
        if not provider:
            raise ProviderPluginError("Provider plugins must define a non-empty provider name.")
        if not callable(self.normalizer_factory):
            raise ProviderPluginError(f"Provider plugin `{provider}` normalizer factory must be callable.")
        if not callable(self.resource_facts_factory):
            raise ProviderPluginError(f"Provider plugin `{provider}` facts factory must be callable.")
        if self.resource_decorator_factory is not None and not callable(self.resource_decorator_factory):
            raise ProviderPluginError(f"Provider plugin `{provider}` decorator factory must be callable.")
        if self.rule_contribution_factory is not None and not callable(self.rule_contribution_factory):
            raise ProviderPluginError(f"Provider plugin `{provider}` rule contribution factory must be callable.")
        if self.boundary_contributor_factory is not None and not callable(self.boundary_contributor_factory):
            raise ProviderPluginError(f"Provider plugin `{provider}` boundary contributor factory must be callable.")
        if not isinstance(self.metadata_namespace, type):
            raise ProviderPluginError(f"Provider plugin `{provider}` metadata namespace must be a type.")

        supported_resource_types = frozenset(str(item).strip() for item in self.supported_resource_types)
        if "" in supported_resource_types:
            raise ProviderPluginError(
                f"Provider plugin `{provider}` supported resource types must be non-empty strings."
            )
        limitations = tuple(str(item).strip() for item in self.limitations)
        if "" in limitations:
            raise ProviderPluginError(f"Provider plugin `{provider}` limitations must be non-empty strings.")
        resource_capabilities = _normalize_resource_capabilities(provider, self.resource_capabilities)

        object.__setattr__(self, "provider", provider)
        object.__setattr__(self, "supported_resource_types", supported_resource_types)
        object.__setattr__(self, "limitations", limitations)
        object.__setattr__(self, "resource_capabilities", MappingProxyType(resource_capabilities))

    def create_normalizer(self) -> ProviderNormalizer:
        normalizer = self.normalizer_factory()
        normalizer_provider = _normalize_provider_name(normalizer.provider)
        if normalizer_provider != self.provider:
            raise ProviderPluginError(
                f"Provider plugin `{self.provider}` created normalizer for `{normalizer_provider}`."
            )
        return normalizer

    def create_resource_decorator(self) -> ProviderResourceDecorator | None:
        if self.resource_decorator_factory is None:
            return None
        return self.resource_decorator_factory()

    def create_rule_contribution(self, finding_factory: FindingFactory) -> RuleContribution | None:
        if self.rule_contribution_factory is None:
            return None
        return self.rule_contribution_factory(finding_factory)

    def create_boundary_contributor(self) -> BoundaryContributor | None:
        if self.boundary_contributor_factory is None:
            return None
        return self.boundary_contributor_factory()

    def supports_resource_type(self, resource_type: str) -> bool:
        return str(resource_type).strip() in self.supported_resource_types

    def resource_types_for_capability(self, capability: ResourceCapability | str) -> frozenset[str]:
        try:
            normalized_capability = _normalize_resource_capability(capability)
        except ProviderResourceCapabilityRegistryError as exc:
            raise ProviderPluginError(str(exc)) from exc
        return self.resource_capabilities.get(normalized_capability, frozenset())

    def facts_registry_entry(self) -> tuple[str, ProviderResourceFactsFactory]:
        return (self.provider, self.resource_facts_factory)

    def capability_registry_entry(self) -> tuple[str, ResourceCapabilityMap]:
        return (self.provider, self.resource_capabilities)

    def limitations_entry(self) -> tuple[str, tuple[str, ...]]:
        return (self.provider, self.limitations)


def provider_registry_from_plugins(plugins: Iterable[ProviderPlugin]) -> ProviderRegistry:
    return ProviderRegistry(plugin.create_normalizer() for plugin in plugins)


def resource_facts_registry_from_plugins(
    plugins: Iterable[ProviderPlugin],
) -> ProviderResourceFactsRegistry:
    return ProviderResourceFactsRegistry(plugin.facts_registry_entry() for plugin in plugins)


def resource_capability_registry_from_plugins(
    plugins: Iterable[ProviderPlugin],
) -> ProviderResourceCapabilityRegistry:
    return ProviderResourceCapabilityRegistry(plugin.capability_registry_entry() for plugin in plugins)


def provider_limitations_from_plugins(plugins: Iterable[ProviderPlugin]) -> dict[str, tuple[str, ...]]:
    return {provider: limitations for provider, limitations in (plugin.limitations_entry() for plugin in plugins)}


def boundary_contributors_from_plugins(
    plugins: Iterable[ProviderPlugin],
    *,
    provider: str | None = None,
) -> tuple[BoundaryContributor, ...]:
    normalized_provider = _normalize_provider_name(provider) if provider is not None else None
    return tuple(
        contributor
        for plugin in plugins
        if normalized_provider is None or plugin.provider == normalized_provider
        if (contributor := plugin.create_boundary_contributor()) is not None
    )


def boundary_contributors_by_provider_from_plugins(
    plugins: Iterable[ProviderPlugin],
) -> dict[str, tuple[BoundaryContributor, ...]]:
    contributors_by_provider: dict[str, list[BoundaryContributor]] = {}
    for plugin in plugins:
        contributor = plugin.create_boundary_contributor()
        if contributor is None:
            continue
        contributors_by_provider.setdefault(plugin.provider, []).append(contributor)
    return {provider: tuple(contributors) for provider, contributors in contributors_by_provider.items()}


def boundary_contributor_factories_by_provider_from_plugins(
    plugins: Iterable[ProviderPlugin],
) -> dict[str, tuple[ProviderBoundaryContributorFactory, ...]]:
    factories_by_provider: dict[str, list[ProviderBoundaryContributorFactory]] = {}
    for plugin in plugins:
        if plugin.boundary_contributor_factory is None:
            continue
        factories_by_provider.setdefault(plugin.provider, []).append(plugin.boundary_contributor_factory)
    return {provider: tuple(factories) for provider, factories in factories_by_provider.items()}


def rule_contribution_from_plugins(
    plugins: Iterable[ProviderPlugin],
    finding_factory: FindingFactory,
) -> RuleContribution:
    from tfstride.analysis.rule_definitions import merge_rule_contributions_by_stage

    return merge_rule_contributions_by_stage(
        *(
            contribution
            for plugin in plugins
            if (contribution := plugin.create_rule_contribution(finding_factory)) is not None
        )
    )


def _normalize_resource_capabilities(
    provider: str,
    capabilities: Mapping[ResourceCapability | str, frozenset[str]],
) -> dict[ResourceCapability, frozenset[str]]:
    try:
        registry = ProviderResourceCapabilityRegistry([(provider, capabilities)])
    except ProviderResourceCapabilityRegistryError as exc:
        raise ProviderPluginError(str(exc)) from exc
    return {
        capability: registry.resource_types_for_provider(provider, capability)
        for capability in ResourceCapability
        if registry.resource_types_for_provider(provider, capability)
    }


def _normalize_resource_capability(capability: ResourceCapability | str) -> ResourceCapability:
    try:
        return capability if isinstance(capability, ResourceCapability) else ResourceCapability(str(capability))
    except ValueError as exc:
        raise ProviderResourceCapabilityRegistryError(f"Unknown resource capability `{capability}`.") from exc


def _normalize_provider_name(provider: str) -> str:
    return str(provider).strip().lower()
