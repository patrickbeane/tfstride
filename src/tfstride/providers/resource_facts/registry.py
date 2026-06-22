from __future__ import annotations

from collections.abc import Iterable

from tfstride.models import NormalizedResource
from tfstride.providers.names import normalize_provider_name
from tfstride.providers.resource_facts.contracts import (
    ProviderResourceFactDomains,
    ProviderResourceFactsFactory,
)
from tfstride.providers.resource_facts.neutral import neutral_provider_resource_fact_domains


class ProviderResourceFactsRegistryError(ValueError):
    """Raised when provider facts registry configuration or lookup fails."""


class ProviderResourceFactsNotRegisteredError(ProviderResourceFactsRegistryError):
    """Raised when a requested provider has no registered facts factory."""


class ProviderResourceFactsRegistry:
    def __init__(
        self,
        factories: Iterable[tuple[str, ProviderResourceFactsFactory]] = (),
    ) -> None:
        self._factories: dict[str, ProviderResourceFactsFactory] = {}
        for provider, factory in factories:
            self.register(provider, factory)

    def register(self, provider: str, factory: ProviderResourceFactsFactory) -> None:
        provider_name = normalize_provider_name(provider)
        if not provider_name:
            raise ProviderResourceFactsRegistryError("Provider facts factories must define a non-empty provider name.")
        if provider_name in self._factories:
            raise ProviderResourceFactsRegistryError(
                f"Provider facts factory already registered for `{provider_name}`."
            )
        if not callable(factory):
            raise ProviderResourceFactsRegistryError(f"Provider facts factory for `{provider_name}` must be callable.")
        self._factories[provider_name] = factory

    def get(self, provider: str) -> ProviderResourceFactsFactory:
        provider_name = normalize_provider_name(provider)
        try:
            return self._factories[provider_name]
        except KeyError as exc:
            raise ProviderResourceFactsNotRegisteredError(
                f"No provider facts factory registered for `{provider_name}`."
            ) from exc

    def facts_for(self, resource: NormalizedResource) -> ProviderResourceFactDomains:
        provider_name = normalize_provider_name(resource.provider)
        factory = self._factories.get(provider_name)
        if factory is None:
            return neutral_provider_resource_fact_domains(resource)
        return factory(resource)

    def providers(self) -> tuple[str, ...]:
        return tuple(self._factories)
