from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.resource_facts import ProviderResourceFactDomains, ProviderResourceFactsRegistry

_DEFAULT_RESOURCE_FACTS_REGISTRY: ProviderResourceFactsRegistry | None = None


def _get_default_registry() -> ProviderResourceFactsRegistry:
    global _DEFAULT_RESOURCE_FACTS_REGISTRY
    if _DEFAULT_RESOURCE_FACTS_REGISTRY is None:
        from tfstride.providers.catalog import default_resource_facts_registry

        _DEFAULT_RESOURCE_FACTS_REGISTRY = default_resource_facts_registry()
    return _DEFAULT_RESOURCE_FACTS_REGISTRY


def analysis_facts(
    resource: NormalizedResource,
    *,
    facts_registry: ProviderResourceFactsRegistry | None = None,
) -> ProviderResourceFactDomains:
    registry = facts_registry or _get_default_registry()
    return registry.facts_for(resource)
