from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.catalog import default_resource_facts_registry
from tfstride.providers.resource_facts import (
    ProviderResourceFacts,
    ProviderResourceFactsRegistry,
)


_DEFAULT_RESOURCE_FACTS_REGISTRY = default_resource_facts_registry()


@dataclass(frozen=True, slots=True)
class AnalysisResourceFacts:
    """Read facade for provider-backed facts used by shared analysis."""

    resource: NormalizedResource
    _provider_facts: ProviderResourceFacts | None = None

    def __post_init__(self) -> None:
        if self._provider_facts is None:
            object.__setattr__(
                self,
                "_provider_facts",
                _DEFAULT_RESOURCE_FACTS_REGISTRY.facts_for(self.resource),
            )

    @property
    def _facts(self) -> ProviderResourceFacts:
        if self._provider_facts is None:
            raise RuntimeError("AnalysisResourceFacts was initialized without provider facts.")
        return self._provider_facts

    @property
    def bucket_name(self) -> str | None:
        return self._facts.bucket_name

    @property
    def bucket_acl(self) -> str:
        return self._facts.bucket_acl

    @property
    def public_access_block(self) -> dict[str, bool] | None:
        return self._facts.public_access_block

    @property
    def policy_document(self) -> dict[str, Any]:
        return self._facts.policy_document

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        return self._facts.trust_statements

    @property
    def database_engine(self) -> str | None:
        return self._facts.engine

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return self._facts.resource_policy_source_addresses


def analysis_facts(
    resource: NormalizedResource,
    *,
    facts_registry: ProviderResourceFactsRegistry | None = None,
) -> AnalysisResourceFacts:
    registry = facts_registry or _DEFAULT_RESOURCE_FACTS_REGISTRY
    return AnalysisResourceFacts(resource, registry.facts_for(resource))