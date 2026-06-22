"""Provider resource-fact contracts, neutral defaults, and registry."""

from tfstride.providers.resource_facts.contracts import (
    ProviderComputeFacts,
    ProviderIamFacts,
    ProviderResourceFactDomains,
    ProviderResourceFactsFactory,
    ProviderSqlFacts,
    ProviderStorageFacts,
    ProviderWorkloadFacts,
)
from tfstride.providers.resource_facts.neutral import (
    NeutralProviderComputeFacts,
    NeutralProviderIamFacts,
    NeutralProviderResourceFacts,
    NeutralProviderSqlFacts,
    NeutralProviderStorageFacts,
    NeutralProviderWorkloadFacts,
    neutral_provider_resource_fact_domains,
)
from tfstride.providers.resource_facts.registry import (
    ProviderResourceFactsNotRegisteredError,
    ProviderResourceFactsRegistry,
    ProviderResourceFactsRegistryError,
)

__all__ = [
    "NeutralProviderComputeFacts",
    "NeutralProviderIamFacts",
    "NeutralProviderResourceFacts",
    "NeutralProviderSqlFacts",
    "NeutralProviderStorageFacts",
    "NeutralProviderWorkloadFacts",
    "ProviderComputeFacts",
    "ProviderIamFacts",
    "ProviderResourceFactDomains",
    "ProviderResourceFactsFactory",
    "ProviderResourceFactsNotRegisteredError",
    "ProviderResourceFactsRegistry",
    "ProviderResourceFactsRegistryError",
    "ProviderSqlFacts",
    "ProviderStorageFacts",
    "ProviderWorkloadFacts",
    "neutral_provider_resource_fact_domains",
]
