from __future__ import annotations

from tfstride.providers.azure.limitations import AZURE_LIMITATIONS
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import SUPPORTED_AZURE_TYPES, AzureNormalizer
from tfstride.providers.azure.resource_capabilities import AZURE_RESOURCE_CAPABILITIES
from tfstride.providers.plugin import ProviderPlugin
from tfstride.providers.resource_facts import neutral_provider_resource_fact_domains


def azure_provider_plugin() -> ProviderPlugin:
    return ProviderPlugin(
        provider="azure",
        normalizer_factory=AzureNormalizer,
        resource_facts_factory=neutral_provider_resource_fact_domains,
        metadata_namespace=AzureResourceMetadata,
        supported_resource_types=SUPPORTED_AZURE_TYPES,
        resource_capabilities=AZURE_RESOURCE_CAPABILITIES,
        limitations=AZURE_LIMITATIONS,
    )
