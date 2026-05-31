from __future__ import annotations

from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import SUPPORTED_GCP_TYPES, GcpNormalizer
from tfstride.providers.gcp.resource_capabilities import GCP_RESOURCE_CAPABILITIES
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.plugin import ProviderPlugin


def gcp_provider_plugin() -> ProviderPlugin:
    return ProviderPlugin(
        provider="gcp",
        normalizer_factory=GcpNormalizer,
        resource_facts_factory=gcp_facts,
        metadata_namespace=GcpResourceMetadata,
        supported_resource_types=frozenset(SUPPORTED_GCP_TYPES),
        resource_capabilities=GCP_RESOURCE_CAPABILITIES,
    )