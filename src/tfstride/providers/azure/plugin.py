from __future__ import annotations

from typing import TYPE_CHECKING

from tfstride.providers.azure.limitations import AZURE_LIMITATIONS
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import SUPPORTED_AZURE_TYPES, AzureNormalizer
from tfstride.providers.azure.resource_capabilities import AZURE_RESOURCE_CAPABILITIES
from tfstride.providers.azure.resource_decorator import AzureResourceDecorator
from tfstride.providers.azure.resource_facts import azure_fact_domains
from tfstride.providers.plugin import ProviderPlugin

if TYPE_CHECKING:
    from tfstride.analysis.finding_factory import FindingFactory
    from tfstride.analysis.rule_definitions import RuleContribution
    from tfstride.analysis.rule_registry import RuleMetadata


def _azure_rule_metadata() -> tuple[RuleMetadata, ...]:
    from tfstride.providers.azure.rule_catalog import AZURE_RULE_METADATA

    return AZURE_RULE_METADATA


def _azure_rule_contribution(finding_factory: FindingFactory) -> RuleContribution:
    from tfstride.providers.azure.rules import build_azure_rule_contribution

    return build_azure_rule_contribution(finding_factory)


def azure_provider_plugin() -> ProviderPlugin:
    return ProviderPlugin(
        provider="azure",
        normalizer_factory=AzureNormalizer,
        resource_facts_factory=azure_fact_domains,
        metadata_namespace=AzureResourceMetadata,
        supported_resource_types=SUPPORTED_AZURE_TYPES,
        resource_capabilities=AZURE_RESOURCE_CAPABILITIES,
        limitations=AZURE_LIMITATIONS,
        resource_decorator_factory=AzureResourceDecorator,
        rule_metadata_factory=_azure_rule_metadata,
        rule_contribution_factory=_azure_rule_contribution,
    )
