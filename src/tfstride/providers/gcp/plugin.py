from __future__ import annotations

from typing import TYPE_CHECKING

from tfstride.providers.gcp.limitations import GCP_LIMITATIONS
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import SUPPORTED_GCP_TYPES, GcpNormalizer
from tfstride.providers.gcp.resource_capabilities import GCP_RESOURCE_CAPABILITIES
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator
from tfstride.providers.gcp.resource_facts import gcp_fact_domains
from tfstride.providers.plugin import ProviderPlugin

if TYPE_CHECKING:
    from tfstride.analysis.boundaries.types import BoundaryContributor
    from tfstride.analysis.finding_factory import FindingFactory
    from tfstride.analysis.rule_definitions import RuleContribution


def _gcp_boundary_contributor() -> BoundaryContributor:
    from tfstride.providers.gcp.boundaries import GcpBoundaryContributor

    return GcpBoundaryContributor()


def _gcp_rule_contribution(finding_factory: FindingFactory) -> RuleContribution:
    from tfstride.providers.gcp.rules import build_gcp_rule_contribution

    return build_gcp_rule_contribution(finding_factory)


def gcp_provider_plugin() -> ProviderPlugin:
    return ProviderPlugin(
        provider="gcp",
        normalizer_factory=GcpNormalizer,
        resource_facts_factory=gcp_fact_domains,
        metadata_namespace=GcpResourceMetadata,
        supported_resource_types=frozenset(SUPPORTED_GCP_TYPES),
        resource_capabilities=GCP_RESOURCE_CAPABILITIES,
        limitations=GCP_LIMITATIONS,
        resource_decorator_factory=GcpResourceDecorator,
        rule_contribution_factory=_gcp_rule_contribution,
        boundary_contributor_factory=_gcp_boundary_contributor,
    )
