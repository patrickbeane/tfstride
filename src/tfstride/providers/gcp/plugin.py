from __future__ import annotations

from typing import TYPE_CHECKING

from tfstride.providers.gcp.limitations import GCP_LIMITATIONS
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import SUPPORTED_GCP_TYPES, GcpNormalizer
from tfstride.providers.gcp.resource_capabilities import GCP_RESOURCE_CAPABILITIES
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator
from tfstride.providers.plugin import ProviderPlugin

if TYPE_CHECKING:
    from tfstride.analysis.boundaries.types import BoundaryContributor
    from tfstride.analysis.finding_factory import FindingFactory
    from tfstride.analysis.rule_definitions import RuleContribution
    from tfstride.analysis.rule_registry import RuleMetadata
    from tfstride.models import ResourceInventory
    from tfstride.providers.gcp.analysis_indexes import GcpAnalysisIndexes


def _gcp_analysis_indexes(inventory: ResourceInventory) -> GcpAnalysisIndexes:
    from tfstride.providers.gcp.analysis_indexes import build_gcp_analysis_indexes

    return build_gcp_analysis_indexes(inventory)


def _gcp_rule_metadata() -> tuple[RuleMetadata, ...]:
    from tfstride.providers.gcp.rule_catalog import GCP_RULE_METADATA

    return GCP_RULE_METADATA


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
        metadata_namespace=GcpResourceMetadata,
        supported_resource_types=frozenset(SUPPORTED_GCP_TYPES),
        resource_capabilities=GCP_RESOURCE_CAPABILITIES,
        limitations=GCP_LIMITATIONS,
        resource_decorator_factory=GcpResourceDecorator,
        rule_metadata_factory=_gcp_rule_metadata,
        rule_contribution_factory=_gcp_rule_contribution,
        boundary_contributor_factory=_gcp_boundary_contributor,
        analysis_index_factory=_gcp_analysis_indexes,
    )
