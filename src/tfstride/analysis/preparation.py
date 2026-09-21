"""Internal preparation of the inputs for one analysis invocation."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from tfstride.analysis.boundaries import default_boundary_contributors, detect_trust_boundaries
from tfstride.analysis.indexes import AnalysisIndexes, AnalysisIndexExtensionFactory, build_analysis_indexes
from tfstride.analysis.stride_rules import ProviderRuleSet
from tfstride.models import ResourceInventory, TrustBoundary
from tfstride.providers.plugin import ProviderBoundaryContributorFactory


@dataclass(frozen=True, slots=True)
class PreparedAnalysis:
    """One invocation's analysis inputs, retaining the inventory by reference.

    Prepare again after changing resources to refresh the indexes and boundaries.
    """

    inventory: ResourceInventory
    indexes: AnalysisIndexes
    boundaries: list[TrustBoundary]
    rule_set: ProviderRuleSet


def prepare_analysis(
    inventory: ResourceInventory,
    *,
    rule_set: ProviderRuleSet,
    provider_extension_factory: AnalysisIndexExtensionFactory,
    provider_boundary_contributor_factories: Sequence[ProviderBoundaryContributorFactory],
) -> PreparedAnalysis:
    """Build fresh indexes and boundaries using explicitly selected provider hooks."""
    indexes = build_analysis_indexes(inventory, provider_extension_factory=provider_extension_factory)
    boundaries = detect_trust_boundaries(
        inventory,
        indexes=indexes,
        contributors=default_boundary_contributors(
            provider_contributors=tuple(factory() for factory in provider_boundary_contributor_factories),
        ),
    )
    return PreparedAnalysis(
        inventory=inventory,
        indexes=indexes,
        boundaries=boundaries,
        rule_set=rule_set,
    )
