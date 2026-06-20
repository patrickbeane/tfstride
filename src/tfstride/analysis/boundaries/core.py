from __future__ import annotations

from collections.abc import Sequence

from tfstride.analysis.boundaries.shared import (
    InternetToServiceBoundaryContributor,
    PublicPrivateSubnetBoundaryContributor,
)
from tfstride.analysis.boundaries.types import (
    BoundaryAccumulator,
    BoundaryContributionContext,
    BoundaryContributor,
)
from tfstride.analysis.indexes import AnalysisIndexes, build_analysis_indexes
from tfstride.models import ResourceInventory, TrustBoundary


class _LegacyBoundaryContributor:
    def contribute(self, context: BoundaryContributionContext) -> None:
        from tfstride.analysis.boundaries._legacy import contribute_trust_boundaries

        contribute_trust_boundaries(context)


def default_boundary_contributors() -> tuple[BoundaryContributor, ...]:
    return (
        InternetToServiceBoundaryContributor(),
        PublicPrivateSubnetBoundaryContributor(),
        _LegacyBoundaryContributor(),
    )


def detect_trust_boundaries(
    inventory: ResourceInventory,
    indexes: AnalysisIndexes | None = None,
    *,
    contributors: Sequence[BoundaryContributor] | None = None,
) -> list[TrustBoundary]:
    analysis_indexes = indexes if indexes is not None else build_analysis_indexes(inventory)
    accumulator = BoundaryAccumulator()
    context = BoundaryContributionContext(
        inventory=inventory,
        indexes=analysis_indexes,
        add_boundary=accumulator.add_boundary,
    )

    resolved_contributors = contributors if contributors is not None else default_boundary_contributors()
    for contributor in resolved_contributors:
        contributor.contribute(context)

    return accumulator.boundaries()
