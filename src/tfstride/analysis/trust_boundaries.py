from __future__ import annotations

from collections.abc import Sequence

from tfstride.analysis.boundaries import core as boundary_core
from tfstride.analysis.boundaries.types import BoundaryContributor
from tfstride.analysis.indexes import AnalysisIndexes
from tfstride.models import ResourceInventory, TrustBoundary
from tfstride.providers.catalog import default_provider_boundary_contributors


def detect_trust_boundaries(
    inventory: ResourceInventory,
    indexes: AnalysisIndexes | None = None,
    *,
    contributors: Sequence[BoundaryContributor] | None = None,
) -> list[TrustBoundary]:
    resolved_contributors = contributors
    if resolved_contributors is None:
        resolved_contributors = boundary_core.default_boundary_contributors(
            provider_contributors=default_provider_boundary_contributors(inventory.provider),
        )
    return boundary_core.detect_trust_boundaries(inventory, indexes=indexes, contributors=resolved_contributors)


__all__ = ["detect_trust_boundaries"]
