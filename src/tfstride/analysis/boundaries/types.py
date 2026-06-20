from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from tfstride.analysis.indexes import AnalysisIndexes
from tfstride.models import BoundaryType, ResourceInventory, TrustBoundary


class BoundaryEmitter(Protocol):
    def __call__(
        self,
        boundary_type: BoundaryType,
        source: str,
        target: str,
        description: str,
        rationale: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class BoundaryContributionContext:
    inventory: ResourceInventory
    indexes: AnalysisIndexes
    add_boundary: BoundaryEmitter


class BoundaryContributor(Protocol):
    def contribute(self, context: BoundaryContributionContext) -> None: ...


class BoundaryAccumulator:
    def __init__(self) -> None:
        self._boundaries: list[TrustBoundary] = []
        self._seen: set[tuple[str, str, str]] = set()

    def add_boundary(
        self,
        boundary_type: BoundaryType,
        source: str,
        target: str,
        description: str,
        rationale: str,
    ) -> None:
        # Multiple heuristics can arrive at the same crossing; dedupe by logical edge so
        # the report stays readable and stable across rule changes.
        key = (boundary_type.value, source, target)
        if key in self._seen:
            return
        self._seen.add(key)
        self._boundaries.append(
            TrustBoundary(
                identifier=f"{boundary_type.value}:{source}->{target}",
                boundary_type=boundary_type,
                source=source,
                target=target,
                description=description,
                rationale=rationale,
            )
        )

    def boundaries(self) -> list[TrustBoundary]:
        return list(self._boundaries)
