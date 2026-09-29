from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Protocol

from tfstride.analysis.indexes import AnalysisIndexes
from tfstride.analysis.relationships import RelationshipAssessment
from tfstride.models import BoundaryType, ResourceInventory, TrustBoundary


class BoundaryEmitter(Protocol):
    def __call__(
        self,
        boundary_type: BoundaryType,
        source: str,
        target: str,
        description: str,
        rationale: str,
        *,
        assessment: RelationshipAssessment | None = None,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class BoundaryContributionContext:
    inventory: ResourceInventory
    indexes: AnalysisIndexes
    add_boundary: BoundaryEmitter


class BoundaryContributor(Protocol):
    def contribute(self, context: BoundaryContributionContext) -> None: ...


@dataclass(frozen=True, slots=True)
class BoundarySupport:
    """One intact presentation contribution and its optional provider assessment.

    Supports are alternatives, not composed proofs. Legacy contributors may omit
    an assessment; their prose must not be promoted into relationship evidence.
    This internal record is deliberately separate from serialized TrustBoundary.
    """

    description: str
    rationale: str
    assessment: RelationshipAssessment | None = None

    def _canonical_key(self) -> tuple[str, str, str]:
        # Preserve tuple ordering inside assessments: canonical ordering of
        # alternatives does not reinterpret provider scopes or conditions.
        assessment = asdict(self.assessment) if self.assessment is not None else None
        return self.description, self.rationale, json.dumps(assessment, sort_keys=True, separators=(",", ":"))


class BoundaryAccumulator:
    def __init__(self) -> None:
        self._supports: dict[tuple[BoundaryType, str, str], dict[tuple[str, str, str], BoundarySupport]] = {}

    def add_boundary(
        self,
        boundary_type: BoundaryType,
        source: str,
        target: str,
        description: str,
        rationale: str,
        *,
        assessment: RelationshipAssessment | None = None,
    ) -> None:
        support = BoundarySupport(description, rationale, assessment)
        key = (boundary_type, source, target)
        self._supports.setdefault(key, {})[support._canonical_key()] = support

    def supports(self, boundary_type: BoundaryType, source: str, target: str) -> tuple[BoundarySupport, ...]:
        """Return distinct alternatives in canonical order without merging them."""
        alternatives = self._supports.get((boundary_type, source, target), {})
        return tuple(alternatives[key] for key in sorted(alternatives))

    def boundaries(self) -> list[TrustBoundary]:
        # Keep legacy edge order and IDs. For competing presentations, select
        # one whole contribution canonically; never splice conditional claims.
        boundaries: list[TrustBoundary] = []
        for boundary_type, source, target in self._supports:
            presentation = self.supports(boundary_type, source, target)[0]
            boundaries.append(
                TrustBoundary(
                    identifier=f"{boundary_type.value}:{source}->{target}",
                    boundary_type=boundary_type,
                    source=source,
                    target=target,
                    description=presentation.description,
                    rationale=presentation.rationale,
                )
            )
        return boundaries
