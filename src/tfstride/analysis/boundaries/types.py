from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from types import MappingProxyType
from typing import Literal, Protocol

from tfstride.analysis.indexes import AnalysisIndexes
from tfstride.analysis.relationships import RelationshipAssessment
from tfstride.models import BoundaryType, ResourceInventory, TrustBoundary

BoundaryKey = tuple[BoundaryType, str, str]
BoundaryAssessmentScope = Literal["relationship", "path_crossing"]


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
        assessment_scope: BoundaryAssessmentScope = "relationship",
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
    # A path crossing represents only a segment of the full assessment, whose
    # original endpoints, scope, and conditions must remain intact.
    assessment_scope: BoundaryAssessmentScope = "relationship"

    def _canonical_key(self) -> tuple[str, str, str, str]:
        # Preserve tuple ordering inside assessments: canonical ordering of
        # alternatives does not reinterpret provider scopes or conditions.
        assessment = asdict(self.assessment) if self.assessment is not None else None
        return (
            self.description,
            self.rationale,
            json.dumps(assessment, sort_keys=True, separators=(",", ":")),
            self.assessment_scope,
        )


class BoundaryAccumulator:
    def __init__(self) -> None:
        self._supports: dict[BoundaryKey, dict[tuple[str, str, str, str], BoundarySupport]] = {}

    def add_boundary(
        self,
        boundary_type: BoundaryType,
        source: str,
        target: str,
        description: str,
        rationale: str,
        *,
        assessment: RelationshipAssessment | None = None,
        assessment_scope: BoundaryAssessmentScope = "relationship",
    ) -> None:
        support = BoundarySupport(description, rationale, assessment, assessment_scope)
        key = (boundary_type, source, target)
        self._supports.setdefault(key, {})[support._canonical_key()] = support

    def supports(self, boundary_type: BoundaryType, source: str, target: str) -> tuple[BoundarySupport, ...]:
        """Return distinct alternatives in canonical order without merging them."""
        alternatives = self._supports.get((boundary_type, source, target), {})
        return tuple(alternatives[key] for key in sorted(alternatives))

    def support_index(self) -> Mapping[BoundaryKey, tuple[BoundarySupport, ...]]:
        """Snapshot internal support for downstream analysis, outside report models."""
        return MappingProxyType({key: self.supports(*key) for key in sorted(self._supports)})

    def boundaries(self) -> list[TrustBoundary]:
        """Select one intact presentation by canonical support order.

        Description and rationale sort lexically; this is a stable presentation
        choice, not a ranking of evidence strength. Duplicate edges with differing
        prose may intentionally differ from legacy first-writer output. Edge
        order, identifiers, and serialized fields retain their existing behavior.
        """
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
