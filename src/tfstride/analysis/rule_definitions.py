from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from tfstride.analysis.indexes import AnalysisIndexes, build_analysis_indexes
from tfstride.analysis.rule_registry import RuleMetadata, RulePolicy, RuleRegistry
from tfstride.models import BoundaryType, Finding, ResourceInventory, TrustBoundary

BoundaryIndex = dict[tuple[BoundaryType, str, str], TrustBoundary]


@dataclass(frozen=True, slots=True)
class RuleEvaluationContext:
    inventory: ResourceInventory
    boundary_index: BoundaryIndex
    rule_registry: RuleRegistry
    analysis_indexes: AnalysisIndexes | None = None
    rule_policy: RulePolicy | None = None

    def __post_init__(self) -> None:
        if self.analysis_indexes is None:
            object.__setattr__(
                self,
                "analysis_indexes",
                build_analysis_indexes(self.inventory),
            )


class RuleDetector(Protocol):
    def __call__(self, context: RuleEvaluationContext, rule_id: str) -> list[Finding]:
        ...


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    metadata: RuleMetadata
    detector: RuleDetector


@dataclass(frozen=True, slots=True)
class ExecutableRule:
    rule_id: str
    detector: RuleDetector

    def evaluate(self, context: RuleEvaluationContext) -> list[Finding]:
        if context.rule_policy is not None and not context.rule_policy.is_enabled(self.rule_id, context.rule_registry):
            return []
        return self.detector(context, self.rule_id)