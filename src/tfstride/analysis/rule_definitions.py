from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from tfstride.analysis.rule_registry import DEFAULT_RULE_REGISTRY, RulePolicy, RuleRegistry
from tfstride.models import BoundaryType, Finding, ResourceInventory, TrustBoundary


BoundaryIndex = dict[tuple[BoundaryType, str, str], TrustBoundary]


@dataclass(frozen=True, slots=True)
class RuleEvaluationContext:
    inventory: ResourceInventory
    boundary_index: BoundaryIndex
    rule_registry: RuleRegistry = DEFAULT_RULE_REGISTRY
    rule_policy: RulePolicy | None = None

class RuleDetector(Protocol):
    def __call__(self, context: RuleEvaluationContext, rule_id: str) -> list[Finding]:
        ...


@dataclass(frozen=True, slots=True)
class ExecutableRule:
    rule_id: str
    detector: RuleDetector

    def evaluate(self, context: RuleEvaluationContext) -> list[Finding]:
        if context.rule_policy is not None and not context.rule_policy.is_enabled(self.rule_id, context.rule_registry):
	        return []
        return self.detector(context, self.rule_id)