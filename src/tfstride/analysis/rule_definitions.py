from __future__ import annotations

from collections.abc import Iterable
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
    def __call__(self, context: RuleEvaluationContext, rule_id: str) -> list[Finding]: ...


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    metadata: RuleMetadata
    detector: RuleDetector


@dataclass(frozen=True, slots=True)
class RuleContribution:
    rule_groups: tuple[tuple[RuleDefinition, ...], ...]


RuleContributionInput = Iterable[Iterable[tuple[str, RuleDetector]]]


def build_rule_registry_from_contribution(contribution: RuleContribution) -> RuleRegistry:
    return RuleRegistry([rule.metadata for rule_group in contribution.rule_groups for rule in rule_group])


def build_rule_contribution(
    rule_groups: RuleContributionInput,
    rule_registry: RuleRegistry,
) -> RuleContribution:
    contribution_groups: list[tuple[RuleDefinition, ...]] = []
    seen_rule_ids: set[str] = set()

    for rule_group in rule_groups:
        definitions: list[RuleDefinition] = []
        for rule_id, detector in rule_group:
            if not rule_id.strip():
                raise ValueError("Rule contributions must define non-empty rule IDs.")
            if rule_id in seen_rule_ids:
                raise ValueError(f"Duplicate rule contribution for `{rule_id}`.")
            seen_rule_ids.add(rule_id)
            try:
                metadata = rule_registry.get(rule_id)
            except KeyError as exc:
                raise ValueError(f"Rule contribution `{rule_id}` has no registered metadata.") from exc
            definitions.append(RuleDefinition(metadata=metadata, detector=detector))
        contribution_groups.append(tuple(definitions))

    return RuleContribution(rule_groups=tuple(contribution_groups))


@dataclass(frozen=True, slots=True)
class ExecutableRule:
    rule_id: str
    detector: RuleDetector

    def evaluate(self, context: RuleEvaluationContext) -> list[Finding]:
        if context.rule_policy is not None and not context.rule_policy.is_enabled(self.rule_id, context.rule_registry):
            return []
        return self.detector(context, self.rule_id)
