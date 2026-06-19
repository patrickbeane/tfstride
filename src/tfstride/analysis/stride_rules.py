from __future__ import annotations

from tfstride.analysis.control_observations import observe_controls as collect_control_observations
from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.indexes import AnalysisIndexes, build_analysis_indexes
from tfstride.analysis.rule_definitions import (
    BoundaryIndex,
    ExecutableRule,
    RuleContribution,
    RuleDefinition,
    RuleEvaluationContext,
    build_rule_registry_from_contribution,
)
from tfstride.analysis.rule_registry import (
    RulePolicy,
    RuleRegistry,
    default_rule_registry,
)
from tfstride.models import Finding, Observation, ResourceInventory, TrustBoundary
from tfstride.providers.catalog import default_rule_contribution


class StrideRuleEngine:
    def __init__(
        self,
        rule_registry: RuleRegistry | None = None,
        rule_contribution: RuleContribution | None = None,
    ) -> None:
        if rule_contribution is None:
            finding_registry = rule_registry if rule_registry is not None else default_rule_registry()
            rule_contribution = default_rule_contribution(FindingFactory(finding_registry))

        self._rule_contribution = rule_contribution
        self._rule_registry = (
            rule_registry if rule_registry is not None else build_rule_registry_from_contribution(rule_contribution)
        )

    def configured_rule_ids(self) -> set[str]:
        return {rule.metadata.rule_id for rule_group in self._rule_groups() for rule in rule_group}

    def evaluate(
        self,
        inventory: ResourceInventory,
        boundaries: list[TrustBoundary],
        *,
        analysis_indexes: AnalysisIndexes | None = None,
        rule_policy: RulePolicy | None = None,
    ) -> list[Finding]:
        resolved_indexes = analysis_indexes if analysis_indexes is not None else build_analysis_indexes(inventory)
        boundary_index: BoundaryIndex = {
            (boundary.boundary_type, boundary.source, boundary.target): boundary for boundary in boundaries
        }
        context = RuleEvaluationContext(
            inventory=inventory,
            boundary_index=boundary_index,
            rule_registry=self._rule_registry,
            analysis_indexes=resolved_indexes,
            rule_policy=rule_policy,
        )

        return self._evaluate_contribution(context)

    def _evaluate_contribution(self, context: RuleEvaluationContext) -> list[Finding]:
        findings: list[Finding] = []
        for rules in self._rule_contribution.rule_groups:
            findings.extend(self._evaluate_rules(rules, context))
        return findings

    def _evaluate_rules(
        self,
        rules: tuple[RuleDefinition, ...],
        context: RuleEvaluationContext,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for definition in rules:
            executable_rule = ExecutableRule(definition.metadata.rule_id, definition.detector)
            findings.extend(executable_rule.evaluate(context))
        return findings

    def _rule_groups(self) -> tuple[tuple[RuleDefinition, ...], ...]:
        return self._rule_contribution.rule_groups

    def observe_controls(self, inventory: ResourceInventory) -> list[Observation]:
        return collect_control_observations(inventory)
