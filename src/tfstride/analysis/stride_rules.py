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
    merge_rule_contributions_by_stage,
)
from tfstride.analysis.rule_registry import (
    RulePolicy,
    RuleRegistry,
    default_rule_registry,
)
from tfstride.models import Finding, Observation, ResourceInventory, TrustBoundary
from tfstride.providers.aws.rules import build_aws_rule_contribution
from tfstride.providers.gcp.rules import build_gcp_rule_contribution


def _default_rule_metadata_registry() -> RuleRegistry:
    return default_rule_registry()


def _build_default_rule_contribution(
    finding_factory: FindingFactory,
    metadata_registry: RuleRegistry,
) -> RuleContribution:
    return merge_rule_contributions_by_stage(
        build_aws_rule_contribution(finding_factory, metadata_registry),
        build_gcp_rule_contribution(finding_factory, metadata_registry),
    )


class StrideRuleEngine:
    def __init__(
        self,
        rule_registry: RuleRegistry | None = None,
        rule_contribution: RuleContribution | None = None,
    ) -> None:
        if rule_contribution is None:
            metadata_registry = _default_rule_metadata_registry()
            finding_registry = rule_registry if rule_registry is not None else metadata_registry
            rule_contribution = _build_default_rule_contribution(
                FindingFactory(finding_registry),
                metadata_registry,
            )

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
