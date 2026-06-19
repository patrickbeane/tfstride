from __future__ import annotations

import unittest

from tfstride.analysis.indexes import build_analysis_indexes
from tfstride.analysis.rule_definitions import (
    ExecutableRule,
    RuleContribution,
    RuleDefinition,
    RuleEvaluationContext,
    build_rule_contribution,
    build_rule_registry_from_contribution,
)
from tfstride.analysis.rule_registry import RuleMetadata, RulePolicy, RuleRegistry
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import Finding, ResourceInventory, StrideCategory


def _metadata(rule_id: str) -> RuleMetadata:
    return RuleMetadata(
        rule_id=rule_id,
        title=f"{rule_id} title",
        category=StrideCategory.SPOOFING,
        recommended_mitigation="Fix the test issue.",
    )


def _detector(received_context: RuleEvaluationContext, rule_id: str) -> list[Finding]:
    return []


class RuleContributionTests(unittest.TestCase):
    def test_build_rule_contribution_preserves_stage_and_rule_order(self) -> None:
        registry = RuleRegistry([_metadata("rule-b"), _metadata("rule-a"), _metadata("rule-c")])

        contribution = build_rule_contribution(
            (
                (("rule-b", _detector), ("rule-a", _detector)),
                (("rule-c", _detector),),
            ),
            registry,
        )

        self.assertIsInstance(contribution, RuleContribution)
        self.assertEqual(
            tuple(tuple(rule.metadata.rule_id for rule in group) for group in contribution.rule_groups),
            (("rule-b", "rule-a"), ("rule-c",)),
        )
        self.assertIs(contribution.rule_groups[0][0].metadata, registry.get("rule-b"))
        self.assertIs(contribution.rule_groups[0][0].detector, _detector)

    def test_build_rule_registry_from_contribution_preserves_metadata_order(self) -> None:
        first_metadata = _metadata("rule-b")
        second_metadata = _metadata("rule-a")
        contribution = RuleContribution(
            (
                (RuleDefinition(first_metadata, _detector),),
                (RuleDefinition(second_metadata, _detector),),
            )
        )

        registry = build_rule_registry_from_contribution(contribution)

        self.assertEqual(registry.rules(), (first_metadata, second_metadata))

    def test_build_rule_contribution_rejects_duplicate_rule_ids(self) -> None:
        registry = RuleRegistry([_metadata("rule-a")])

        with self.assertRaisesRegex(ValueError, "Duplicate rule contribution"):
            build_rule_contribution(
                ((("rule-a", _detector),), (("rule-a", _detector),)),
                registry,
            )

    def test_build_rule_contribution_rejects_missing_metadata(self) -> None:
        registry = RuleRegistry([])

        with self.assertRaisesRegex(ValueError, "has no registered metadata"):
            build_rule_contribution(((("rule-a", _detector),),), registry)

    def test_build_rule_contribution_rejects_empty_rule_ids(self) -> None:
        registry = RuleRegistry([])

        with self.assertRaisesRegex(ValueError, "non-empty rule IDs"):
            build_rule_contribution((((" ", _detector),),), registry)


class ExecutableRuleTests(unittest.TestCase):
    def test_rule_evaluation_context_builds_analysis_indexes_by_default(self) -> None:
        inventory = ResourceInventory(provider="aws", resources=[])

        context = RuleEvaluationContext(
            inventory=inventory,
            boundary_index={},
            rule_registry=RuleRegistry([]),
        )

        self.assertIsNotNone(context.analysis_indexes)
        self.assertEqual(context.analysis_indexes.resources_by_security_group, {})

    def test_rule_engine_passes_supplied_analysis_indexes_to_detectors(self) -> None:
        inventory = ResourceInventory(provider="aws", resources=[])
        analysis_indexes = build_analysis_indexes(inventory)
        metadata = RuleMetadata(
            rule_id="aws-test-rule",
            title="Test rule",
            category=StrideCategory.SPOOFING,
            recommended_mitigation="Fix the test issue.",
        )
        received_indexes = []

        def detector(received_context: RuleEvaluationContext, rule_id: str) -> list[Finding]:
            received_indexes.append(received_context.analysis_indexes)
            return []

        engine = StrideRuleEngine(
            rule_contribution=RuleContribution(((RuleDefinition(metadata=metadata, detector=detector),),))
        )

        self.assertEqual(
            engine.evaluate(inventory, [], analysis_indexes=analysis_indexes),
            [],
        )
        self.assertEqual(received_indexes, [analysis_indexes])

    def test_rule_definition_keeps_metadata_with_detector(self) -> None:
        metadata = RuleMetadata(
            rule_id="aws-test-rule",
            title="Test rule",
            category=StrideCategory.SPOOFING,
            recommended_mitigation="Fix the test issue.",
        )

        def detector(received_context: RuleEvaluationContext, rule_id: str) -> list[Finding]:
            return []

        definition = RuleDefinition(metadata=metadata, detector=detector)

        self.assertIs(definition.metadata, metadata)
        self.assertIs(definition.detector, detector)

    def test_evaluate_passes_context_and_rule_id_to_detector(self) -> None:
        calls: list[tuple[RuleEvaluationContext, str]] = []
        context = RuleEvaluationContext(
            inventory=ResourceInventory(provider="aws", resources=[]),
            boundary_index={},
            rule_registry=RuleRegistry([]),
        )

        def detector(received_context: RuleEvaluationContext, rule_id: str) -> list[Finding]:
            calls.append((received_context, rule_id))
            return []

        result = ExecutableRule("aws-test-rule", detector).evaluate(context)

        self.assertEqual(result, [])
        self.assertEqual(calls, [(context, "aws-test-rule")])

    def test_evaluate_skips_disabled_rule_without_invoking_detector(self) -> None:
        calls: list[str] = []
        context = RuleEvaluationContext(
            inventory=ResourceInventory(provider="aws", resources=[]),
            boundary_index={},
            rule_registry=RuleRegistry([]),
            rule_policy=RulePolicy(enabled_rule_ids=frozenset()),
        )

        def detector(received_context: RuleEvaluationContext, rule_id: str) -> list[Finding]:
            calls.append(rule_id)
            return []

        result = ExecutableRule("aws-test-rule", detector).evaluate(context)

        self.assertEqual(result, [])
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
