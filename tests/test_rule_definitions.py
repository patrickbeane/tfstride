from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RuleMetadata, RulePolicy
from tfstride.analysis.rule_definitions import ExecutableRule, RuleDefinition, RuleEvaluationContext
from tfstride.models import Finding, ResourceInventory, StrideCategory


class ExecutableRuleTests(unittest.TestCase):
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