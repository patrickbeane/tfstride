from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy, apply_severity_overrides
from tfstride.models import Finding, Severity, SeverityReasoning, StrideCategory


class SeverityOverridePolicyTests(unittest.TestCase):
    def test_apply_severity_overrides_updates_finding_and_preserves_computed_severity(self) -> None:
        finding = _finding(
            rule_id="aws-test-rule",
            severity=Severity.HIGH,
            severity_reasoning=SeverityReasoning(
                internet_exposure=2,
                privilege_breadth=1,
                data_sensitivity=1,
                lateral_movement=1,
                blast_radius=1,
                final_score=6,
                severity=Severity.HIGH,
            ),
        )

        adjusted = apply_severity_overrides(
            [finding],
            RulePolicy(severity_overrides={"aws-test-rule": Severity.LOW}),
        )

        self.assertEqual(len(adjusted), 1)
        self.assertEqual(adjusted[0].severity, Severity.LOW)
        self.assertIsNotNone(adjusted[0].severity_reasoning)
        self.assertEqual(adjusted[0].severity_reasoning.severity, Severity.LOW)
        self.assertEqual(adjusted[0].severity_reasoning.computed_severity, Severity.HIGH)

    def test_apply_severity_overrides_does_not_filter_disabled_rules(self) -> None:
        finding = _finding(rule_id="aws-test-rule", severity=Severity.MEDIUM)

        adjusted = apply_severity_overrides(
            [finding],
            RulePolicy(enabled_rule_ids=frozenset()),
        )

        self.assertEqual(adjusted, [finding])


def _finding(
    *,
    rule_id: str,
    severity: Severity,
    severity_reasoning: SeverityReasoning | None = None,
) -> Finding:
    return Finding(
        title="Test finding",
        category=StrideCategory.ELEVATION_OF_PRIVILEGE,
        severity=severity,
        affected_resources=["aws_resource.example"],
        trust_boundary_id=None,
        rationale="Test rationale.",
        recommended_mitigation="Test mitigation.",
        rule_id=rule_id,
        severity_reasoning=severity_reasoning,
    )


if __name__ == "__main__":
    unittest.main()