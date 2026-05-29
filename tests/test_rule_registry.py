from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import (
    DEFAULT_RULE_METADATA,
    DEFAULT_RULE_REGISTRY,
    RuleMetadata,
    RulePolicy,
    RuleRegistry,
    apply_severity_overrides,
    default_rule_metadata,
    default_rule_registry,
)
from tfstride.models import Finding, Severity, SeverityReasoning, StrideCategory


class RuleRegistryTests(unittest.TestCase):
    def test_default_registry_is_derived_from_shared_metadata(self) -> None:
        self.assertEqual(DEFAULT_RULE_REGISTRY.rules(), DEFAULT_RULE_METADATA)

    def test_default_registry_factory_returns_distinct_registry_from_same_metadata(self) -> None:
        registry = default_rule_registry()

        self.assertIsNot(registry, DEFAULT_RULE_REGISTRY)
        self.assertEqual(registry.rules(), DEFAULT_RULE_METADATA)

    def test_default_rule_metadata_uses_shared_metadata_lookup(self) -> None:
        metadata = default_rule_metadata("aws-s3-public-access")

        self.assertIs(metadata, DEFAULT_RULE_REGISTRY.get("aws-s3-public-access"))

    def test_rules_preserves_registry_order(self) -> None:
        first = RuleMetadata(
            rule_id="aws-first-rule",
            title="First rule",
            category=StrideCategory.SPOOFING,
            recommended_mitigation="Fix the first issue.",
        )
        second = RuleMetadata(
            rule_id="aws-second-rule",
            title="Second rule",
            category=StrideCategory.TAMPERING,
            recommended_mitigation="Fix the second issue.",
        )

        registry = RuleRegistry([first, second])

        self.assertEqual(registry.rules(), (first, second))


class SeverityOverridePolicyTests(unittest.TestCase):
    def test_rule_policy_defensively_freezes_severity_overrides(self) -> None:
        overrides = {"aws-test-rule": Severity.LOW}

        policy = RulePolicy(severity_overrides=overrides)
        overrides["aws-test-rule"] = Severity.HIGH

        self.assertEqual(policy.severity_overrides["aws-test-rule"], Severity.LOW)
        with self.assertRaises(TypeError):
            policy.severity_overrides["aws-other-rule"] = Severity.MEDIUM

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