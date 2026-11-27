from __future__ import annotations

import unittest

from tfstride.coverage_policy import CoverageCheck, CoveragePolicy, evaluate_coverage_policy
from tfstride.models import AnalysisCoverage, ReferenceCoverage, ResourceCoverage


def _coverage(
    *,
    normalized: int = 3,
    unsupported_types: dict[str, int] | None = None,
    unresolved_references: int = 0,
    ambiguous: int = 0,
    unresolved: int = 0,
    unsupported: int = 0,
) -> AnalysisCoverage:
    unsupported_types = unsupported_types or {}
    return AnalysisCoverage(
        resources=ResourceCoverage(
            total_resources=normalized + sum(unsupported_types.values()),
            provider_resources=normalized + sum(unsupported_types.values()),
            normalized_resources=normalized,
            unsupported_resources=sum(unsupported_types.values()),
            unsupported_resource_types=unsupported_types,
        ),
        references=ReferenceCoverage(
            unresolved_reference_count=unresolved_references,
            ambiguous_symbolic_relationships=ambiguous,
            unresolved_symbolic_relationships=unresolved,
            unsupported_symbolic_relationships=unsupported,
        ),
    )


class CoveragePolicyTests(unittest.TestCase):
    def test_default_policy_enforces_nothing(self) -> None:
        coverage = _coverage(normalized=0, unsupported_types={"aws_foo": 2}, unresolved=4)

        self.assertEqual(evaluate_coverage_policy(coverage, CoveragePolicy()), [])

    def test_no_resources_check_fails_when_nothing_was_analyzed(self) -> None:
        policy = CoveragePolicy(checks=frozenset({CoverageCheck.NO_RESOURCES}))

        violations = evaluate_coverage_policy(_coverage(normalized=0), policy)

        self.assertEqual([violation.check for violation in violations], [CoverageCheck.NO_RESOURCES])
        self.assertIn("no resources were analyzed", violations[0].message)
        self.assertEqual(evaluate_coverage_policy(_coverage(normalized=1), policy), [])

    def test_no_resources_check_fails_for_plans_with_only_unsupported_resources(self) -> None:
        policy = CoveragePolicy(checks=frozenset({CoverageCheck.NO_RESOURCES}))

        violations = evaluate_coverage_policy(_coverage(normalized=0, unsupported_types={"aws_foo": 1}), policy)

        self.assertEqual(len(violations), 1)

    def test_allowed_unsupported_types_do_not_satisfy_no_resources_check(self) -> None:
        policy = CoveragePolicy(
            checks=frozenset({CoverageCheck.NO_RESOURCES, CoverageCheck.UNSUPPORTED_RESOURCES}),
            allowed_unsupported_types=frozenset({"aws_foo"}),
        )

        violations = evaluate_coverage_policy(_coverage(normalized=0, unsupported_types={"aws_foo": 1}), policy)

        self.assertEqual([violation.check for violation in violations], [CoverageCheck.NO_RESOURCES])

    def test_unsupported_resources_check_lists_types_and_counts(self) -> None:
        policy = CoveragePolicy(checks=frozenset({CoverageCheck.UNSUPPORTED_RESOURCES}))

        violations = evaluate_coverage_policy(_coverage(unsupported_types={"aws_foo": 2, "aws_bar": 1}), policy)

        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].check, CoverageCheck.UNSUPPORTED_RESOURCES)
        self.assertIn("aws_bar (1), aws_foo (2)", violations[0].message)
        self.assertEqual(evaluate_coverage_policy(_coverage(), policy), [])

    def test_unsupported_resources_check_honors_allowed_types(self) -> None:
        policy = CoveragePolicy(
            checks=frozenset({CoverageCheck.UNSUPPORTED_RESOURCES}),
            allowed_unsupported_types=frozenset({"aws_foo"}),
        )

        self.assertEqual(evaluate_coverage_policy(_coverage(unsupported_types={"aws_foo": 2}), policy), [])
        violations = evaluate_coverage_policy(_coverage(unsupported_types={"aws_foo": 2, "aws_bar": 1}), policy)
        self.assertEqual(len(violations), 1)
        self.assertIn("aws_bar (1)", violations[0].message)
        self.assertNotIn("aws_foo", violations[0].message)

    def test_unresolved_relationships_check_sums_reference_gaps(self) -> None:
        policy = CoveragePolicy(checks=frozenset({CoverageCheck.UNRESOLVED_RELATIONSHIPS}))

        gaps = {
            "unresolved reference": _coverage(unresolved_references=2),
            "ambiguous relationship": _coverage(ambiguous=2),
            "unresolved relationship": _coverage(unresolved=2),
            "unsupported relationship": _coverage(unsupported=2),
        }
        for name, coverage in gaps.items():
            with self.subTest(name=name):
                violations = evaluate_coverage_policy(coverage, policy)

                self.assertEqual(
                    [violation.check for violation in violations], [CoverageCheck.UNRESOLVED_RELATIONSHIPS]
                )
        self.assertEqual(evaluate_coverage_policy(_coverage(), policy), [])

    def test_multiple_checks_report_each_violation_in_check_order(self) -> None:
        policy = CoveragePolicy(checks=frozenset(CoverageCheck))
        coverage = _coverage(normalized=0, unsupported_types={"aws_foo": 1}, unresolved=1)

        violations = evaluate_coverage_policy(coverage, policy)

        self.assertEqual(
            [violation.check for violation in violations],
            [
                CoverageCheck.NO_RESOURCES,
                CoverageCheck.UNSUPPORTED_RESOURCES,
                CoverageCheck.UNRESOLVED_RELATIONSHIPS,
            ],
        )

    def test_check_values_are_cli_and_config_spellings(self) -> None:
        self.assertEqual(
            [check.value for check in CoverageCheck],
            ["no-resources", "unsupported-resources", "unresolved-relationships"],
        )


if __name__ == "__main__":
    unittest.main()
