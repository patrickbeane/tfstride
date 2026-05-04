from __future__ import annotations

import unittest

from tfstride.analysis.coverage import build_analysis_coverage
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.models import NormalizedResource, ResourceCategory, ResourceInventory, Severity


class AnalysisCoverageTests(unittest.TestCase):
    def test_build_analysis_coverage_summarizes_resources_rules_and_unresolved_references(self) -> None:
        resource = NormalizedResource(
            address="aws_instance.app",
            provider="aws",
            resource_type="aws_instance",
            name="app",
            category=ResourceCategory.COMPUTE,
            metadata={
                "unresolved_instance_profiles": ["missing-profile"],
                "unresolved_role_references": ["missing-role"],
            },
        )
        inventory = ResourceInventory(
            provider="aws",
            resources=[resource],
            unsupported_resources=["aws_cloudwatch_log_group.app"],
            metadata={
                "total_input_resources": 2,
                "provider_resource_count": 2,
                "unsupported_resource_types": {"aws_cloudwatch_log_group": 1},
            },
        )
        coverage = build_analysis_coverage(
            inventory,
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset({"aws-s3-public-access"}),
                severity_overrides={"aws-s3-public-access": Severity.LOW},
            ),
        )

        self.assertEqual(coverage.resources.total_resources, 2)
        self.assertEqual(coverage.resources.provider_resources, 2)
        self.assertEqual(coverage.resources.normalized_resources, 1)
        self.assertEqual(coverage.resources.unsupported_resources, 1)
        self.assertEqual(coverage.resources.unsupported_resource_types, {"aws_cloudwatch_log_group": 1})
        self.assertEqual(coverage.rules.enabled_rules, ["aws-s3-public-access"])
        self.assertIn("aws-public-compute-broad-ingress", coverage.rules.disabled_rules)
        self.assertEqual(coverage.rules.severity_overrides, {"aws-s3-public-access": Severity.LOW})
        self.assertEqual(coverage.references.unresolved_reference_count, 2)
        self.assertEqual(len(coverage.references.unresolved_references), 1)
        self.assertEqual(coverage.references.unresolved_references[0].resource, "aws_instance.app")
        self.assertEqual(
            coverage.references.unresolved_references[0].references,
            {
                "unresolved_instance_profiles": ["missing-profile"],
                "unresolved_role_references": ["missing-role"],
            },
        )


if __name__ == "__main__":
    unittest.main()