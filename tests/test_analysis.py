from __future__ import annotations

from collections import Counter
import unittest
from pathlib import Path

from cloud_threat_modeler.app import CloudThreatModeler
from cloud_threat_modeler.models import BoundaryType, Severity


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"
FIXTURE_PATH = FIXTURES_DIR / "sample_aws_plan.json"
SAFE_FIXTURE_PATH = FIXTURES_DIR / "sample_aws_safe_plan.json"
NIGHTMARE_FIXTURE_PATH = FIXTURES_DIR / "sample_aws_nightmare_plan.json"


class CloudThreatModelerAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = CloudThreatModeler()
        self.result = self.engine.analyze_plan(FIXTURE_PATH)

    def test_analysis_normalizes_supported_resources_and_tracks_unsupported(self) -> None:
        self.assertEqual(len(self.result.inventory.resources), 19)
        self.assertIn("aws_cloudwatch_log_group.processor", self.result.inventory.unsupported_resources)
        resource_types = {resource.resource_type for resource in self.result.inventory.resources}
        self.assertIn("aws_security_group_rule", resource_types)
        self.assertIn("aws_iam_role_policy_attachment", resource_types)

    def test_analysis_discovers_expected_trust_boundaries(self) -> None:
        boundary_types = {boundary.boundary_type for boundary in self.result.trust_boundaries}
        self.assertIn(BoundaryType.INTERNET_TO_SERVICE, boundary_types)
        self.assertIn(BoundaryType.PUBLIC_TO_PRIVATE, boundary_types)
        self.assertIn(BoundaryType.WORKLOAD_TO_DATA_STORE, boundary_types)
        self.assertIn(BoundaryType.CONTROL_TO_WORKLOAD, boundary_types)
        self.assertIn(BoundaryType.CROSS_ACCOUNT_OR_ROLE, boundary_types)

    def test_analysis_emits_deterministic_findings(self) -> None:
        findings_by_title = {finding.title: finding for finding in self.result.findings}
        expected_titles = {
            "Internet-exposed compute service permits overly broad ingress",
            "Database is reachable from overly permissive sources",
            "Object storage is publicly accessible",
            "IAM policy grants wildcard privileges",
            "Workload role carries sensitive permissions",
            "Private data tier directly trusts the public application tier",
            "Role trust relationship expands blast radius",
        }
        self.assertTrue(expected_titles.issubset(findings_by_title))
        self.assertEqual(findings_by_title["Database is reachable from overly permissive sources"].severity, Severity.HIGH)
        self.assertEqual(findings_by_title["Workload role carries sensitive permissions"].severity, Severity.HIGH)

    def test_fixture_scenarios_have_expected_finding_profiles(self) -> None:
        scenarios = {
            "safe": (SAFE_FIXTURE_PATH, 1, {"medium": 1}),
            "mixed": (FIXTURE_PATH, 8, {"high": 3, "medium": 5}),
            "nightmare": (NIGHTMARE_FIXTURE_PATH, 13, {"high": 5, "medium": 8}),
        }

        expected_titles = {
            "safe": {"IAM policy grants wildcard privileges": 1},
            "mixed": {
                "Database is reachable from overly permissive sources": 1,
                "Private data tier directly trusts the public application tier": 1,
                "Workload role carries sensitive permissions": 1,
                "IAM policy grants wildcard privileges": 2,
                "Internet-exposed compute service permits overly broad ingress": 1,
                "Object storage is publicly accessible": 1,
                "Role trust relationship expands blast radius": 1,
            },
            "nightmare": {
                "Database is reachable from overly permissive sources": 1,
                "Private data tier directly trusts the public application tier": 1,
                "Role trust relationship expands blast radius": 2,
                "Workload role carries sensitive permissions": 2,
                "IAM policy grants wildcard privileges": 3,
                "Internet-exposed compute service permits overly broad ingress": 2,
                "Object storage is publicly accessible": 2,
            },
        }

        for name, (fixture_path, expected_count, expected_severities) in scenarios.items():
            with self.subTest(scenario=name):
                result = self.engine.analyze_plan(fixture_path)
                severity_counts = Counter(finding.severity.value for finding in result.findings)
                title_counts = Counter(finding.title for finding in result.findings)

                self.assertEqual(len(result.findings), expected_count)
                self.assertEqual(dict(severity_counts), expected_severities)
                self.assertEqual(dict(title_counts), expected_titles[name])

    def test_safe_fixture_public_access_block_suppresses_bucket_exposure(self) -> None:
        result = self.engine.analyze_plan(SAFE_FIXTURE_PATH)
        bucket = result.inventory.get_by_address("aws_s3_bucket.artifacts")

        self.assertIsNotNone(bucket)
        self.assertFalse(bucket.public_exposure)
        self.assertIn("public_access_block", bucket.metadata)
        finding_titles = {finding.title for finding in result.findings}
        self.assertNotIn("Object storage is publicly accessible", finding_titles)

    def test_role_policy_attachments_extend_effective_role_permissions(self) -> None:
        safe_result = self.engine.analyze_plan(SAFE_FIXTURE_PATH)
        mixed_result = self.engine.analyze_plan(FIXTURE_PATH)

        safe_role = safe_result.inventory.get_by_address("aws_iam_role.workload")
        mixed_role = mixed_result.inventory.get_by_address("aws_iam_role.workload")

        self.assertIn("aws_iam_policy.artifact_read", safe_role.metadata.get("attached_policy_addresses", []))
        self.assertTrue(
            any("s3:GetObject" in statement.actions for statement in safe_role.policy_statements)
        )
        self.assertIn("aws_iam_policy.admin_like", mixed_role.metadata.get("attached_policy_addresses", []))

    def test_standalone_security_group_rules_merge_into_target_groups(self) -> None:
        safe_result = self.engine.analyze_plan(SAFE_FIXTURE_PATH)
        mixed_result = self.engine.analyze_plan(FIXTURE_PATH)

        safe_app_group = safe_result.inventory.get_by_address("aws_security_group.app")
        mixed_db_group = mixed_result.inventory.get_by_address("aws_security_group.db")

        self.assertIn("aws_security_group_rule.app_from_lb", safe_app_group.metadata.get("standalone_rule_addresses", []))
        self.assertEqual(len(safe_app_group.network_rules), 2)
        self.assertIn("aws_security_group_rule.db_from_public_app", mixed_db_group.metadata.get("standalone_rule_addresses", []))
        self.assertIn("aws_security_group_rule.db_from_internet", mixed_db_group.metadata.get("standalone_rule_addresses", []))
        self.assertEqual(len(mixed_db_group.network_rules), 3)


if __name__ == "__main__":
    unittest.main()
