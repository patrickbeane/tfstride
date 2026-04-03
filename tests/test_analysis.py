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
ALB_EC2_RDS_FIXTURE_PATH = FIXTURES_DIR / "sample_aws_alb_ec2_rds_plan.json"


class CloudThreatModelerAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = CloudThreatModeler()
        self.result = self.engine.analyze_plan(FIXTURE_PATH)

    def test_analysis_normalizes_supported_resources_and_tracks_unsupported(self) -> None:
        self.assertEqual(len(self.result.inventory.resources), 23)
        self.assertIn("aws_cloudwatch_log_group.processor", self.result.inventory.unsupported_resources)
        resource_types = {resource.resource_type for resource in self.result.inventory.resources}
        self.assertIn("aws_security_group_rule", resource_types)
        self.assertIn("aws_nat_gateway", resource_types)
        self.assertIn("aws_iam_role_policy_attachment", resource_types)
        self.assertIn("aws_route_table_association", resource_types)

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

    def test_findings_include_structured_evidence_and_severity_reasoning(self) -> None:
        findings_by_title = {finding.title: finding for finding in self.result.findings}
        database_finding = findings_by_title["Database is reachable from overly permissive sources"]

        evidence_by_key = {item.key: item.values for item in database_finding.evidence}
        self.assertIn("security_group_rules", evidence_by_key)
        self.assertIn("network_path", evidence_by_key)
        self.assertIn("subnet_posture", evidence_by_key)
        self.assertIsNotNone(database_finding.severity_reasoning)
        self.assertEqual(database_finding.severity_reasoning.final_score, 6)
        self.assertEqual(database_finding.severity_reasoning.severity, Severity.HIGH)

    def test_unencrypted_rds_instances_are_detected_with_evidence(self) -> None:
        nightmare_result = self.engine.analyze_plan(NIGHTMARE_FIXTURE_PATH)
        findings_by_title = {finding.title: finding for finding in nightmare_result.findings}
        encryption_finding = findings_by_title["Database storage encryption is disabled"]

        self.assertEqual(encryption_finding.severity, Severity.MEDIUM)
        self.assertEqual(encryption_finding.affected_resources, ["aws_db_instance.customer"])
        self.assertIsNone(encryption_finding.trust_boundary_id)
        evidence_by_key = {item.key: item.values for item in encryption_finding.evidence}
        self.assertEqual(
            evidence_by_key["encryption_posture"],
            ["storage_encrypted is false", "engine is postgres"],
        )
        self.assertEqual(encryption_finding.severity_reasoning.final_score, 3)

    def test_fixture_scenarios_have_expected_finding_profiles(self) -> None:
        scenarios = {
            "safe": (SAFE_FIXTURE_PATH, 1, {"medium": 1}),
            "mixed": (FIXTURE_PATH, 8, {"high": 3, "medium": 5}),
            "nightmare": (NIGHTMARE_FIXTURE_PATH, 14, {"high": 5, "medium": 9}),
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
                "Database storage encryption is disabled": 1,
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

    def test_route_table_associations_and_nat_gateways_refine_subnet_classification(self) -> None:
        safe_result = self.engine.analyze_plan(SAFE_FIXTURE_PATH)
        mixed_result = self.engine.analyze_plan(FIXTURE_PATH)

        safe_public_subnet = safe_result.inventory.get_by_address("aws_subnet.public_edge")
        safe_private_subnet = safe_result.inventory.get_by_address("aws_subnet.private_app")
        mixed_private_subnet = mixed_result.inventory.get_by_address("aws_subnet.private_data")

        self.assertEqual(safe_public_subnet.metadata.get("route_table_ids"), ["rtb-safe-001"])
        self.assertTrue(safe_public_subnet.metadata.get("is_public_subnet"))
        self.assertFalse(safe_public_subnet.metadata.get("has_nat_gateway_egress"))

        self.assertEqual(safe_private_subnet.metadata.get("route_table_ids"), ["rtb-safe-private-001"])
        self.assertFalse(safe_private_subnet.metadata.get("is_public_subnet"))
        self.assertTrue(safe_private_subnet.metadata.get("has_nat_gateway_egress"))

        self.assertEqual(mixed_private_subnet.metadata.get("route_table_ids"), ["rtb-private-001"])
        self.assertTrue(mixed_private_subnet.metadata.get("has_nat_gateway_egress"))

    def test_database_reachability_prefers_security_group_evidence_over_same_vpc_only(self) -> None:
        safe_result = self.engine.analyze_plan(SAFE_FIXTURE_PATH)
        mixed_result = self.engine.analyze_plan(FIXTURE_PATH)

        safe_boundary = next(
            boundary
            for boundary in safe_result.trust_boundaries
            if boundary.boundary_type == BoundaryType.WORKLOAD_TO_DATA_STORE
            and boundary.source == "aws_instance.app"
            and boundary.target == "aws_db_instance.app"
        )
        self.assertIn("explicitly trust the workload security group", safe_boundary.rationale)

        mixed_db = mixed_result.inventory.get_by_address("aws_db_instance.app")
        internet_boundaries_to_db = [
            boundary
            for boundary in mixed_result.trust_boundaries
            if boundary.boundary_type == BoundaryType.INTERNET_TO_SERVICE
            and boundary.target == "aws_db_instance.app"
        ]

        self.assertFalse(mixed_db.public_exposure)
        self.assertTrue(mixed_db.metadata.get("internet_ingress_capable"))
        self.assertEqual(internet_boundaries_to_db, [])

    def test_realistic_alb_ec2_rds_fixture_stays_quiet_but_preserves_boundaries(self) -> None:
        result = self.engine.analyze_plan(ALB_EC2_RDS_FIXTURE_PATH)
        boundary_types = Counter(boundary.boundary_type for boundary in result.trust_boundaries)

        self.assertEqual(len(result.findings), 0)
        self.assertEqual(len(result.inventory.resources), 19)
        self.assertEqual(boundary_types[BoundaryType.INTERNET_TO_SERVICE], 1)
        self.assertEqual(boundary_types[BoundaryType.PUBLIC_TO_PRIVATE], 2)
        self.assertEqual(boundary_types[BoundaryType.WORKLOAD_TO_DATA_STORE], 1)


if __name__ == "__main__":
    unittest.main()
