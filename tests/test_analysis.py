from __future__ import annotations

from collections import Counter
import json
import tempfile
import unittest
from pathlib import Path

from cloud_threat_modeler.app import CloudThreatModeler
from cloud_threat_modeler.models import BoundaryType, Severity, TerraformResource
from cloud_threat_modeler.providers.aws.normalizer import AwsNormalizer


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"
FIXTURE_PATH = FIXTURES_DIR / "sample_aws_plan.json"
SAFE_FIXTURE_PATH = FIXTURES_DIR / "sample_aws_safe_plan.json"
NIGHTMARE_FIXTURE_PATH = FIXTURES_DIR / "sample_aws_nightmare_plan.json"
ALB_EC2_RDS_FIXTURE_PATH = FIXTURES_DIR / "sample_aws_alb_ec2_rds_plan.json"
LAMBDA_DEPLOY_ROLE_FIXTURE_PATH = FIXTURES_DIR / "sample_aws_lambda_deploy_role_plan.json"
CROSS_ACCOUNT_TRUST_UNCONSTRAINED_FIXTURE_PATH = (
    FIXTURES_DIR / "sample_aws_cross_account_trust_unconstrained_plan.json"
)
CROSS_ACCOUNT_TRUST_CONSTRAINED_FIXTURE_PATH = (
    FIXTURES_DIR / "sample_aws_cross_account_trust_constrained_plan.json"
)


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
            "Cross-account or broad role trust lacks narrowing conditions",
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
            "mixed": (FIXTURE_PATH, 9, {"high": 3, "medium": 6}),
            "nightmare": (NIGHTMARE_FIXTURE_PATH, 16, {"high": 5, "medium": 11}),
        }

        expected_titles = {
            "safe": {"IAM policy grants wildcard privileges": 1},
            "mixed": {
                "Cross-account or broad role trust lacks narrowing conditions": 1,
                "Database is reachable from overly permissive sources": 1,
                "Private data tier directly trusts the public application tier": 1,
                "Workload role carries sensitive permissions": 1,
                "IAM policy grants wildcard privileges": 2,
                "Internet-exposed compute service permits overly broad ingress": 1,
                "Object storage is publicly accessible": 1,
                "Role trust relationship expands blast radius": 1,
            },
            "nightmare": {
                "Cross-account or broad role trust lacks narrowing conditions": 2,
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

    def test_unconstrained_cross_account_trust_without_narrowing_conditions_is_detected(self) -> None:
        result = self.engine.analyze_plan(CROSS_ACCOUNT_TRUST_UNCONSTRAINED_FIXTURE_PATH)
        severity_counts = Counter(finding.severity.value for finding in result.findings)
        title_counts = Counter(finding.title for finding in result.findings)

        self.assertEqual(len(result.inventory.resources), 2)
        self.assertEqual(dict(severity_counts), {"medium": 2})
        self.assertEqual(
            dict(title_counts),
            {
                "Cross-account or broad role trust lacks narrowing conditions": 1,
                "Role trust relationship expands blast radius": 1,
            },
        )

        trust_finding = next(
            finding
            for finding in result.findings
            if finding.title == "Cross-account or broad role trust lacks narrowing conditions"
        )
        evidence_by_key = {item.key: item.values for item in trust_finding.evidence}
        self.assertEqual(
            evidence_by_key["trust_principals"],
            ["arn:aws:iam::444455556666:role/github-actions-deployer"],
        )
        self.assertEqual(
            evidence_by_key["trust_scope"],
            ["principal belongs to foreign account 444455556666"],
        )
        self.assertEqual(
            evidence_by_key["trust_narrowing"],
            [
                "supported narrowing conditions present: false",
                "supported narrowing condition keys: none",
            ],
        )
        self.assertEqual(trust_finding.severity, Severity.MEDIUM)
        self.assertIsNotNone(trust_finding.severity_reasoning)
        self.assertEqual(trust_finding.severity_reasoning.final_score, 4)

    def test_constrained_cross_account_trust_skips_missing_narrowing_rule(self) -> None:
        result = self.engine.analyze_plan(CROSS_ACCOUNT_TRUST_CONSTRAINED_FIXTURE_PATH)
        severity_counts = Counter(finding.severity.value for finding in result.findings)
        title_counts = Counter(finding.title for finding in result.findings)
        role = result.inventory.get_by_address("aws_iam_role.deployer")

        self.assertEqual(len(result.inventory.resources), 2)
        self.assertEqual(dict(severity_counts), {"medium": 1})
        self.assertEqual(
            dict(title_counts),
            {"Role trust relationship expands blast radius": 1},
        )
        self.assertNotIn(
            "Cross-account or broad role trust lacks narrowing conditions",
            title_counts,
        )
        self.assertIsNotNone(role)
        external_statement = next(
            statement
            for statement in role.metadata.get("trust_statements", [])
            if "arn:aws:iam::444455556666:role/github-actions-deployer" in statement["principals"]
        )
        self.assertEqual(
            external_statement["narrowing_condition_keys"],
            ["aws:SourceAccount", "aws:SourceArn", "sts:ExternalId"],
        )
        self.assertTrue(external_statement["has_narrowing_conditions"])
        self.assertEqual(len(result.observations), 1)
        trust_observation = result.observations[0]
        self.assertEqual(
            trust_observation.title,
            "Cross-account or broad role trust is narrowed by assume-role conditions",
        )
        self.assertEqual(trust_observation.category, "iam")
        trust_evidence = {item.key: item.values for item in trust_observation.evidence}
        self.assertEqual(
            trust_evidence["trust_principals"],
            ["arn:aws:iam::444455556666:role/github-actions-deployer"],
        )
        self.assertEqual(
            trust_evidence["trust_narrowing"],
            [
                "supported narrowing conditions present: true",
                "supported narrowing condition keys: aws:SourceAccount, aws:SourceArn, sts:ExternalId",
            ],
        )

    def test_safe_fixture_emits_observations_for_s3_block_and_private_encrypted_rds(self) -> None:
        result = self.engine.analyze_plan(SAFE_FIXTURE_PATH)
        observation_titles = [observation.title for observation in result.observations]
        observations_by_title = {observation.title: observation for observation in result.observations}

        self.assertEqual(
            observation_titles,
            [
                "RDS instance is private and storage encrypted",
                "S3 public access is reduced by a public access block",
            ],
        )

        bucket_observation = observations_by_title["S3 public access is reduced by a public access block"]
        bucket_evidence = {item.key: item.values for item in bucket_observation.evidence}
        self.assertEqual(
            bucket_evidence["mitigated_public_access"],
            [
                "bucket ACL `public-read` would otherwise grant public access",
                "bucket policy would otherwise allow anonymous access",
            ],
        )
        self.assertIn("block_public_acls is true", bucket_evidence["control_posture"])
        self.assertIn("block_public_policy is true", bucket_evidence["control_posture"])

        database_observation = observations_by_title["RDS instance is private and storage encrypted"]
        database_evidence = {item.key: item.values for item in database_observation.evidence}
        self.assertEqual(
            database_evidence["database_posture"],
            [
                "publicly_accessible is false",
                "storage_encrypted is true",
                "no attached security group allows internet ingress",
                "engine is postgres",
            ],
        )

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

    def test_analysis_surfaces_trust_statement_summaries_on_roles(self) -> None:
        role = self.result.inventory.get_by_address("aws_iam_role.workload")

        self.assertIsNotNone(role)
        self.assertEqual(
            role.metadata.get("trust_statements"),
            [
                {
                    "principals": ["lambda.amazonaws.com"],
                    "narrowing_condition_keys": [],
                    "has_narrowing_conditions": False,
                },
                {
                    "principals": ["arn:aws:iam::999988887777:root"],
                    "narrowing_condition_keys": [],
                    "has_narrowing_conditions": False,
                },
            ],
        )

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

    def test_public_ip_without_internet_ingress_does_not_create_internet_boundary(self) -> None:
        payload = {
            "format_version": "1.2",
            "terraform_version": "1.8.5",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_vpc.main",
                            "mode": "managed",
                            "type": "aws_vpc",
                            "name": "main",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {"id": "vpc-1"},
                        },
                        {
                            "address": "aws_subnet.public",
                            "mode": "managed",
                            "type": "aws_subnet",
                            "name": "public",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "subnet-1",
                                "vpc_id": "vpc-1",
                                "cidr_block": "10.0.1.0/24",
                                "map_public_ip_on_launch": True,
                            },
                        },
                        {
                            "address": "aws_internet_gateway.main",
                            "mode": "managed",
                            "type": "aws_internet_gateway",
                            "name": "main",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {"id": "igw-1", "vpc_id": "vpc-1"},
                        },
                        {
                            "address": "aws_route_table.public",
                            "mode": "managed",
                            "type": "aws_route_table",
                            "name": "public",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "rtb-1",
                                "vpc_id": "vpc-1",
                                "route": [{"cidr_block": "0.0.0.0/0", "gateway_id": "igw-1"}],
                            },
                        },
                        {
                            "address": "aws_route_table_association.public",
                            "mode": "managed",
                            "type": "aws_route_table_association",
                            "name": "public",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "assoc-1",
                                "subnet_id": "subnet-1",
                                "route_table_id": "rtb-1",
                            },
                        },
                        {
                            "address": "aws_security_group.web",
                            "mode": "managed",
                            "type": "aws_security_group",
                            "name": "web",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "sg-1",
                                "vpc_id": "vpc-1",
                                "ingress": [],
                                "egress": [{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}],
                            },
                        },
                        {
                            "address": "aws_instance.web",
                            "mode": "managed",
                            "type": "aws_instance",
                            "name": "web",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "i-1",
                                "subnet_id": "subnet-1",
                                "vpc_security_group_ids": ["sg-1"],
                                "associate_public_ip_address": True,
                            },
                        },
                    ]
                }
            },
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            plan_path = Path(tmp_dir) / "plan.json"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")
            result = self.engine.analyze_plan(plan_path)

        instance = result.inventory.get_by_address("aws_instance.web")
        internet_boundaries = [
            boundary
            for boundary in result.trust_boundaries
            if boundary.boundary_type == BoundaryType.INTERNET_TO_SERVICE
            and boundary.target == "aws_instance.web"
        ]

        self.assertIsNotNone(instance)
        self.assertTrue(instance.public_access_configured)
        self.assertTrue(instance.metadata.get("public_subnet"))
        self.assertFalse(instance.metadata.get("internet_ingress_capable"))
        self.assertFalse(instance.public_exposure)
        self.assertEqual(instance.metadata.get("public_access_reasons"), ["instance requests an associated public IP address"])
        self.assertEqual(instance.metadata.get("public_exposure_reasons"), [])
        self.assertEqual(internet_boundaries, [])
        self.assertNotIn(
            "Internet-exposed compute service permits overly broad ingress",
            {finding.title for finding in result.findings},
        )

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

    def test_realistic_lambda_deploy_role_fixture_surfaces_three_medium_findings(self) -> None:
        result = self.engine.analyze_plan(LAMBDA_DEPLOY_ROLE_FIXTURE_PATH)
        boundary_types = Counter(boundary.boundary_type for boundary in result.trust_boundaries)
        severity_counts = Counter(finding.severity.value for finding in result.findings)
        title_counts = Counter(finding.title for finding in result.findings)

        self.assertEqual(len(result.inventory.resources), 13)
        self.assertEqual(len(result.findings), 3)
        self.assertEqual(dict(severity_counts), {"medium": 3})
        self.assertEqual(
            dict(title_counts),
            {
                "Cross-account or broad role trust lacks narrowing conditions": 1,
                "Role trust relationship expands blast radius": 1,
                "Workload role carries sensitive permissions": 1,
            },
        )
        self.assertEqual(boundary_types[BoundaryType.INTERNET_TO_SERVICE], 0)
        self.assertEqual(boundary_types[BoundaryType.PUBLIC_TO_PRIVATE], 1)
        self.assertEqual(boundary_types[BoundaryType.WORKLOAD_TO_DATA_STORE], 1)
        self.assertEqual(boundary_types[BoundaryType.CONTROL_TO_WORKLOAD], 1)
        self.assertEqual(boundary_types[BoundaryType.CROSS_ACCOUNT_OR_ROLE], 1)

    def test_same_account_specific_role_trust_does_not_emit_trust_expansion_findings(self) -> None:
        payload = {
            "format_version": "1.2",
            "terraform_version": "1.8.5",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_iam_role.target",
                            "mode": "managed",
                            "type": "aws_iam_role",
                            "name": "target",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "target",
                                "name": "target",
                                "arn": "arn:aws:iam::111122223333:role/target",
                                "assume_role_policy": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "sts:AssumeRole",
                                            "Principal": {"AWS": "arn:aws:iam::111122223333:role/deployer"},
                                        }
                                    ],
                                },
                            },
                        }
                    ]
                }
            },
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            plan_path = Path(tmp_dir) / "plan.json"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")
            result = self.engine.analyze_plan(plan_path)

        self.assertEqual(result.trust_boundaries[0].boundary_type, BoundaryType.CROSS_ACCOUNT_OR_ROLE)
        self.assertEqual(result.findings, [])


class AwsNormalizerTrustConditionTests(unittest.TestCase):
    def test_normalizer_extracts_supported_trust_narrowing_condition_keys(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                TerraformResource(
                    address="aws_iam_role.constrained",
                    mode="managed",
                    resource_type="aws_iam_role",
                    name="constrained",
                    provider_name="registry.terraform.io/hashicorp/aws",
                    values={
                        "id": "constrained-role",
                        "name": "constrained-role",
                        "arn": "arn:aws:iam::111122223333:role/constrained-role",
                        "assume_role_policy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "sts:AssumeRole",
                                    "Principal": {"Service": "lambda.amazonaws.com"},
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": "sts:AssumeRole",
                                    "Principal": {"AWS": "arn:aws:iam::444455556666:role/deployer"},
                                    "Condition": {
                                        "StringEquals": {
                                            "sts:ExternalId": "release-pipeline",
                                            "aws:SourceAccount": "444455556666",
                                            "aws:PrincipalArn": "arn:aws:iam::444455556666:role/deployer",
                                        },
                                        "ArnLike": {
                                            "aws:SourceArn": "arn:aws:codebuild:us-east-1:444455556666:project/release-*"
                                        },
                                    },
                                },
                            ],
                        },
                    },
                )
            ]
        )
        role = inventory.get_by_address("aws_iam_role.constrained")

        self.assertIsNotNone(role)
        self.assertEqual(
            role.metadata.get("trust_statements"),
            [
                {
                    "principals": ["lambda.amazonaws.com"],
                    "narrowing_condition_keys": [],
                    "has_narrowing_conditions": False,
                },
                {
                    "principals": ["arn:aws:iam::444455556666:role/deployer"],
                    "narrowing_condition_keys": [
                        "aws:SourceAccount",
                        "aws:SourceArn",
                        "sts:ExternalId",
                    ],
                    "has_narrowing_conditions": True,
                },
            ],
        )


class AwsCoverageExpansionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = CloudThreatModeler()

    def _analyze_payload(self, payload: dict) -> object:
        with tempfile.TemporaryDirectory() as tmp_dir:
            plan_path = Path(tmp_dir) / "plan.json"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")
            return self.engine.analyze_plan(plan_path)

    def test_instance_profiles_and_inline_role_policy_extend_ec2_workload_risk_and_secret_boundary(self) -> None:
        result = self._analyze_payload(
            {
                "format_version": "1.2",
                "terraform_version": "1.8.5",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "address": "aws_iam_role.web",
                                "mode": "managed",
                                "type": "aws_iam_role",
                                "name": "web",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "web",
                                    "name": "web",
                                    "arn": "arn:aws:iam::111122223333:role/web",
                                    "assume_role_policy": {
                                        "Version": "2012-10-17",
                                        "Statement": [
                                            {
                                                "Effect": "Allow",
                                                "Action": "sts:AssumeRole",
                                                "Principal": {"Service": "ec2.amazonaws.com"},
                                            }
                                        ],
                                    },
                                },
                            },
                            {
                                "address": "aws_iam_role_policy.web_secret_read",
                                "mode": "managed",
                                "type": "aws_iam_role_policy",
                                "name": "web_secret_read",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "web:web-secret-read",
                                    "name": "web-secret-read",
                                    "role": "web",
                                    "policy": {
                                        "Version": "2012-10-17",
                                        "Statement": [
                                            {
                                                "Effect": "Allow",
                                                "Action": "secretsmanager:GetSecretValue",
                                                "Resource": "*",
                                            }
                                        ],
                                    },
                                },
                            },
                            {
                                "address": "aws_iam_instance_profile.web",
                                "mode": "managed",
                                "type": "aws_iam_instance_profile",
                                "name": "web",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "web-profile",
                                    "name": "web-profile",
                                    "arn": "arn:aws:iam::111122223333:instance-profile/web-profile",
                                    "role": "web",
                                },
                            },
                            {
                                "address": "aws_instance.app",
                                "mode": "managed",
                                "type": "aws_instance",
                                "name": "app",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "i-123",
                                    "iam_instance_profile": "web-profile",
                                },
                            },
                            {
                                "address": "aws_secretsmanager_secret.app",
                                "mode": "managed",
                                "type": "aws_secretsmanager_secret",
                                "name": "app",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "app-secret",
                                    "name": "app-secret",
                                    "arn": "arn:aws:secretsmanager:us-east-1:111122223333:secret:app-secret",
                                },
                            },
                        ]
                    }
                },
            }
        )

        instance = result.inventory.get_by_address("aws_instance.app")
        role = result.inventory.get_by_address("aws_iam_role.web")
        findings_by_title = Counter(finding.title for finding in result.findings)
        boundary_pairs = {(boundary.boundary_type, boundary.source, boundary.target) for boundary in result.trust_boundaries}

        self.assertIsNotNone(instance)
        self.assertIsNotNone(role)
        self.assertIn("arn:aws:iam::111122223333:role/web", instance.attached_role_arns)
        self.assertIn("aws_iam_role_policy.web_secret_read", role.metadata.get("inline_policy_resource_addresses", []))
        self.assertIn(
            (BoundaryType.CONTROL_TO_WORKLOAD, "aws_iam_role.web", "aws_instance.app"),
            boundary_pairs,
        )
        self.assertIn(
            (BoundaryType.WORKLOAD_TO_DATA_STORE, "aws_instance.app", "aws_secretsmanager_secret.app"),
            boundary_pairs,
        )
        self.assertEqual(findings_by_title["Workload role carries sensitive permissions"], 1)

    def test_resource_policy_findings_cover_secret_kms_and_lambda_permissions(self) -> None:
        result = self._analyze_payload(
            {
                "format_version": "1.2",
                "terraform_version": "1.8.5",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "address": "aws_secretsmanager_secret.app",
                                "mode": "managed",
                                "type": "aws_secretsmanager_secret",
                                "name": "app",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "app-secret",
                                    "name": "app-secret",
                                    "arn": "arn:aws:secretsmanager:us-east-1:111122223333:secret:app-secret",
                                },
                            },
                            {
                                "address": "aws_secretsmanager_secret_policy.app",
                                "mode": "managed",
                                "type": "aws_secretsmanager_secret_policy",
                                "name": "app",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "app-policy",
                                    "secret_arn": "arn:aws:secretsmanager:us-east-1:111122223333:secret:app-secret",
                                    "policy": {
                                        "Version": "2012-10-17",
                                        "Statement": [
                                            {
                                                "Effect": "Allow",
                                                "Principal": {"AWS": "arn:aws:iam::444455556666:root"},
                                                "Action": "secretsmanager:GetSecretValue",
                                                "Resource": "*",
                                            }
                                        ],
                                    },
                                },
                            },
                            {
                                "address": "aws_kms_key.shared",
                                "mode": "managed",
                                "type": "aws_kms_key",
                                "name": "shared",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "kms-shared",
                                    "arn": "arn:aws:kms:us-east-1:111122223333:key/1234",
                                    "policy": {
                                        "Version": "2012-10-17",
                                        "Statement": [
                                            {
                                                "Effect": "Allow",
                                                "Principal": {"AWS": "arn:aws:iam::444455556666:root"},
                                                "Action": "kms:Decrypt",
                                                "Resource": "*",
                                            }
                                        ],
                                    },
                                },
                            },
                            {
                                "address": "aws_lambda_function.processor",
                                "mode": "managed",
                                "type": "aws_lambda_function",
                                "name": "processor",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "processor",
                                    "function_name": "processor",
                                    "arn": "arn:aws:lambda:us-east-1:111122223333:function:processor",
                                },
                            },
                            {
                                "address": "aws_lambda_permission.public_invoke",
                                "mode": "managed",
                                "type": "aws_lambda_permission",
                                "name": "public_invoke",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "public-invoke",
                                    "statement_id": "public-invoke",
                                    "function_name": "processor",
                                    "action": "lambda:InvokeFunction",
                                    "principal": "*",
                                },
                            },
                        ]
                    }
                },
            }
        )

        severity_counts = Counter(finding.severity.value for finding in result.findings)
        title_counts = Counter(finding.title for finding in result.findings)
        secret = result.inventory.get_by_address("aws_secretsmanager_secret.app")
        lambda_function = result.inventory.get_by_address("aws_lambda_function.processor")

        self.assertEqual(dict(severity_counts), {"high": 3})
        self.assertEqual(title_counts["Sensitive resource policy allows public or cross-account access"], 2)
        self.assertEqual(title_counts["Service resource policy allows public or cross-account access"], 1)
        self.assertIn("aws_secretsmanager_secret_policy.app", secret.metadata.get("resource_policy_source_addresses", []))
        self.assertIn("aws_lambda_permission.public_invoke", lambda_function.metadata.get("resource_policy_source_addresses", []))

    def test_normalizer_supports_bucket_policy_queue_and_topic_policies(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                TerraformResource(
                    address="aws_s3_bucket.artifacts",
                    mode="managed",
                    resource_type="aws_s3_bucket",
                    name="artifacts",
                    provider_name="registry.terraform.io/hashicorp/aws",
                    values={
                        "id": "artifacts-bucket",
                        "bucket": "artifacts-bucket",
                        "arn": "arn:aws:s3:::artifacts-bucket",
                    },
                ),
                TerraformResource(
                    address="aws_s3_bucket_policy.artifacts",
                    mode="managed",
                    resource_type="aws_s3_bucket_policy",
                    name="artifacts",
                    provider_name="registry.terraform.io/hashicorp/aws",
                    values={
                        "id": "artifacts-policy",
                        "bucket": "artifacts-bucket",
                        "policy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": "arn:aws:iam::444455556666:root"},
                                    "Action": "s3:GetObject",
                                    "Resource": "*",
                                }
                            ],
                        },
                    },
                ),
                TerraformResource(
                    address="aws_sqs_queue.jobs",
                    mode="managed",
                    resource_type="aws_sqs_queue",
                    name="jobs",
                    provider_name="registry.terraform.io/hashicorp/aws",
                    values={
                        "id": "https://sqs.us-east-1.amazonaws.com/111122223333/jobs",
                        "name": "jobs",
                        "arn": "arn:aws:sqs:us-east-1:111122223333:jobs",
                        "policy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": "arn:aws:iam::444455556666:root"},
                                    "Action": "sqs:SendMessage",
                                    "Resource": "*",
                                }
                            ],
                        },
                    },
                ),
                TerraformResource(
                    address="aws_sns_topic.events",
                    mode="managed",
                    resource_type="aws_sns_topic",
                    name="events",
                    provider_name="registry.terraform.io/hashicorp/aws",
                    values={
                        "id": "arn:aws:sns:us-east-1:111122223333:events",
                        "name": "events",
                        "arn": "arn:aws:sns:us-east-1:111122223333:events",
                        "policy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": "arn:aws:iam::444455556666:root"},
                                    "Action": "sns:Publish",
                                    "Resource": "*",
                                }
                            ],
                        },
                    },
                ),
            ]
        )

        bucket = inventory.get_by_address("aws_s3_bucket.artifacts")
        queue = inventory.get_by_address("aws_sqs_queue.jobs")
        topic = inventory.get_by_address("aws_sns_topic.events")

        self.assertEqual(bucket.policy_statements[0].principals, ["arn:aws:iam::444455556666:root"])
        self.assertIn("aws_s3_bucket_policy.artifacts", bucket.metadata.get("resource_policy_source_addresses", []))
        self.assertEqual(queue.policy_statements[0].actions, ["sqs:SendMessage"])
        self.assertEqual(topic.policy_statements[0].actions, ["sns:Publish"])


if __name__ == "__main__":
    unittest.main()
