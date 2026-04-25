from __future__ import annotations

from collections import Counter
import json
import tempfile
import unittest
from pathlib import Path

from tfstride.analysis.rule_registry import DEFAULT_RULE_REGISTRY, RuleMetadata, RulePolicy, RuleRegistry
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.app import TfStride
from tfstride.models import (
    BoundaryType,
    IAMPolicyCondition,
    IAMPolicyStatement,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
    SecurityGroupRule,
    Severity,
    StrideCategory,
    TerraformResource,
)
from tfstride.providers.aws.normalizer import AwsNormalizer


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"
BASELINE_FIXTURE_PATH = FIXTURES_DIR / "sample_aws_baseline_plan.json"
FIXTURE_PATH = FIXTURES_DIR / "sample_aws_plan.json"
SAFE_FIXTURE_PATH = FIXTURES_DIR / "sample_aws_safe_plan.json"
NIGHTMARE_FIXTURE_PATH = FIXTURES_DIR / "sample_aws_nightmare_plan.json"
ALB_EC2_RDS_FIXTURE_PATH = FIXTURES_DIR / "sample_aws_alb_ec2_rds_plan.json"
ECS_FARGATE_FIXTURE_PATH = FIXTURES_DIR / "sample_aws_ecs_fargate_plan.json"
LAMBDA_DEPLOY_ROLE_FIXTURE_PATH = FIXTURES_DIR / "sample_aws_lambda_deploy_role_plan.json"
CROSS_ACCOUNT_TRUST_UNCONSTRAINED_FIXTURE_PATH = (
    FIXTURES_DIR / "sample_aws_cross_account_trust_unconstrained_plan.json"
)
CROSS_ACCOUNT_TRUST_CONSTRAINED_FIXTURE_PATH = (
    FIXTURES_DIR / "sample_aws_cross_account_trust_constrained_plan.json"
)


class RuleRegistryIntegrationTests(unittest.TestCase):
    def test_rule_engine_uses_injected_registry_metadata_for_findings(self) -> None:
        registry = RuleRegistry(
            [
                RuleMetadata(
                    rule_id="aws-public-compute-broad-ingress",
                    title="Registry supplied public compute title",
                    category=StrideCategory.DENIAL_OF_SERVICE,
                    recommended_mitigation="Registry supplied mitigation.",
                )
            ]
        )
        security_group = NormalizedResource(
            address="aws_security_group.web",
            provider="aws",
            resource_type="aws_security_group",
            name="web",
            category=ResourceCategory.NETWORK,
            identifier="sg-web",
            network_rules=[
                SecurityGroupRule(
                    direction="ingress",
                    protocol="tcp",
                    from_port=22,
                    to_port=22,
                    cidr_blocks=["0.0.0.0/0"],
                )
            ],
        )
        instance = NormalizedResource(
            address="aws_instance.web",
            provider="aws",
            resource_type="aws_instance",
            name="web",
            category=ResourceCategory.COMPUTE,
            security_group_ids=["sg-web"],
            public_exposure=True,
            metadata={"public_exposure_reasons": ["instance has a public internet path"]},
        )
        inventory = ResourceInventory(provider="aws", resources=[instance, security_group])

        findings = StrideRuleEngine(rule_registry=registry).evaluate(inventory, [])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "aws-public-compute-broad-ingress")
        self.assertEqual(finding.title, "Registry supplied public compute title")
        self.assertEqual(finding.category, StrideCategory.DENIAL_OF_SERVICE)
        self.assertEqual(finding.recommended_mitigation, "Registry supplied mitigation.")

    def test_rule_engine_executes_iam_rule_definitions_with_registry_metadata(self) -> None:
        registry = RuleRegistry(
            [
                RuleMetadata(
                    rule_id="aws-iam-wildcard-permissions",
                    title="Registry supplied IAM wildcard title",
                    category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                    recommended_mitigation="Registry supplied wildcard mitigation.",
                ),
                RuleMetadata(
                    rule_id="aws-workload-role-sensitive-permissions",
                    title="Registry supplied workload role title",
                    category=StrideCategory.INFORMATION_DISCLOSURE,
                    recommended_mitigation="Registry supplied workload role mitigation.",
                ),
            ]
        )
        wildcard_policy = NormalizedResource(
            address="aws_iam_policy.admin",
            provider="aws",
            resource_type="aws_iam_policy",
            name="admin",
            category=ResourceCategory.IAM,
            policy_statements=[
                IAMPolicyStatement(
                    effect="Allow",
                    actions=["s3:*"],
                    resources=["arn:aws:s3:::customer-data/*"],
                )
            ],
        )
        role = NormalizedResource(
            address="aws_iam_role.worker",
            provider="aws",
            resource_type="aws_iam_role",
            name="worker",
            category=ResourceCategory.IAM,
            arn="arn:aws:iam::111122223333:role/worker",
            policy_statements=[
                IAMPolicyStatement(
                    effect="Allow",
                    actions=["secretsmanager:GetSecretValue"],
                    resources=["arn:aws:secretsmanager:us-east-1:111122223333:secret:customer"],
                )
            ],
        )
        workload = NormalizedResource(
            address="aws_lambda_function.worker",
            provider="aws",
            resource_type="aws_lambda_function",
            name="worker",
            category=ResourceCategory.COMPUTE,
            attached_role_arns=["arn:aws:iam::111122223333:role/worker"],
        )
        inventory = ResourceInventory(provider="aws", resources=[wildcard_policy, role, workload])

        findings = StrideRuleEngine(rule_registry=registry).evaluate(inventory, [])
        findings_by_rule = {finding.rule_id: finding for finding in findings}

        self.assertEqual(
            set(findings_by_rule),
            {
                "aws-iam-wildcard-permissions",
                "aws-workload-role-sensitive-permissions",
            },
        )
        self.assertEqual(
            findings_by_rule["aws-iam-wildcard-permissions"].title,
            "Registry supplied IAM wildcard title",
        )
        self.assertEqual(
            findings_by_rule["aws-iam-wildcard-permissions"].recommended_mitigation,
            "Registry supplied wildcard mitigation.",
        )
        self.assertEqual(
            findings_by_rule["aws-workload-role-sensitive-permissions"].title,
            "Registry supplied workload role title",
        )
        self.assertEqual(
            findings_by_rule["aws-workload-role-sensitive-permissions"].recommended_mitigation,
            "Registry supplied workload role mitigation.",
        )

    def test_rule_engine_skips_disabled_iam_executable_rules(self) -> None:
        wildcard_policy = NormalizedResource(
            address="aws_iam_policy.admin",
            provider="aws",
            resource_type="aws_iam_policy",
            name="admin",
            category=ResourceCategory.IAM,
            policy_statements=[
                IAMPolicyStatement(
                    effect="Allow",
                    actions=["s3:*"],
                    resources=["arn:aws:s3:::customer-data/*"],
                )
            ],
        )
        role = NormalizedResource(
            address="aws_iam_role.worker",
            provider="aws",
            resource_type="aws_iam_role",
            name="worker",
            category=ResourceCategory.IAM,
            arn="arn:aws:iam::111122223333:role/worker",
            policy_statements=[
                IAMPolicyStatement(
                    effect="Allow",
                    actions=["secretsmanager:GetSecretValue"],
                    resources=["arn:aws:secretsmanager:us-east-1:111122223333:secret:customer"],
                )
            ],
        )
        workload = NormalizedResource(
            address="aws_lambda_function.worker",
            provider="aws",
            resource_type="aws_lambda_function",
            name="worker",
            category=ResourceCategory.COMPUTE,
            attached_role_arns=["arn:aws:iam::111122223333:role/worker"],
        )
        inventory = ResourceInventory(provider="aws", resources=[wildcard_policy, role, workload])
        enabled_rule_ids = DEFAULT_RULE_REGISTRY.default_enabled_rule_ids()
        enabled_rule_ids.difference_update(
            {
                "aws-iam-wildcard-permissions",
                "aws-workload-role-sensitive-permissions",
            }
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset(enabled_rule_ids)),
        )

        self.assertEqual(findings, [])


class TFSAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = TfStride()
        self.result = self.engine.analyze_plan(FIXTURE_PATH)

    def _analyze_payload(self, payload: dict) -> object:
        with tempfile.TemporaryDirectory() as tmp_dir:
            plan_path = Path(tmp_dir) / "plan.json"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")
            return self.engine.analyze_plan(plan_path)

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
            "safe": (SAFE_FIXTURE_PATH, 0, {}),
            "baseline": (BASELINE_FIXTURE_PATH, 2, {"medium": 2}),
            "mixed": (FIXTURE_PATH, 9, {"high": 3, "medium": 6}),
            "nightmare": (NIGHTMARE_FIXTURE_PATH, 16, {"high": 5, "medium": 11}),
        }

        expected_titles = {
            "safe": {},
            "baseline": {
                "IAM policy grants wildcard privileges": 1,
                "Sensitive data tier is transitively reachable from an internet-exposed path": 1,
            },
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
        self.assertEqual(dict(severity_counts), {})
        self.assertEqual(dict(title_counts), {})
        self.assertNotIn(
            "Cross-account or broad role trust lacks narrowing conditions",
            title_counts,
        )
        self.assertNotIn(
            "Role trust relationship expands blast radius",
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
                    "narrowing_conditions": [],
                    "has_narrowing_conditions": False,
                },
                {
                    "principals": ["arn:aws:iam::999988887777:root"],
                    "narrowing_condition_keys": [],
                    "narrowing_conditions": [],
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
        self.assertTrue(safe_public_subnet.metadata.get("has_public_route"))
        self.assertNotIn("in_public_subnet", safe_public_subnet.metadata)
        self.assertFalse(safe_public_subnet.metadata.get("has_nat_gateway_egress"))

        self.assertEqual(safe_private_subnet.metadata.get("route_table_ids"), ["rtb-safe-private-001"])
        self.assertFalse(safe_private_subnet.metadata.get("is_public_subnet"))
        self.assertNotIn("in_public_subnet", safe_private_subnet.metadata)
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
        self.assertTrue(instance.metadata.get("in_public_subnet"))
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

    def test_realistic_alb_ec2_rds_fixture_surfaces_transitive_data_path(self) -> None:
        result = self.engine.analyze_plan(ALB_EC2_RDS_FIXTURE_PATH)
        boundary_types = Counter(boundary.boundary_type for boundary in result.trust_boundaries)
        title_counts = Counter(finding.title for finding in result.findings)

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(len(result.inventory.resources), 19)
        self.assertEqual(
            dict(title_counts),
            {"Sensitive data tier is transitively reachable from an internet-exposed path": 1},
        )
        self.assertEqual(boundary_types[BoundaryType.INTERNET_TO_SERVICE], 1)
        self.assertEqual(boundary_types[BoundaryType.PUBLIC_TO_PRIVATE], 2)
        self.assertEqual(boundary_types[BoundaryType.WORKLOAD_TO_DATA_STORE], 1)

    def test_realistic_ecs_fargate_fixture_models_private_workload_boundaries(self) -> None:
        result = self.engine.analyze_plan(ECS_FARGATE_FIXTURE_PATH)
        ecs_service = result.inventory.get_by_address("aws_ecs_service.app")
        boundary_pairs = {(boundary.boundary_type, boundary.source, boundary.target) for boundary in result.trust_boundaries}
        findings_by_title = Counter(finding.title for finding in result.findings)

        self.assertIsNotNone(ecs_service)
        self.assertFalse(ecs_service.public_exposure)
        self.assertFalse(ecs_service.metadata.get("in_public_subnet"))
        self.assertTrue(ecs_service.metadata.get("fronted_by_internet_facing_load_balancer"))
        self.assertEqual(
            ecs_service.metadata.get("internet_facing_load_balancer_addresses"),
            ["aws_lb.web"],
        )
        self.assertEqual(
            ecs_service.attached_role_arns,
            ["arn:aws:iam::111122223333:role/app-task-role"],
        )
        self.assertEqual(
            ecs_service.metadata.get("execution_role_arn"),
            "arn:aws:iam::111122223333:role/app-execution-role",
        )
        self.assertIn(
            (BoundaryType.INTERNET_TO_SERVICE, "internet", "aws_lb.web"),
            boundary_pairs,
        )
        self.assertNotIn(
            (BoundaryType.INTERNET_TO_SERVICE, "internet", "aws_ecs_service.app"),
            boundary_pairs,
        )
        self.assertIn(
            (BoundaryType.WORKLOAD_TO_DATA_STORE, "aws_ecs_service.app", "aws_db_instance.app"),
            boundary_pairs,
        )
        self.assertIn(
            (BoundaryType.WORKLOAD_TO_DATA_STORE, "aws_ecs_service.app", "aws_secretsmanager_secret.app"),
            boundary_pairs,
        )
        self.assertIn(
            (BoundaryType.CONTROL_TO_WORKLOAD, "aws_iam_role.task", "aws_ecs_service.app"),
            boundary_pairs,
        )
        self.assertNotIn(
            (BoundaryType.CONTROL_TO_WORKLOAD, "aws_iam_role.execution", "aws_ecs_service.app"),
            boundary_pairs,
        )
        self.assertEqual(findings_by_title["Workload role carries sensitive permissions"], 1)

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

    def test_transitive_private_data_path_from_public_edge_is_detected(self) -> None:
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
                            "values": {"id": "vpc-1", "cidr_block": "10.42.0.0/16"},
                        },
                        {
                            "address": "aws_subnet.public_edge",
                            "mode": "managed",
                            "type": "aws_subnet",
                            "name": "public_edge",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "subnet-public-1",
                                "vpc_id": "vpc-1",
                                "cidr_block": "10.42.1.0/24",
                                "map_public_ip_on_launch": True,
                            },
                        },
                        {
                            "address": "aws_subnet.private_app",
                            "mode": "managed",
                            "type": "aws_subnet",
                            "name": "private_app",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "subnet-private-app-1",
                                "vpc_id": "vpc-1",
                                "cidr_block": "10.42.2.0/24",
                                "map_public_ip_on_launch": False,
                            },
                        },
                        {
                            "address": "aws_subnet.private_worker",
                            "mode": "managed",
                            "type": "aws_subnet",
                            "name": "private_worker",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "subnet-private-worker-1",
                                "vpc_id": "vpc-1",
                                "cidr_block": "10.42.3.0/24",
                                "map_public_ip_on_launch": False,
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
                                "id": "rtb-public-1",
                                "vpc_id": "vpc-1",
                                "route": [{"cidr_block": "0.0.0.0/0", "gateway_id": "igw-1"}],
                            },
                        },
                        {
                            "address": "aws_nat_gateway.main",
                            "mode": "managed",
                            "type": "aws_nat_gateway",
                            "name": "main",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "nat-1",
                                "subnet_id": "subnet-public-1",
                                "allocation_id": "eipalloc-1",
                                "connectivity_type": "public",
                            },
                        },
                        {
                            "address": "aws_route_table.private",
                            "mode": "managed",
                            "type": "aws_route_table",
                            "name": "private",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "rtb-private-1",
                                "vpc_id": "vpc-1",
                                "route": [{"cidr_block": "0.0.0.0/0", "nat_gateway_id": "nat-1"}],
                            },
                        },
                        {
                            "address": "aws_route_table_association.public_edge",
                            "mode": "managed",
                            "type": "aws_route_table_association",
                            "name": "public_edge",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "assoc-public-1",
                                "subnet_id": "subnet-public-1",
                                "route_table_id": "rtb-public-1",
                            },
                        },
                        {
                            "address": "aws_route_table_association.private_app",
                            "mode": "managed",
                            "type": "aws_route_table_association",
                            "name": "private_app",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "assoc-private-app-1",
                                "subnet_id": "subnet-private-app-1",
                                "route_table_id": "rtb-private-1",
                            },
                        },
                        {
                            "address": "aws_route_table_association.private_worker",
                            "mode": "managed",
                            "type": "aws_route_table_association",
                            "name": "private_worker",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "assoc-private-worker-1",
                                "subnet_id": "subnet-private-worker-1",
                                "route_table_id": "rtb-private-1",
                            },
                        },
                        {
                            "address": "aws_security_group.lb",
                            "mode": "managed",
                            "type": "aws_security_group",
                            "name": "lb",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "sg-lb-1",
                                "vpc_id": "vpc-1",
                                "ingress": [
                                    {
                                        "protocol": "tcp",
                                        "from_port": 443,
                                        "to_port": 443,
                                        "cidr_blocks": ["0.0.0.0/0"],
                                    }
                                ],
                                "egress": [{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}],
                            },
                        },
                        {
                            "address": "aws_security_group.app",
                            "mode": "managed",
                            "type": "aws_security_group",
                            "name": "app",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "sg-app-1",
                                "vpc_id": "vpc-1",
                                "ingress": [],
                                "egress": [{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}],
                            },
                        },
                        {
                            "address": "aws_security_group_rule.app_from_lb",
                            "mode": "managed",
                            "type": "aws_security_group_rule",
                            "name": "app_from_lb",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "sgr-app-from-lb",
                                "type": "ingress",
                                "protocol": "tcp",
                                "from_port": 8443,
                                "to_port": 8443,
                                "security_group_id": "sg-app-1",
                                "source_security_group_id": "sg-lb-1",
                            },
                        },
                        {
                            "address": "aws_security_group.worker",
                            "mode": "managed",
                            "type": "aws_security_group",
                            "name": "worker",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "sg-worker-1",
                                "vpc_id": "vpc-1",
                                "ingress": [],
                                "egress": [{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}],
                            },
                        },
                        {
                            "address": "aws_security_group_rule.worker_from_app",
                            "mode": "managed",
                            "type": "aws_security_group_rule",
                            "name": "worker_from_app",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "sgr-worker-from-app",
                                "type": "ingress",
                                "protocol": "tcp",
                                "from_port": 9000,
                                "to_port": 9000,
                                "security_group_id": "sg-worker-1",
                                "source_security_group_id": "sg-app-1",
                            },
                        },
                        {
                            "address": "aws_security_group.db",
                            "mode": "managed",
                            "type": "aws_security_group",
                            "name": "db",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "sg-db-1",
                                "vpc_id": "vpc-1",
                                "ingress": [],
                                "egress": [{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}],
                            },
                        },
                        {
                            "address": "aws_security_group_rule.db_from_worker",
                            "mode": "managed",
                            "type": "aws_security_group_rule",
                            "name": "db_from_worker",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "sgr-db-from-worker",
                                "type": "ingress",
                                "protocol": "tcp",
                                "from_port": 5432,
                                "to_port": 5432,
                                "security_group_id": "sg-db-1",
                                "source_security_group_id": "sg-worker-1",
                            },
                        },
                        {
                            "address": "aws_lb.edge",
                            "mode": "managed",
                            "type": "aws_lb",
                            "name": "edge",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "alb-1",
                                "arn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/edge/123456",
                                "name": "edge",
                                "internal": False,
                                "load_balancer_type": "application",
                                "security_groups": ["sg-lb-1"],
                                "subnets": ["subnet-public-1"],
                            },
                        },
                        {
                            "address": "aws_instance.app",
                            "mode": "managed",
                            "type": "aws_instance",
                            "name": "app",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "i-app-1",
                                "arn": "arn:aws:ec2:us-east-1:111122223333:instance/i-app-1",
                                "subnet_id": "subnet-private-app-1",
                                "vpc_security_group_ids": ["sg-app-1"],
                                "associate_public_ip_address": False,
                            },
                        },
                        {
                            "address": "aws_instance.worker",
                            "mode": "managed",
                            "type": "aws_instance",
                            "name": "worker",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "i-worker-1",
                                "arn": "arn:aws:ec2:us-east-1:111122223333:instance/i-worker-1",
                                "subnet_id": "subnet-private-worker-1",
                                "vpc_security_group_ids": ["sg-worker-1"],
                                "associate_public_ip_address": False,
                            },
                        },
                        {
                            "address": "aws_db_instance.app",
                            "mode": "managed",
                            "type": "aws_db_instance",
                            "name": "app",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "db-1",
                                "identifier": "private-app-db",
                                "arn": "arn:aws:rds:us-east-1:111122223333:db:private-app-db",
                                "engine": "postgres",
                                "publicly_accessible": False,
                                "storage_encrypted": True,
                                "db_subnet_group_name": "private-data",
                                "vpc_security_group_ids": ["sg-db-1"],
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

        transitive_finding = next(
            finding
            for finding in result.findings
            if finding.title == "Sensitive data tier is transitively reachable from an internet-exposed path"
        )
        evidence_by_key = {item.key: item.values for item in transitive_finding.evidence}

        self.assertEqual(transitive_finding.severity, Severity.MEDIUM)
        self.assertEqual(
            transitive_finding.affected_resources,
            [
                "aws_lb.edge",
                "aws_instance.app",
                "aws_instance.worker",
                "aws_db_instance.app",
                "aws_security_group.app",
                "aws_security_group.worker",
            ],
        )
        self.assertEqual(
            evidence_by_key["network_path"],
            [
                "internet reaches aws_lb.edge",
                "aws_lb.edge reaches aws_instance.app",
                "aws_instance.app reaches aws_instance.worker",
                "aws_instance.worker reaches aws_db_instance.app",
            ],
        )
        self.assertIn(
            "aws_security_group.app ingress tcp 8443 from sg-lb-1",
            evidence_by_key["security_group_rules"][0],
        )
        self.assertIn(
            "aws_security_group.worker ingress tcp 9000 from sg-app-1",
            evidence_by_key["security_group_rules"][1],
        )
        self.assertEqual(
            evidence_by_key["data_tier_posture"],
            [
                "aws_db_instance.app is not directly public",
                "database has no direct internet ingress path",
            ],
        )
        self.assertIsNotNone(transitive_finding.trust_boundary_id)
        self.assertEqual(
            transitive_finding.trust_boundary_id,
            "workload-to-data-store:aws_instance.worker->aws_db_instance.app",
        )
        self.assertEqual(transitive_finding.severity_reasoning.final_score, 5)

    def test_rule_policy_can_disable_rules_and_override_severity(self) -> None:
        enabled_rule_ids = DEFAULT_RULE_REGISTRY.default_enabled_rule_ids()
        enabled_rule_ids.remove("aws-database-permissive-ingress")
        engine = TfStride(
            rule_policy=RulePolicy(
                enabled_rule_ids=frozenset(enabled_rule_ids),
                severity_overrides={"aws-workload-role-sensitive-permissions": Severity.LOW},
            )
        )

        result = engine.analyze_plan(FIXTURE_PATH)
        finding_titles = {finding.title for finding in result.findings}
        workload_finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "aws-workload-role-sensitive-permissions"
        )

        self.assertNotIn("Database is reachable from overly permissive sources", finding_titles)
        self.assertEqual(workload_finding.severity, Severity.LOW)
        self.assertIsNotNone(workload_finding.severity_reasoning)
        self.assertEqual(workload_finding.severity_reasoning.severity, Severity.LOW)
        self.assertEqual(workload_finding.severity_reasoning.computed_severity, Severity.HIGH)

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

    def test_cross_account_control_plane_path_to_private_secret_and_database_is_detected(self) -> None:
        result = self._analyze_payload(
            {
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
                                "values": {"id": "vpc-1", "cidr_block": "10.50.0.0/16"},
                            },
                            {
                                "address": "aws_subnet.private_app",
                                "mode": "managed",
                                "type": "aws_subnet",
                                "name": "private_app",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "subnet-private-1",
                                    "vpc_id": "vpc-1",
                                    "cidr_block": "10.50.1.0/24",
                                    "map_public_ip_on_launch": False,
                                },
                            },
                            {
                                "address": "aws_security_group.lambda",
                                "mode": "managed",
                                "type": "aws_security_group",
                                "name": "lambda",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "sg-lambda-1",
                                    "vpc_id": "vpc-1",
                                    "ingress": [],
                                    "egress": [
                                        {
                                            "from_port": 0,
                                            "to_port": 0,
                                            "protocol": "-1",
                                            "cidr_blocks": ["0.0.0.0/0"],
                                            "ipv6_cidr_blocks": [],
                                            "security_groups": [],
                                        }
                                    ],
                                },
                            },
                            {
                                "address": "aws_security_group.db",
                                "mode": "managed",
                                "type": "aws_security_group",
                                "name": "db",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "sg-db-1",
                                    "vpc_id": "vpc-1",
                                    "ingress": [
                                        {
                                            "from_port": 5432,
                                            "to_port": 5432,
                                            "protocol": "tcp",
                                            "cidr_blocks": [],
                                            "ipv6_cidr_blocks": [],
                                            "security_groups": ["sg-lambda-1"],
                                        }
                                    ],
                                    "egress": [],
                                },
                            },
                            {
                                "address": "aws_iam_role.deployer",
                                "mode": "managed",
                                "type": "aws_iam_role",
                                "name": "deployer",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "deployer",
                                    "name": "deployer",
                                    "arn": "arn:aws:iam::111122223333:role/deployer",
                                    "assume_role_policy": {
                                        "Version": "2012-10-17",
                                        "Statement": [
                                            {
                                                "Effect": "Allow",
                                                "Action": "sts:AssumeRole",
                                                "Principal": {
                                                    "AWS": "arn:aws:iam::444455556666:role/ci-deployer"
                                                },
                                            },
                                            {
                                                "Effect": "Allow",
                                                "Action": "sts:AssumeRole",
                                                "Principal": {"Service": "lambda.amazonaws.com"},
                                            },
                                        ],
                                    },
                                    "inline_policy": [
                                        {
                                            "name": "data-access",
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
                                        }
                                    ],
                                },
                            },
                            {
                                "address": "aws_lambda_function.deployer",
                                "mode": "managed",
                                "type": "aws_lambda_function",
                                "name": "deployer",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "release-deployer",
                                    "function_name": "release-deployer",
                                    "arn": "arn:aws:lambda:us-east-1:111122223333:function:release-deployer",
                                    "role": "arn:aws:iam::111122223333:role/deployer",
                                    "runtime": "python3.12",
                                    "handler": "handler.main",
                                    "vpc_config": [
                                        {
                                            "subnet_ids": ["subnet-private-1"],
                                            "security_group_ids": ["sg-lambda-1"],
                                        }
                                    ],
                                },
                            },
                            {
                                "address": "aws_db_instance.customer",
                                "mode": "managed",
                                "type": "aws_db_instance",
                                "name": "customer",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "customer-db",
                                    "identifier": "customer-db",
                                    "engine": "postgres",
                                    "publicly_accessible": False,
                                    "storage_encrypted": True,
                                    "vpc_security_group_ids": ["sg-db-1"],
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

        findings = [
            finding
            for finding in result.findings
            if finding.title == "Broad or cross-account control-plane path can influence a sensitive workload"
        ]

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        evidence = {item.key: item.values for item in finding.evidence}

        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(
            finding.affected_resources,
            [
                "aws_iam_role.deployer",
                "aws_lambda_function.deployer",
                "aws_db_instance.customer",
                "aws_secretsmanager_secret.app",
            ],
        )
        self.assertEqual(
            evidence["trust_principals"],
            ["arn:aws:iam::444455556666:role/ci-deployer"],
        )
        self.assertEqual(
            evidence["trust_scope"],
            ["principal belongs to foreign account 444455556666"],
        )
        self.assertEqual(
            evidence["sensitive_data_targets"],
            ["aws_db_instance.customer", "aws_secretsmanager_secret.app"],
        )
        self.assertIn(
            "arn:aws:iam::444455556666:role/ci-deployer assumes aws_iam_role.deployer",
            evidence["control_path"],
        )
        self.assertIn(
            "aws_iam_role.deployer governs aws_lambda_function.deployer",
            evidence["control_path"],
        )
        self.assertIn(
            "aws_lambda_function.deployer reaches aws_db_instance.customer",
            evidence["control_path"],
        )
        self.assertIn(
            "aws_lambda_function.deployer reaches aws_secretsmanager_secret.app",
            evidence["control_path"],
        )
        self.assertIsNotNone(finding.trust_boundary_id)
        self.assertEqual(
            finding.trust_boundary_id,
            "cross-account-or-role-access:arn:aws:iam::444455556666:role/ci-deployer->aws_iam_role.deployer",
        )
        self.assertEqual(finding.severity_reasoning.final_score, 6)

    def test_ecs_service_with_missing_task_definition_and_network_data_degrades_gracefully(self) -> None:
        result = self._analyze_payload(
            {
                "format_version": "1.2",
                "terraform_version": "1.8.5",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "address": "aws_ecs_cluster.main",
                                "mode": "managed",
                                "type": "aws_ecs_cluster",
                                "name": "main",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "arn:aws:ecs:us-east-1:111122223333:cluster/main",
                                    "arn": "arn:aws:ecs:us-east-1:111122223333:cluster/main",
                                    "name": "main",
                                },
                            },
                            {
                                "address": "aws_ecs_service.app",
                                "mode": "managed",
                                "type": "aws_ecs_service",
                                "name": "app",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "arn:aws:ecs:us-east-1:111122223333:service/main/app",
                                    "name": "app",
                                    "cluster": "arn:aws:ecs:us-east-1:111122223333:cluster/main",
                                },
                            },
                        ]
                    }
                },
            }
        )

        ecs_service = result.inventory.get_by_address("aws_ecs_service.app")

        self.assertIsNotNone(ecs_service)
        self.assertEqual(ecs_service.subnet_ids, [])
        self.assertEqual(ecs_service.security_group_ids, [])
        self.assertEqual(ecs_service.attached_role_arns, [])
        self.assertFalse(ecs_service.public_exposure)
        self.assertFalse(ecs_service.metadata.get("fronted_by_internet_facing_load_balancer", False))
        self.assertEqual(result.inventory.unsupported_resources, [])
        self.assertEqual(result.findings, [])
        self.assertEqual(result.trust_boundaries, [])


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
                    "narrowing_conditions": [],
                    "has_narrowing_conditions": False,
                },
                {
                    "principals": ["arn:aws:iam::444455556666:role/deployer"],
                    "narrowing_condition_keys": [
                        "aws:SourceAccount",
                        "aws:SourceArn",
                        "sts:ExternalId",
                    ],
                    "narrowing_conditions": [
                        {
                            "operator": "ArnLike",
                            "key": "aws:SourceArn",
                            "values": [
                                "arn:aws:codebuild:us-east-1:444455556666:project/release-*"
                            ],
                        },
                        {
                            "operator": "StringEquals",
                            "key": "aws:SourceAccount",
                            "values": ["444455556666"],
                        },
                        {
                            "operator": "StringEquals",
                            "key": "sts:ExternalId",
                            "values": ["release-pipeline"],
                        },
                    ],
                    "has_narrowing_conditions": True,
                },
            ],
        )

    def test_normalizer_tracks_supported_trust_condition_operators(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                TerraformResource(
                    address="aws_iam_role.operator_constrained",
                    mode="managed",
                    resource_type="aws_iam_role",
                    name="operator_constrained",
                    provider_name="registry.terraform.io/hashicorp/aws",
                    values={
                        "id": "operator-constrained-role",
                        "name": "operator-constrained-role",
                        "arn": "arn:aws:iam::111122223333:role/operator-constrained-role",
                        "assume_role_policy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "sts:AssumeRole",
                                    "Principal": {"AWS": "arn:aws:iam::444455556666:role/deployer"},
                                    "Condition": {
                                        "NumericEquals": {
                                            "aws:SourceAccount": "444455556666",
                                        },
                                        "StringLike": {
                                            "sts:ExternalId": "release-*",
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
        role = inventory.get_by_address("aws_iam_role.operator_constrained")

        self.assertIsNotNone(role)
        self.assertEqual(
            role.metadata.get("trust_statements"),
            [
                {
                    "principals": ["arn:aws:iam::444455556666:role/deployer"],
                    "narrowing_condition_keys": [
                        "aws:SourceArn",
                        "sts:ExternalId",
                    ],
                    "narrowing_conditions": [
                        {
                            "operator": "ArnLike",
                            "key": "aws:SourceArn",
                            "values": [
                                "arn:aws:codebuild:us-east-1:444455556666:project/release-*"
                            ],
                        },
                        {
                            "operator": "StringLike",
                            "key": "sts:ExternalId",
                            "values": ["release-*"],
                        },
                    ],
                    "has_narrowing_conditions": True,
                }
            ],
        )

    def test_normalizer_preserves_structured_policy_conditions(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                TerraformResource(
                    address="aws_iam_policy.publisher",
                    mode="managed",
                    resource_type="aws_iam_policy",
                    name="publisher",
                    provider_name="registry.terraform.io/hashicorp/aws",
                    values={
                        "id": "publisher",
                        "name": "publisher",
                        "arn": "arn:aws:iam::111122223333:policy/publisher",
                        "policy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "sns:Publish",
                                    "Resource": "*",
                                    "Condition": {
                                        "ArnLike": {
                                            "aws:SourceArn": "arn:aws:events:us-east-1:111122223333:rule/release-*"
                                        },
                                        "StringEquals": {
                                            "aws:SourceAccount": "111122223333",
                                        },
                                    },
                                }
                            ],
                        },
                    },
                ),
                TerraformResource(
                    address="aws_lambda_permission.invoke",
                    mode="managed",
                    resource_type="aws_lambda_permission",
                    name="invoke",
                    provider_name="registry.terraform.io/hashicorp/aws",
                    values={
                        "id": "permission-1",
                        "statement_id": "allow-events",
                        "action": "lambda:InvokeFunction",
                        "function_name": "processor",
                        "principal": "events.amazonaws.com",
                        "source_arn": "arn:aws:events:us-east-1:111122223333:rule/release-trigger",
                        "source_account": "111122223333",
                    },
                ),
            ]
        )

        policy = inventory.get_by_address("aws_iam_policy.publisher")
        lambda_permission = inventory.get_by_address("aws_lambda_permission.invoke")

        self.assertIsNotNone(policy)
        self.assertIsNotNone(lambda_permission)
        self.assertEqual(
            policy.policy_statements[0].conditions,
            [
                IAMPolicyCondition(
                    operator="ArnLike",
                    key="aws:SourceArn",
                    values=["arn:aws:events:us-east-1:111122223333:rule/release-*"],
                ),
                IAMPolicyCondition(
                    operator="StringEquals",
                    key="aws:SourceAccount",
                    values=["111122223333"],
                ),
            ],
        )
        self.assertEqual(
            lambda_permission.policy_statements[0].conditions,
            [
                IAMPolicyCondition(
                    operator="ArnLike",
                    key="aws:SourceArn",
                    values=["arn:aws:events:us-east-1:111122223333:rule/release-trigger"],
                ),
                IAMPolicyCondition(
                    operator="StringEquals",
                    key="aws:SourceAccount",
                    values=["111122223333"],
                ),
            ],
        )


class AwsCoverageExpansionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = TfStride()

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
        self.assertEqual(title_counts["Sensitive resource policy allows broad or cross-account access"], 2)
        self.assertEqual(title_counts["Service resource policy allows broad or cross-account access"], 1)
        self.assertIn("aws_secretsmanager_secret_policy.app", secret.metadata.get("resource_policy_source_addresses", []))
        self.assertIn("aws_lambda_permission.public_invoke", lambda_function.metadata.get("resource_policy_source_addresses", []))

    def test_same_account_root_kms_policy_is_not_overstated_as_cross_account_exposure(self) -> None:
        result = self._analyze_payload(
            {
                "format_version": "1.2",
                "terraform_version": "1.8.5",
                "planned_values": {
                    "root_module": {
                        "resources": [
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
                                                "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                                                "Action": "kms:Decrypt",
                                                "Resource": "*",
                                            }
                                        ],
                                    },
                                },
                            }
                        ]
                    }
                },
            }
        )

        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        evidence = {item.key: item.values for item in finding.evidence}

        self.assertEqual(finding.title, "Sensitive resource policy allows broad or cross-account access")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertIn("same-account root through its key policy", finding.rationale)
        self.assertEqual(evidence["trust_scope"], ["principal is account root 111122223333"])
        self.assertEqual(finding.severity_reasoning.final_score, 4)

    def test_resource_policy_findings_are_narrowed_by_source_arn_conditions(self) -> None:
        result = self._analyze_payload(
            {
                "format_version": "1.2",
                "terraform_version": "1.8.5",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "address": "aws_sqs_queue.jobs",
                                "mode": "managed",
                                "type": "aws_sqs_queue",
                                "name": "jobs",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "https://sqs.us-east-1.amazonaws.com/111122223333/jobs",
                                    "name": "jobs",
                                    "arn": "arn:aws:sqs:us-east-1:111122223333:jobs",
                                    "policy": {
                                        "Version": "2012-10-17",
                                        "Statement": [
                                            {
                                                "Effect": "Allow",
                                                "Principal": {"AWS": "*"},
                                                "Action": "sqs:SendMessage",
                                                "Resource": "*",
                                                "Condition": {
                                                    "ArnEquals": {
                                                        "aws:SourceArn": "arn:aws:sns:us-east-1:111122223333:events"
                                                    },
                                                    "StringEquals": {
                                                        "aws:SourceAccount": "111122223333"
                                                    },
                                                },
                                            }
                                        ],
                                    },
                                },
                            }
                        ]
                    }
                },
            }
        )

        self.assertEqual(result.findings, [])

    def test_resource_policy_findings_remain_when_only_source_account_is_present(self) -> None:
        result = self._analyze_payload(
            {
                "format_version": "1.2",
                "terraform_version": "1.8.5",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "address": "aws_sqs_queue.jobs",
                                "mode": "managed",
                                "type": "aws_sqs_queue",
                                "name": "jobs",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "https://sqs.us-east-1.amazonaws.com/111122223333/jobs",
                                    "name": "jobs",
                                    "arn": "arn:aws:sqs:us-east-1:111122223333:jobs",
                                    "policy": {
                                        "Version": "2012-10-17",
                                        "Statement": [
                                            {
                                                "Effect": "Allow",
                                                "Principal": {"AWS": "*"},
                                                "Action": "sqs:SendMessage",
                                                "Resource": "*",
                                                "Condition": {
                                                    "StringEquals": {
                                                        "aws:SourceAccount": "111122223333"
                                                    },
                                                },
                                            }
                                        ],
                                    },
                                },
                            }
                        ]
                    }
                },
            }
        )

        self.assertEqual(
            [finding.title for finding in result.findings],
            ["Service resource policy allows broad or cross-account access"],
        )

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
