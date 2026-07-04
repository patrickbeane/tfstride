from __future__ import annotations

import unittest

from tfstride.analysis.rule_definitions import RuleDefinition
from tfstride.analysis.rule_registry import RuleMetadata, RulePolicy, RuleRegistry, default_rule_registry
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import (
    BoundaryType,
    IAMPolicyStatement,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
    SecurityGroupRule,
    StrideCategory,
    TrustBoundary,
)
from tfstride.providers.aws.metadata import AwsResourceMetadata


class RuleRegistryIntegrationTests(unittest.TestCase):
    def test_rule_engine_rule_groups_are_built_from_rule_definitions(self) -> None:
        engine = StrideRuleEngine()

        self.assertTrue(
            all(isinstance(rule, RuleDefinition) for rule_group in engine._rule_groups() for rule in rule_group)
        )

    def test_rule_engine_derives_default_registry_from_rule_definitions(self) -> None:
        engine = StrideRuleEngine()
        second_engine = StrideRuleEngine()
        definition_metadata = tuple(rule.metadata for rule_group in engine._rule_groups() for rule in rule_group)

        self.assertIsNot(engine._rule_registry, second_engine._rule_registry)
        self.assertEqual(engine._rule_registry.rules(), definition_metadata)

    def test_rule_registry_matches_configured_executable_rules(self) -> None:
        self.assertEqual(
            StrideRuleEngine().configured_rule_ids(),
            default_rule_registry().known_rule_ids(),
        )

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
        enabled_rule_ids = default_rule_registry().default_enabled_rule_ids()
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

    def test_rule_engine_skips_disabled_resource_policy_executable_rule_only(self) -> None:
        sensitive_secret = NormalizedResource(
            address="aws_secretsmanager_secret.customer",
            provider="aws",
            resource_type="aws_secretsmanager_secret",
            name="customer",
            category=ResourceCategory.DATA,
            metadata={
                AwsResourceMetadata.SECRETS_MANAGER_KMS_KEY_ID: "arn:aws:kms:us-east-1:111122223333:key/secret",
                AwsResourceMetadata.SECRETS_MANAGER_ROTATION_SOURCE_ADDRESS: (
                    "aws_secretsmanager_secret_rotation.customer"
                ),
                AwsResourceMetadata.SECRETS_MANAGER_ROTATION_AUTOMATICALLY_AFTER_DAYS: 30,
            },
            policy_statements=[
                IAMPolicyStatement(
                    effect="Allow",
                    actions=["secretsmanager:GetSecretValue"],
                    resources=["*"],
                    principals=["arn:aws:iam::444455556666:root"],
                )
            ],
        )
        service_queue = NormalizedResource(
            address="aws_sqs_queue.jobs",
            provider="aws",
            resource_type="aws_sqs_queue",
            name="jobs",
            category=ResourceCategory.COMPUTE,
            policy_statements=[
                IAMPolicyStatement(
                    effect="Allow",
                    actions=["sqs:SendMessage"],
                    resources=["*"],
                    principals=["*"],
                )
            ],
        )
        inventory = ResourceInventory(
            provider="aws",
            resources=[sensitive_secret, service_queue],
            metadata={"primary_account_id": "111122223333"},
        )
        enabled_rule_ids = default_rule_registry().default_enabled_rule_ids()
        enabled_rule_ids.remove("aws-sensitive-resource-policy-external-access")

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset(enabled_rule_ids)),
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["aws-service-resource-policy-external-access"],
        )

    def test_rule_engine_skips_disabled_trust_executable_rule_only(self) -> None:
        role = NormalizedResource(
            address="aws_iam_role.deployer",
            provider="aws",
            resource_type="aws_iam_role",
            name="deployer",
            category=ResourceCategory.IAM,
            metadata={
                "trust_statements": [
                    {
                        "principals": ["arn:aws:iam::444455556666:role/deployer"],
                        "narrowing_condition_keys": [],
                        "narrowing_conditions": [],
                        "has_narrowing_conditions": False,
                    }
                ]
            },
        )
        inventory = ResourceInventory(
            provider="aws",
            resources=[role],
            metadata={"primary_account_id": "111122223333"},
        )
        enabled_rule_ids = default_rule_registry().default_enabled_rule_ids()
        enabled_rule_ids.remove("aws-role-trust-expansion")

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset(enabled_rule_ids)),
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["aws-role-trust-missing-narrowing"],
        )

    def test_rule_engine_skips_disabled_posture_executable_rule_only(self) -> None:
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
        database = NormalizedResource(
            address="aws_db_instance.customer",
            provider="aws",
            resource_type="aws_db_instance",
            name="customer",
            category=ResourceCategory.DATA,
            metadata={"engine": "postgres"},
        )
        bucket = NormalizedResource(
            address="aws_s3_bucket.assets",
            provider="aws",
            resource_type="aws_s3_bucket",
            name="assets",
            category=ResourceCategory.DATA,
            public_exposure=True,
            metadata={"public_exposure_reasons": ["bucket policy allows public read"]},
        )
        inventory = ResourceInventory(
            provider="aws",
            resources=[security_group, instance, database, bucket],
        )
        posture_rule_ids = {
            "aws-public-compute-broad-ingress",
            "aws-rds-storage-encryption-disabled",
            "aws-s3-public-access",
        }

        for disabled_rule_id in posture_rule_ids:
            with self.subTest(disabled_rule_id=disabled_rule_id):
                enabled_rule_ids = default_rule_registry().default_enabled_rule_ids()
                enabled_rule_ids.remove(disabled_rule_id)

                findings = StrideRuleEngine().evaluate(
                    inventory,
                    [],
                    rule_policy=RulePolicy(enabled_rule_ids=frozenset(enabled_rule_ids)),
                )

                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    posture_rule_ids - {disabled_rule_id},
                )

    def test_rule_engine_skips_disabled_network_data_executable_rule_only(self) -> None:
        public_security_group = NormalizedResource(
            address="aws_security_group.public_app",
            provider="aws",
            resource_type="aws_security_group",
            name="public_app",
            category=ResourceCategory.NETWORK,
            identifier="sg-public-app",
        )
        public_app = NormalizedResource(
            address="aws_instance.public_app",
            provider="aws",
            resource_type="aws_instance",
            name="public_app",
            category=ResourceCategory.COMPUTE,
            security_group_ids=["sg-public-app"],
            public_exposure=True,
        )
        database_security_group = NormalizedResource(
            address="aws_security_group.database",
            provider="aws",
            resource_type="aws_security_group",
            name="database",
            category=ResourceCategory.NETWORK,
            identifier="sg-database",
            network_rules=[
                SecurityGroupRule(
                    direction="ingress",
                    protocol="tcp",
                    from_port=5432,
                    to_port=5432,
                    referenced_security_group_ids=["sg-public-app"],
                )
            ],
        )
        database = NormalizedResource(
            address="aws_db_instance.customer",
            provider="aws",
            resource_type="aws_db_instance",
            name="customer",
            category=ResourceCategory.DATA,
            security_group_ids=["sg-database"],
            metadata={
                "storage_encrypted": True,
                "rds_kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/rds",
            },
        )
        inventory = ResourceInventory(
            provider="aws",
            resources=[public_security_group, public_app, database_security_group, database],
        )
        network_data_rule_ids = {
            "aws-database-permissive-ingress",
            "aws-missing-tier-segmentation",
        }

        for disabled_rule_id in network_data_rule_ids:
            with self.subTest(disabled_rule_id=disabled_rule_id):
                enabled_rule_ids = default_rule_registry().default_enabled_rule_ids()
                enabled_rule_ids.remove(disabled_rule_id)

                findings = StrideRuleEngine().evaluate(
                    inventory,
                    [],
                    rule_policy=RulePolicy(enabled_rule_ids=frozenset(enabled_rule_ids)),
                )

                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    network_data_rule_ids - {disabled_rule_id},
                )

    def test_rule_engine_skips_disabled_path_chain_executable_rule_only(self) -> None:
        principal = "arn:aws:iam::444455556666:role/deployer"
        edge_security_group = NormalizedResource(
            address="aws_security_group.edge",
            provider="aws",
            resource_type="aws_security_group",
            name="edge",
            category=ResourceCategory.NETWORK,
            identifier="sg-edge",
        )
        worker_security_group = NormalizedResource(
            address="aws_security_group.worker",
            provider="aws",
            resource_type="aws_security_group",
            name="worker",
            category=ResourceCategory.NETWORK,
            identifier="sg-worker",
            network_rules=[
                SecurityGroupRule(
                    direction="ingress",
                    protocol="tcp",
                    from_port=9000,
                    to_port=9000,
                    referenced_security_group_ids=["sg-edge"],
                )
            ],
        )
        edge = NormalizedResource(
            address="aws_instance.edge",
            provider="aws",
            resource_type="aws_instance",
            name="edge",
            category=ResourceCategory.COMPUTE,
            security_group_ids=["sg-edge"],
        )
        worker = NormalizedResource(
            address="aws_instance.worker",
            provider="aws",
            resource_type="aws_instance",
            name="worker",
            category=ResourceCategory.COMPUTE,
            security_group_ids=["sg-worker"],
        )
        database = NormalizedResource(
            address="aws_db_instance.customer",
            provider="aws",
            resource_type="aws_db_instance",
            name="customer",
            category=ResourceCategory.DATA,
        )
        role = NormalizedResource(
            address="aws_iam_role.deployer",
            provider="aws",
            resource_type="aws_iam_role",
            name="deployer",
            category=ResourceCategory.IAM,
            metadata={
                "trust_statements": [
                    {
                        "principals": [principal],
                        "narrowing_condition_keys": [],
                        "narrowing_conditions": [],
                        "has_narrowing_conditions": False,
                    }
                ]
            },
        )
        boundaries = [
            TrustBoundary(
                identifier="internet-to-edge",
                boundary_type=BoundaryType.INTERNET_TO_SERVICE,
                source="internet",
                target=edge.address,
                description="internet reaches edge",
                rationale="edge is internet-facing",
            ),
            TrustBoundary(
                identifier="worker-to-database",
                boundary_type=BoundaryType.WORKLOAD_TO_DATA_STORE,
                source=worker.address,
                target=database.address,
                description="worker reaches database",
                rationale="database security group trusts worker",
            ),
            TrustBoundary(
                identifier="role-to-worker",
                boundary_type=BoundaryType.CONTROL_TO_WORKLOAD,
                source=role.address,
                target=worker.address,
                description="role governs worker",
                rationale="role credentials are projected into worker",
            ),
        ]
        inventory = ResourceInventory(
            provider="aws",
            resources=[
                edge_security_group,
                worker_security_group,
                edge,
                worker,
                database,
                role,
            ],
            metadata={"primary_account_id": "111122223333"},
        )
        path_chain_rule_ids = {
            "aws-private-data-transitive-exposure",
            "aws-control-plane-sensitive-workload-chain",
        }

        for disabled_rule_id in path_chain_rule_ids:
            with self.subTest(disabled_rule_id=disabled_rule_id):
                enabled_rule_ids = path_chain_rule_ids - {disabled_rule_id}

                findings = StrideRuleEngine().evaluate(
                    inventory,
                    boundaries,
                    rule_policy=RulePolicy(enabled_rule_ids=frozenset(enabled_rule_ids)),
                )

                self.assertEqual(
                    {finding.rule_id for finding in findings},
                    enabled_rule_ids,
                )


if __name__ == "__main__":
    unittest.main()
