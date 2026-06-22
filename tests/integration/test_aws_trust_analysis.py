from __future__ import annotations

import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from tests.integration.analysis_support import (
    CROSS_ACCOUNT_TRUST_CONSTRAINED_FIXTURE_PATH,
    CROSS_ACCOUNT_TRUST_UNCONSTRAINED_FIXTURE_PATH,
    FIXTURE_PATH,
    SAFE_FIXTURE_PATH,
    TFSIntegrationTestCase,
)
from tfstride.models import (
    BoundaryType,
    Severity,
)


class AwsTrustAnalysisIntegrationTests(TFSIntegrationTestCase):
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

    def test_role_policy_attachments_extend_effective_role_permissions(self) -> None:
        safe_result = self.engine.analyze_plan(SAFE_FIXTURE_PATH)
        mixed_result = self.engine.analyze_plan(FIXTURE_PATH)

        safe_role = safe_result.inventory.get_by_address("aws_iam_role.workload")
        mixed_role = mixed_result.inventory.get_by_address("aws_iam_role.workload")

        self.assertIn("aws_iam_policy.artifact_read", safe_role.metadata.get("attached_policy_addresses", []))
        self.assertTrue(any("s3:GetObject" in statement.actions for statement in safe_role.policy_statements))
        self.assertIn("aws_iam_policy.admin_like", mixed_role.metadata.get("attached_policy_addresses", []))

    def test_analysis_surfaces_trust_statement_summaries_on_roles(self) -> None:
        role = self.result.inventory.get_by_address("aws_iam_role.workload")

        self.assertIsNotNone(role)
        self.assertEqual(
            role.metadata.get("trust_statements"),
            [
                {
                    "principals": ["lambda.amazonaws.com"],
                    "principal_entries": [{"kind": "Service", "value": "lambda.amazonaws.com"}],
                    "narrowing_condition_keys": [],
                    "narrowing_conditions": [],
                    "has_narrowing_conditions": False,
                },
                {
                    "principals": ["arn:aws:iam::999988887777:root"],
                    "principal_entries": [{"kind": "AWS", "value": "arn:aws:iam::999988887777:root"}],
                    "narrowing_condition_keys": [],
                    "narrowing_conditions": [],
                    "has_narrowing_conditions": False,
                },
            ],
        )

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

    def test_same_account_federated_role_trust_without_audience_narrowing_is_flagged(self) -> None:
        result = self._analyze_payload(
            {
                "format_version": "1.2",
                "terraform_version": "1.8.5",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "address": "aws_iam_role.federated",
                                "mode": "managed",
                                "type": "aws_iam_role",
                                "name": "federated",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "federated",
                                    "name": "federated",
                                    "arn": "arn:aws:iam::111122223333:role/federated",
                                    "assume_role_policy": {
                                        "Version": "2012-10-17",
                                        "Statement": [
                                            {
                                                "Effect": "Allow",
                                                "Action": "sts:AssumeRoleWithSAML",
                                                "Principal": {
                                                    "Federated": ("arn:aws:iam::111122223333:saml-provider/CorpSSO")
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

        boundary = result.trust_boundaries[0]

        self.assertEqual(boundary.boundary_type, BoundaryType.CROSS_ACCOUNT_OR_ROLE)
        self.assertEqual(boundary.source, "arn:aws:iam::111122223333:saml-provider/CorpSSO")
        self.assertEqual(boundary.target, "aws_iam_role.federated")
        self.assertIn("as a SAML identity provider", boundary.description)
        self.assertEqual(
            boundary.rationale,
            "A federated identity provider can cross into this role's trust boundary.",
        )
        self.assertEqual(
            Counter(finding.rule_id for finding in result.findings),
            {
                "aws-role-trust-expansion": 1,
                "aws-role-trust-missing-narrowing": 1,
            },
        )

    def test_saml_audience_narrows_same_account_federated_role_trust(self) -> None:
        result = self._analyze_payload(
            {
                "format_version": "1.2",
                "terraform_version": "1.8.5",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "address": "aws_iam_role.federated",
                                "mode": "managed",
                                "type": "aws_iam_role",
                                "name": "federated",
                                "provider_name": "registry.terraform.io/hashicorp/aws",
                                "values": {
                                    "id": "federated",
                                    "name": "federated",
                                    "arn": "arn:aws:iam::111122223333:role/federated",
                                    "assume_role_policy": {
                                        "Version": "2012-10-17",
                                        "Statement": [
                                            {
                                                "Effect": "Allow",
                                                "Action": "sts:AssumeRoleWithSAML",
                                                "Principal": {
                                                    "Federated": ("arn:aws:iam::111122223333:saml-provider/CorpSSO")
                                                },
                                                "Condition": {
                                                    "StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}
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
        self.assertEqual(len(result.observations), 1)
        trust_evidence = {item.key: item.values for item in result.observations[0].evidence}
        self.assertEqual(
            trust_evidence["trust_scope"],
            ["SAML identity provider belongs to account 111122223333"],
        )
        self.assertEqual(
            trust_evidence["trust_narrowing"],
            [
                "supported narrowing conditions present: true",
                "supported narrowing condition keys: SAML:aud",
            ],
        )

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
                                                "Principal": {"AWS": "arn:aws:iam::444455556666:role/ci-deployer"},
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


if __name__ == "__main__":
    unittest.main()
