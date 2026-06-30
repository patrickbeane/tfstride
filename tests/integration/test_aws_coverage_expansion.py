from __future__ import annotations

import unittest
from collections import Counter

from tests.integration.analysis_support import (
    TFSIntegrationTestCase,
)
from tfstride.models import (
    BoundaryType,
    Severity,
    TerraformResource,
)
from tfstride.providers.aws.normalizer import AwsNormalizer


class AwsCoverageExpansionTests(TFSIntegrationTestCase):
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
        boundary_pairs = {
            (boundary.boundary_type, boundary.source, boundary.target) for boundary in result.trust_boundaries
        }

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

        self.assertEqual(dict(severity_counts), {"high": 4})
        self.assertEqual(title_counts["Sensitive resource policy allows broad or cross-account access"], 2)
        self.assertEqual(title_counts["Service resource policy allows broad or cross-account access"], 1)
        self.assertEqual(title_counts["Lambda function allows public invocation"], 1)
        self.assertIn(
            "aws_secretsmanager_secret_policy.app", secret.metadata.get("resource_policy_source_addresses", [])
        )
        self.assertIn(
            "aws_lambda_permission.public_invoke", lambda_function.metadata.get("resource_policy_source_addresses", [])
        )

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
                                                    "StringEquals": {"aws:SourceAccount": "111122223333"},
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
                                                    "StringEquals": {"aws:SourceAccount": "111122223333"},
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
