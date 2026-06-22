from __future__ import annotations

import unittest

from tfstride.models import (
    IAMPolicyCondition,
    TerraformResource,
)
from tfstride.providers.aws.normalizer import AwsNormalizer


class AwsNormalizerTrustConditionTests(unittest.TestCase):
    def test_normalizer_preserves_trust_principal_kinds(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                TerraformResource(
                    address="aws_iam_role.federated",
                    mode="managed",
                    resource_type="aws_iam_role",
                    name="federated",
                    provider_name="registry.terraform.io/hashicorp/aws",
                    values={
                        "id": "federated-role",
                        "name": "federated-role",
                        "arn": "arn:aws:iam::111122223333:role/federated-role",
                        "assume_role_policy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "sts:AssumeRoleWithSAML",
                                    "Principal": {"Federated": "arn:aws:iam::111122223333:saml-provider/CorpSSO"},
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": "sts:AssumeRole",
                                    "Principal": {"Service": "lambda.amazonaws.com"},
                                },
                            ],
                        },
                    },
                )
            ]
        )
        role = inventory.get_by_address("aws_iam_role.federated")

        self.assertIsNotNone(role)
        self.assertEqual(
            role.metadata.get("trust_statements"),
            [
                {
                    "principals": ["arn:aws:iam::111122223333:saml-provider/CorpSSO"],
                    "principal_entries": [
                        {
                            "kind": "Federated",
                            "value": "arn:aws:iam::111122223333:saml-provider/CorpSSO",
                        }
                    ],
                    "narrowing_condition_keys": [],
                    "narrowing_conditions": [],
                    "has_narrowing_conditions": False,
                },
                {
                    "principals": ["lambda.amazonaws.com"],
                    "principal_entries": [{"kind": "Service", "value": "lambda.amazonaws.com"}],
                    "narrowing_condition_keys": [],
                    "narrowing_conditions": [],
                    "has_narrowing_conditions": False,
                },
            ],
        )

    def test_normalizer_extracts_federated_trust_narrowing_condition_keys(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                TerraformResource(
                    address="aws_iam_role.federated",
                    mode="managed",
                    resource_type="aws_iam_role",
                    name="federated",
                    provider_name="registry.terraform.io/hashicorp/aws",
                    values={
                        "id": "federated-role",
                        "name": "federated-role",
                        "arn": "arn:aws:iam::111122223333:role/federated-role",
                        "assume_role_policy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "sts:AssumeRoleWithSAML",
                                    "Principal": {"Federated": "arn:aws:iam::111122223333:saml-provider/CorpSSO"},
                                    "Condition": {
                                        "StringEquals": {
                                            "SAML:aud": "https://signin.aws.amazon.com/saml",
                                            "SAML:sub": "alice@example.com",
                                        }
                                    },
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": "sts:AssumeRoleWithWebIdentity",
                                    "Principal": {
                                        "Federated": (
                                            "arn:aws:iam::111122223333:"
                                            "oidc-provider/token.actions.githubusercontent.com"
                                        )
                                    },
                                    "Condition": {
                                        "StringEquals": {
                                            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                                            "aws:PrincipalArn": "arn:aws:iam::111122223333:role/ignored",
                                        },
                                        "StringLike": {"token.actions.githubusercontent.com:sub": "repo:example/app:*"},
                                    },
                                },
                            ],
                        },
                    },
                )
            ]
        )
        role = inventory.get_by_address("aws_iam_role.federated")

        self.assertIsNotNone(role)
        trust_statements = role.metadata.get("trust_statements")
        self.assertEqual(trust_statements[0]["narrowing_condition_keys"], ["SAML:aud"])
        self.assertEqual(
            trust_statements[0]["narrowing_conditions"],
            [
                {
                    "operator": "StringEquals",
                    "key": "SAML:aud",
                    "values": ["https://signin.aws.amazon.com/saml"],
                }
            ],
        )
        self.assertEqual(
            trust_statements[1]["narrowing_condition_keys"],
            [
                "token.actions.githubusercontent.com:aud",
                "token.actions.githubusercontent.com:sub",
            ],
        )
        self.assertEqual(
            trust_statements[1]["narrowing_conditions"],
            [
                {
                    "operator": "StringEquals",
                    "key": "token.actions.githubusercontent.com:aud",
                    "values": ["sts.amazonaws.com"],
                },
                {
                    "operator": "StringLike",
                    "key": "token.actions.githubusercontent.com:sub",
                    "values": ["repo:example/app:*"],
                },
            ],
        )

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
                    "principal_entries": [{"kind": "Service", "value": "lambda.amazonaws.com"}],
                    "narrowing_condition_keys": [],
                    "narrowing_conditions": [],
                    "has_narrowing_conditions": False,
                },
                {
                    "principals": ["arn:aws:iam::444455556666:role/deployer"],
                    "principal_entries": [{"kind": "AWS", "value": "arn:aws:iam::444455556666:role/deployer"}],
                    "narrowing_condition_keys": [
                        "aws:SourceAccount",
                        "aws:SourceArn",
                        "sts:ExternalId",
                    ],
                    "narrowing_conditions": [
                        {
                            "operator": "ArnLike",
                            "key": "aws:SourceArn",
                            "values": ["arn:aws:codebuild:us-east-1:444455556666:project/release-*"],
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
                    "principal_entries": [{"kind": "AWS", "value": "arn:aws:iam::444455556666:role/deployer"}],
                    "narrowing_condition_keys": [
                        "aws:SourceArn",
                        "sts:ExternalId",
                    ],
                    "narrowing_conditions": [
                        {
                            "operator": "ArnLike",
                            "key": "aws:SourceArn",
                            "values": ["arn:aws:codebuild:us-east-1:444455556666:project/release-*"],
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


if __name__ == "__main__":
    unittest.main()
