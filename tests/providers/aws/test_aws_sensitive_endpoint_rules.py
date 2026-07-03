from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer

_SECRETS_RULE = "aws-workload-secretsmanager-vpc-endpoint-missing"
_KMS_RULE = "aws-workload-kms-vpc-endpoint-missing"
_S3_RULE = "aws-workload-s3-vpc-endpoint-missing"
_ALL_RULES = (_SECRETS_RULE, _KMS_RULE, _S3_RULE)
_ROLE_ARN = "arn:aws:iam::111122223333:role/app"


def _resource(
    address: str,
    resource_type: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


def _subnet() -> TerraformResource:
    return _resource(
        "aws_subnet.app",
        "aws_subnet",
        {
            "id": "subnet-app",
            "vpc_id": "vpc-app",
            "cidr_block": "10.0.1.0/24",
        },
    )


def _lambda_function(*, vpc_enabled: bool = True) -> TerraformResource:
    values: dict[str, Any] = {
        "id": "worker",
        "function_name": "worker",
        "arn": "arn:aws:lambda:us-east-1:111122223333:function:worker",
        "role": _ROLE_ARN,
    }
    if vpc_enabled:
        values["vpc_config"] = [{"subnet_ids": ["subnet-app"], "security_group_ids": ["sg-app"]}]
    return _resource("aws_lambda_function.worker", "aws_lambda_function", values)


def _role(actions: list[str], *, resources: list[str] | None = None) -> TerraformResource:
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": actions,
                "Resource": resources or ["*"],
            }
        ]
    }
    return _resource(
        "aws_iam_role.app",
        "aws_iam_role",
        {
            "name": "app",
            "arn": _ROLE_ARN,
            "assume_role_policy": json.dumps({"Statement": []}),
            "inline_policy": [{"name": "service-access", "policy": json.dumps(policy)}],
        },
    )


def _vpc_endpoint(
    name: str,
    service_name: str | None,
    *,
    endpoint_type: str = "Interface",
    unknown_service_name: bool = False,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": f"vpce-{name}",
        "vpc_endpoint_type": endpoint_type,
        "vpc_id": "vpc-app",
        "subnet_ids": ["subnet-app"] if endpoint_type == "Interface" else [],
        "route_table_ids": ["rtb-private"] if endpoint_type == "Gateway" else [],
        "private_dns_enabled": endpoint_type == "Interface",
    }
    if service_name is not None:
        values["service_name"] = service_name
    return _resource(
        f"aws_vpc_endpoint.{name}",
        "aws_vpc_endpoint",
        values,
        unknown_values={"service_name": True} if unknown_service_name else None,
    )


def _findings(resources: list[TerraformResource], *rule_ids: str):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsSensitiveEndpointRuleTests(unittest.TestCase):
    def test_secretsmanager_dependency_without_interface_endpoint_is_detected(self) -> None:
        findings = _findings(
            [
                _subnet(),
                _lambda_function(),
                _role(
                    ["secretsmanager:GetSecretValue"],
                    resources=["arn:aws:secretsmanager:us-east-1:111122223333:secret:api"],
                ),
            ],
            _SECRETS_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_SECRETS_RULE])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["aws_lambda_function.worker", "aws_iam_role.app"])
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["target_workload"],
            [
                "address=aws_lambda_function.worker",
                "type=aws_lambda_function",
                "vpc_id=vpc-app",
                "subnet_ids=[subnet-app]",
                "security_group_ids=[sg-app]",
            ],
        )
        self.assertEqual(
            evidence["sensitive_service_dependency"],
            [
                "service=secretsmanager",
                "role=aws_iam_role.app",
                "actions=[secretsmanager:GetSecretValue]",
                "resources=[arn:aws:secretsmanager:us-east-1:111122223333:secret:api]",
            ],
        )
        self.assertEqual(
            evidence["vpc_endpoint_coverage"],
            [
                "vpc_id=vpc-app",
                "service=secretsmanager",
                "expected_endpoint_type=interface",
                "vpc_endpoint_coverage=missing",
            ],
        )

    def test_secretsmanager_interface_endpoint_suppresses_finding(self) -> None:
        findings = _findings(
            [
                _subnet(),
                _lambda_function(),
                _role(["secretsmanager:GetSecretValue"]),
                _vpc_endpoint("secrets", "com.amazonaws.us-east-1.secretsmanager"),
            ],
            _SECRETS_RULE,
        )

        self.assertEqual(findings, [])

    def test_kms_dependency_without_interface_endpoint_is_detected(self) -> None:
        findings = _findings(
            [
                _subnet(),
                _lambda_function(),
                _role(["kms:Decrypt", "kms:GenerateDataKey"]),
            ],
            _KMS_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_KMS_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["sensitive_service_dependency"],
            [
                "service=kms",
                "role=aws_iam_role.app",
                "actions=[kms:Decrypt, kms:GenerateDataKey]",
                "resources=[*]",
            ],
        )
        self.assertIn("expected_endpoint_type=interface", evidence["vpc_endpoint_coverage"])

    def test_kms_interface_endpoint_suppresses_finding(self) -> None:
        findings = _findings(
            [
                _subnet(),
                _lambda_function(),
                _role(["kms:Decrypt"]),
                _vpc_endpoint("kms", "com.amazonaws.us-east-1.kms"),
            ],
            _KMS_RULE,
        )

        self.assertEqual(findings, [])

    def test_s3_dependency_without_vpc_endpoint_uses_egress_path_wording(self) -> None:
        findings = _findings(
            [
                _subnet(),
                _lambda_function(),
                _role(["s3:GetObject"], resources=["arn:aws:s3:::customer-data/*"]),
            ],
            _S3_RULE,
        )

        self.assertEqual([finding.rule_id for finding in findings], [_S3_RULE])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertIn("S3 access may therefore depend on public AWS service endpoints", finding.rationale)
        self.assertIn("does not imply the bucket itself is public", finding.rationale)
        self.assertNotIn("bucket is public", finding.rationale.lower())
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["vpc_endpoint_coverage"],
            [
                "vpc_id=vpc-app",
                "service=s3",
                "expected_endpoint_type=gateway_or_interface",
                "vpc_endpoint_coverage=missing",
            ],
        )

    def test_s3_gateway_endpoint_suppresses_finding(self) -> None:
        findings = _findings(
            [
                _subnet(),
                _lambda_function(),
                _role(["s3:GetObject"]),
                _vpc_endpoint("s3", "com.amazonaws.us-east-1.s3", endpoint_type="Gateway"),
            ],
            _S3_RULE,
        )

        self.assertEqual(findings, [])

    def test_workload_without_vpc_context_is_not_flagged(self) -> None:
        findings = _findings(
            [
                _lambda_function(vpc_enabled=False),
                _role(["secretsmanager:GetSecretValue", "kms:Decrypt", "s3:GetObject"]),
            ],
            *_ALL_RULES,
        )

        self.assertEqual(findings, [])

    def test_unresolved_endpoint_service_name_suppresses_missing_endpoint_overclaim(self) -> None:
        findings = _findings(
            [
                _subnet(),
                _lambda_function(),
                _role(["secretsmanager:GetSecretValue"]),
                _vpc_endpoint("computed", None, unknown_service_name=True),
            ],
            _SECRETS_RULE,
        )

        self.assertEqual(findings, [])

    def test_global_wildcard_permission_is_not_treated_as_deterministic_service_dependency(self) -> None:
        findings = _findings(
            [
                _subnet(),
                _lambda_function(),
                _role(["*"]),
            ],
            *_ALL_RULES,
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
