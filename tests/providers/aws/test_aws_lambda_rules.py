from __future__ import annotations

import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer

_RULE_ID = "aws-lambda-public-invocation"


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


def _lambda_function(name: str = "worker") -> TerraformResource:
    return _resource(
        f"aws_lambda_function.{name}",
        "aws_lambda_function",
        {
            "id": name,
            "function_name": name,
            "arn": f"arn:aws:lambda:us-east-1:111122223333:function:{name}",
        },
    )


def _lambda_function_url(
    *,
    authorization_type: str | None = "NONE",
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    values: dict[str, Any] = {
        "function_name": "worker",
        "function_url": "https://abc.lambda-url.us-east-1.on.aws/",
        "url_id": "abc",
        "cors": [
            {
                "allow_credentials": False,
                "allow_methods": ["GET"],
                "allow_origins": ["https://example.com"],
            }
        ],
    }
    if authorization_type is not None:
        values["authorization_type"] = authorization_type
    return _resource(
        "aws_lambda_function_url.worker",
        "aws_lambda_function_url",
        values,
        unknown_values=unknown_values,
    )


def _lambda_permission(
    *,
    principal: str = "*",
    action: str = "lambda:InvokeFunction",
    source_arn: str | None = None,
) -> TerraformResource:
    values = {
        "id": "invoke",
        "statement_id": "invoke",
        "function_name": "worker",
        "action": action,
        "principal": principal,
    }
    if source_arn is not None:
        values["source_arn"] = source_arn
    return _resource("aws_lambda_permission.invoke", "aws_lambda_permission", values)


def _findings(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


class AwsLambdaRuleTests(unittest.TestCase):
    def test_lambda_function_url_without_authorization_is_detected(self) -> None:
        findings = _findings([_lambda_function_url(authorization_type="NONE")])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, _RULE_ID)
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.affected_resources, ["aws_lambda_function_url.worker"])
        self.assertIsNone(finding.trust_boundary_id)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["target_resource"],
            [
                "address=aws_lambda_function_url.worker",
                "type=aws_lambda_function_url",
                "function_name=worker",
                "function_url=https://abc.lambda-url.us-east-1.on.aws/",
            ],
        )
        self.assertEqual(
            evidence["function_url_posture"],
            [
                "authorization_type=NONE",
                "authorization_type NONE permits unauthenticated function URL invocation",
            ],
        )
        self.assertEqual(
            evidence["cors_evidence"],
            [
                "allow_origins=https://example.com",
                "allow_methods=GET",
                "allow_credentials_state=disabled",
            ],
        )

    def test_lambda_function_url_with_iam_authorization_is_not_flagged(self) -> None:
        self.assertEqual(_findings([_lambda_function_url(authorization_type="AWS_IAM")]), [])

    def test_lambda_function_url_unknown_authorization_is_not_overclaimed(self) -> None:
        self.assertEqual(
            _findings(
                [
                    _lambda_function_url(
                        authorization_type=None,
                        unknown_values={"authorization_type": True},
                    )
                ]
            ),
            [],
        )

    def test_wildcard_lambda_permission_without_source_narrowing_is_detected(self) -> None:
        findings = _findings([_lambda_function(), _lambda_permission()])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, _RULE_ID)
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            ["aws_lambda_function.worker", "aws_lambda_permission.invoke"],
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["target_resource"],
            [
                "address=aws_lambda_function.worker",
                "type=aws_lambda_function",
                "function_name=worker",
                "arn=arn:aws:lambda:us-east-1:111122223333:function:worker",
            ],
        )
        self.assertEqual(
            evidence["public_invocation_policy"],
            [
                "principal=*",
                "narrowing_condition=none",
                "actions=lambda:InvokeFunction",
                "Allow actions=[lambda:InvokeFunction] resources=[worker]",
            ],
        )
        self.assertEqual(evidence["resource_policy_sources"], ["aws_lambda_permission.invoke"])

    def test_lambda_permission_with_source_arn_narrowing_is_not_flagged(self) -> None:
        self.assertEqual(
            _findings(
                [
                    _lambda_function(),
                    _lambda_permission(source_arn="arn:aws:events:us-east-1:111122223333:rule/schedule"),
                ]
            ),
            [],
        )

    def test_lambda_permission_service_principal_is_not_treated_as_public(self) -> None:
        self.assertEqual(
            _findings([_lambda_function(), _lambda_permission(principal="events.amazonaws.com")]),
            [],
        )


if __name__ == "__main__":
    unittest.main()
