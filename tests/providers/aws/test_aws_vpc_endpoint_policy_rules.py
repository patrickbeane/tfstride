from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer

_RULE = "aws-vpc-endpoint-policy-broad-access"


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


def _vpc_endpoint(
    name: str,
    service_name: str,
    *,
    endpoint_type: str = "Interface",
    policy: dict[str, Any] | None = None,
    unknown_policy: bool = False,
) -> TerraformResource:
    values: dict[str, Any] = {
        "id": f"vpce-{name}",
        "service_name": service_name,
        "vpc_endpoint_type": endpoint_type,
        "vpc_id": "vpc-app",
        "subnet_ids": ["subnet-app"] if endpoint_type == "Interface" else [],
        "route_table_ids": ["rtb-private"] if endpoint_type == "Gateway" else [],
        "private_dns_enabled": endpoint_type == "Interface",
    }
    if policy is not None:
        values["policy"] = json.dumps(policy)
    return _resource(
        f"aws_vpc_endpoint.{name}",
        "aws_vpc_endpoint",
        values,
        unknown_values={"policy": True} if unknown_policy else None,
    )


def _policy_statement(
    *,
    principals: str | list[str] = "arn:aws:iam::111122223333:role/app",
    actions: str | list[str],
    resources: str | list[str],
) -> dict[str, Any]:
    return {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": principals},
                "Action": actions,
                "Resource": resources,
            }
        ]
    }


def _findings(*resources: TerraformResource):
    inventory = AwsNormalizer().normalize(list(resources))
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE})),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsVpcEndpointPolicyRuleTests(unittest.TestCase):
    def test_absent_s3_endpoint_policy_is_flagged_as_default_broad_policy(self) -> None:
        findings = _findings(
            _vpc_endpoint(
                "s3",
                "com.amazonaws.us-east-1.s3",
                endpoint_type="Gateway",
            )
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertIn("does not imply any S3 bucket, secret, or key is public", finding.rationale)
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["vpc_endpoint"],
            [
                "address=aws_vpc_endpoint.s3",
                "service_family=s3",
                "service_name=com.amazonaws.us-east-1.s3",
                "endpoint_type=Gateway",
                "vpc_id=vpc-app",
                "endpoint_id=vpce-s3",
            ],
        )
        self.assertEqual(
            evidence["policy_posture"],
            [
                "policy_document=absent_or_default",
                "default endpoint policy allows all principals, actions, and resources for the service",
            ],
        )
        self.assertNotIn("policy_statements", evidence)

    def test_secretsmanager_endpoint_policy_with_wildcard_principal_and_action_is_flagged(self) -> None:
        findings = _findings(
            _vpc_endpoint(
                "secrets",
                "com.amazonaws.us-east-1.secretsmanager",
                policy=_policy_statement(
                    principals="*",
                    actions="secretsmanager:*",
                    resources="arn:aws:secretsmanager:us-east-1:111122223333:secret:api",
                ),
            )
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["policy_posture"], ["principal=*", "action=secretsmanager:*"])
        self.assertEqual(
            evidence["policy_statements"],
            ["Allow actions=[secretsmanager:*] resources=[arn:aws:secretsmanager:us-east-1:111122223333:secret:api]"],
        )

    def test_kms_endpoint_policy_with_service_wide_resource_is_flagged(self) -> None:
        findings = _findings(
            _vpc_endpoint(
                "kms",
                "com.amazonaws.us-east-1.kms",
                policy=_policy_statement(
                    actions="kms:Decrypt",
                    resources="arn:aws:kms:*:*:key/*",
                ),
            )
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["policy_posture"], ["resource=arn:aws:kms:*:*:key/*"])

    def test_narrow_s3_endpoint_policy_is_quiet(self) -> None:
        findings = _findings(
            _vpc_endpoint(
                "s3",
                "com.amazonaws.us-east-1.s3",
                endpoint_type="Gateway",
                policy=_policy_statement(
                    actions=["s3:GetObject"],
                    resources=["arn:aws:s3:::customer-data/*"],
                ),
            )
        )

        self.assertEqual(findings, [])

    def test_unknown_endpoint_policy_is_not_overclaimed(self) -> None:
        findings = _findings(
            _vpc_endpoint(
                "kms",
                "com.amazonaws.us-east-1.kms",
                unknown_policy=True,
            )
        )

        self.assertEqual(findings, [])

    def test_unsupported_endpoint_service_is_ignored_even_with_broad_policy(self) -> None:
        findings = _findings(
            _vpc_endpoint(
                "ecr",
                "com.amazonaws.us-east-1.ecr.api",
                policy=_policy_statement(
                    principals="*",
                    actions="*",
                    resources="*",
                ),
            )
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
