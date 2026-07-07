from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer

_RULE_ID = "aws-iam-privileged-role-assignment"
_ROLE_ARN = "arn:aws:iam::111122223333:role/app"
_POLICY_ARN = "arn:aws:iam::111122223333:policy/admin"


def _resource(address: str, resource_type: str, values: dict[str, Any]) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
    )


def _role(*, inline_policy: dict[str, Any] | None = None) -> TerraformResource:
    values: dict[str, Any] = {
        "name": "app-role",
        "arn": _ROLE_ARN,
        "assume_role_policy": json.dumps({"Statement": []}),
    }
    if inline_policy is not None:
        values["inline_policy"] = [{"name": "inline-admin", "policy": json.dumps(inline_policy)}]
    return _resource("aws_iam_role.app", "aws_iam_role", values)


def _policy(actions: list[str], *, resources: list[str] | None = None) -> TerraformResource:
    return _resource(
        "aws_iam_policy.admin",
        "aws_iam_policy",
        {
            "name": "admin-policy",
            "arn": _POLICY_ARN,
            "policy": json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": actions,
                            "Resource": resources or ["*"],
                        }
                    ]
                }
            ),
        },
    )


def _attachment(policy_arn: str = _POLICY_ARN) -> TerraformResource:
    return _resource(
        "aws_iam_role_policy_attachment.app_admin",
        "aws_iam_role_policy_attachment",
        {
            "role": "app-role",
            "policy_arn": policy_arn,
        },
    )


def _findings(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsIamAssignmentRuleTests(unittest.TestCase):
    def test_attached_policy_with_privileged_iam_actions_is_detected(self) -> None:
        findings = _findings(
            [
                _role(),
                _policy(["iam:AttachRolePolicy", "iam:PassRole"]),
                _attachment(),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.affected_resources, ["aws_iam_role.app", "aws_iam_policy.admin"])
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["iam_role"],
            [
                "address=aws_iam_role.app",
                "type=aws_iam_role",
                f"arn={_ROLE_ARN}",
                "identifier=app-role",
            ],
        )
        self.assertEqual(
            evidence["privilege_categories"],
            ["iam-admin", "privilege-escalation", "role-assignment"],
        )
        self.assertEqual(evidence["permission_patterns"], ["iam:AttachRolePolicy", "iam:PassRole"])
        self.assertEqual(evidence["grant_scopes"], ["scope_kind=account; scope_value=*"])
        self.assertEqual(evidence["grant_confidence"], ["high"])
        self.assertEqual(
            evidence["attached_policies"],
            [
                f"attached_policy_arn={_POLICY_ARN}",
                "attached_policy_address=aws_iam_policy.admin",
            ],
        )

    def test_inline_full_admin_policy_is_detected_without_policy_attachment(self) -> None:
        findings = _findings(
            [
                _role(
                    inline_policy={
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*",
                            }
                        ]
                    }
                )
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = _evidence_by_key(findings[0])
        self.assertEqual(evidence["privilege_categories"], ["full-admin"])
        self.assertEqual(evidence["permission_patterns"], ["*"])
        self.assertEqual(evidence["inline_policy_sources"], ["inline_policy_name=inline-admin"])

    def test_read_only_iam_policy_stays_quiet(self) -> None:
        findings = _findings(
            [
                _role(),
                _policy(["iam:GetRole", "s3:GetObject"], resources=["arn:aws:s3:::logs/*"]),
                _attachment(),
            ]
        )

        self.assertEqual(findings, [])

    def test_unresolved_policy_attachment_does_not_overclaim_privilege(self) -> None:
        findings = _findings(
            [
                _role(),
                _attachment("arn:aws:iam::111122223333:policy/not-in-plan"),
            ]
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
