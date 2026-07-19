from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_RULE_ID = "aws-ecs-secret-access-blast-radius"
_ACCOUNT_ID = "111122223333"
_REGION = "us-east-1"
_EXECUTION_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/execution"
_TASK_ROLE_ARN = f"arn:aws:iam::{_ACCOUNT_ID}:role/task"
_SECRET_ARN = f"arn:aws:secretsmanager:{_REGION}:{_ACCOUNT_ID}:secret:orders-db-abc123"
_OTHER_SECRET_ARN = f"arn:aws:secretsmanager:{_REGION}:{_ACCOUNT_ID}:secret:payments-db-def456"


def _resource(resource_type: str, name: str, values: dict[str, Any]) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
    )


def _statement(
    effect: str,
    actions: str | list[str],
    resources: str | list[str],
    *,
    condition: dict[str, Any] | None = None,
) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "Effect": effect,
        "Action": actions,
        "Resource": resources,
    }
    if condition is not None:
        statement["Condition"] = condition
    return statement


def _role(name: str, arn: str, statements: list[dict[str, Any]] | None = None) -> TerraformResource:
    values: dict[str, Any] = {"name": name, "arn": arn}
    if statements is not None:
        values["inline_policy"] = [
            {
                "name": "secret-access",
                "policy": json.dumps({"Version": "2012-10-17", "Statement": statements}),
            }
        ]
    return _resource("aws_iam_role", name, values)


def _role_policy_attachment(role_reference: str, policy_arn: str) -> TerraformResource:
    return _resource(
        "aws_iam_role_policy_attachment",
        "external",
        {"role": role_reference, "policy_arn": policy_arn},
    )


def _task_definition(
    secret_arns: tuple[str, ...] = (_SECRET_ARN,),
    *,
    task_role_arn: str | None = _TASK_ROLE_ARN,
    execution_role_arn: str = _EXECUTION_ROLE_ARN,
) -> TerraformResource:
    secrets = [
        {
            "name": f"SECRET_{index}",
            "valueFrom": secret_arn,
        }
        for index, secret_arn in enumerate(secret_arns)
    ]
    values: dict[str, Any] = {
        "family": "orders",
        "revision": 1,
        "execution_role_arn": execution_role_arn,
        "container_definitions": json.dumps([{"name": "orders", "secrets": secrets}]),
    }
    if task_role_arn is not None:
        values["task_role_arn"] = task_role_arn
    return _resource("aws_ecs_task_definition", "orders", values)


def _evaluate(resources: list[TerraformResource]):
    return StrideRuleEngine().evaluate(
        AwsNormalizer().normalize(resources),
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsEcsSecretAccessBlastRadiusRuleTests(unittest.TestCase):
    def test_rule_id_is_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_wildcard_get_secret_value_scope_is_reported(self) -> None:
        findings = _evaluate(
            [
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [_statement("Allow", "secretsmanager:GetSecretValue", "*")],
                ),
                _task_definition(task_role_arn=None),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            ["aws_ecs_task_definition.orders", "aws_iam_role.execution"],
        )
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["execution_role"],
            [
                "address=aws_iam_role.execution",
                "role_kind=ecs_task_execution_role",
                "credential_context=ecs_agent_secret_delivery",
                "role_policy_complete=true",
                f"arn={_EXECUTION_ROLE_ARN}",
            ],
        )
        self.assertEqual(evidence["consumed_secrets"][0], f"secret_arn={_SECRET_ARN}")
        self.assertEqual(
            evidence["broader_policy_grants"],
            ["reasons=wildcard_resource_scope; actions=secretsmanager:GetSecretValue; resources=*"],
        )

    def test_wildcard_secrets_manager_action_on_consumed_secret_is_reported(self) -> None:
        findings = _evaluate(
            [
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [_statement("Allow", "secretsmanager:*", _SECRET_ARN)],
                ),
                _task_definition(task_role_arn=None),
            ]
        )

        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["broader_policy_grants"],
            [f"reasons=broad_action_scope; actions=secretsmanager:*; resources={_SECRET_ARN}"],
        )

    def test_get_secret_value_grant_for_unconsumed_secret_is_reported(self) -> None:
        findings = _evaluate(
            [
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "secretsmanager:GetSecretValue",
                            [_SECRET_ARN, _OTHER_SECRET_ARN],
                        )
                    ],
                ),
                _task_definition(task_role_arn=None),
            ]
        )

        evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            evidence["broader_policy_grants"],
            [
                "reasons=unconsumed_secret_scope; "
                f"actions=secretsmanager:GetSecretValue; resources={_SECRET_ARN},{_OTHER_SECRET_ARN}"
            ],
        )

    def test_exact_grants_for_all_consumed_secrets_remain_quiet(self) -> None:
        findings = _evaluate(
            [
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "secretsmanager:GetSecretValue",
                            [_SECRET_ARN, _OTHER_SECRET_ARN],
                        )
                    ],
                ),
                _task_definition((_SECRET_ARN, _OTHER_SECRET_ARN), task_role_arn=None),
            ]
        )

        self.assertEqual(findings, [])

    def test_task_role_breadth_does_not_become_delivery_role_breadth(self) -> None:
        findings = _evaluate(
            [
                _role(
                    "task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "secretsmanager:*", "*")],
                ),
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [_statement("Allow", "secretsmanager:GetSecretValue", _SECRET_ARN)],
                ),
                _task_definition(),
            ]
        )

        self.assertEqual(findings, [])

    def test_explicit_deny_keeps_broad_allow_quiet(self) -> None:
        findings = _evaluate(
            [
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [
                        _statement("Allow", "secretsmanager:GetSecretValue", "*"),
                        _statement("Deny", "secretsmanager:GetSecretValue", _SECRET_ARN),
                    ],
                ),
                _task_definition(task_role_arn=None),
            ]
        )

        self.assertEqual(findings, [])

    def test_conditional_broad_allow_remains_quiet(self) -> None:
        findings = _evaluate(
            [
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "secretsmanager:GetSecretValue",
                            "*",
                            condition={"StringEquals": {"aws:PrincipalAccount": _ACCOUNT_ID}},
                        )
                    ],
                ),
                _task_definition(task_role_arn=None),
            ]
        )

        self.assertEqual(findings, [])

    def test_unresolved_attached_policy_keeps_blast_radius_unknown(self) -> None:
        findings = _evaluate(
            [
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [_statement("Allow", "secretsmanager:GetSecretValue", "*")],
                ),
                _role_policy_attachment(
                    _EXECUTION_ROLE_ARN,
                    "arn:aws:iam::aws:policy/ExternalSecretAccess",
                ),
                _task_definition(task_role_arn=None),
            ]
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
