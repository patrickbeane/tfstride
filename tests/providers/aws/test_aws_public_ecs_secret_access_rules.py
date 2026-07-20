from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_ecs_secret_access_paths import (
    _ACCOUNT_ID,
    _EXECUTION_ROLE_ARN,
    _SECRET_ARN,
    _resource,
    _role,
    _role_policy_attachment,
    _statement,
    _task_definition,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_RULE_ID = "aws-public-ecs-secret-access"


def _load_balancer(*, internal: bool = False) -> TerraformResource:
    return _resource(
        "aws_lb",
        "public",
        {
            "name": "public",
            "arn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/public/abc",
            "internal": internal,
            "load_balancer_type": "application",
        },
    )


def _service(task_definition: str = "orders:1") -> TerraformResource:
    return _resource(
        "aws_ecs_service",
        "orders",
        {
            "name": "orders",
            "task_definition": task_definition,
            "load_balancer": [
                {
                    "elb_name": "public",
                    "container_name": "orders",
                    "container_port": 8080,
                }
            ],
        },
    )


def _secret() -> TerraformResource:
    return _resource(
        "aws_secretsmanager_secret",
        "orders",
        {
            "name": "orders-db",
            "arn": _SECRET_ARN,
        },
    )


def _evaluate(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )
    return inventory, boundaries, findings


class AwsPublicEcsSecretAccessRuleTests(unittest.TestCase):
    def test_rule_id_is_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_internet_facing_service_with_allowed_secret_path_is_reported(self) -> None:
        _, _, findings = _evaluate(
            [
                _load_balancer(),
                _secret(),
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [_statement("Allow", "secretsmanager:GetSecretValue", _SECRET_ARN)],
                ),
                _task_definition(task_role_arn=None),
                _service(),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(
            finding.affected_resources,
            [
                "aws_lb.public",
                "aws_ecs_service.orders",
                "aws_ecs_task_definition.orders",
                "aws_iam_role.execution",
                "aws_secretsmanager_secret.orders",
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->aws_lb.public",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["network_path"],
            [
                "internet reaches aws_lb.public",
                "aws_lb.public fronts aws_ecs_service.orders",
            ],
        )
        self.assertEqual(
            evidence["task_definitions"],
            ["address=aws_ecs_task_definition.orders"],
        )
        self.assertIn("address=aws_iam_role.execution", evidence["execution_roles"][0])
        self.assertIn(f"secret_arn={_SECRET_ARN}", evidence["secret_access_paths"][0])
        self.assertIn("access_state=allowed", evidence["secret_access_paths"][0])
        self.assertIn("explicit_deny=false", evidence["secret_access_paths"][0])
        self.assertIn("conditions=none", evidence["secret_access_paths"][0])
        self.assertIn("does not mean that the Secrets Manager secret itself is public", finding.rationale)

    def test_non_deterministic_or_non_public_paths_remain_quiet(self) -> None:
        external_policy_arn = "arn:aws:iam::aws:policy/ExternalSecretAccess"
        cases = {
            "explicit deny": [
                _load_balancer(),
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [
                        _statement("Allow", "secretsmanager:GetSecretValue", _SECRET_ARN),
                        _statement("Deny", "secretsmanager:GetSecretValue", _SECRET_ARN),
                    ],
                ),
                _task_definition(task_role_arn=None),
                _service(),
            ],
            "conditional allow": [
                _load_balancer(),
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "secretsmanager:GetSecretValue",
                            _SECRET_ARN,
                            condition={"StringEquals": {"aws:PrincipalAccount": _ACCOUNT_ID}},
                        )
                    ],
                ),
                _task_definition(task_role_arn=None),
                _service(),
            ],
            "incomplete policy": [
                _load_balancer(),
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [_statement("Allow", "secretsmanager:GetSecretValue", _SECRET_ARN)],
                ),
                _role_policy_attachment(_EXECUTION_ROLE_ARN, external_policy_arn),
                _task_definition(task_role_arn=None),
                _service(),
            ],
            "unresolved execution role": [
                _load_balancer(),
                _task_definition(task_role_arn=None),
                _service(),
            ],
            "unresolved task definition": [
                _load_balancer(),
                _service("missing:1"),
            ],
            "internal load balancer": [
                _load_balancer(internal=True),
                _role(
                    "execution",
                    _EXECUTION_ROLE_ARN,
                    [_statement("Allow", "secretsmanager:GetSecretValue", _SECRET_ARN)],
                ),
                _task_definition(task_role_arn=None),
                _service(),
            ],
        }

        for case, resources in cases.items():
            with self.subTest(case=case):
                _, _, findings = _evaluate(resources)
                self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
