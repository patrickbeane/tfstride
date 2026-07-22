from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _BUCKET_ARN,
    _EXECUTION_ROLE_ARN,
    _TASK_ROLE_ARN,
    _bucket,
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

_RULE_ID = "aws-public-ecs-s3-mutation-access"


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


def _evaluate(resources: list[TerraformResource]):
    inventory = AwsNormalizer().normalize(resources)
    boundaries = detect_trust_boundaries(inventory)
    findings = StrideRuleEngine().evaluate(
        inventory,
        boundaries,
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )
    return inventory, boundaries, findings


class AwsPublicEcsS3MutationRuleTests(unittest.TestCase):
    def test_rule_id_is_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_public_service_with_exact_task_role_mutation_access_is_reported(self) -> None:
        _, _, findings = _evaluate(
            [
                _load_balancer(),
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            ["s3:PutObject", "s3:DeleteObject"],
                            f"{_BUCKET_ARN}/*",
                        ),
                        _statement("Allow", "s3:PutBucketPolicy", _BUCKET_ARN),
                    ],
                ),
                _task_definition(execution_role_arn=None),
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
                "aws_iam_role.orders_task",
                "aws_s3_bucket.orders",
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
        self.assertIn("address=aws_iam_role.orders_task", evidence["task_roles"][0])
        self.assertIn("role_kind=ecs_task_role", evidence["task_roles"][0])
        self.assertIn("bucket_address=aws_s3_bucket.orders", evidence["s3_mutation_paths"][0])
        self.assertIn(f"bucket_arn={_BUCKET_ARN}", evidence["s3_mutation_paths"][0])
        self.assertIn("mutation_classes=write,delete,administrative", evidence["s3_mutation_paths"][0])
        self.assertIn("s3:PutObject", evidence["s3_mutation_paths"][0])
        self.assertIn("s3:DeleteObject", evidence["s3_mutation_paths"][0])
        self.assertIn("s3:PutBucketPolicy", evidence["s3_mutation_paths"][0])
        self.assertIn("access_state=allowed", evidence["s3_mutation_paths"][0])
        self.assertIn("does not mean that the S3 bucket itself is public", finding.rationale)

    def test_unrelated_read_deny_does_not_hide_write_access(self) -> None:
        _, _, findings = _evaluate(
            [
                _load_balancer(),
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/*"),
                        _statement("Deny", "s3:GetObject", f"{_BUCKET_ARN}/*"),
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ]
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertIn("actions=s3:PutObject", evidence["s3_mutation_paths"][0])
        self.assertIn("denied_actions=s3:GetObject", evidence["s3_mutation_paths"][0])

    def test_non_deterministic_non_mutating_or_non_public_paths_remain_quiet(self) -> None:
        external_policy_arn = "arn:aws:iam::aws:policy/ExternalS3Access"
        cases = {
            "read only": [
                _load_balancer(),
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "s3:GetObject", f"{_BUCKET_ARN}/*")],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "comparable explicit deny": [
                _load_balancer(),
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/*"),
                        _statement("Deny", "s3:PutObject", f"{_BUCKET_ARN}/*"),
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "conditional allow": [
                _load_balancer(),
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement(
                            "Allow",
                            "s3:PutObject",
                            f"{_BUCKET_ARN}/*",
                            condition={"StringEquals": {"aws:SourceVpc": "vpc-123"}},
                        )
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "conditional deny": [
                _load_balancer(),
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [
                        _statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/*"),
                        _statement(
                            "Deny",
                            "s3:PutObject",
                            f"{_BUCKET_ARN}/*",
                            condition={"StringNotEquals": {"aws:SourceVpc": "vpc-123"}},
                        ),
                    ],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "incomplete task role policy": [
                _load_balancer(),
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/*")],
                ),
                _role_policy_attachment(_TASK_ROLE_ARN, external_policy_arn),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "execution role only": [
                _load_balancer(),
                _bucket(),
                _role("orders_task", _TASK_ROLE_ARN, []),
                _role(
                    "orders_execution",
                    _EXECUTION_ROLE_ARN,
                    [_statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/*")],
                ),
                _task_definition(),
                _service(),
            ],
            "non-exact bucket resource": [
                _load_balancer(),
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "s3:PutObject", "arn:aws:s3:::orders-*/*")],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "internal load balancer": [
                _load_balancer(internal=True),
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/*")],
                ),
                _task_definition(execution_role_arn=None),
                _service(),
            ],
            "unresolved task definition": [
                _load_balancer(),
                _bucket(),
                _role(
                    "orders_task",
                    _TASK_ROLE_ARN,
                    [_statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/*")],
                ),
                _service("missing:1"),
            ],
        }

        for case, resources in cases.items():
            with self.subTest(case=case):
                _, _, findings = _evaluate(resources)
                self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
