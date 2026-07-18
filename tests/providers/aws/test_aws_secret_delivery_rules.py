from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS

_RULE_ID = "aws-ecs-sensitive-environment-value-inline"


def _task_definition(
    definition: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address="aws_ecs_task_definition.orders",
        mode="managed",
        resource_type="aws_ecs_task_definition",
        name="orders",
        provider_name="registry.terraform.io/hashicorp/aws",
        values={
            "family": "orders",
            "revision": 4,
            "container_definitions": json.dumps([definition]),
        },
        unknown_values=unknown_values or {},
    )


def _evaluate(resource: TerraformResource):
    return StrideRuleEngine().evaluate(
        AwsNormalizer().normalize([resource]),
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AwsSecretDeliveryRuleTests(unittest.TestCase):
    def test_rule_id_is_registered(self) -> None:
        registered = {rule_id for group in AWS_RULE_GROUP_IDS for rule_id in group}

        self.assertIn(_RULE_ID, registered)

    def test_sensitive_literal_environment_value_is_reported_without_its_value(self) -> None:
        literal = "do-not-leak-this-password"
        findings = _evaluate(
            _task_definition(
                {
                    "name": "orders",
                    "environment": [{"name": "DB_PASSWORD", "value": literal}],
                }
            )
        )

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["aws_ecs_task_definition.orders"])
        evidence = _evidence_by_key(finding)
        self.assertEqual(
            evidence["sensitive_setting"],
            [
                "path=container_definitions[0].environment[0].value; "
                "setting=db_password; category=password; value=<redacted>"
            ],
        )
        self.assertEqual(
            evidence["delivery_posture"],
            ["source=aws_ecs_task_definition", "container_name=orders", "state=literal"],
        )
        self.assertNotIn(literal, repr(finding))

    def test_provider_native_secret_references_remain_quiet_without_modeled_targets(self) -> None:
        references = (
            "arn:aws:secretsmanager:us-east-1:111122223333:secret:orders-db-abc123",
            "$" + "{aws_secretsmanager_secret.orders.arn}",
            "arn:aws:ssm:us-east-1:111122223333:parameter/orders/database-password",
        )

        for reference in references:
            with self.subTest(reference=reference):
                findings = _evaluate(
                    _task_definition(
                        {
                            "name": "orders",
                            "secrets": [{"name": "DB_PASSWORD", "valueFrom": reference}],
                        }
                    )
                )
                self.assertEqual(findings, [])

    def test_unknown_sensitive_value_remains_quiet(self) -> None:
        findings = _evaluate(
            _task_definition(
                {
                    "name": "orders",
                    "environment": [{"name": "API_KEY", "value": "unknown"}],
                },
                unknown_values={"container_definitions": [{"environment": [{"value": True}]}]},
            )
        )

        self.assertEqual(findings, [])

    def test_non_sensitive_literal_setting_remains_quiet(self) -> None:
        findings = _evaluate(
            _task_definition(
                {
                    "name": "orders",
                    "environment": [
                        {"name": "LOG_LEVEL", "value": "debug"},
                        {"name": "SECRET_ARN", "value": "not-secret-material"},
                    ],
                }
            )
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
