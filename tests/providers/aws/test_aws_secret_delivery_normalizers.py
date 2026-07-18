from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.aws.compute_normalizers import normalize_ecs_task_definition
from tfstride.providers.aws.resource_facts import aws_facts


def _resource(definitions: object, *, unknown_values: dict[str, Any] | None = None) -> TerraformResource:
    return TerraformResource(
        address="aws_ecs_task_definition.app",
        mode="managed",
        resource_type="aws_ecs_task_definition",
        name="app",
        provider_name="registry.terraform.io/hashicorp/aws",
        values={
            "family": "app",
            "container_definitions": json.dumps(definitions) if isinstance(definitions, list) else definitions,
        },
        unknown_values=unknown_values or {},
    )


class AwsSecretDeliveryNormalizerTests(unittest.TestCase):
    def test_captures_secrets_manager_reference_and_version_evidence(self) -> None:
        facts = aws_facts(
            normalize_ecs_task_definition(
                _resource(
                    [
                        {
                            "name": "orders",
                            "secrets": [
                                {
                                    "name": "DB_PASSWORD",
                                    "valueFrom": (
                                        "arn:aws:secretsmanager:us-east-1:111122223333:secret:orders-db-abc123:"
                                        "password:AWSCURRENT:version-001"
                                    ),
                                }
                            ],
                        }
                    ]
                )
            )
        )
        reference = facts.ecs_secret_references[0]
        self.assertEqual(reference["state"], "reference")
        self.assertEqual(reference["reference_kind"], "secrets_manager_arn")
        self.assertEqual(reference["target_resolution"], "resolved")
        self.assertEqual(reference["setting_name"], "DB_PASSWORD")
        self.assertEqual(reference["path"], "container_definitions[0].secrets[0]")
        self.assertEqual(reference["json_key"], "password")
        self.assertEqual(reference["version_stage"], "AWSCURRENT")
        self.assertEqual(reference["version_id"], "version-001")
        self.assertEqual(reference["aws_account_id"], "111122223333")
        self.assertEqual(facts.ecs_secret_posture_uncertainties, [])

    def test_preserves_terraform_and_ssm_references_without_claiming_ssm_modeling(self) -> None:
        facts = aws_facts(
            normalize_ecs_task_definition(
                _resource(
                    [
                        {
                            "name": "orders",
                            "secrets": [
                                {
                                    "name": "DB_PASSWORD",
                                    "valueFrom": "$" + "{aws_secretsmanager_secret.orders.arn}",
                                },
                                {
                                    "name": "DB_HOST",
                                    "valueFrom": ("arn:aws:ssm:us-east-1:111122223333:parameter/orders/database-host"),
                                },
                            ],
                        }
                    ]
                )
            )
        )
        terraform_reference, ssm_reference = facts.ecs_secret_references
        self.assertEqual(terraform_reference["reference_kind"], "terraform")
        self.assertEqual(terraform_reference["target_resolution"], "unresolved")
        self.assertFalse(terraform_reference["is_resolved"])
        self.assertEqual(ssm_reference["reference_kind"], "ssm_parameter_arn")
        self.assertEqual(ssm_reference["target_resolution"], "unsupported")
        self.assertTrue(ssm_reference["is_resolved"])
        self.assertNotIn("secrets_manager_secret_arn", ssm_reference)

    def test_captures_sensitive_literal_environment_settings_without_the_literal(self) -> None:
        facts = aws_facts(
            normalize_ecs_task_definition(
                _resource(
                    [
                        {
                            "name": "orders",
                            "environment": [
                                {"name": "DB_PASSWORD", "value": "do-not-store-this"},
                                {"name": "SECRET_ARN", "value": "arn:aws:secretsmanager:..."},
                                {"name": "LOG_LEVEL", "value": "info"},
                            ],
                        }
                    ]
                )
            )
        )
        references = facts.ecs_secret_references
        self.assertEqual(len(references), 1)
        self.assertEqual(references[0]["state"], "literal")
        self.assertEqual(references[0]["setting_name"], "DB_PASSWORD")
        self.assertNotIn("do-not-store-this", repr(references))
        self.assertNotIn("arn:aws:secretsmanager", repr(references))

    def test_unknown_secret_fields_remain_explicit(self) -> None:
        facts = aws_facts(
            normalize_ecs_task_definition(
                _resource(
                    [
                        {
                            "name": "orders",
                            "secrets": [{"name": "DB_PASSWORD", "valueFrom": "unknown"}],
                            "environment": [{"name": "API_KEY", "value": "unknown"}],
                        }
                    ],
                    unknown_values={
                        "container_definitions": [
                            {
                                "secrets": [{"valueFrom": True}],
                                "environment": [{"value": True}],
                            }
                        ]
                    },
                )
            )
        )
        references = facts.ecs_secret_references
        self.assertEqual([reference["state"] for reference in references], ["unknown", "unknown"])
        self.assertEqual(
            facts.ecs_secret_posture_uncertainties,
            [
                "container_definitions[0].secrets[0]: container_definitions[0].secrets[0].valueFrom is unknown after planning",
                "container_definitions[0].environment[0]: container_definitions[0].environment[0].value is unknown after planning",
            ],
        )

    def test_malformed_and_missing_secret_references_are_preserved_as_unknown(self) -> None:
        facts = aws_facts(
            normalize_ecs_task_definition(
                _resource(
                    [
                        {
                            "name": "orders",
                            "secrets": [
                                {"name": "DB_PASSWORD", "valueFrom": "not-a-reference"},
                                {"name": "API_KEY"},
                            ],
                        }
                    ]
                )
            )
        )
        references = facts.ecs_secret_references
        self.assertEqual(references[0]["state"], "reference")
        self.assertEqual(references[0]["target_resolution"], "unresolved")
        self.assertEqual(references[1]["state"], "unknown")
        self.assertIn("not a recognized AWS ARN", references[0]["unresolved_reason"])
        self.assertIn("not represented", references[1]["unresolved_reason"])

    def test_unknown_container_definitions_are_explicit_and_image_facts_remain_unchanged(self) -> None:
        facts = aws_facts(
            normalize_ecs_task_definition(
                _resource([{"name": "orders"}], unknown_values={"container_definitions": True})
            )
        )
        self.assertEqual(facts.container_image_references, [])
        self.assertEqual(facts.ecs_secret_references, [])
        self.assertEqual(
            facts.ecs_secret_posture_uncertainties,
            ["container_definitions is unknown after planning"],
        )


if __name__ == "__main__":
    unittest.main()
