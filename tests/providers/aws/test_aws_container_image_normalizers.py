from __future__ import annotations

import json
import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.aws.compute_normalizers import (
    normalize_ecs_task_definition,
    normalize_lambda_function,
)
from tfstride.providers.aws.ecr_normalizers import normalize_ecr_repository
from tfstride.providers.aws.resource_facts import aws_facts


def _resource(
    resource_type: str,
    values: dict[str, Any],
    *,
    name: str = "app",
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


class AwsContainerImageNormalizerTests(unittest.TestCase):
    def test_ecs_task_definition_normalizes_ecr_and_non_ecr_image_references(self) -> None:
        digest = "sha256:" + "a" * 64
        normalized = normalize_ecs_task_definition(
            _resource(
                "aws_ecs_task_definition",
                {
                    "family": "orders",
                    "revision": 3,
                    "container_definitions": json.dumps(
                        [
                            {
                                "name": "orders",
                                "image": "111122223333.dkr.ecr.us-east-1.amazonaws.com/orders:stable",
                            },
                            {"name": "proxy", "image": "docker.io/library/nginx:1.27"},
                            {
                                "name": "worker",
                                "image": f"111122223333.dkr.ecr.us-east-1.amazonaws.com/orders@{digest}",
                            },
                        ]
                    ),
                },
            )
        )
        references = aws_facts(normalized).container_image_references

        self.assertEqual(len(references), 3)
        self.assertEqual(
            references[0],
            {
                "source": "aws_ecs_task_definition",
                "path": "container_definitions[0].image",
                "raw": "111122223333.dkr.ecr.us-east-1.amazonaws.com/orders:stable",
                "registry_host": "111122223333.dkr.ecr.us-east-1.amazonaws.com",
                "repository": "orders",
                "tag": "stable",
                "digest": None,
                "digest_pinned": False,
                "is_resolved": True,
                "ecr_account_id": "111122223333",
                "ecr_region": "us-east-1",
                "ecr_repository_path": "orders",
                "ecr_repository_url": "111122223333.dkr.ecr.us-east-1.amazonaws.com/orders",
            },
        )
        self.assertEqual(references[1]["registry_host"], "docker.io")
        self.assertEqual(references[1]["repository"], "library/nginx")
        self.assertEqual(references[1]["tag"], "1.27")
        self.assertNotIn("ecr_repository_url", references[1])
        self.assertTrue(references[2]["digest_pinned"])
        self.assertEqual(references[2]["digest"], digest)
        self.assertEqual(aws_facts(normalized).container_image_posture_uncertainties, [])

    def test_lambda_image_package_preserves_image_and_exact_ecr_identity(self) -> None:
        image_uri = "111122223333.dkr.ecr.eu-west-1.amazonaws.com/functions/worker:2026-07-12"
        normalized = normalize_lambda_function(
            _resource(
                "aws_lambda_function",
                {
                    "function_name": "worker",
                    "package_type": "Image",
                    "image_uri": image_uri,
                    "arn": "arn:aws:lambda:eu-west-1:111122223333:function:worker",
                },
                name="worker",
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(facts.lambda_package_type, "Image")
        self.assertEqual(
            facts.container_image_references,
            [
                {
                    "source": "aws_lambda_function",
                    "path": "image_uri",
                    "raw": image_uri,
                    "registry_host": "111122223333.dkr.ecr.eu-west-1.amazonaws.com",
                    "repository": "functions/worker",
                    "tag": "2026-07-12",
                    "digest": None,
                    "digest_pinned": False,
                    "is_resolved": True,
                    "package_type": "Image",
                    "ecr_account_id": "111122223333",
                    "ecr_region": "eu-west-1",
                    "ecr_repository_path": "functions/worker",
                    "ecr_repository_url": "111122223333.dkr.ecr.eu-west-1.amazonaws.com/functions/worker",
                }
            ],
        )
        self.assertEqual(facts.container_image_posture_uncertainties, [])

    def test_lambda_zip_package_does_not_create_an_image_reference(self) -> None:
        facts = aws_facts(
            normalize_lambda_function(
                _resource(
                    "aws_lambda_function",
                    {"function_name": "worker", "package_type": "Zip", "filename": "worker.zip"},
                    name="worker",
                )
            )
        )

        self.assertEqual(facts.lambda_package_type, "Zip")
        self.assertEqual(facts.container_image_references, [])
        self.assertEqual(facts.container_image_posture_uncertainties, [])

    def test_unknown_and_unresolved_image_values_remain_explicit(self) -> None:
        unknown_lambda = aws_facts(
            normalize_lambda_function(
                _resource(
                    "aws_lambda_function",
                    {"function_name": "worker", "package_type": "Image"},
                    name="worker",
                    unknown_values={"image_uri": True},
                )
            )
        )
        self.assertEqual(len(unknown_lambda.container_image_references), 1)
        self.assertFalse(unknown_lambda.container_image_references[0]["is_resolved"])
        self.assertEqual(
            unknown_lambda.container_image_references[0]["unresolved_reason"],
            "image reference is unknown after planning",
        )
        self.assertEqual(unknown_lambda.container_image_posture_uncertainties, ["image_uri is unknown after planning"])

        unresolved_ecs = aws_facts(
            normalize_ecs_task_definition(
                _resource(
                    "aws_ecs_task_definition",
                    {
                        "family": "orders",
                        "container_definitions": json.dumps([{"name": "orders", "image": "${var.container_image}"}]),
                    },
                )
            )
        )
        self.assertEqual(unresolved_ecs.container_image_references[0]["raw"], "${var.container_image}")
        self.assertFalse(unresolved_ecs.container_image_references[0]["is_resolved"])
        self.assertEqual(
            unresolved_ecs.container_image_references[0]["unresolved_reason"],
            "image reference is unresolved",
        )
        self.assertEqual(
            unresolved_ecs.container_image_posture_uncertainties,
            ["container_definitions[0].image: image reference is unresolved"],
        )

        unknown_ecs = aws_facts(
            normalize_ecs_task_definition(
                _resource(
                    "aws_ecs_task_definition",
                    {"family": "orders"},
                    unknown_values={"container_definitions": True},
                )
            )
        )
        self.assertEqual(unknown_ecs.container_image_references, [])
        self.assertEqual(
            unknown_ecs.container_image_posture_uncertainties,
            ["container_definitions is unknown after planning"],
        )

    def test_ecr_repository_preserves_exact_repository_url_for_future_matching(self) -> None:
        facts = aws_facts(
            normalize_ecr_repository(
                _resource(
                    "aws_ecr_repository",
                    {
                        "id": "orders",
                        "name": "orders",
                        "repository_url": "111122223333.dkr.ecr.us-east-1.amazonaws.com/orders",
                    },
                    name="orders",
                )
            )
        )

        self.assertEqual(
            facts.ecr_repository_url,
            "111122223333.dkr.ecr.us-east-1.amazonaws.com/orders",
        )


if __name__ == "__main__":
    unittest.main()
