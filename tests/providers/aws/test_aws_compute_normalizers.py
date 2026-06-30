from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.aws.compute_normalizers import normalize_lambda_function_url
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.aws.resource_facts import aws_facts


def _terraform_resource(
    resource_type: str,
    values: dict[str, Any],
    *,
    unknown_values: dict[str, Any] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.app",
        mode="managed",
        resource_type=resource_type,
        name="app",
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values=unknown_values or {},
    )


class AwsComputeNormalizerTests(unittest.TestCase):
    def test_lambda_function_url_normalizes_authorization_target_and_cors_evidence(self) -> None:
        resource = _terraform_resource(
            "aws_lambda_function_url",
            {
                "id": "worker",
                "function_name": "worker",
                "function_url": "https://abc.lambda-url.us-east-1.on.aws/",
                "authorization_type": "NONE",
                "qualifier": "prod",
                "invoke_mode": "BUFFERED",
                "url_id": "abc",
                "cors": [
                    {
                        "allow_credentials": False,
                        "allow_headers": ["authorization", "content-type"],
                        "allow_methods": ["GET", "POST"],
                        "allow_origins": ["https://example.com"],
                        "expose_headers": ["x-request-id"],
                        "max_age": 3600,
                    }
                ],
            },
        )

        normalized = normalize_lambda_function_url(resource)
        facts = aws_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.EDGE)
        self.assertEqual(normalized.identifier, "https://abc.lambda-url.us-east-1.on.aws/")
        self.assertFalse(normalized.public_access_configured)
        self.assertFalse(normalized.public_exposure)
        self.assertEqual(facts.lambda_function_url_function_reference, "worker")
        self.assertEqual(facts.lambda_function_url, "https://abc.lambda-url.us-east-1.on.aws/")
        self.assertEqual(facts.lambda_function_url_authorization_type, "NONE")
        self.assertEqual(facts.lambda_function_url_qualifier, "prod")
        self.assertEqual(facts.lambda_function_url_invoke_mode, "BUFFERED")
        self.assertEqual(
            facts.lambda_function_url_cors,
            {
                "allow_credentials": False,
                "allow_headers": ["authorization", "content-type"],
                "allow_methods": ["GET", "POST"],
                "allow_origins": ["https://example.com"],
                "expose_headers": ["x-request-id"],
                "max_age": 3600,
            },
        )
        self.assertEqual(facts.lambda_function_url_cors_allow_credentials_state, "disabled")
        self.assertFalse(facts.lambda_function_url_cors_allow_credentials)
        self.assertEqual(facts.lambda_function_url_cors_allow_headers, ["authorization", "content-type"])
        self.assertEqual(facts.lambda_function_url_cors_allow_methods, ["GET", "POST"])
        self.assertEqual(facts.lambda_function_url_cors_allow_origins, ["https://example.com"])
        self.assertEqual(facts.lambda_function_url_cors_expose_headers, ["x-request-id"])
        self.assertEqual(facts.lambda_function_url_cors_max_age, 3600)
        self.assertEqual(facts.lambda_function_url_posture_uncertainties, [])

    def test_lambda_function_url_without_cors_keeps_posture_absent(self) -> None:
        facts = aws_facts(
            normalize_lambda_function_url(
                _terraform_resource(
                    "aws_lambda_function_url",
                    {
                        "function_name": "worker",
                        "authorization_type": "AWS_IAM",
                        "url_id": "abc",
                    },
                )
            )
        )

        self.assertEqual(facts.lambda_function_url_function_reference, "worker")
        self.assertEqual(facts.lambda_function_url_authorization_type, "AWS_IAM")
        self.assertIsNone(facts.lambda_function_url)
        self.assertEqual(facts.lambda_function_url_cors, {})
        self.assertIsNone(facts.lambda_function_url_cors_allow_credentials_state)
        self.assertIsNone(facts.lambda_function_url_cors_allow_credentials)
        self.assertEqual(facts.lambda_function_url_cors_allow_headers, [])
        self.assertEqual(facts.lambda_function_url_cors_allow_methods, [])
        self.assertEqual(facts.lambda_function_url_cors_allow_origins, [])
        self.assertEqual(facts.lambda_function_url_cors_expose_headers, [])
        self.assertIsNone(facts.lambda_function_url_cors_max_age)
        self.assertEqual(facts.lambda_function_url_posture_uncertainties, [])

    def test_lambda_function_url_preserves_unknown_values(self) -> None:
        resource = _terraform_resource(
            "aws_lambda_function_url",
            {
                "url_id": "abc",
                "cors": [{}],
            },
            unknown_values={
                "function_name": True,
                "authorization_type": True,
                "function_url": True,
                "qualifier": True,
                "invoke_mode": True,
                "cors": [
                    {
                        "allow_credentials": True,
                        "allow_headers": True,
                        "allow_methods": True,
                        "allow_origins": True,
                        "expose_headers": True,
                        "max_age": True,
                    }
                ],
            },
        )

        normalized = normalize_lambda_function_url(resource)
        facts = aws_facts(normalized)

        self.assertEqual(normalized.identifier, "abc")
        self.assertIsNone(facts.lambda_function_url_function_reference)
        self.assertIsNone(facts.lambda_function_url_authorization_type)
        self.assertIsNone(facts.lambda_function_url)
        self.assertIsNone(facts.lambda_function_url_qualifier)
        self.assertIsNone(facts.lambda_function_url_invoke_mode)
        self.assertEqual(facts.lambda_function_url_cors, {})
        self.assertIsNone(facts.lambda_function_url_cors_allow_credentials_state)
        self.assertEqual(facts.lambda_function_url_cors_allow_headers, [])
        self.assertEqual(facts.lambda_function_url_cors_allow_methods, [])
        self.assertEqual(facts.lambda_function_url_cors_allow_origins, [])
        self.assertEqual(facts.lambda_function_url_cors_expose_headers, [])
        self.assertIsNone(facts.lambda_function_url_cors_max_age)
        self.assertEqual(
            facts.lambda_function_url_posture_uncertainties,
            [
                "function_name is unknown after planning",
                "authorization_type is unknown after planning",
                "function_url is unknown after planning",
                "qualifier is unknown after planning",
                "invoke_mode is unknown after planning",
                "cors.allow_credentials is unknown after planning",
                "cors.allow_headers is unknown after planning",
                "cors.allow_methods is unknown after planning",
                "cors.allow_origins is unknown after planning",
                "cors.expose_headers is unknown after planning",
                "cors.max_age is unknown after planning",
            ],
        )

    def test_lambda_function_url_is_registered_as_supported_aws_resource(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _terraform_resource(
                    "aws_lambda_function_url",
                    {
                        "function_name": "worker",
                        "authorization_type": "AWS_IAM",
                    },
                )
            ]
        )

        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual([resource.resource_type for resource in inventory.resources], ["aws_lambda_function_url"])


if __name__ == "__main__":
    unittest.main()
