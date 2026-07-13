from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.aws.api_gateway_normalizers import (
    normalize_api_gateway_authorizer,
    normalize_api_gateway_method,
    normalize_api_gateway_rest_api,
    normalize_api_gateway_stage,
    normalize_apigatewayv2_api,
    normalize_apigatewayv2_route,
    normalize_apigatewayv2_stage,
)
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES, AwsNormalizer
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


class AwsApiGatewayNormalizerTests(unittest.TestCase):
    def test_rest_api_normalizes_public_regional_endpoint_posture(self) -> None:
        execution_arn = "arn:aws:execute-api:us-east-1:111122223333:api123"
        normalized = normalize_api_gateway_rest_api(
            _terraform_resource(
                "aws_api_gateway_rest_api",
                {
                    "id": "api123",
                    "name": "orders",
                    "description": "orders API",
                    "execution_arn": execution_arn,
                    "disable_execute_api_endpoint": False,
                    "endpoint_configuration": [
                        {
                            "types": ["REGIONAL"],
                            "vpc_endpoint_ids": [],
                        }
                    ],
                    "tags": {"Environment": "prod"},
                },
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.EDGE)
        self.assertEqual(normalized.identifier, "api123")
        self.assertEqual(normalized.arn, execution_arn)
        self.assertTrue(normalized.public_access_configured)
        self.assertTrue(normalized.public_exposure)
        self.assertEqual(normalized.public_access_reasons, ["API Gateway REST API endpoint is public"])
        self.assertEqual(normalized.public_exposure_reasons, ["API Gateway REST API endpoint is public"])
        self.assertEqual(normalized.metadata["tags"], {"Environment": "prod"})
        self.assertEqual(facts.api_gateway_api_id, "api123")
        self.assertEqual(facts.api_gateway_name, "orders")
        self.assertEqual(facts.api_gateway_description, "orders API")
        self.assertEqual(facts.api_gateway_execution_arn, execution_arn)
        self.assertEqual(facts.api_gateway_endpoint_types, ["REGIONAL"])
        self.assertEqual(facts.api_gateway_vpc_endpoint_ids, [])
        self.assertEqual(facts.api_gateway_endpoint_configuration, {"types": ["REGIONAL"]})
        self.assertEqual(facts.api_gateway_execute_api_endpoint_state, "enabled")
        self.assertEqual(facts.api_gateway_public_endpoint_state, "enabled")
        self.assertEqual(facts.api_gateway_posture_uncertainties, [])

    def test_rest_api_private_endpoint_is_not_marked_public(self) -> None:
        normalized = normalize_api_gateway_rest_api(
            _terraform_resource(
                "aws_api_gateway_rest_api",
                {
                    "id": "api-private",
                    "name": "internal-orders",
                    "disable_execute_api_endpoint": False,
                    "endpoint_configuration": [
                        {
                            "types": ["PRIVATE"],
                            "vpc_endpoint_ids": ["vpce-123"],
                        }
                    ],
                },
            )
        )
        facts = aws_facts(normalized)

        self.assertFalse(normalized.public_access_configured)
        self.assertFalse(normalized.public_exposure)
        self.assertEqual(normalized.public_access_reasons, [])
        self.assertEqual(normalized.public_exposure_reasons, [])
        self.assertEqual(facts.api_gateway_endpoint_types, ["PRIVATE"])
        self.assertEqual(facts.api_gateway_vpc_endpoint_ids, ["vpce-123"])
        self.assertEqual(
            facts.api_gateway_endpoint_configuration,
            {"types": ["PRIVATE"], "vpc_endpoint_ids": ["vpce-123"]},
        )
        self.assertEqual(facts.api_gateway_execute_api_endpoint_state, "enabled")
        self.assertEqual(facts.api_gateway_public_endpoint_state, "disabled")

    def test_http_api_v2_normalizes_public_endpoint_and_cors_evidence(self) -> None:
        endpoint = "https://abc123.execute-api.us-east-1.amazonaws.com"
        execution_arn = "arn:aws:execute-api:us-east-1:111122223333:abc123"
        normalized = normalize_apigatewayv2_api(
            _terraform_resource(
                "aws_apigatewayv2_api",
                {
                    "id": "abc123",
                    "name": "orders-http",
                    "description": "orders HTTP API",
                    "protocol_type": "HTTP",
                    "api_endpoint": endpoint,
                    "execution_arn": execution_arn,
                    "route_selection_expression": "$request.method $request.path",
                    "disable_execute_api_endpoint": False,
                    "cors_configuration": [
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
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.EDGE)
        self.assertEqual(normalized.identifier, endpoint)
        self.assertEqual(normalized.arn, execution_arn)
        self.assertTrue(normalized.public_access_configured)
        self.assertTrue(normalized.public_exposure)
        self.assertEqual(normalized.public_access_reasons, ["API Gateway v2 execute-api endpoint is public"])
        self.assertEqual(facts.api_gateway_api_id, "abc123")
        self.assertEqual(facts.api_gateway_name, "orders-http")
        self.assertEqual(facts.api_gateway_protocol_type, "HTTP")
        self.assertEqual(facts.api_gateway_api_endpoint, endpoint)
        self.assertEqual(facts.api_gateway_execution_arn, execution_arn)
        self.assertEqual(facts.api_gateway_execute_api_endpoint_state, "enabled")
        self.assertEqual(facts.api_gateway_public_endpoint_state, "enabled")
        self.assertEqual(facts.api_gateway_route_selection_expression, "$request.method $request.path")
        self.assertEqual(
            facts.api_gateway_cors_configuration,
            {
                "allow_credentials": False,
                "allow_headers": ["authorization", "content-type"],
                "allow_methods": ["GET", "POST"],
                "allow_origins": ["https://example.com"],
                "expose_headers": ["x-request-id"],
                "max_age": 3600,
            },
        )
        self.assertEqual(facts.api_gateway_posture_uncertainties, [])

    def test_http_api_v2_disabled_execute_api_endpoint_is_not_marked_public(self) -> None:
        normalized = normalize_apigatewayv2_api(
            _terraform_resource(
                "aws_apigatewayv2_api",
                {
                    "id": "abc123",
                    "name": "private-http",
                    "protocol_type": "HTTP",
                    "disable_execute_api_endpoint": True,
                },
            )
        )
        facts = aws_facts(normalized)

        self.assertFalse(normalized.public_access_configured)
        self.assertFalse(normalized.public_exposure)
        self.assertEqual(facts.api_gateway_execute_api_endpoint_state, "disabled")
        self.assertEqual(facts.api_gateway_public_endpoint_state, "disabled")
        self.assertIsNone(facts.api_gateway_api_endpoint)

    def test_api_gateway_unknown_values_are_preserved_as_uncertainty(self) -> None:
        normalized = normalize_api_gateway_rest_api(
            _terraform_resource(
                "aws_api_gateway_rest_api",
                {},
                unknown_values={
                    "id": True,
                    "name": True,
                    "execution_arn": True,
                    "disable_execute_api_endpoint": True,
                    "endpoint_configuration": True,
                },
            )
        )
        facts = aws_facts(normalized)

        self.assertEqual(normalized.identifier, "app")
        self.assertFalse(normalized.public_access_configured)
        self.assertFalse(normalized.public_exposure)
        self.assertIsNone(facts.api_gateway_api_id)
        self.assertEqual(facts.api_gateway_name, "app")
        self.assertIsNone(facts.api_gateway_execution_arn)
        self.assertEqual(facts.api_gateway_endpoint_types, [])
        self.assertEqual(facts.api_gateway_vpc_endpoint_ids, [])
        self.assertEqual(facts.api_gateway_endpoint_configuration, {})
        self.assertEqual(facts.api_gateway_execute_api_endpoint_state, "unknown")
        self.assertEqual(facts.api_gateway_public_endpoint_state, "unknown")
        self.assertEqual(
            facts.api_gateway_posture_uncertainties,
            [
                "id is unknown after planning",
                "name is unknown after planning",
                "execution_arn is unknown after planning",
                "disable_execute_api_endpoint is unknown after planning",
                "endpoint_configuration is unknown after planning",
            ],
        )

    def test_rest_api_children_normalize_authorization_and_access_log_facts(self) -> None:
        method = normalize_api_gateway_method(
            _terraform_resource(
                "aws_api_gateway_method",
                {
                    "rest_api_id": "rest-123",
                    "resource_id": "orders-resource",
                    "http_method": "POST",
                    "authorization": "COGNITO_USER_POOLS",
                    "authorizer_id": "authorizer-123",
                    "authorization_scopes": ["orders.write"],
                },
            )
        )
        stage = normalize_api_gateway_stage(
            _terraform_resource(
                "aws_api_gateway_stage",
                {
                    "rest_api_id": "rest-123",
                    "stage_name": "prod",
                    "access_log_settings": [
                        {
                            "destination_arn": "arn:aws:logs:us-east-1:111122223333:log-group:api-access",
                            "format": '{"requestId":"$context.requestId"}',
                        }
                    ],
                },
            )
        )
        authorizer = normalize_api_gateway_authorizer(
            _terraform_resource(
                "aws_api_gateway_authorizer",
                {
                    "rest_api_id": "rest-123",
                    "id": "authorizer-123",
                    "name": "orders-users",
                    "type": "COGNITO_USER_POOLS",
                    "identity_source": "method.request.header.Authorization",
                    "provider_arns": ["arn:aws:cognito-idp:us-east-1:111122223333:userpool/us-east-1_pool"],
                    "authorizer_result_ttl_in_seconds": 300,
                },
            )
        )

        method_facts = aws_facts(method)
        stage_facts = aws_facts(stage)
        authorizer_facts = aws_facts(authorizer)

        self.assertEqual(method.category, ResourceCategory.EDGE)
        self.assertEqual(method.identifier, "rest-123:orders-resource:POST")
        self.assertEqual(method_facts.api_gateway_api_id, "rest-123")
        self.assertEqual(method_facts.api_gateway_method_resource_id, "orders-resource")
        self.assertEqual(method_facts.api_gateway_method_http_method, "POST")
        self.assertEqual(method_facts.api_gateway_authorization_type, "COGNITO_USER_POOLS")
        self.assertEqual(method_facts.api_gateway_authorizer_id, "authorizer-123")
        self.assertEqual(method_facts.api_gateway_authorization_scopes, ["orders.write"])
        self.assertEqual(stage_facts.api_gateway_stage_name, "prod")
        self.assertEqual(
            stage_facts.api_gateway_access_log_destination_arn,
            "arn:aws:logs:us-east-1:111122223333:log-group:api-access",
        )
        self.assertEqual(stage_facts.api_gateway_access_log_format, '{"requestId":"$context.requestId"}')
        self.assertEqual(authorizer_facts.api_gateway_authorizer_id, "authorizer-123")
        self.assertEqual(authorizer_facts.api_gateway_authorizer_name, "orders-users")
        self.assertEqual(authorizer_facts.api_gateway_authorizer_type, "COGNITO_USER_POOLS")
        self.assertEqual(authorizer_facts.api_gateway_identity_source, "method.request.header.Authorization")
        self.assertEqual(
            authorizer_facts.api_gateway_authorizer_provider_arns,
            ["arn:aws:cognito-idp:us-east-1:111122223333:userpool/us-east-1_pool"],
        )
        self.assertEqual(authorizer_facts.api_gateway_authorizer_result_ttl, 300)

    def test_v2_routes_and_stages_normalize_authorization_and_access_log_facts(self) -> None:
        route = normalize_apigatewayv2_route(
            _terraform_resource(
                "aws_apigatewayv2_route",
                {
                    "api_id": "v2-123",
                    "route_key": "GET /orders",
                    "authorization_type": "JWT",
                    "authorizer_id": "v2-authorizer",
                    "authorization_scopes": ["orders.read"],
                },
            )
        )
        stage = normalize_apigatewayv2_stage(
            _terraform_resource(
                "aws_apigatewayv2_stage",
                {
                    "api_id": "v2-123",
                    "name": "$default",
                    "access_log_settings": [
                        {
                            "destination_arn": "arn:aws:logs:us-east-1:111122223333:log-group:http-api-access",
                            "format": "$context.requestId",
                        }
                    ],
                },
            )
        )

        route_facts = aws_facts(route)
        stage_facts = aws_facts(stage)

        self.assertEqual(route.identifier, "v2-123:GET /orders")
        self.assertEqual(route_facts.api_gateway_api_id, "v2-123")
        self.assertEqual(route_facts.api_gateway_route_key, "GET /orders")
        self.assertEqual(route_facts.api_gateway_authorization_type, "JWT")
        self.assertEqual(route_facts.api_gateway_authorizer_id, "v2-authorizer")
        self.assertEqual(route_facts.api_gateway_authorization_scopes, ["orders.read"])
        self.assertEqual(stage_facts.api_gateway_stage_name, "$default")
        self.assertEqual(
            stage_facts.api_gateway_access_log_destination_arn,
            "arn:aws:logs:us-east-1:111122223333:log-group:http-api-access",
        )
        self.assertEqual(stage_facts.api_gateway_access_log_format, "$context.requestId")

    def test_api_gateway_child_unknown_values_are_preserved_as_uncertainty(self) -> None:
        normalized = normalize_api_gateway_stage(
            _terraform_resource(
                "aws_api_gateway_stage",
                {"stage_name": "prod", "access_log_settings": [{}]},
                unknown_values={
                    "rest_api_id": True,
                    "access_log_settings": [{"destination_arn": True, "format": True}],
                },
            )
        )
        facts = aws_facts(normalized)

        self.assertIsNone(facts.api_gateway_api_id)
        self.assertEqual(facts.api_gateway_stage_name, "prod")
        self.assertIsNone(facts.api_gateway_access_log_destination_arn)
        self.assertIsNone(facts.api_gateway_access_log_format)
        self.assertEqual(
            facts.api_gateway_posture_uncertainties,
            [
                "rest_api_id is unknown after planning",
                "access_log_settings.destination_arn is unknown after planning",
                "access_log_settings.format is unknown after planning",
            ],
        )

    def test_api_gateway_resources_are_registered_as_supported_aws_resources(self) -> None:
        inventory = AwsNormalizer().normalize(
            [
                _terraform_resource(
                    "aws_api_gateway_rest_api",
                    {
                        "id": "api123",
                        "name": "orders",
                    },
                ),
                _terraform_resource(
                    "aws_apigatewayv2_api",
                    {
                        "id": "abc123",
                        "name": "orders-http",
                    },
                ),
            ]
        )

        self.assertIn("aws_api_gateway_rest_api", SUPPORTED_AWS_TYPES)
        self.assertIn("aws_api_gateway_method", SUPPORTED_AWS_TYPES)
        self.assertIn("aws_api_gateway_stage", SUPPORTED_AWS_TYPES)
        self.assertIn("aws_api_gateway_authorizer", SUPPORTED_AWS_TYPES)
        self.assertIn("aws_apigatewayv2_api", SUPPORTED_AWS_TYPES)
        self.assertIn("aws_apigatewayv2_route", SUPPORTED_AWS_TYPES)
        self.assertIn("aws_apigatewayv2_stage", SUPPORTED_AWS_TYPES)
        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual(
            [resource.resource_type for resource in inventory.resources],
            ["aws_api_gateway_rest_api", "aws_apigatewayv2_api"],
        )


if __name__ == "__main__":
    unittest.main()
