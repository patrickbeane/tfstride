from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import TerraformResource
from tfstride.providers.aws.api_gateway_normalizers import (
    normalize_api_gateway_authorizer,
    normalize_api_gateway_method,
    normalize_api_gateway_rest_api,
    normalize_api_gateway_stage,
    normalize_apigatewayv2_api,
    normalize_apigatewayv2_route,
    normalize_apigatewayv2_stage,
)
from tfstride.providers.aws.resource_decoration.api_gateway import ResolveApiGatewayRelationshipsStage
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext, AwsResourceIndexBuilder


def _resource(address: str, resource_type: str, values: dict[str, Any]) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name="registry.terraform.io/hashicorp/aws",
        values=values,
        unknown_values={},
    )


class AwsApiGatewayRelationshipTests(unittest.TestCase):
    def test_relationships_resolve_by_exact_api_id_and_aggregate_child_evidence(self) -> None:
        rest_api = normalize_api_gateway_rest_api(
            _resource(
                "aws_api_gateway_rest_api.orders",
                "aws_api_gateway_rest_api",
                {"id": "rest-123", "name": "orders"},
            )
        )
        rest_method = normalize_api_gateway_method(
            _resource(
                "aws_api_gateway_method.orders",
                "aws_api_gateway_method",
                {
                    "rest_api_id": "rest-123",
                    "resource_id": "orders-resource",
                    "http_method": "POST",
                    "authorization": "CUSTOM",
                    "authorizer_id": "authorizer-123",
                },
            )
        )
        rest_stage = normalize_api_gateway_stage(
            _resource(
                "aws_api_gateway_stage.production",
                "aws_api_gateway_stage",
                {
                    "rest_api_id": "rest-123",
                    "stage_name": "production",
                    "access_log_settings": [
                        {
                            "destination_arn": "arn:aws:logs:us-east-1:111122223333:log-group:orders",
                            "format": "$context.requestId",
                        }
                    ],
                },
            )
        )
        rest_authorizer = normalize_api_gateway_authorizer(
            _resource(
                "aws_api_gateway_authorizer.orders",
                "aws_api_gateway_authorizer",
                {
                    "rest_api_id": "rest-123",
                    "id": "authorizer-123",
                    "name": "orders-authorizer",
                    "type": "REQUEST",
                    "identity_source": "method.request.header.Authorization",
                    "identity_validation_expression": "^Bearer [-0-9a-zA-Z\\._]+$",
                },
            )
        )
        v2_api = normalize_apigatewayv2_api(
            _resource(
                "aws_apigatewayv2_api.orders",
                "aws_apigatewayv2_api",
                {"id": "v2-123", "name": "orders-v2", "protocol_type": "HTTP"},
            )
        )
        v2_route = normalize_apigatewayv2_route(
            _resource(
                "aws_apigatewayv2_route.orders",
                "aws_apigatewayv2_route",
                {
                    "api_id": "v2-123",
                    "route_key": "GET /orders",
                    "authorization_type": "JWT",
                    "authorization_scopes": ["orders.read"],
                },
            )
        )
        v2_stage = normalize_apigatewayv2_stage(
            _resource(
                "aws_apigatewayv2_stage.production",
                "aws_apigatewayv2_stage",
                {
                    "api_id": "v2-123",
                    "name": "$default",
                    "access_log_settings": [
                        {
                            "destination_arn": "arn:aws:logs:us-east-1:111122223333:log-group:orders-v2",
                            "format": "$context.requestId",
                        }
                    ],
                },
            )
        )
        unmatched_method = normalize_api_gateway_method(
            _resource(
                "aws_api_gateway_method.unmatched",
                "aws_api_gateway_method",
                {
                    "rest_api_id": "rest-999",
                    "resource_id": "orders-resource",
                    "http_method": "GET",
                    "authorization": "NONE",
                },
            )
        )
        resources = [
            rest_api,
            rest_method,
            rest_stage,
            rest_authorizer,
            v2_api,
            v2_route,
            v2_stage,
            unmatched_method,
        ]

        ResolveApiGatewayRelationshipsStage().apply(
            resources,
            AwsDecorationContext(index=AwsResourceIndexBuilder().build(resources)),
        )

        rest_facts = aws_facts(rest_api)
        v2_facts = aws_facts(v2_api)
        self.assertEqual(aws_facts(rest_method).api_gateway_parent_api_address, rest_api.address)
        self.assertEqual(aws_facts(rest_stage).api_gateway_parent_api_address, rest_api.address)
        self.assertEqual(aws_facts(rest_authorizer).api_gateway_parent_api_address, rest_api.address)
        self.assertEqual(aws_facts(v2_route).api_gateway_parent_api_address, v2_api.address)
        self.assertEqual(aws_facts(v2_stage).api_gateway_parent_api_address, v2_api.address)
        self.assertIsNone(aws_facts(unmatched_method).api_gateway_parent_api_address)
        self.assertEqual(aws_facts(unmatched_method).unresolved_api_gateway_api_ids, ["rest-999"])
        self.assertEqual(
            rest_facts.api_gateway_methods,
            [
                {
                    "address": rest_method.address,
                    "resource_id": "orders-resource",
                    "http_method": "POST",
                    "authorization_type": "CUSTOM",
                    "authorizer_id": "authorizer-123",
                }
            ],
        )
        self.assertEqual(
            rest_facts.api_gateway_stages,
            [
                {
                    "address": rest_stage.address,
                    "resource_type": "aws_api_gateway_stage",
                    "stage_name": "production",
                    "access_log_destination_arn": "arn:aws:logs:us-east-1:111122223333:log-group:orders",
                    "access_log_format": "$context.requestId",
                }
            ],
        )
        self.assertEqual(
            rest_facts.api_gateway_authorizers,
            [
                {
                    "address": rest_authorizer.address,
                    "authorizer_id": "authorizer-123",
                    "name": "orders-authorizer",
                    "type": "REQUEST",
                    "identity_source": "method.request.header.Authorization",
                    "identity_validation_expression": "^Bearer [-0-9a-zA-Z\\._]+$",
                }
            ],
        )
        self.assertEqual(
            v2_facts.api_gateway_routes,
            [
                {
                    "address": v2_route.address,
                    "route_key": "GET /orders",
                    "authorization_type": "JWT",
                    "authorization_scopes": ["orders.read"],
                }
            ],
        )
        self.assertEqual(
            v2_facts.api_gateway_stages,
            [
                {
                    "address": v2_stage.address,
                    "resource_type": "aws_apigatewayv2_stage",
                    "stage_name": "$default",
                    "access_log_destination_arn": "arn:aws:logs:us-east-1:111122223333:log-group:orders-v2",
                    "access_log_format": "$context.requestId",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
