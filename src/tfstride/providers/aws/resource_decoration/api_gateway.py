from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext

_REST_API_CHILD_TYPES = frozenset(
    {
        "aws_api_gateway_method",
        "aws_api_gateway_stage",
        "aws_api_gateway_authorizer",
    }
)
_V2_API_CHILD_TYPES = frozenset(
    {
        "aws_apigatewayv2_route",
        "aws_apigatewayv2_stage",
    }
)


class ResolveApiGatewayRelationshipsStage:
    """Attach API Gateway child resources through their exact API IDs."""

    name = "resolve_api_gateway_relationships"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for child in resources:
            parent = _parent_api_for(child, context)
            if parent is None:
                _record_unresolved_api(child, context)
                continue

            child_facts = aws_facts(child)
            child_facts.set_api_gateway_parent_api_address(parent.address)
            parent_facts = aws_facts(parent)
            parent_facts.extend_api_gateway_posture_uncertainties(
                _source_uncertainties(child, child_facts.api_gateway_posture_uncertainties)
            )
            _attach_child_record(parent, child)


def _parent_api_for(
    child: NormalizedResource,
    context: AwsDecorationContext,
) -> NormalizedResource | None:
    api_id = aws_facts(child).api_gateway_api_id
    if not api_id:
        return None
    if child.resource_type in _REST_API_CHILD_TYPES:
        return context.index.api_gateway_rest_apis.get(api_id)
    if child.resource_type in _V2_API_CHILD_TYPES:
        return context.index.apigatewayv2_apis.get(api_id)
    return None


def _record_unresolved_api(child: NormalizedResource, context: AwsDecorationContext) -> None:
    if child.resource_type not in _REST_API_CHILD_TYPES | _V2_API_CHILD_TYPES:
        return
    api_id = aws_facts(child).api_gateway_api_id
    if api_id:
        aws_facts(child).add_unresolved_api_gateway_api_id(api_id)


def _attach_child_record(parent: NormalizedResource, child: NormalizedResource) -> None:
    parent_facts = aws_facts(parent)
    if child.resource_type == "aws_api_gateway_method":
        parent_facts.add_api_gateway_method(_method_record(child))
    elif child.resource_type in {"aws_api_gateway_stage", "aws_apigatewayv2_stage"}:
        parent_facts.add_api_gateway_stage(_stage_record(child))
    elif child.resource_type == "aws_api_gateway_authorizer":
        parent_facts.add_api_gateway_authorizer(_authorizer_record(child))
    elif child.resource_type == "aws_apigatewayv2_route":
        parent_facts.add_api_gateway_route(_route_record(child))


def _method_record(resource: NormalizedResource) -> dict[str, Any]:
    facts = aws_facts(resource)
    return _compact_record(
        {
            "address": resource.address,
            "resource_id": facts.api_gateway_method_resource_id,
            "http_method": facts.api_gateway_method_http_method,
            "authorization_type": facts.api_gateway_authorization_type,
            "authorizer_id": facts.api_gateway_authorizer_id,
            "authorization_scopes": facts.api_gateway_authorization_scopes,
        }
    )


def _stage_record(resource: NormalizedResource) -> dict[str, Any]:
    facts = aws_facts(resource)
    return _compact_record(
        {
            "address": resource.address,
            "resource_type": resource.resource_type,
            "stage_name": facts.api_gateway_stage_name,
            "access_log_destination_arn": facts.api_gateway_access_log_destination_arn,
            "access_log_format": facts.api_gateway_access_log_format,
        }
    )


def _authorizer_record(resource: NormalizedResource) -> dict[str, Any]:
    facts = aws_facts(resource)
    return _compact_record(
        {
            "address": resource.address,
            "authorizer_id": facts.api_gateway_authorizer_id,
            "name": facts.api_gateway_authorizer_name,
            "type": facts.api_gateway_authorizer_type,
            "identity_source": facts.api_gateway_identity_source,
            "identity_validation_expression": facts.api_gateway_identity_validation_expression,
            "authorizer_uri": facts.api_gateway_authorizer_uri,
            "authorizer_credentials": facts.api_gateway_authorizer_credentials,
            "provider_arns": facts.api_gateway_authorizer_provider_arns,
            "result_ttl": facts.api_gateway_authorizer_result_ttl,
        }
    )


def _route_record(resource: NormalizedResource) -> dict[str, Any]:
    facts = aws_facts(resource)
    return _compact_record(
        {
            "address": resource.address,
            "route_key": facts.api_gateway_route_key,
            "authorization_type": facts.api_gateway_authorization_type,
            "authorizer_id": facts.api_gateway_authorizer_id,
            "authorization_scopes": facts.api_gateway_authorization_scopes,
        }
    )


def _compact_record(values: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value not in (None, [], {}, "")}


def _source_uncertainties(resource: NormalizedResource, uncertainties: list[str]) -> list[str]:
    return [f"{resource.address}: {uncertainty}" for uncertainty in uncertainties]
