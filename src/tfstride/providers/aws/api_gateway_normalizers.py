from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.network_normalizers import AWS_PROVIDER
from tfstride.providers.aws.resource_mutations import aws_mutations
from tfstride.providers.coercion import (
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_UNKNOWN,
    as_optional_int,
    attribute_unknown,
    first_mapping,
    known_block_bool,
    known_block_int,
    known_block_string,
    known_block_strings,
    known_bool,
    known_string,
    known_string_list,
    unknown_block_at,
)

_REST_PUBLIC_ENDPOINT_TYPES = frozenset({"EDGE", "REGIONAL"})
_PRIVATE_ENDPOINT_TYPE = "PRIVATE"


def normalize_api_gateway_rest_api(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    api_id = known_string(values, unknown_values, "id", uncertainties)
    name = known_string(values, unknown_values, "name", uncertainties) or resource.name
    description = known_string(values, unknown_values, "description", uncertainties)
    execution_arn = known_string(values, unknown_values, "execution_arn", uncertainties)
    arn = known_string(values, unknown_values, "arn", uncertainties) or execution_arn
    disable_execute_api_endpoint = known_bool(
        values,
        unknown_values,
        "disable_execute_api_endpoint",
        uncertainties,
        allow_string=False,
    )
    endpoint_configuration, endpoint_unknown = _first_api_gateway_block(
        values,
        unknown_values,
        "endpoint_configuration",
        uncertainties,
    )
    if endpoint_configuration is None and endpoint_unknown is True:
        endpoint_types: list[str] = []
        vpc_endpoint_ids: list[str] = []
    else:
        endpoint_types = known_block_strings(
            endpoint_configuration,
            endpoint_unknown,
            "types",
            uncertainties,
            path="endpoint_configuration",
        )
        vpc_endpoint_ids = known_block_strings(
            endpoint_configuration,
            endpoint_unknown,
            "vpc_endpoint_ids",
            uncertainties,
            path="endpoint_configuration",
        )
    execute_api_endpoint_state = _execute_api_endpoint_state(disable_execute_api_endpoint)
    public_endpoint_state = _rest_api_public_endpoint_state(endpoint_types, execute_api_endpoint_state)

    normalized = NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=api_id or name or resource.address,
        arn=arn,
        public_access_configured=public_endpoint_state == STATE_ENABLED,
        public_exposure=public_endpoint_state == STATE_ENABLED,
        metadata={
            AwsResourceMetadata.API_GATEWAY_API_ID: api_id,
            AwsResourceMetadata.API_GATEWAY_NAME: name,
            AwsResourceMetadata.API_GATEWAY_DESCRIPTION: description,
            AwsResourceMetadata.API_GATEWAY_EXECUTION_ARN: execution_arn,
            AwsResourceMetadata.API_GATEWAY_ENDPOINT_TYPES: endpoint_types,
            AwsResourceMetadata.API_GATEWAY_VPC_ENDPOINT_IDS: vpc_endpoint_ids,
            AwsResourceMetadata.API_GATEWAY_ENDPOINT_CONFIGURATION: _endpoint_configuration_evidence(
                endpoint_configuration,
                endpoint_types,
                vpc_endpoint_ids,
            ),
            AwsResourceMetadata.API_GATEWAY_EXECUTE_API_ENDPOINT_STATE: execute_api_endpoint_state,
            AwsResourceMetadata.API_GATEWAY_PUBLIC_ENDPOINT_STATE: public_endpoint_state,
            AwsResourceMetadata.API_GATEWAY_POSTURE_UNCERTAINTIES: uncertainties,
            "tags": values.get("tags", {}),
        },
    )
    _set_public_endpoint_reasons(normalized, public_endpoint_state, "API Gateway REST API endpoint is public")
    return normalized


def normalize_apigatewayv2_api(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    api_id = known_string(values, unknown_values, "id", uncertainties)
    name = known_string(values, unknown_values, "name", uncertainties) or resource.name
    description = known_string(values, unknown_values, "description", uncertainties)
    protocol_type = known_string(values, unknown_values, "protocol_type", uncertainties)
    api_endpoint = known_string(values, unknown_values, "api_endpoint", uncertainties)
    execution_arn = known_string(values, unknown_values, "execution_arn", uncertainties)
    route_selection_expression = known_string(values, unknown_values, "route_selection_expression", uncertainties)
    disable_execute_api_endpoint = known_bool(
        values,
        unknown_values,
        "disable_execute_api_endpoint",
        uncertainties,
        allow_string=False,
    )
    cors_configuration = _api_gateway_cors_configuration(values, unknown_values, uncertainties)
    execute_api_endpoint_state = _execute_api_endpoint_state(disable_execute_api_endpoint)
    public_endpoint_state = _v2_api_public_endpoint_state(api_endpoint, execute_api_endpoint_state)

    normalized = NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=api_endpoint or api_id or name or resource.address,
        arn=execution_arn,
        public_access_configured=public_endpoint_state == STATE_ENABLED,
        public_exposure=public_endpoint_state == STATE_ENABLED,
        metadata={
            AwsResourceMetadata.API_GATEWAY_API_ID: api_id,
            AwsResourceMetadata.API_GATEWAY_NAME: name,
            AwsResourceMetadata.API_GATEWAY_DESCRIPTION: description,
            AwsResourceMetadata.API_GATEWAY_PROTOCOL_TYPE: protocol_type,
            AwsResourceMetadata.API_GATEWAY_API_ENDPOINT: api_endpoint,
            AwsResourceMetadata.API_GATEWAY_EXECUTION_ARN: execution_arn,
            AwsResourceMetadata.API_GATEWAY_EXECUTE_API_ENDPOINT_STATE: execute_api_endpoint_state,
            AwsResourceMetadata.API_GATEWAY_PUBLIC_ENDPOINT_STATE: public_endpoint_state,
            AwsResourceMetadata.API_GATEWAY_ROUTE_SELECTION_EXPRESSION: route_selection_expression,
            AwsResourceMetadata.API_GATEWAY_CORS_CONFIGURATION: cors_configuration,
            AwsResourceMetadata.API_GATEWAY_POSTURE_UNCERTAINTIES: uncertainties,
            "tags": values.get("tags", {}),
        },
    )
    _set_public_endpoint_reasons(normalized, public_endpoint_state, "API Gateway v2 execute-api endpoint is public")
    return normalized


def _execute_api_endpoint_state(disable_execute_api_endpoint: bool | None) -> str:
    if disable_execute_api_endpoint is True:
        return STATE_DISABLED
    if disable_execute_api_endpoint is False:
        return STATE_ENABLED
    return STATE_UNKNOWN


def _rest_api_public_endpoint_state(endpoint_types: list[str], execute_api_endpoint_state: str) -> str:
    normalized_types = {endpoint_type.strip().upper() for endpoint_type in endpoint_types if endpoint_type.strip()}
    if normalized_types and normalized_types <= {_PRIVATE_ENDPOINT_TYPE}:
        return STATE_DISABLED
    if execute_api_endpoint_state == STATE_DISABLED:
        return STATE_DISABLED
    if normalized_types & _REST_PUBLIC_ENDPOINT_TYPES:
        return STATE_ENABLED
    if execute_api_endpoint_state == STATE_ENABLED:
        return STATE_ENABLED
    return STATE_UNKNOWN


def _v2_api_public_endpoint_state(api_endpoint: str | None, execute_api_endpoint_state: str) -> str:
    if execute_api_endpoint_state == STATE_DISABLED:
        return STATE_DISABLED
    if api_endpoint or execute_api_endpoint_state == STATE_ENABLED:
        return STATE_ENABLED
    return STATE_UNKNOWN


def _endpoint_configuration_evidence(
    endpoint_configuration: Mapping[str, Any] | None,
    endpoint_types: list[str],
    vpc_endpoint_ids: list[str],
) -> dict[str, Any] | None:
    if endpoint_configuration is None and not endpoint_types and not vpc_endpoint_ids:
        return None
    evidence = dict(endpoint_configuration or {})
    if endpoint_types:
        evidence["types"] = endpoint_types
    if vpc_endpoint_ids:
        evidence["vpc_endpoint_ids"] = vpc_endpoint_ids
    return _compact_record(evidence)


def _api_gateway_cors_configuration(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> dict[str, Any] | None:
    cors, unknown_block = _first_api_gateway_block(values, unknown_values, "cors_configuration", uncertainties)
    if cors is None:
        return None
    unknown_fields: list[str] = []
    allow_credentials = known_block_bool(
        cors,
        unknown_block,
        "allow_credentials",
        uncertainties,
        path="cors_configuration",
        unknown_fields=unknown_fields,
    )
    allow_headers = known_block_strings(
        cors,
        unknown_block,
        "allow_headers",
        uncertainties,
        path="cors_configuration",
        unknown_fields=unknown_fields,
    )
    allow_methods = known_block_strings(
        cors,
        unknown_block,
        "allow_methods",
        uncertainties,
        path="cors_configuration",
        unknown_fields=unknown_fields,
    )
    allow_origins = known_block_strings(
        cors,
        unknown_block,
        "allow_origins",
        uncertainties,
        path="cors_configuration",
        unknown_fields=unknown_fields,
    )
    expose_headers = known_block_strings(
        cors,
        unknown_block,
        "expose_headers",
        uncertainties,
        path="cors_configuration",
        unknown_fields=unknown_fields,
    )
    max_age = known_block_int(
        cors,
        unknown_block,
        "max_age",
        uncertainties,
        path="cors_configuration",
        unknown_fields=unknown_fields,
    )
    return _compact_record(
        {
            "allow_credentials": allow_credentials,
            "allow_headers": allow_headers,
            "allow_methods": allow_methods,
            "allow_origins": allow_origins,
            "expose_headers": expose_headers,
            "max_age": max_age,
        }
    )


def _first_api_gateway_block(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
) -> tuple[Mapping[str, Any] | None, Any]:
    unknown_value = unknown_values.get(key) if isinstance(unknown_values, Mapping) else None
    if unknown_value is True:
        uncertainties.append(f"{key} is unknown after planning")
        return None, True
    raw = values.get(key)
    unknown_block = unknown_block_at(unknown_value, 0)
    if raw in (None, [], {}):
        if unknown_block not in (None, False, [], {}):
            return {}, unknown_block
        return None, unknown_block
    block = first_mapping(raw, expand_tuples=True)
    if block is None:
        uncertainties.append(f"{key} has an unrecognized value shape")
    return block, unknown_block


def _compact_record(values: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value not in (None, [], {}, "")}


def _set_public_endpoint_reasons(resource: NormalizedResource, public_endpoint_state: str, reason: str) -> None:
    reasons = [reason] if public_endpoint_state == STATE_ENABLED else []
    mutations = aws_mutations(resource)
    mutations.set_public_access_reasons(reasons)
    mutations.set_public_exposure_reasons(reasons)


def normalize_api_gateway_method(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    api_id = known_string(values, unknown_values, "rest_api_id", uncertainties)
    resource_id = known_string(values, unknown_values, "resource_id", uncertainties)
    http_method = known_string(values, unknown_values, "http_method", uncertainties)
    authorization_type = known_string(values, unknown_values, "authorization", uncertainties)
    authorizer_id = known_string(values, unknown_values, "authorizer_id", uncertainties)
    authorization_scopes = known_string_list(values, unknown_values, "authorization_scopes", uncertainties)

    return _api_gateway_child_resource(
        resource,
        api_id=api_id,
        identifier=_api_gateway_child_identifier(
            api_id,
            resource_id,
            http_method,
            fallback=resource.address,
        ),
        metadata={
            AwsResourceMetadata.API_GATEWAY_METHOD_RESOURCE_ID: resource_id,
            AwsResourceMetadata.API_GATEWAY_METHOD_HTTP_METHOD: http_method,
            AwsResourceMetadata.API_GATEWAY_AUTHORIZATION_TYPE: authorization_type,
            AwsResourceMetadata.API_GATEWAY_AUTHORIZER_ID: authorizer_id,
            AwsResourceMetadata.API_GATEWAY_AUTHORIZATION_SCOPES: authorization_scopes,
        },
        uncertainties=uncertainties,
    )


def normalize_api_gateway_stage(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    api_id = known_string(values, unknown_values, "rest_api_id", uncertainties)
    stage_name = known_string(values, unknown_values, "stage_name", uncertainties)
    destination_arn, log_format = _api_gateway_access_log_settings(values, unknown_values, uncertainties)

    return _api_gateway_child_resource(
        resource,
        api_id=api_id,
        identifier=_api_gateway_child_identifier(api_id, stage_name, fallback=resource.address),
        metadata={
            AwsResourceMetadata.API_GATEWAY_STAGE_NAME: stage_name,
            AwsResourceMetadata.API_GATEWAY_ACCESS_LOG_DESTINATION_ARN: destination_arn,
            AwsResourceMetadata.API_GATEWAY_ACCESS_LOG_FORMAT: log_format,
        },
        uncertainties=uncertainties,
    )


def normalize_api_gateway_authorizer(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    api_id = known_string(values, unknown_values, "rest_api_id", uncertainties)
    authorizer_id = known_string(values, unknown_values, "id", uncertainties)
    name = known_string(values, unknown_values, "name", uncertainties) or resource.name
    authorizer_type = known_string(values, unknown_values, "type", uncertainties)
    authorizer_uri = known_string(values, unknown_values, "authorizer_uri", uncertainties)
    authorizer_credentials = known_string(values, unknown_values, "authorizer_credentials", uncertainties)
    identity_source = known_string(values, unknown_values, "identity_source", uncertainties)
    identity_validation_expression = known_string(
        values,
        unknown_values,
        "identity_validation_expression",
        uncertainties,
    )
    provider_arns = known_string_list(values, unknown_values, "provider_arns", uncertainties)
    result_ttl = _known_api_gateway_int(
        values,
        unknown_values,
        "authorizer_result_ttl_in_seconds",
        uncertainties,
    )

    return _api_gateway_child_resource(
        resource,
        api_id=api_id,
        identifier=_api_gateway_child_identifier(api_id, authorizer_id or name, fallback=resource.address),
        metadata={
            AwsResourceMetadata.API_GATEWAY_AUTHORIZER_ID: authorizer_id,
            AwsResourceMetadata.API_GATEWAY_AUTHORIZER_NAME: name,
            AwsResourceMetadata.API_GATEWAY_AUTHORIZER_TYPE: authorizer_type,
            AwsResourceMetadata.API_GATEWAY_AUTHORIZER_URI: authorizer_uri,
            AwsResourceMetadata.API_GATEWAY_AUTHORIZER_CREDENTIALS: authorizer_credentials,
            AwsResourceMetadata.API_GATEWAY_IDENTITY_SOURCE: identity_source,
            AwsResourceMetadata.API_GATEWAY_IDENTITY_VALIDATION_EXPRESSION: identity_validation_expression,
            AwsResourceMetadata.API_GATEWAY_AUTHORIZER_PROVIDER_ARNS: provider_arns,
            AwsResourceMetadata.API_GATEWAY_AUTHORIZER_RESULT_TTL: result_ttl,
        },
        uncertainties=uncertainties,
    )


def normalize_apigatewayv2_route(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    api_id = known_string(values, unknown_values, "api_id", uncertainties)
    route_key = known_string(values, unknown_values, "route_key", uncertainties)
    authorization_type = known_string(values, unknown_values, "authorization_type", uncertainties)
    authorizer_id = known_string(values, unknown_values, "authorizer_id", uncertainties)
    authorization_scopes = known_string_list(values, unknown_values, "authorization_scopes", uncertainties)

    return _api_gateway_child_resource(
        resource,
        api_id=api_id,
        identifier=_api_gateway_child_identifier(api_id, route_key, fallback=resource.address),
        metadata={
            AwsResourceMetadata.API_GATEWAY_ROUTE_KEY: route_key,
            AwsResourceMetadata.API_GATEWAY_AUTHORIZATION_TYPE: authorization_type,
            AwsResourceMetadata.API_GATEWAY_AUTHORIZER_ID: authorizer_id,
            AwsResourceMetadata.API_GATEWAY_AUTHORIZATION_SCOPES: authorization_scopes,
        },
        uncertainties=uncertainties,
    )


def normalize_apigatewayv2_stage(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    api_id = known_string(values, unknown_values, "api_id", uncertainties)
    stage_name = known_string(values, unknown_values, "name", uncertainties)
    destination_arn, log_format = _api_gateway_access_log_settings(values, unknown_values, uncertainties)

    return _api_gateway_child_resource(
        resource,
        api_id=api_id,
        identifier=_api_gateway_child_identifier(api_id, stage_name, fallback=resource.address),
        metadata={
            AwsResourceMetadata.API_GATEWAY_STAGE_NAME: stage_name,
            AwsResourceMetadata.API_GATEWAY_ACCESS_LOG_DESTINATION_ARN: destination_arn,
            AwsResourceMetadata.API_GATEWAY_ACCESS_LOG_FORMAT: log_format,
        },
        uncertainties=uncertainties,
    )


def _api_gateway_child_resource(
    resource: TerraformResource,
    *,
    api_id: str | None,
    identifier: str,
    metadata: dict[object, Any],
    uncertainties: list[str],
) -> NormalizedResource:
    child_metadata: dict[object, Any] = {
        AwsResourceMetadata.API_GATEWAY_API_ID: api_id,
        AwsResourceMetadata.API_GATEWAY_POSTURE_UNCERTAINTIES: uncertainties,
        "tags": resource.values.get("tags", {}),
    }
    child_metadata.update(metadata)
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=identifier,
        metadata=child_metadata,
    )


def _api_gateway_child_identifier(
    api_id: str | None,
    *components: str | None,
    fallback: str,
) -> str:
    known_components = [component for component in components if component]
    if api_id and known_components:
        return ":".join((api_id, *known_components))
    return api_id or next(iter(known_components), fallback)


def _api_gateway_access_log_settings(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    uncertainties: list[str],
) -> tuple[str | None, str | None]:
    settings, unknown_block = _first_api_gateway_block(values, unknown_values, "access_log_settings", uncertainties)
    if settings is None:
        return None, None
    destination_arn = known_block_string(
        settings,
        unknown_block,
        "destination_arn",
        uncertainties,
        path="access_log_settings",
    )
    log_format = known_block_string(
        settings,
        unknown_block,
        "format",
        uncertainties,
        path="access_log_settings",
    )
    return destination_arn, log_format


def _known_api_gateway_int(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
) -> int | None:
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{key} is unknown after planning")
        return None
    value = values.get(key)
    if value is None:
        return None
    parsed = as_optional_int(value)
    if parsed is None or isinstance(value, bool):
        uncertainties.append(f"{key} has an unrecognized value shape")
        return None
    return parsed
