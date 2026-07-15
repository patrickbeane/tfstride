from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from tfstride.models import IAMPolicyStatement, NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.aws.coercion import as_bool, as_list, as_optional_int, compact, first_item
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.network_normalizers import AWS_PROVIDER
from tfstride.providers.aws.policy_documents import (
    compact_condition_entries,
    condition_entry,
    lambda_permission_principal_entries,
)
from tfstride.providers.aws.resource_mutations import aws_mutations
from tfstride.providers.aws.resource_utils import ecs_task_definition_identifier
from tfstride.providers.coercion import (
    attribute_unknown,
    first_mapping,
    known_block_bool_state,
    known_block_int,
    known_block_strings,
    known_string,
    value_is_unknown,
)
from tfstride.providers.container_images import ContainerImageReference, parse_container_image_reference


def normalize_instance(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    public_ip_requested = bool(values.get("associate_public_ip_address", False))
    public_access_reasons = ["instance requests an associated public IP address"] if public_ip_requested else []
    normalized = NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=values.get("id"),
        arn=values.get("arn"),
        subnet_ids=tuple(compact([values.get("subnet_id")])),
        security_group_ids=tuple(as_list(values.get("vpc_security_group_ids"))),
        public_access_configured=public_ip_requested,
        metadata={
            "ami": values.get("ami"),
            "instance_type": values.get("instance_type"),
            "associate_public_ip_address": public_ip_requested,
            "iam_instance_profile": values.get("iam_instance_profile"),
            "tags": values.get("tags", {}),
        },
    )
    mutations = aws_mutations(normalized)
    mutations.set_public_access_reasons(public_access_reasons)
    mutations.set_public_exposure_reasons([])
    return normalized


def normalize_ecs_cluster(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=values.get("name") or values.get("id"),
        arn=values.get("arn"),
        metadata={
            "name": values.get("name"),
            "capacity_providers": as_list(values.get("capacity_providers")),
        },
    )


def normalize_ecs_task_definition(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    revision = as_optional_int(values.get("revision"))
    image_references, image_uncertainties = _ecs_container_image_references(resource)
    family = values.get("family")
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=ecs_task_definition_identifier(family, revision) or values.get("id") or family,
        arn=values.get("arn"),
        metadata={
            "family": family,
            "revision": revision,
            "network_mode": values.get("network_mode"),
            "requires_compatibilities": compact(as_list(values.get("requires_compatibilities"))),
            "task_role_arn": values.get("task_role_arn"),
            "execution_role_arn": values.get("execution_role_arn"),
            AwsResourceMetadata.CONTAINER_IMAGE_REFERENCES: image_references,
            AwsResourceMetadata.CONTAINER_IMAGE_POSTURE_UNCERTAINTIES: image_uncertainties,
        },
    )


def normalize_ecs_service(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    network_configuration = first_item(values.get("network_configuration"))
    assign_public_ip = as_bool(network_configuration.get("assign_public_ip")) if network_configuration else False
    public_access_reasons = ["ECS service assigns public IPs to tasks"] if assign_public_ip else []
    normalized = NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=values.get("name") or values.get("id"),
        arn=values.get("arn"),
        subnet_ids=tuple(compact(network_configuration.get("subnets", []) if network_configuration else [])),
        security_group_ids=tuple(
            compact(network_configuration.get("security_groups", []) if network_configuration else [])
        ),
        public_access_configured=assign_public_ip,
        metadata={
            "cluster": values.get("cluster"),
            "task_definition": values.get("task_definition"),
            "desired_count": as_optional_int(values.get("desired_count")),
            "launch_type": values.get("launch_type"),
            "platform_version": values.get("platform_version"),
            "assign_public_ip": assign_public_ip,
            AwsResourceMetadata.ECS_LOAD_BALANCERS: as_list(values.get("load_balancer")),
        },
    )
    mutations = aws_mutations(normalized)
    mutations.set_public_access_reasons(public_access_reasons)
    mutations.set_public_exposure_reasons([])
    return normalized


def normalize_lambda_function(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    vpc_config = first_item(values.get("vpc_config"))
    uncertainties: list[str] = []
    package_type = known_string(values, unknown_values, "package_type", uncertainties, require_string=True)
    image_uri = known_string(values, unknown_values, "image_uri", uncertainties, require_string=True)
    package_type_unknown = attribute_unknown(unknown_values, "package_type")
    image_uri_unknown = attribute_unknown(unknown_values, "image_uri")
    image_references: list[dict[str, Any]] = []
    if package_type == "Image" or package_type_unknown or image_uri is not None or "image_uri" in values:
        image_reference = (
            _unknown_image_reference(image_uri) if image_uri_unknown else parse_container_image_reference(image_uri)
        )
        image_references.append(
            _aws_image_reference_record(
                image_reference,
                source="aws_lambda_function",
                path="image_uri",
                package_type=package_type,
            )
        )
        if not image_uri_unknown:
            _append_image_uncertainty(uncertainties, "image_uri", image_reference)

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=values.get("function_name") or values.get("id"),
        arn=values.get("arn"),
        subnet_ids=tuple(as_list(vpc_config.get("subnet_ids") if vpc_config else [])),
        security_group_ids=tuple(as_list(vpc_config.get("security_group_ids") if vpc_config else [])),
        attached_role_arns=compact([values.get("role")]),
        metadata={
            "runtime": values.get("runtime"),
            "handler": values.get("handler"),
            "vpc_enabled": bool(vpc_config),
            AwsResourceMetadata.LAMBDA_PACKAGE_TYPE: package_type,
            AwsResourceMetadata.CONTAINER_IMAGE_REFERENCES: image_references,
            AwsResourceMetadata.CONTAINER_IMAGE_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_lambda_function_url(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    function_name = known_string(values, unknown_values, "function_name", uncertainties)
    authorization_type = known_string(values, unknown_values, "authorization_type", uncertainties)
    function_url = known_string(values, unknown_values, "function_url", uncertainties)
    qualifier = known_string(values, unknown_values, "qualifier", uncertainties)
    invoke_mode = known_string(values, unknown_values, "invoke_mode", uncertainties)

    cors = first_mapping(values.get("cors"), scan_all=True)
    unknown_cors = first_mapping(unknown_values.get("cors"), scan_all=True)
    if cors is None and unknown_values.get("cors") is True:
        uncertainties.append("cors is unknown after planning")

    cors_allow_credentials_state = known_block_bool_state(
        cors,
        unknown_cors,
        "allow_credentials",
        uncertainties,
        path="cors",
    )
    cors_allow_headers = known_block_strings(cors, unknown_cors, "allow_headers", uncertainties, path="cors")
    cors_allow_methods = known_block_strings(cors, unknown_cors, "allow_methods", uncertainties, path="cors")
    cors_allow_origins = known_block_strings(cors, unknown_cors, "allow_origins", uncertainties, path="cors")
    cors_expose_headers = known_block_strings(cors, unknown_cors, "expose_headers", uncertainties, path="cors")
    cors_max_age = known_block_int(cors, unknown_cors, "max_age", uncertainties, path="cors")

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=function_url or values.get("url_id") or values.get("id") or function_name or resource.address,
        metadata={
            AwsResourceMetadata.FUNCTION_NAME: function_name,
            AwsResourceMetadata.LAMBDA_FUNCTION_URL: function_url,
            AwsResourceMetadata.LAMBDA_FUNCTION_URL_AUTHORIZATION_TYPE: authorization_type,
            AwsResourceMetadata.LAMBDA_FUNCTION_URL_QUALIFIER: qualifier,
            AwsResourceMetadata.LAMBDA_FUNCTION_URL_INVOKE_MODE: invoke_mode,
            AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS: _lambda_function_url_cors_evidence(cors),
            AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_ALLOW_CREDENTIALS_STATE: cors_allow_credentials_state,
            AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_ALLOW_HEADERS: cors_allow_headers,
            AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_ALLOW_METHODS: cors_allow_methods,
            AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_ALLOW_ORIGINS: cors_allow_origins,
            AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_EXPOSE_HEADERS: cors_expose_headers,
            AwsResourceMetadata.LAMBDA_FUNCTION_URL_CORS_MAX_AGE: cors_max_age,
            AwsResourceMetadata.LAMBDA_FUNCTION_URL_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def _lambda_function_url_cors_evidence(cors: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if cors is None:
        return None
    return {
        key: cors[key]
        for key in (
            "allow_credentials",
            "allow_headers",
            "allow_methods",
            "allow_origins",
            "expose_headers",
            "max_age",
        )
        if key in cors
    }


def _ecs_container_image_references(
    resource: TerraformResource,
) -> tuple[list[dict[str, Any]], list[str]]:
    values = resource.values
    unknown_values = resource.unknown_values
    raw_definitions = values.get("container_definitions")
    if unknown_values.get("container_definitions") is True:
        return [], ["container_definitions is unknown after planning"]
    if raw_definitions is None:
        return [], ["container_definitions is not represented in planned values"]

    if isinstance(raw_definitions, str):
        try:
            definitions = json.loads(raw_definitions)
        except json.JSONDecodeError:
            return [], ["container_definitions is not valid JSON"]
    else:
        definitions = raw_definitions

    if not isinstance(definitions, list):
        return [], ["container_definitions is not a JSON array"]

    references: list[dict[str, Any]] = []
    uncertainties: list[str] = []
    unknown_definition_values = unknown_values.get("container_definitions")
    for index, definition in enumerate(definitions):
        if not isinstance(definition, Mapping):
            uncertainties.append(f"container_definitions[{index}] is not an object")
            continue
        unknown_definition = (
            unknown_definition_values[index]
            if isinstance(unknown_definition_values, list) and index < len(unknown_definition_values)
            else None
        )
        if "image" not in definition:
            continue
        path = f"container_definitions[{index}].image"
        image_value = definition.get("image")
        image_reference = (
            _unknown_image_reference(image_value)
            if isinstance(unknown_definition, Mapping) and value_is_unknown(unknown_definition.get("image"))
            else parse_container_image_reference(image_value)
        )
        references.append(
            _aws_image_reference_record(
                image_reference,
                source="aws_ecs_task_definition",
                path=path,
            )
        )
        _append_image_uncertainty(uncertainties, path, image_reference)
    return references, uncertainties


def _unknown_image_reference(value: object) -> ContainerImageReference:
    return ContainerImageReference(
        raw=value if isinstance(value, str) else None,
        registry_host=None,
        repository=None,
        tag=None,
        digest=None,
        digest_pinned=None,
        unresolved_value=value,
        unresolved_reason="image reference is unknown after planning",
    )


def _aws_image_reference_record(
    reference: ContainerImageReference,
    *,
    source: str,
    path: str,
    package_type: str | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "source": source,
        "path": path,
        "raw": reference.raw,
        "registry_host": reference.registry_host,
        "repository": reference.repository,
        "tag": reference.tag,
        "digest": reference.digest,
        "digest_pinned": reference.digest_pinned,
        "is_resolved": reference.is_resolved,
    }
    if package_type is not None:
        record["package_type"] = package_type
    if reference.unresolved_value is not None:
        record["unresolved_value"] = reference.unresolved_value
    if reference.unresolved_reason is not None:
        record["unresolved_reason"] = reference.unresolved_reason

    if reference.registry_host and reference.repository:
        match = _ECR_REGISTRY_HOST_PATTERN.fullmatch(reference.registry_host.lower())
        if match:
            record.update(
                {
                    "ecr_account_id": match.group("account_id"),
                    "ecr_region": match.group("region"),
                    "ecr_repository_path": reference.repository,
                    "ecr_repository_url": f"{reference.registry_host.lower()}/{reference.repository}",
                }
            )
    return record


def _append_image_uncertainty(
    uncertainties: list[str],
    path: str,
    reference: ContainerImageReference,
) -> None:
    if reference.unresolved_reason:
        uncertainties.append(f"{path}: {reference.unresolved_reason}")


_ECR_REGISTRY_HOST_PATTERN = re.compile(
    r"^(?P<account_id>\d{12})\.dkr\.ecr\.(?P<region>[a-z0-9-]+)\.amazonaws\.com(?:\.cn)?$"
)


def normalize_lambda_permission(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    function_name = values.get("function_name") or values.get("function_arn")
    source_arn = values.get("source_arn")
    source_account = values.get("source_account")
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=values.get("statement_id") or values.get("id") or resource.address,
        policy_statements=[
            IAMPolicyStatement(
                effect="Allow",
                actions=compact([values.get("action")]),
                resources=compact([function_name]),
                principals=compact([values.get("principal")]),
                principal_entries=lambda_permission_principal_entries(values.get("principal")),
                conditions=compact_condition_entries(
                    [
                        condition_entry(
                            operator="ArnLike",
                            key="aws:SourceArn",
                            values=compact([source_arn]),
                        ),
                        condition_entry(
                            operator="StringEquals",
                            key="aws:SourceAccount",
                            values=compact([source_account]),
                        ),
                    ]
                ),
            )
        ],
        metadata={
            "function_name": function_name,
            "source_arn": source_arn,
            "source_account": source_account,
        },
    )
