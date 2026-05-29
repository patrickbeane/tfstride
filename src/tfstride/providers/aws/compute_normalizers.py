from __future__ import annotations

from tfstride.models import IAMPolicyStatement, NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.aws.coercion import as_bool, as_list, as_optional_int, compact, first_item
from tfstride.providers.aws.network_normalizers import AWS_PROVIDER
from tfstride.providers.aws.policy_documents import (
    compact_condition_entries,
    condition_entry,
    lambda_permission_principal_entries,
)
from tfstride.providers.aws.resource_utils import ecs_task_definition_identifier


def normalize_instance(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    public_ip_requested = bool(values.get("associate_public_ip_address", False))
    return NormalizedResource(
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
            "public_access_reasons": (
                ["instance requests an associated public IP address"]
                if public_ip_requested
                else []
            ),
            "public_exposure_reasons": [],
            "tags": values.get("tags", {}),
        },
    )


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
    family = values.get("family")
    revision = as_optional_int(values.get("revision"))
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
        },
    )


def normalize_ecs_service(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    network_configuration = first_item(values.get("network_configuration"))
    assign_public_ip = as_bool(network_configuration.get("assign_public_ip")) if network_configuration else False
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=values.get("name") or values.get("id"),
        arn=values.get("arn"),
        subnet_ids=tuple(compact(network_configuration.get("subnets", []) if network_configuration else [])),
        security_group_ids=tuple(compact(network_configuration.get("security_groups", []) if network_configuration else [])),
        public_access_configured=assign_public_ip,
        metadata={
            "cluster": values.get("cluster"),
            "task_definition": values.get("task_definition"),
            "desired_count": as_optional_int(values.get("desired_count")),
            "launch_type": values.get("launch_type"),
            "platform_version": values.get("platform_version"),
            "assign_public_ip": assign_public_ip,
            "load_balancers": as_list(values.get("load_balancer")),
            "public_access_reasons": (
                ["ECS service assigns public IPs to tasks"]
                if assign_public_ip
                else []
            ),
            "public_exposure_reasons": [],
        },
    )


def normalize_lambda_function(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    vpc_config = first_item(values.get("vpc_config"))
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
        },
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