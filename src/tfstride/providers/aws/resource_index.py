from __future__ import annotations

from dataclasses import dataclass, field

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_utils import (
    ecs_task_definition_identifier,
    route_table_has_internet_route,
)


@dataclass(slots=True)
class AwsResourceIndex:
    subnets: dict[str | None, NormalizedResource]
    security_groups: dict[str | None, NormalizedResource]
    route_tables: dict[str | None, NormalizedResource]
    buckets: dict[str, NormalizedResource]
    secrets: dict[str, NormalizedResource]
    sqs_queues: dict[str, NormalizedResource]
    lambda_functions: dict[str, NormalizedResource]
    ecs_clusters: dict[str, NormalizedResource]
    ecs_task_definitions: dict[str, NormalizedResource]
    load_balancers: dict[str, NormalizedResource]
    load_balancer_listeners: dict[str, NormalizedResource]
    load_balancer_listener_rules: tuple[NormalizedResource, ...]
    load_balancer_target_groups: dict[str, NormalizedResource]
    role_index: dict[str, NormalizedResource]
    instance_profile_index: dict[str, NormalizedResource]
    policy_index: dict[str, NormalizedResource]
    api_gateway_rest_apis: dict[str, NormalizedResource]
    apigatewayv2_apis: dict[str, NormalizedResource]
    vpcs_with_igw: set[str]
    vpcs_with_public_routes: set[str]
    nat_gateway_ids: set[str]


@dataclass(slots=True)
class AwsDecorationContext:
    index: AwsResourceIndex
    public_subnet_ids: set[str] = field(default_factory=set)


class AwsResourceIndexBuilder:
    def build(self, resources: list[NormalizedResource]) -> AwsResourceIndex:
        subnets: dict[str | None, NormalizedResource] = {}
        security_groups: dict[str | None, NormalizedResource] = {}
        route_tables: dict[str | None, NormalizedResource] = {}
        buckets: dict[str, NormalizedResource] = {}
        secrets: dict[str, NormalizedResource] = {}
        sqs_queues: dict[str, NormalizedResource] = {}
        lambda_functions: dict[str, NormalizedResource] = {}
        ecs_clusters: dict[str, NormalizedResource] = {}
        ecs_task_definitions: dict[str, NormalizedResource] = {}
        load_balancers: dict[str, NormalizedResource] = {}
        load_balancer_listeners: dict[str, NormalizedResource] = {}
        load_balancer_listener_rules: list[NormalizedResource] = []
        load_balancer_target_groups: dict[str, NormalizedResource] = {}
        role_index: dict[str, NormalizedResource] = {}
        instance_profile_index: dict[str, NormalizedResource] = {}
        policy_index: dict[str, NormalizedResource] = {}
        api_gateway_rest_apis: dict[str, NormalizedResource] = {}
        apigatewayv2_apis: dict[str, NormalizedResource] = {}
        vpcs_with_igw: set[str] = set()
        vpcs_with_public_routes: set[str] = set()
        nat_gateway_ids: set[str] = set()

        for resource in resources:
            resource_type = resource.resource_type
            facts = aws_facts(resource)
            if resource_type == "aws_subnet":
                subnets[resource.identifier] = resource
            elif resource_type == "aws_security_group":
                security_groups[resource.identifier] = resource
            elif resource_type == "aws_route_table":
                route_tables[resource.identifier] = resource
                if resource.vpc_id and route_table_has_internet_route(facts.routes):
                    vpcs_with_public_routes.add(resource.vpc_id)
            elif resource_type == "aws_s3_bucket":
                _index_resource_aliases(
                    buckets,
                    resource,
                    (resource.identifier, resource.address, resource.arn),
                )
            elif resource_type == "aws_secretsmanager_secret":
                _index_resource_aliases(
                    secrets,
                    resource,
                    (
                        resource.identifier,
                        resource.address,
                        f"{resource.address}.id",
                        f"{resource.address}.arn",
                        resource.arn,
                        facts.name,
                    ),
                )
            elif resource_type == "aws_sqs_queue":
                _index_resource_aliases(
                    sqs_queues,
                    resource,
                    (
                        resource.address,
                        f"{resource.address}.id",
                        f"{resource.address}.url",
                        facts.sqs_queue_url,
                    ),
                )
            elif resource_type == "aws_lambda_function":
                _index_resource_aliases(
                    lambda_functions,
                    resource,
                    (resource.identifier, resource.address, resource.arn),
                )
            elif resource_type == "aws_ecs_cluster":
                _index_resource_aliases(
                    ecs_clusters,
                    resource,
                    (
                        resource.identifier,
                        resource.address,
                        resource.arn,
                        facts.name,
                    ),
                )
            elif resource_type == "aws_ecs_task_definition":
                _index_resource_aliases(
                    ecs_task_definitions,
                    resource,
                    (
                        resource.identifier,
                        resource.address,
                        resource.arn,
                        facts.task_definition_family,
                        ecs_task_definition_identifier(
                            facts.task_definition_family,
                            facts.task_definition_revision,
                        ),
                    ),
                )
            elif resource_type == "aws_lb":
                _index_resource_aliases(
                    load_balancers,
                    resource,
                    (
                        resource.identifier,
                        resource.address,
                        f"{resource.address}.id",
                        f"{resource.address}.arn",
                        resource.arn,
                        resource.name,
                    ),
                )
            elif resource_type == "aws_lb_listener":
                _index_resource_aliases(
                    load_balancer_listeners,
                    resource,
                    (
                        resource.identifier,
                        resource.address,
                        f"{resource.address}.id",
                        f"{resource.address}.arn",
                        resource.arn,
                    ),
                )
            elif resource_type == "aws_lb_listener_rule":
                load_balancer_listener_rules.append(resource)
            elif resource_type == "aws_lb_target_group":
                _index_resource_aliases(
                    load_balancer_target_groups,
                    resource,
                    (
                        resource.identifier,
                        resource.address,
                        f"{resource.address}.id",
                        f"{resource.address}.arn",
                        f"{resource.address}.name",
                        resource.arn,
                        resource.name,
                        aws_facts(resource).name,
                    ),
                )
            elif resource_type == "aws_iam_role":
                _index_resource_aliases(
                    role_index,
                    resource,
                    (resource.identifier, resource.address, resource.arn),
                )
            elif resource_type == "aws_iam_instance_profile":
                _index_resource_aliases(
                    instance_profile_index,
                    resource,
                    (resource.identifier, resource.address, resource.arn),
                )
            elif resource_type == "aws_iam_policy":
                _index_resource_aliases(
                    policy_index,
                    resource,
                    (resource.identifier, resource.address, resource.arn),
                )
            elif resource_type == "aws_api_gateway_rest_api" and facts.api_gateway_api_id:
                api_gateway_rest_apis[facts.api_gateway_api_id] = resource
            elif resource_type == "aws_apigatewayv2_api" and facts.api_gateway_api_id:
                apigatewayv2_apis[facts.api_gateway_api_id] = resource
            elif resource_type == "aws_internet_gateway":
                if resource.vpc_id:
                    vpcs_with_igw.add(resource.vpc_id)
            elif resource_type == "aws_nat_gateway":
                if resource.identifier:
                    nat_gateway_ids.add(resource.identifier)

        return AwsResourceIndex(
            subnets=subnets,
            security_groups=security_groups,
            route_tables=route_tables,
            buckets=buckets,
            secrets=secrets,
            sqs_queues=sqs_queues,
            lambda_functions=lambda_functions,
            ecs_clusters=ecs_clusters,
            ecs_task_definitions=ecs_task_definitions,
            load_balancers=load_balancers,
            load_balancer_listeners=load_balancer_listeners,
            load_balancer_listener_rules=tuple(load_balancer_listener_rules),
            load_balancer_target_groups=load_balancer_target_groups,
            role_index=role_index,
            instance_profile_index=instance_profile_index,
            policy_index=policy_index,
            api_gateway_rest_apis=api_gateway_rest_apis,
            apigatewayv2_apis=apigatewayv2_apis,
            vpcs_with_igw=vpcs_with_igw,
            vpcs_with_public_routes=vpcs_with_public_routes,
            nat_gateway_ids=nat_gateway_ids,
        )


def _index_resource_aliases(
    index: dict[str, NormalizedResource],
    resource: NormalizedResource,
    aliases: tuple[str | None, ...],
) -> None:
    for alias in aliases:
        if alias:
            index[alias] = resource
