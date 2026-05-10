from __future__ import annotations

from dataclasses import dataclass, field

from tfstride.models import NormalizedResource
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
    lambda_functions: dict[str, NormalizedResource]
    ecs_clusters: dict[str, NormalizedResource]
    ecs_task_definitions: dict[str, NormalizedResource]
    role_index: dict[str, NormalizedResource]
    instance_profile_index: dict[str, NormalizedResource]
    policy_index: dict[str, NormalizedResource]
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
        lambda_functions: dict[str, NormalizedResource] = {}
        ecs_clusters: dict[str, NormalizedResource] = {}
        ecs_task_definitions: dict[str, NormalizedResource] = {}
        role_index: dict[str, NormalizedResource] = {}
        instance_profile_index: dict[str, NormalizedResource] = {}
        policy_index: dict[str, NormalizedResource] = {}
        vpcs_with_igw: set[str] = set()
        vpcs_with_public_routes: set[str] = set()
        nat_gateway_ids: set[str] = set()

        for resource in resources:
            resource_type = resource.resource_type
            if resource_type == "aws_subnet":
                subnets[resource.identifier] = resource
            elif resource_type == "aws_security_group":
                security_groups[resource.identifier] = resource
            elif resource_type == "aws_route_table":
                route_tables[resource.identifier] = resource
                if resource.vpc_id and route_table_has_internet_route(resource.routes):
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
                    (resource.identifier, resource.address, resource.arn, resource.secret_name),
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
                    (resource.identifier, resource.address, resource.arn, resource.cluster_name),
                )
            elif resource_type == "aws_ecs_task_definition":
                _index_resource_aliases(
                    ecs_task_definitions,
                    resource,
                    (
                        resource.identifier,
                        resource.address,
                        resource.arn,
                        resource.task_definition_family,
                        ecs_task_definition_identifier(
                            resource.task_definition_family,
                            resource.task_definition_revision,
                        ),
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
            lambda_functions=lambda_functions,
            ecs_clusters=ecs_clusters,
            ecs_task_definitions=ecs_task_definitions,
            role_index=role_index,
            instance_profile_index=instance_profile_index,
            policy_index=policy_index,
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
