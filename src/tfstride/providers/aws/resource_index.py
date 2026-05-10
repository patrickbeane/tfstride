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
        return AwsResourceIndex(
            subnets={resource.identifier: resource for resource in resources if resource.resource_type == "aws_subnet"},
            security_groups={
                resource.identifier: resource for resource in resources if resource.resource_type == "aws_security_group"
            },
            route_tables={
                resource.identifier: resource for resource in resources if resource.resource_type == "aws_route_table"
            },
            buckets={
                key: resource
                for resource in resources
                if resource.resource_type == "aws_s3_bucket"
                for key in (resource.identifier, resource.address, resource.arn)
                if key
            },
            secrets={
                key: resource
                for resource in resources
                if resource.resource_type == "aws_secretsmanager_secret"
                for key in (resource.identifier, resource.address, resource.arn, resource.secret_name)
                if key
            },
            lambda_functions={
                key: resource
                for resource in resources
                if resource.resource_type == "aws_lambda_function"
                for key in (resource.identifier, resource.address, resource.arn)
                if key
            },
            ecs_clusters={
                key: resource
                for resource in resources
                if resource.resource_type == "aws_ecs_cluster"
                for key in (resource.identifier, resource.address, resource.arn, resource.cluster_name)
                if key
            },
            ecs_task_definitions={
                key: resource
                for resource in resources
                if resource.resource_type == "aws_ecs_task_definition"
                for key in (
                    resource.identifier,
                    resource.address,
                    resource.arn,
                    resource.task_definition_family,
                    ecs_task_definition_identifier(
                        resource.task_definition_family,
                        resource.task_definition_revision,
                    ),
                )
                if key
            },
            role_index={
                key: resource
                for resource in resources
                if resource.resource_type == "aws_iam_role"
                for key in (resource.identifier, resource.address, resource.arn)
                if key
            },
            instance_profile_index={
                key: resource
                for resource in resources
                if resource.resource_type == "aws_iam_instance_profile"
                for key in (resource.identifier, resource.address, resource.arn)
                if key
            },
            policy_index={
                key: resource
                for resource in resources
                if resource.resource_type == "aws_iam_policy"
                for key in (resource.identifier, resource.address, resource.arn)
                if key
            },
            vpcs_with_igw={
                resource.vpc_id
                for resource in resources
                if resource.resource_type == "aws_internet_gateway" and resource.vpc_id
            },
            vpcs_with_public_routes={
                resource.vpc_id
                for resource in resources
                if resource.resource_type == "aws_route_table"
                and resource.vpc_id
                and route_table_has_internet_route(resource.routes)
            },
            nat_gateway_ids={
                resource.identifier
                for resource in resources
                if resource.resource_type == "aws_nat_gateway" and resource.identifier
            },
        )
