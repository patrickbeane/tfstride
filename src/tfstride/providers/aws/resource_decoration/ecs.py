from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext
from tfstride.providers.aws.resource_mutations import aws_mutations


class ResolveEcsServiceRelationshipsStage:
    name = "resolve_ecs_service_relationships"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for ecs_service_resource in resources:
            if ecs_service_resource.resource_type != "aws_ecs_service":
                continue
            cluster_ref = aws_facts(ecs_service_resource).cluster_reference
            if cluster_ref:
                cluster = context.index.ecs_clusters.get(cluster_ref)
                if cluster is None:
                    aws_facts(ecs_service_resource).add_unresolved_cluster_reference(
                        str(cluster_ref)
                    )
                else:
                    aws_facts(ecs_service_resource).add_resolved_cluster_address(
                        cluster.address
                    )

            task_definition_ref = aws_facts(ecs_service_resource).task_definition_reference
            if not task_definition_ref:
                continue
            task_definition = context.index.ecs_task_definitions.get(task_definition_ref)
            if task_definition is None:
                aws_facts(ecs_service_resource).add_unresolved_task_definition_reference(
                    str(task_definition_ref)
                )
                continue
            aws_facts(ecs_service_resource).add_resolved_task_definition_address(
                task_definition.address
            )
            aws_facts(ecs_service_resource).set_network_mode(
                aws_facts(task_definition).network_mode
            )
            aws_facts(ecs_service_resource).set_requires_compatibilities(
                aws_facts(task_definition).requires_compatibilities
            )
            task_role_arn = aws_facts(task_definition).task_role_arn
            execution_role_arn = aws_facts(task_definition).execution_role_arn
            if task_role_arn:
                aws_facts(ecs_service_resource).set_task_role_arn(task_role_arn)
                aws_mutations(ecs_service_resource).attach_role_arn(task_role_arn)
                task_role = context.index.role_index.get(task_role_arn)
                if task_role is not None:
                    aws_facts(ecs_service_resource).add_resolved_task_role_address(
                        task_role.address
                    )
                else:
                    aws_facts(ecs_service_resource).add_unresolved_task_role_arn(
                        str(task_role_arn)
                    )
            if execution_role_arn:
                aws_facts(ecs_service_resource).set_execution_role_arn(execution_role_arn)
                execution_role = context.index.role_index.get(execution_role_arn)
                if execution_role is not None:
                    aws_facts(ecs_service_resource).add_resolved_execution_role_address(
                        execution_role.address
                    )
                else:
                    aws_facts(ecs_service_resource).add_unresolved_execution_role_arn(
                        str(execution_role_arn)
                    )


class MarkEcsLoadBalancerExposureStage:
    name = "mark_ecs_services_fronted_by_internet_facing_load_balancers"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        internet_facing_load_balancers_by_security_group: dict[
            str,
            list[NormalizedResource],
        ] = {}
        for resource in resources:
            if resource.resource_type != "aws_lb" or not resource.public_exposure:
                continue
            for security_group_id in resource.security_group_ids:
                internet_facing_load_balancers_by_security_group.setdefault(
                    security_group_id,
                    [],
                ).append(resource)

        for resource in resources:
            if resource.resource_type != "aws_ecs_service":
                continue
            fronting_load_balancers: list[str] = []
            seen_load_balancers: set[str] = set()
            attached_security_groups = [
                context.index.security_groups[sg_id]
                for sg_id in resource.security_group_ids
                if sg_id in context.index.security_groups
            ]
            for security_group in attached_security_groups:
                for rule in security_group.network_rules:
                    if rule.direction != "ingress":
                        continue
                    for security_group_id in rule.referenced_security_group_ids:
                        for load_balancer in internet_facing_load_balancers_by_security_group.get(
                            security_group_id,
                            [],
                        ):
                            if load_balancer.address in seen_load_balancers:
                                continue
                            seen_load_balancers.add(load_balancer.address)
                            fronting_load_balancers.append(load_balancer.address)
            aws_facts(resource).set_fronted_by_internet_facing_load_balancer(
                bool(fronting_load_balancers)
            )
            if fronting_load_balancers:
                aws_facts(resource).set_internet_facing_load_balancer_addresses(
                    fronting_load_balancers
                )