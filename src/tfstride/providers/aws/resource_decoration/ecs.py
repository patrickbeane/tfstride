from __future__ import annotations

from typing import TypeGuard

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import (
    AwsDecorationContext,
    AwsReferenceRelationshipKey,
    AwsResourceIndex,
    aws_reference_relationship_key,
)
from tfstride.providers.aws.resource_mutations import aws_mutations
from tfstride.providers.coercion import append_unique, dedupe


class ResolveEcsServiceRelationshipsStage:
    name = "resolve_ecs_service_relationships"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        for ecs_service_resource in resources:
            if ecs_service_resource.resource_type != "aws_ecs_service":
                continue
            cluster_ref = aws_facts(ecs_service_resource).cluster_reference
            if cluster_ref:
                cluster = context.index.ecs_clusters.get(cluster_ref, source=ecs_service_resource)
                if cluster is None:
                    aws_facts(ecs_service_resource).add_unresolved_cluster_reference(str(cluster_ref))
                else:
                    aws_facts(ecs_service_resource).add_resolved_cluster_address(cluster.address)

            task_definition_ref = aws_facts(ecs_service_resource).task_definition_reference
            if not task_definition_ref:
                continue
            task_definition = context.index.ecs_task_definitions.get(task_definition_ref, source=ecs_service_resource)
            if task_definition is None:
                aws_facts(ecs_service_resource).add_unresolved_task_definition_reference(str(task_definition_ref))
                continue
            aws_facts(ecs_service_resource).add_resolved_task_definition_address(task_definition.address)
            aws_facts(ecs_service_resource).set_network_mode(aws_facts(task_definition).network_mode)
            aws_facts(ecs_service_resource).set_requires_compatibilities(
                aws_facts(task_definition).requires_compatibilities
            )
            task_role_arn = aws_facts(task_definition).task_role_arn
            execution_role_arn = aws_facts(task_definition).execution_role_arn
            if task_role_arn:
                aws_facts(ecs_service_resource).set_task_role_arn(task_role_arn)
                aws_mutations(ecs_service_resource).attach_role_arn(task_role_arn)
                task_role = context.index.role_index.get(task_role_arn, source=task_definition)
                if task_role is not None:
                    aws_facts(ecs_service_resource).add_resolved_task_role_address(task_role.address)
                else:
                    aws_facts(ecs_service_resource).add_unresolved_task_role_arn(str(task_role_arn))
            if execution_role_arn:
                aws_facts(ecs_service_resource).set_execution_role_arn(execution_role_arn)
                execution_role = context.index.role_index.get(execution_role_arn, source=task_definition)
                if execution_role is not None:
                    aws_facts(ecs_service_resource).add_resolved_execution_role_address(execution_role.address)
                else:
                    aws_facts(ecs_service_resource).add_unresolved_execution_role_arn(str(execution_role_arn))


class MarkEcsLoadBalancerExposureStage:
    name = "mark_ecs_services_fronted_by_internet_facing_load_balancers"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        public_load_balancers_by_target_group = _internet_facing_load_balancer_addresses_by_target_group(context.index)
        public_load_balancers_by_security_group = _internet_facing_load_balancer_addresses_by_security_group(
            context.index
        )

        for resource in resources:
            if resource.resource_type != "aws_ecs_service":
                continue
            fronting_load_balancers = _fronting_load_balancers_for_ecs_service(
                resource,
                context.index,
                public_load_balancers_by_target_group,
                public_load_balancers_by_security_group,
            )
            aws_facts(resource).set_fronted_by_internet_facing_load_balancer(bool(fronting_load_balancers))
            if fronting_load_balancers:
                aws_facts(resource).set_internet_facing_load_balancer_addresses(fronting_load_balancers)


def _internet_facing_load_balancer_addresses_by_target_group(
    index: AwsResourceIndex,
) -> dict[AwsReferenceRelationshipKey, list[str]]:
    load_balancers_by_target_group: dict[AwsReferenceRelationshipKey, list[str]] = {}
    for listener in index.load_balancer_listeners.resources:
        load_balancer = _listener_load_balancer(listener, index)
        if not _is_internet_facing_load_balancer(load_balancer):
            continue
        for target_group_reference in aws_facts(listener).load_balancer_target_group_arns:
            _append_load_balancer_target_group_references(
                load_balancers_by_target_group,
                index,
                target_group_reference,
                load_balancer.address,
                source=listener,
            )

    for listener_rule in index.load_balancer_listener_rules:
        listener = index.load_balancer_listeners.get(
            aws_facts(listener_rule).listener_arn,
            source=listener_rule,
        )
        load_balancer = _listener_load_balancer(listener, index)
        if not _is_internet_facing_load_balancer(load_balancer):
            continue
        for target_group_reference in aws_facts(listener_rule).load_balancer_target_group_arns:
            _append_load_balancer_target_group_references(
                load_balancers_by_target_group,
                index,
                target_group_reference,
                load_balancer.address,
                source=listener_rule,
            )
    return load_balancers_by_target_group


def _internet_facing_load_balancer_addresses_by_security_group(
    index: AwsResourceIndex,
) -> dict[AwsReferenceRelationshipKey, list[str]]:
    load_balancers_by_security_group: dict[AwsReferenceRelationshipKey, list[str]] = {}
    for load_balancer in index.load_balancers.resources:
        if not _is_internet_facing_load_balancer(load_balancer):
            continue
        for security_group_id in load_balancer.security_group_ids:
            key = aws_reference_relationship_key(
                index.security_groups,
                security_group_id,
                source=load_balancer,
            )
            if key is not None:
                append_unique(
                    load_balancers_by_security_group.setdefault(key, []),
                    load_balancer.address,
                )
    return load_balancers_by_security_group


def _fronting_load_balancers_for_ecs_service(
    service: NormalizedResource,
    index: AwsResourceIndex,
    public_load_balancers_by_target_group: dict[AwsReferenceRelationshipKey, list[str]],
    public_load_balancers_by_security_group: dict[AwsReferenceRelationshipKey, list[str]],
) -> list[str]:
    fronting_load_balancers: list[str] = []
    for load_balancer_reference in _ecs_load_balancer_references(service):
        load_balancer = index.load_balancers.get(load_balancer_reference, source=service)
        if _is_internet_facing_load_balancer(load_balancer):
            append_unique(fronting_load_balancers, load_balancer.address)

    for target_group_reference in _ecs_target_group_references(service):
        key = aws_reference_relationship_key(
            index.load_balancer_target_groups,
            target_group_reference,
            source=service,
        )
        if key is None:
            continue
        for load_balancer_address in public_load_balancers_by_target_group.get(key, []):
            append_unique(fronting_load_balancers, load_balancer_address)

    for load_balancer_address in _security_group_fronting_load_balancers(
        service,
        index,
        public_load_balancers_by_security_group,
    ):
        append_unique(fronting_load_balancers, load_balancer_address)

    return fronting_load_balancers


def _security_group_fronting_load_balancers(
    service: NormalizedResource,
    index: AwsResourceIndex,
    public_load_balancers_by_security_group: dict[AwsReferenceRelationshipKey, list[str]],
) -> list[str]:
    fronting_load_balancers: list[str] = []
    security_group_references = dedupe(
        [*service.security_group_ids, *aws_facts(service).ecs_symbolic_security_group_addresses]
    )
    attached_security_groups = [
        security_group
        for security_group_id in security_group_references
        if (security_group := index.security_groups.get(security_group_id, source=service)) is not None
    ]
    for security_group in attached_security_groups:
        for rule in security_group.network_rules:
            if rule.direction != "ingress":
                continue
            for security_group_id in rule.referenced_security_group_ids:
                key = aws_reference_relationship_key(
                    index.security_groups,
                    security_group_id,
                    source=security_group,
                )
                if key is None:
                    continue
                for load_balancer_address in public_load_balancers_by_security_group.get(key, []):
                    append_unique(fronting_load_balancers, load_balancer_address)
    return fronting_load_balancers


def _append_load_balancer_target_group_references(
    load_balancers_by_target_group: dict[AwsReferenceRelationshipKey, list[str]],
    index: AwsResourceIndex,
    target_group_reference: str,
    load_balancer_address: str,
    *,
    source: NormalizedResource,
) -> None:
    key = aws_reference_relationship_key(
        index.load_balancer_target_groups,
        target_group_reference,
        source=source,
    )
    if key is not None:
        append_unique(
            load_balancers_by_target_group.setdefault(key, []),
            load_balancer_address,
        )


def _listener_load_balancer(
    listener: NormalizedResource | None,
    index: AwsResourceIndex,
) -> NormalizedResource | None:
    if listener is None:
        return None
    return index.load_balancers.get(
        aws_facts(listener).load_balancer_arn,
        source=listener,
    )


def _is_internet_facing_load_balancer(
    resource: NormalizedResource | None,
) -> TypeGuard[NormalizedResource]:
    return resource is not None and resource.resource_type == "aws_lb" and resource.public_exposure


def _ecs_target_group_references(service: NormalizedResource) -> list[str]:
    references: list[str] = []
    for load_balancer in aws_facts(service).ecs_load_balancers:
        target_group_arn = load_balancer.get("target_group_arn")
        if target_group_arn:
            references.append(str(target_group_arn))
    return dedupe(references)


def _ecs_load_balancer_references(service: NormalizedResource) -> list[str]:
    references: list[str] = []
    for load_balancer in aws_facts(service).ecs_load_balancers:
        elb_name = load_balancer.get("elb_name")
        if elb_name:
            references.append(str(elb_name))
    return dedupe(references)
