from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext, AwsResourceIndex
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
                    aws_facts(ecs_service_resource).add_unresolved_cluster_reference(str(cluster_ref))
                else:
                    aws_facts(ecs_service_resource).add_resolved_cluster_address(cluster.address)

            task_definition_ref = aws_facts(ecs_service_resource).task_definition_reference
            if not task_definition_ref:
                continue
            task_definition = context.index.ecs_task_definitions.get(task_definition_ref)
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
                task_role = context.index.role_index.get(task_role_arn)
                if task_role is not None:
                    aws_facts(ecs_service_resource).add_resolved_task_role_address(task_role.address)
                else:
                    aws_facts(ecs_service_resource).add_unresolved_task_role_arn(str(task_role_arn))
            if execution_role_arn:
                aws_facts(ecs_service_resource).set_execution_role_arn(execution_role_arn)
                execution_role = context.index.role_index.get(execution_role_arn)
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
) -> dict[str, list[str]]:
    load_balancers_by_target_group: dict[str, list[str]] = {}
    for listener in _unique_resources(index.load_balancer_listeners.values()):
        load_balancer = _listener_load_balancer(listener, index)
        if not _is_internet_facing_load_balancer(load_balancer):
            continue
        for target_group_reference in _metadata_string_list(listener, "target_group_arns"):
            _append_load_balancer_target_group_references(
                load_balancers_by_target_group,
                index,
                target_group_reference,
                load_balancer.address,
            )

    for listener_rule in index.load_balancer_listener_rules:
        listener = _resource_by_reference(
            index.load_balancer_listeners,
            _metadata_string(listener_rule, "listener_arn"),
        )
        load_balancer = _listener_load_balancer(listener, index)
        if not _is_internet_facing_load_balancer(load_balancer):
            continue
        for target_group_reference in _metadata_string_list(listener_rule, "target_group_arns"):
            _append_load_balancer_target_group_references(
                load_balancers_by_target_group,
                index,
                target_group_reference,
                load_balancer.address,
            )
    return load_balancers_by_target_group


def _internet_facing_load_balancer_addresses_by_security_group(
    index: AwsResourceIndex,
) -> dict[str, list[str]]:
    load_balancers_by_security_group: dict[str, list[str]] = {}
    for load_balancer in _unique_resources(index.load_balancers.values()):
        if not _is_internet_facing_load_balancer(load_balancer):
            continue
        for security_group_id in load_balancer.security_group_ids:
            _append_unique(
                load_balancers_by_security_group.setdefault(security_group_id, []),
                load_balancer.address,
            )
    return load_balancers_by_security_group


def _fronting_load_balancers_for_ecs_service(
    service: NormalizedResource,
    index: AwsResourceIndex,
    public_load_balancers_by_target_group: dict[str, list[str]],
    public_load_balancers_by_security_group: dict[str, list[str]],
) -> list[str]:
    fronting_load_balancers: list[str] = []
    for load_balancer_reference in _ecs_load_balancer_references(service):
        load_balancer = _resource_by_reference(index.load_balancers, load_balancer_reference)
        if _is_internet_facing_load_balancer(load_balancer):
            _append_unique(fronting_load_balancers, load_balancer.address)

    for target_group_reference in _ecs_target_group_references(service):
        target_group = _resource_by_reference(
            index.load_balancer_target_groups,
            target_group_reference,
        )
        references = _resource_reference_values(target_group) if target_group is not None else [target_group_reference]
        for reference in references:
            for load_balancer_address in public_load_balancers_by_target_group.get(
                reference,
                [],
            ):
                _append_unique(fronting_load_balancers, load_balancer_address)

    for load_balancer_address in _security_group_fronting_load_balancers(
        service,
        index,
        public_load_balancers_by_security_group,
    ):
        _append_unique(fronting_load_balancers, load_balancer_address)

    return fronting_load_balancers


def _security_group_fronting_load_balancers(
    service: NormalizedResource,
    index: AwsResourceIndex,
    public_load_balancers_by_security_group: dict[str, list[str]],
) -> list[str]:
    fronting_load_balancers: list[str] = []
    attached_security_groups = [
        index.security_groups[sg_id] for sg_id in service.security_group_ids if sg_id in index.security_groups
    ]
    for security_group in attached_security_groups:
        for rule in security_group.network_rules:
            if rule.direction != "ingress":
                continue
            for security_group_id in rule.referenced_security_group_ids:
                for load_balancer_address in public_load_balancers_by_security_group.get(
                    security_group_id,
                    [],
                ):
                    _append_unique(fronting_load_balancers, load_balancer_address)
    return fronting_load_balancers


def _append_load_balancer_target_group_references(
    load_balancers_by_target_group: dict[str, list[str]],
    index: AwsResourceIndex,
    target_group_reference: str,
    load_balancer_address: str,
) -> None:
    target_group = _resource_by_reference(
        index.load_balancer_target_groups,
        target_group_reference,
    )
    references = _resource_reference_values(target_group) if target_group is not None else [target_group_reference]
    for reference in references:
        _append_unique(
            load_balancers_by_target_group.setdefault(reference, []),
            load_balancer_address,
        )


def _listener_load_balancer(
    listener: NormalizedResource | None,
    index: AwsResourceIndex,
) -> NormalizedResource | None:
    if listener is None:
        return None
    return _resource_by_reference(
        index.load_balancers,
        _metadata_string(listener, "load_balancer_arn"),
    )


def _is_internet_facing_load_balancer(resource: NormalizedResource | None) -> bool:
    return resource is not None and resource.resource_type == "aws_lb" and resource.public_exposure


def _ecs_target_group_references(service: NormalizedResource) -> list[str]:
    references: list[str] = []
    for load_balancer in _metadata_dict_list(service, "load_balancers"):
        target_group_arn = load_balancer.get("target_group_arn")
        if target_group_arn:
            references.append(str(target_group_arn))
    return _dedupe(references)


def _ecs_load_balancer_references(service: NormalizedResource) -> list[str]:
    references: list[str] = []
    for load_balancer in _metadata_dict_list(service, "load_balancers"):
        elb_name = load_balancer.get("elb_name")
        if elb_name:
            references.append(str(elb_name))
    return _dedupe(references)


def _resource_by_reference(
    index: dict[str, NormalizedResource],
    reference: str | None,
) -> NormalizedResource | None:
    if not reference:
        return None
    return index.get(reference)


def _resource_reference_values(resource: NormalizedResource) -> list[str]:
    return _dedupe(
        [
            value
            for value in (
                resource.identifier,
                resource.address,
                resource.arn,
                resource.name,
                _metadata_string(resource, "name"),
            )
            if value
        ]
    )


def _metadata_string(resource: NormalizedResource, key: str) -> str | None:
    value = resource.metadata.get(key)
    if value in (None, "", []):
        return None
    return str(value)


def _metadata_string_list(resource: NormalizedResource, key: str) -> list[str]:
    value = resource.metadata.get(key)
    if value in (None, "", []):
        return []
    if isinstance(value, list):
        return _dedupe(str(item) for item in value if item not in (None, "", []))
    return [str(value)]


def _metadata_dict_list(resource: NormalizedResource, key: str) -> list[dict]:
    value = resource.metadata.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _unique_resources(resources) -> tuple[NormalizedResource, ...]:
    unique: list[NormalizedResource] = []
    seen: set[str] = set()
    for resource in resources:
        if resource.address in seen:
            continue
        seen.add(resource.address)
        unique.append(resource)
    return tuple(unique)


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _dedupe(values) -> list[str]:
    deduped: list[str] = []
    for value in values:
        if value in deduped:
            continue
        deduped.append(value)
    return deduped
