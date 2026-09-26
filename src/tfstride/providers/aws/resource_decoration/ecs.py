from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.aws.listener_conditions import listener_request_witness
from tfstride.providers.aws.load_balancer_forwarding import forwarding_targets
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import (
    AwsDecorationContext,
    AwsResourceIndex,
    resolve_aws_network_reference,
)
from tfstride.providers.aws.resource_mutations import aws_mutations


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
        routes, route_uncertainties = _listener_forwarding(context.index)
        for service in resources:
            if service.resource_type != "aws_ecs_service":
                continue
            associations: list[dict[str, Any]] = []
            uncertainties: list[str] = []
            for binding in aws_facts(service).ecs_load_balancers:
                target = resolve_aws_network_reference(
                    context.index.load_balancer_target_groups, binding.get("target_group_arn"), service
                )
                if target is None:
                    uncertainties.append("ECS binding target group is unresolved, ambiguous, or lacks provider scope")
                    continue
                container_name = binding.get("container_name")
                container_port = binding.get("container_port")
                if (
                    not isinstance(container_name, str)
                    or not container_name
                    or type(container_port) is not int
                    or not 1 <= container_port <= 65535
                ):
                    uncertainties.append(f"{target.address}: ECS container binding is incomplete")
                    continue
                for route in routes.get(target.address, []):
                    associations.append({**route, "container_name": container_name, "container_port": container_port})
                uncertainties.extend(route_uncertainties.get(target.address, []))
                if not routes.get(target.address):
                    uncertainties.append(f"{target.address}: no established public listener/action forwarding chain")
            facts = aws_facts(service)
            associations.sort(
                key=lambda item: (
                    item["load_balancer_address"],
                    item["listener_address"],
                    item["action_source_address"],
                    item["target_group_address"],
                    item["container_name"],
                    item["container_port"],
                )
            )
            # Keep configured forwarding chains for packet evaluation, including
            # blocked ones, without widening the existing exposure flags.
            addresses = sorted(
                {
                    association["load_balancer_address"]
                    for association in associations
                    if context.index.resources_by_address[association["load_balancer_address"]].public_exposure
                }
            )
            facts.set_ecs_forwarding(associations, uncertainties)
            facts.set_fronted_by_internet_facing_load_balancer(bool(addresses))
            # Re-running decoration must not leave evidence from a removed listener.
            facts.set_internet_facing_load_balancer_addresses(addresses)


def _listener_rules(index: AwsResourceIndex) -> dict[str, list[tuple[NormalizedResource, bool]]]:
    result: dict[str, list[tuple[NormalizedResource, bool]]] = {}
    for rule in sorted(index.load_balancer_listener_rules, key=lambda item: item.address):
        reference = aws_facts(rule).listener_arn
        listener = resolve_aws_network_reference(index.load_balancer_listeners, reference, rule)
        if listener is not None:
            result.setdefault(listener.address, []).append((rule, True))
            continue
        candidates = index.load_balancer_listeners.resolve(reference, source=rule).candidates
        if not candidates:
            # A known exact reference to an unmodeled listener cannot affect a different listener.
            if reference and (reference.startswith("arn:") or reference.startswith("aws_lb_listener.")):
                continue
            candidates = tuple(
                item
                for item in index.load_balancer_listeners.resources
                if not rule.provider_config_key
                or not item.provider_config_key
                or item.provider_config_key == rule.provider_config_key
            )
        for candidate in candidates:
            result.setdefault(candidate.address, []).append((rule, False))
    return result


def _listener_forwarding(index: AwsResourceIndex) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[str]]]:
    routes: dict[str, list[dict[str, Any]]] = {}
    uncertainties: dict[str, list[str]] = {}
    rules_by_listener = _listener_rules(index)
    for listener in sorted(index.load_balancer_listeners.resources, key=lambda item: item.address):
        load_balancer = resolve_aws_network_reference(
            index.load_balancers, aws_facts(listener).load_balancer_arn, listener
        )
        rules = rules_by_listener.get(listener.address, [])
        for source in [listener, *(rule for rule, certain in rules if certain)]:
            facts = aws_facts(source)
            actions = facts.load_balancer_actions
            positive_targets, action_uncertainties = forwarding_targets(actions)
            conditions = [] if source is listener else facts.load_balancer_conditions
            reasons = list(action_uncertainties)
            if source is not listener:
                reasons.extend(facts.load_balancer_condition_uncertainties)
                if not conditions:
                    reasons.append("listener rule conditions are not established")
                if facts.load_balancer_rule_priority is None:
                    reasons.append("listener rule priority is unknown or invalid")
            predecessors = [
                aws_facts(rule).load_balancer_conditions
                if certain
                and not aws_facts(rule).load_balancer_condition_uncertainties
                and aws_facts(rule).load_balancer_conditions
                else None
                for rule, certain in rules
                if rule is not source
                and (
                    not certain
                    or source is listener
                    or _could_precede(aws_facts(rule).load_balancer_rule_priority, facts.load_balancer_rule_priority)
                )
            ]
            witness = listener_request_witness(conditions, predecessors) if not reasons else None
            if witness is None:
                reasons.append("no request is proven to reach this action after preceding listener rules")
            if load_balancer is None or not (load_balancer.public_access_configured or load_balancer.public_exposure):
                reasons.append("listener load balancer is unresolved or not established as public")
            all_targets = [target for action in actions for target in action["targets"]]
            for target in all_targets:
                target_group = resolve_aws_network_reference(
                    index.load_balancer_target_groups, target["reference"], source
                )
                if target_group is None:
                    continue
                target_reasons = list(reasons)
                if target not in positive_targets:
                    target_reasons.append("target has no established positive-weight forwarding action")
                if target_reasons:
                    uncertainties.setdefault(target_group.address, []).extend(
                        f"{source.address}: {reason}" for reason in target_reasons
                    )
                    continue
                assert load_balancer is not None
                routes.setdefault(target_group.address, []).append(
                    {
                        "load_balancer_address": load_balancer.address,
                        "listener_address": listener.address,
                        "action_source_address": source.address,
                        "target_group_address": target_group.address,
                        "target_weight": target["weight"],
                        "conditions": conditions,
                        "request_witness": witness,
                        "authentication_actions": [
                            action["type"]
                            for action in actions
                            if action["type"] in {"authenticate-cognito", "authenticate-oidc"}
                        ],
                    }
                )
    return routes, uncertainties


def _could_precede(priority: int | None, current_priority: int | None) -> bool:
    return priority is None or current_priority is None or priority <= current_priority
