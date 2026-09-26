"""Verify ALB listener and awsvpc backend traffic before public-path consumers run."""

from __future__ import annotations

import re
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsDecorationContext, AwsResourceIndex, resolve_aws_network_reference
from tfstride.providers.aws.security_group_traffic import (
    AwsSecurityGroupTrafficIndex,
    TrafficDecision,
    traffic_decision,
)

_INTERNET_VERSIONS: dict[str, tuple[int, ...]] = {
    "ipv4": (4,),
    "dualstack": (4, 6),
    "dualstack-without-public-ipv4": (6,),
}


class DeriveEcsPublicIngressStage:
    name = "derive_ecs_public_ingress"

    def apply(self, resources: list[NormalizedResource], context: AwsDecorationContext) -> None:
        services = [resource for resource in resources if resource.resource_type == "aws_ecs_service"]
        if not services:
            return
        traffic = AwsSecurityGroupTrafficIndex(context.index)
        for service in services:
            facts = aws_facts(service)
            decisions = [
                _evaluate_association(service, association, context.index, traffic)
                for association in facts.ecs_forwarding_associations
            ]
            uncertainties = [
                reason for decision in decisions if decision["state"] == "unknown" for reason in decision["reasons"]
            ]
            uncertainties.extend(facts.ecs_forwarding_uncertainties)
            facts.set_ecs_public_ingress(decisions, uncertainties)


def _evaluate_association(
    service: NormalizedResource,
    association: dict[str, Any],
    index: AwsResourceIndex,
    traffic: AwsSecurityGroupTrafficIndex,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        **association,
        "service_address": service.address,
        "state": "unknown",
        "checks": {},
        "reasons": [],
        "evaluation_scope": "modeled_listener_container_and_security_group_permissions",
    }
    load_balancer = index.resources_by_address.get(association["load_balancer_address"])
    listener = index.resources_by_address.get(association["listener_address"])
    target = index.resources_by_address.get(association["target_group_address"])
    if load_balancer is None or listener is None or target is None:
        result["reasons"] = ["forwarding association resources are no longer resolved"]
        return result
    lb_facts, listener_facts, target_facts = aws_facts(load_balancer), aws_facts(listener), aws_facts(target)
    if lb_facts.load_balancer_type != "application" or not load_balancer.public_access_configured:
        result["reasons"] = ["an internet-facing application load balancer is not established"]
        return result
    listener_port = listener_facts.load_balancer_listener_port
    if listener_port is None or listener_facts.load_balancer_listener_protocol not in {"HTTP", "HTTPS"}:
        result["reasons"] = [f"{listener.address}: listener protocol/port is unknown or unsupported"]
        return result
    versions = _INTERNET_VERSIONS.get(lb_facts.load_balancer_ip_address_type or "")
    if versions is None:
        result["reasons"] = [f"{load_balancer.address}: public IP address family is unknown or unsupported"]
        return result
    backend_port = association["container_port"]
    mapping = _container_binding(service, association, index)
    if (
        target_facts.load_balancer_target_type != "ip"
        or target_facts.load_balancer_target_protocol not in {"HTTP", "HTTPS"}
        or target_facts.load_balancer_target_ip_address_type != "ipv4"
    ):
        mapping = traffic_decision("unknown", f"{target.address}: an HTTP/HTTPS IPv4 IP target is not established")
    checks: dict[str, TrafficDecision] = {
        "container_binding": mapping,
        "listener_ingress": traffic.permission(load_balancer, "ingress", listener_port, internet_versions=versions),
        "load_balancer_egress": traffic.permission(load_balancer, "egress", backend_port, peer=service),
        "service_ingress": traffic.permission(service, "ingress", backend_port, peer=load_balancer),
    }
    # Backend permissions are evaluated at the ECS registration port, which can
    # differ both from the listener port and the target group's default port.
    result.update(
        listener_port=listener_port,
        listener_protocol=listener_facts.load_balancer_listener_protocol,
        backend_port=backend_port,
        backend_protocol=target_facts.load_balancer_target_protocol,
        transport_protocol="tcp",
        checks=checks,
    )
    if mapping["state"] != "allowed":
        result["state"] = "unknown"
    elif any(check["state"] == "blocked" for check in checks.values()):
        result["state"] = "blocked"
    elif all(check["state"] == "allowed" for check in checks.values()):
        result["state"] = "allowed"
    result["reasons"] = sorted({f"{name}: {reason}" for name, check in checks.items() for reason in check["reasons"]})
    return result


def _container_binding(
    service: NormalizedResource, association: dict[str, Any], index: AwsResourceIndex
) -> TrafficDecision:
    reference = aws_facts(service).task_definition_reference
    task = resolve_aws_network_reference(index.ecs_task_definitions, reference, service)
    if task is None:
        return traffic_decision("unknown", "task definition is unresolved or ambiguous")
    inputs = aws_facts(task).ecs_container_network
    if inputs.get("network_mode") != "awsvpc":
        return traffic_decision("unknown", f"{task.address}: awsvpc network mode is not established")
    if inputs.get("uncertainties"):
        return traffic_decision("unknown", *inputs["uncertainties"])
    containers = inputs.get("containers", [])
    matching = [container for container in containers if container["name"] == association["container_name"]]
    if len(matching) != 1 or any(container["name"] is None for container in containers):
        return traffic_decision("unknown", f"{task.address}: the bound container name is absent, unknown, or ambiguous")
    port = association["container_port"]
    for mapping in matching[0]["port_mappings"]:
        if mapping["protocol"] != "tcp":
            continue
        if not mapping["host_port_omitted"] and mapping["host_port"] != port:
            continue
        if (mapping["container_range_omitted"] and mapping["container_port"] == port) or (
            mapping["container_port_omitted"] and _port_in_range(port, mapping["container_port_range"])
        ):
            return traffic_decision(
                "allowed",
                evidence=[
                    {
                        "task_definition_address": task.address,
                        "container_name": association["container_name"],
                        "container_port": port,
                        "network_mode": "awsvpc",
                        "protocol": "tcp",
                    }
                ],
            )
    return traffic_decision("unknown", f"{task.address}: TCP port {port} has no established awsvpc container mapping")


def _port_in_range(port: int, value: str | None) -> bool:
    if value is None or re.fullmatch(r"[0-9]+-[0-9]+", value) is None:
        return False
    start, end = (int(part) for part in value.split("-"))
    return 1 <= start <= port <= end <= 65535
