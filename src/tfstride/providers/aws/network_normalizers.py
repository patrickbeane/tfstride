from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, SecurityGroupRule, TerraformResource
from tfstride.providers.aws.coercion import as_list, as_optional_int, compact
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.resource_mutations import aws_mutations
from tfstride.providers.coercion import known_string

AWS_PROVIDER = "aws"


def normalize_vpc(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=values.get("id"),
        metadata={"cidr_block": values.get("cidr_block"), "tags": values.get("tags", {})},
    )


def normalize_subnet(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=values.get("id"),
        vpc_id=values.get("vpc_id"),
        metadata={
            "cidr_block": values.get("cidr_block"),
            "availability_zone": values.get("availability_zone"),
            "map_public_ip_on_launch": bool(values.get("map_public_ip_on_launch", False)),
            "tags": values.get("tags", {}),
        },
    )


def normalize_internet_gateway(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=values.get("id"),
        vpc_id=values.get("vpc_id"),
    )


def normalize_route_table(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=values.get("id"),
        vpc_id=values.get("vpc_id"),
        metadata={"routes": as_list(values.get("route") or values.get("routes"))},
    )


def normalize_route_table_association(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=values.get("id") or resource.address,
        metadata={
            "route_table_id": values.get("route_table_id"),
            "subnet_id": values.get("subnet_id"),
            "gateway_id": values.get("gateway_id"),
        },
    )


def normalize_security_group(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=values.get("id"),
        vpc_id=values.get("vpc_id"),
        network_rules=parse_security_group_rules(values),
        metadata={
            "description": values.get("description"),
            "group_name": values.get("name"),
        },
    )


def normalize_security_group_rule(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=values.get("id") or resource.address,
        network_rules=[parse_standalone_security_group_rule(values)],
        metadata={"security_group_id": values.get("security_group_id")},
    )


def normalize_nat_gateway(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=values.get("id"),
        subnet_ids=tuple(compact([values.get("subnet_id")])),
        metadata={
            "allocation_id": values.get("allocation_id"),
            "connectivity_type": values.get("connectivity_type", "public"),
        },
    )


def normalize_load_balancer(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    internet_facing = not bool(values.get("internal", False))
    public_access_reasons = ["load balancer is configured as internet-facing"] if internet_facing else []
    normalized = NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=values.get("id"),
        arn=values.get("arn"),
        subnet_ids=tuple(as_list(values.get("subnets"))),
        security_group_ids=tuple(as_list(values.get("security_groups"))),
        public_access_configured=internet_facing,
        metadata={
            "internal": not internet_facing,
            "load_balancer_type": values.get("load_balancer_type"),
        },
    )
    mutations = aws_mutations(normalized)
    mutations.set_public_access_reasons(public_access_reasons)
    mutations.set_public_exposure_reasons([])
    return normalized


def normalize_load_balancer_listener(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    protocol = known_string(values, unknown_values, "protocol", uncertainties)
    certificate_arn = known_string(values, unknown_values, "certificate_arn", uncertainties)
    ssl_policy = known_string(values, unknown_values, "ssl_policy", uncertainties)
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=values.get("id") or values.get("arn"),
        arn=values.get("arn"),
        metadata={
            "load_balancer_arn": values.get("load_balancer_arn"),
            "target_group_arns": _load_balancer_action_target_group_arns(values.get("default_action")),
            "port": as_optional_int(values.get("port")),
            "protocol": protocol,
            AwsResourceMetadata.LOAD_BALANCER_LISTENER_PROTOCOL: protocol,
            AwsResourceMetadata.LOAD_BALANCER_LISTENER_CERTIFICATE_ARN: certificate_arn,
            AwsResourceMetadata.LOAD_BALANCER_LISTENER_SSL_POLICY: ssl_policy,
            AwsResourceMetadata.LOAD_BALANCER_LISTENER_TLS_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_load_balancer_listener_rule(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=values.get("id") or values.get("arn"),
        arn=values.get("arn"),
        metadata={
            "listener_arn": values.get("listener_arn"),
            "target_group_arns": _load_balancer_action_target_group_arns(values.get("action")),
            "listener_rule_priority": as_optional_int(values.get("priority")),
        },
    )


def normalize_load_balancer_target_group(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=values.get("id") or values.get("arn") or values.get("name"),
        arn=values.get("arn"),
        vpc_id=values.get("vpc_id"),
        metadata={
            "name": values.get("name"),
            "port": as_optional_int(values.get("port")),
            "protocol": values.get("protocol"),
            "target_type": values.get("target_type"),
        },
    )


def parse_security_group_rules(values: dict[str, Any]) -> list[SecurityGroupRule]:
    rules: list[SecurityGroupRule] = []
    for direction in ("ingress", "egress"):
        for rule in as_list(values.get(direction)):
            rules.append(
                SecurityGroupRule(
                    direction=direction,
                    protocol=str(rule.get("protocol", "-1")),
                    from_port=as_optional_int(rule.get("from_port")),
                    to_port=as_optional_int(rule.get("to_port")),
                    cidr_blocks=as_list(rule.get("cidr_blocks")),
                    ipv6_cidr_blocks=as_list(rule.get("ipv6_cidr_blocks")),
                    referenced_security_group_ids=as_list(rule.get("security_groups")),
                    description=rule.get("description"),
                )
            )
    return rules


def parse_standalone_security_group_rule(values: dict[str, Any]) -> SecurityGroupRule:
    referenced_security_group_ids = compact([values.get("source_security_group_id")])
    if values.get("self") and values.get("security_group_id"):
        referenced_security_group_ids.append(str(values["security_group_id"]))
    return SecurityGroupRule(
        direction=str(values.get("type", "ingress")),
        protocol=str(values.get("protocol", "-1")),
        from_port=as_optional_int(values.get("from_port")),
        to_port=as_optional_int(values.get("to_port")),
        cidr_blocks=as_list(values.get("cidr_blocks")),
        ipv6_cidr_blocks=as_list(values.get("ipv6_cidr_blocks")),
        referenced_security_group_ids=referenced_security_group_ids,
        description=values.get("description"),
    )


def _load_balancer_action_target_group_arns(actions: Any) -> list[str]:
    target_group_arns: list[str] = []
    for action in as_list(actions):
        if not isinstance(action, dict):
            continue
        target_group_arn = action.get("target_group_arn")
        if target_group_arn:
            target_group_arns.append(str(target_group_arn))
        for forward in as_list(action.get("forward")):
            if not isinstance(forward, dict):
                continue
            for target_group in as_list(forward.get("target_group")):
                if not isinstance(target_group, dict):
                    continue
                target_group_arn = target_group.get("arn")
                if target_group_arn:
                    target_group_arns.append(str(target_group_arn))
    return _dedupe(target_group_arns)


def _dedupe(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped
