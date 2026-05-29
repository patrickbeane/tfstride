from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, SecurityGroupRule, TerraformResource
from tfstride.providers.aws.coercion import as_list, as_optional_int, compact


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
    return NormalizedResource(
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
            "public_access_reasons": (
                ["load balancer is configured as internet-facing"]
                if internet_facing
                else []
            ),
            "public_exposure_reasons": [],
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