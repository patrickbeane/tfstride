from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, SecurityGroupRule, TerraformResource
from tfstride.providers.gcp.coercion import as_bool, as_list, as_optional_int, compact
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_utils import resource_identifier, resource_name


GCP_PROVIDER = "gcp"


def normalize_compute_network(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=resource_identifier(resource),
        metadata={
            GcpResourceMetadata.NAME.key: resource_name(resource),
            GcpResourceMetadata.SELF_LINK.key: values.get("self_link"),
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.AUTO_CREATE_SUBNETWORKS.key: as_bool(values.get("auto_create_subnetworks")),
            "routing_mode": values.get("routing_mode"),
            "description": values.get("description"),
        },
    )


def normalize_compute_subnetwork(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=resource_identifier(resource),
        vpc_id=values.get("network"),
        metadata={
            GcpResourceMetadata.NAME.key: resource_name(resource),
            GcpResourceMetadata.SELF_LINK.key: values.get("self_link"),
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.REGION.key: values.get("region"),
            GcpResourceMetadata.NETWORK.key: values.get("network"),
            GcpResourceMetadata.CIDR_RANGE.key: values.get("ip_cidr_range"),
            GcpResourceMetadata.PRIVATE_IP_GOOGLE_ACCESS.key: as_bool(values.get("private_ip_google_access")),
            "purpose": values.get("purpose"),
            "stack_type": values.get("stack_type"),
            "secondary_ip_ranges": as_list(values.get("secondary_ip_range")),
        },
    )


def normalize_compute_firewall(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=resource_identifier(resource),
        vpc_id=values.get("network"),
        network_rules=parse_firewall_allow_rules(values),
        metadata={
            GcpResourceMetadata.NAME.key: resource_name(resource),
            GcpResourceMetadata.SELF_LINK.key: values.get("self_link"),
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.NETWORK.key: values.get("network"),
            GcpResourceMetadata.FIREWALL_ALLOW.key: as_list(values.get("allow")),
            GcpResourceMetadata.FIREWALL_DENY.key: as_list(values.get("deny")),
            GcpResourceMetadata.FIREWALL_SOURCE_RANGES.key: compact(as_list(values.get("source_ranges"))),
            GcpResourceMetadata.FIREWALL_DESTINATION_RANGES.key: compact(as_list(values.get("destination_ranges"))),
            GcpResourceMetadata.FIREWALL_TARGET_TAGS.key: compact(as_list(values.get("target_tags"))),
            GcpResourceMetadata.FIREWALL_SOURCE_TAGS.key: compact(as_list(values.get("source_tags"))),
            "direction": str(values.get("direction") or "INGRESS").lower(),
            "priority": as_optional_int(values.get("priority")),
            "disabled": as_bool(values.get("disabled")),
        },
    )


def parse_firewall_allow_rules(values: dict[str, Any]) -> list[SecurityGroupRule]:
    direction = str(values.get("direction") or "INGRESS").strip().lower()
    cidr_blocks = _firewall_cidr_blocks(values, direction)
    rules: list[SecurityGroupRule] = []
    for allow in as_list(values.get("allow")):
        if not isinstance(allow, dict):
            continue
        protocol = str(allow.get("protocol") or "-1")
        ports = compact(as_list(allow.get("ports")))
        if not ports:
            rules.append(_firewall_rule(direction, protocol, None, None, cidr_blocks))
            continue
        for port in ports:
            from_port, to_port = _parse_port_range(port)
            rules.append(_firewall_rule(direction, protocol, from_port, to_port, cidr_blocks))
    return rules


def _firewall_rule(
    direction: str,
    protocol: str,
    from_port: int | None,
    to_port: int | None,
    cidr_blocks: list[str],
) -> SecurityGroupRule:
    return SecurityGroupRule(
        direction=direction,
        protocol="-1" if protocol.lower() in {"all", "-1"} else protocol,
        from_port=from_port,
        to_port=to_port,
        cidr_blocks=list(cidr_blocks),
    )


def _firewall_cidr_blocks(values: dict[str, Any], direction: str) -> list[str]:
    source_ranges = compact(as_list(values.get("source_ranges")))
    destination_ranges = compact(as_list(values.get("destination_ranges")))
    if direction == "egress" and destination_ranges:
        return destination_ranges
    if source_ranges:
        return source_ranges
    return ["0.0.0.0/0"] if direction == "ingress" else []


def _parse_port_range(value: Any) -> tuple[int | None, int | None]:
    text = str(value).strip()
    if not text:
        return (None, None)
    if "-" not in text:
        port = as_optional_int(text)
        return (port, port)
    start, end = text.split("-", 1)
    return (as_optional_int(start.strip()), as_optional_int(end.strip()))