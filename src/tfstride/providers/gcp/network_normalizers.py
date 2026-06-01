from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, SecurityGroupRule, TerraformResource
from tfstride.providers.gcp.coercion import as_bool, as_list, as_optional_int, compact, first_item
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_identifier, resource_name


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


def normalize_compute_route(resource: TerraformResource) -> NormalizedResource:
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
            GcpResourceMetadata.NETWORK.key: values.get("network"),
            GcpResourceMetadata.ROUTE_DEST_RANGE.key: values.get("dest_range"),
            GcpResourceMetadata.ROUTE_NEXT_HOP_GATEWAY.key: values.get("next_hop_gateway"),
            GcpResourceMetadata.ROUTE_NEXT_HOP_INSTANCE.key: values.get("next_hop_instance"),
            GcpResourceMetadata.ROUTE_NEXT_HOP_IP.key: values.get("next_hop_ip"),
            GcpResourceMetadata.ROUTE_NEXT_HOP_ILB.key: values.get("next_hop_ilb"),
            GcpResourceMetadata.ROUTE_NEXT_HOP_VPN_TUNNEL.key: values.get("next_hop_vpn_tunnel"),
            GcpResourceMetadata.ROUTE_TAGS.key: compact(as_list(values.get("tags"))),
            "priority": as_optional_int(values.get("priority")),
            "description": values.get("description"),
        },
    )


def normalize_compute_router(resource: TerraformResource) -> NormalizedResource:
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
            "bgp": first_item(values.get("bgp")) or {},
            "description": values.get("description"),
            "encrypted_interconnect_router": as_bool(values.get("encrypted_interconnect_router", False)),
        },
    )


def normalize_compute_router_nat(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    router_reference = first_non_empty(values.get("router"))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=resource_identifier(resource),
        metadata={
            GcpResourceMetadata.NAME.key: resource_name(resource),
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.REGION.key: values.get("region"),
            GcpResourceMetadata.ROUTER_REFERENCE.key: router_reference,
            GcpResourceMetadata.NAT_SUBNETWORKS.key: as_list(values.get("subnetwork")),
            "nat_ip_allocate_option": values.get("nat_ip_allocate_option"),
            "source_subnetwork_ip_ranges_to_nat": values.get("source_subnetwork_ip_ranges_to_nat"),
            "min_ports_per_vm": as_optional_int(values.get("min_ports_per_vm")),
            "enable_endpoint_independent_mapping": as_bool(values.get("enable_endpoint_independent_mapping", False)),
            "log_config": first_item(values.get("log_config")) or {},
        },
    )


def normalize_compute_forwarding_rule(resource: TerraformResource) -> NormalizedResource:
    return _normalize_forwarding_rule(resource)


def normalize_compute_global_forwarding_rule(resource: TerraformResource) -> NormalizedResource:
    return _normalize_forwarding_rule(resource)


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
            GcpResourceMetadata.FIREWALL_TARGET_SERVICE_ACCOUNTS.key: compact(
                as_list(values.get("target_service_accounts"))
            ),
            GcpResourceMetadata.FIREWALL_SOURCE_SERVICE_ACCOUNTS.key: compact(
                as_list(values.get("source_service_accounts"))
            ),
            "direction": str(values.get("direction") or "INGRESS").lower(),
            "priority": as_optional_int(values.get("priority")),
            "disabled": as_bool(values.get("disabled")),
        },
    )


def _normalize_forwarding_rule(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    public_access_configured = _forwarding_rule_is_public(values)
    public_reasons = (
        ["forwarding rule uses an external load balancing scheme"]
        if public_access_configured
        else []
    )
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        vpc_id=values.get("network"),
        subnet_ids=tuple(compact([values.get("subnetwork")])),
        public_access_configured=public_access_configured,
        public_exposure=public_access_configured,
        metadata={
            GcpResourceMetadata.NAME.key: resource_name(resource),
            GcpResourceMetadata.SELF_LINK.key: values.get("self_link"),
            GcpResourceMetadata.PROJECT.key: values.get("project"),
            GcpResourceMetadata.REGION.key: values.get("region"),
            GcpResourceMetadata.NETWORK.key: values.get("network"),
            GcpResourceMetadata.SUBNETWORK.key: values.get("subnetwork"),
            GcpResourceMetadata.FORWARDING_RULE_IP_ADDRESS.key: values.get("ip_address"),
            GcpResourceMetadata.FORWARDING_RULE_LOAD_BALANCING_SCHEME.key: values.get("load_balancing_scheme"),
            GcpResourceMetadata.FORWARDING_RULE_TARGET.key: values.get("target"),
            GcpResourceMetadata.FORWARDING_RULE_BACKEND_SERVICE.key: values.get("backend_service"),
            GcpResourceMetadata.FORWARDING_RULE_PORTS.key: compact(as_list(values.get("ports"))),
            GcpResourceMetadata.FORWARDING_RULE_SOURCE_IP_RANGES.key: compact(
                as_list(values.get("source_ip_ranges"))
            ),
            "ip_protocol": values.get("ip_protocol"),
            "port_range": values.get("port_range"),
            "all_ports": as_bool(values.get("all_ports", False)),
            "allow_global_access": as_bool(values.get("allow_global_access", False)),
            "direct_internet_reachable": public_access_configured,
            "internet_ingress_capable": public_access_configured,
            "public_access_reasons": public_reasons,
            "public_exposure_reasons": public_reasons,
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
    source_tags = compact(as_list(values.get("source_tags")))
    source_service_accounts = compact(as_list(values.get("source_service_accounts")))
    if direction == "ingress" and not source_tags and not source_service_accounts:
        return ["0.0.0.0/0"]
    return []


def _forwarding_rule_is_public(values: dict[str, Any]) -> bool:
    scheme = str(values.get("load_balancing_scheme") or "EXTERNAL").strip().upper()
    return scheme in {"EXTERNAL", "EXTERNAL_MANAGED"}


def _parse_port_range(value: Any) -> tuple[int | None, int | None]:
    text = str(value).strip()
    if not text:
        return (None, None)
    if "-" not in text:
        port = as_optional_int(text)
        return (port, port)
    start, end = text.split("-", 1)
    return (as_optional_int(start.strip()), as_optional_int(end.strip()))