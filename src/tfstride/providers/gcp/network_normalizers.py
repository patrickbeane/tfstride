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


def normalize_compute_url_map(resource: TerraformResource) -> NormalizedResource:
    return _normalize_url_map(resource)


def normalize_compute_region_url_map(resource: TerraformResource) -> NormalizedResource:
    return _normalize_url_map(resource)


def normalize_compute_target_http_proxy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_proxy(resource)


def normalize_compute_target_https_proxy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_proxy(resource)


def normalize_compute_region_target_http_proxy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_proxy(resource)


def normalize_compute_region_target_https_proxy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_proxy(resource)


def normalize_compute_backend_service(resource: TerraformResource) -> NormalizedResource:
    return _normalize_backend_service(resource)


def normalize_compute_region_backend_service(resource: TerraformResource) -> NormalizedResource:
    return _normalize_backend_service(resource)


def normalize_compute_backend_bucket(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.LOAD_BALANCER_BACKEND_BUCKET_NAME.key: values.get("bucket_name"),
            },
        ),
    )


def normalize_compute_network_endpoint_group(resource: TerraformResource) -> NormalizedResource:
    return _normalize_network_endpoint_group(resource)


def normalize_compute_region_network_endpoint_group(resource: TerraformResource) -> NormalizedResource:
    return _normalize_network_endpoint_group(resource)


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


def normalize_compute_firewall_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=first_non_empty(values.get("short_name"), values.get("name"), resource_identifier(resource)),
        metadata={
            GcpResourceMetadata.NAME.key: first_non_empty(values.get("short_name"), values.get("name")),
            GcpResourceMetadata.SELF_LINK.key: values.get("self_link"),
            GcpResourceMetadata.FIREWALL_POLICY_REFERENCE.key: values.get("name"),
            GcpResourceMetadata.FIREWALL_POLICY_PARENT.key: values.get("parent"),
            "description": values.get("description"),
            "display_name": values.get("display_name"),
        },
    )


def normalize_compute_firewall_policy_rule(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    match = _firewall_policy_match(values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=_firewall_policy_rule_identifier(resource),
        network_rules=parse_firewall_policy_allow_rules(values),
        metadata={
            GcpResourceMetadata.NAME.key: first_non_empty(values.get("name")),
            GcpResourceMetadata.SELF_LINK.key: values.get("self_link"),
            GcpResourceMetadata.FIREWALL_POLICY_REFERENCE.key: values.get("firewall_policy"),
            GcpResourceMetadata.FIREWALL_POLICY_ACTION.key: values.get("action"),
            GcpResourceMetadata.FIREWALL_POLICY_DIRECTION.key: _firewall_policy_direction(values),
            GcpResourceMetadata.FIREWALL_POLICY_PRIORITY.key: as_optional_int(values.get("priority")),
            GcpResourceMetadata.FIREWALL_POLICY_MATCH.key: match,
            GcpResourceMetadata.FIREWALL_SOURCE_RANGES.key: _firewall_policy_source_ranges(match),
            GcpResourceMetadata.FIREWALL_DESTINATION_RANGES.key: _firewall_policy_destination_ranges(match),
            GcpResourceMetadata.FIREWALL_POLICY_TARGET_RESOURCES.key: compact(as_list(values.get("target_resources"))),
            GcpResourceMetadata.FIREWALL_POLICY_TARGET_SERVICE_ACCOUNTS.key: compact(
                as_list(values.get("target_service_accounts"))
            ),
            "disabled": as_bool(values.get("disabled")),
            "enable_logging": as_bool(values.get("enable_logging")),
            "description": values.get("description"),
        },
    )


def normalize_compute_firewall_policy_association(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=first_non_empty(values.get("attachment_target"), values.get("name"), resource_identifier(resource)),
        metadata={
            GcpResourceMetadata.NAME.key: first_non_empty(values.get("name")),
            GcpResourceMetadata.SELF_LINK.key: values.get("self_link"),
            GcpResourceMetadata.FIREWALL_POLICY_REFERENCE.key: values.get("firewall_policy"),
            GcpResourceMetadata.FIREWALL_POLICY_ATTACHMENT_TARGET.key: values.get("attachment_target"),
            "display_name": values.get("display_name"),
        },
    )


def _normalize_url_map(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.LOAD_BALANCER_DEFAULT_SERVICE.key: values.get("default_service"),
                GcpResourceMetadata.LOAD_BALANCER_HOST_RULES.key: _dict_list(values.get("host_rule")),
                GcpResourceMetadata.LOAD_BALANCER_PATH_MATCHERS.key: _dict_list(values.get("path_matcher")),
            },
        ),
    )


def _normalize_target_proxy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.LOAD_BALANCER_URL_MAP.key: values.get("url_map"),
                GcpResourceMetadata.LOAD_BALANCER_SSL_CERTIFICATES.key: compact(
                    as_list(values.get("ssl_certificates"))
                ),
            },
        ),
    )


def _normalize_backend_service(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.LOAD_BALANCER_BACKEND_SERVICE_PROTOCOL.key: values.get("protocol"),
                GcpResourceMetadata.LOAD_BALANCER_BACKEND_SERVICE_LOAD_BALANCING_SCHEME.key: values.get(
                    "load_balancing_scheme"
                ),
                GcpResourceMetadata.LOAD_BALANCER_BACKENDS.key: _dict_list(values.get("backend")),
            },
        ),
    )


def _normalize_network_endpoint_group(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        vpc_id=values.get("network"),
        subnet_ids=tuple(compact([values.get("subnetwork")])),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.NETWORK.key: values.get("network"),
                GcpResourceMetadata.SUBNETWORK.key: values.get("subnetwork"),
                GcpResourceMetadata.LOAD_BALANCER_NETWORK_ENDPOINT_TYPE.key: values.get(
                    "network_endpoint_type"
                ),
                GcpResourceMetadata.LOAD_BALANCER_SERVERLESS_ENDPOINTS.key: _serverless_neg_endpoints(values),
                GcpResourceMetadata.LOAD_BALANCER_NETWORK_ENDPOINTS.key: _dict_list(
                    values.get("network_endpoint")
                ),
            },
        ),
    )


def _load_balancer_metadata(values: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        GcpResourceMetadata.NAME.key: first_non_empty(values.get("name")),
        GcpResourceMetadata.SELF_LINK.key: values.get("self_link"),
        GcpResourceMetadata.PROJECT.key: values.get("project"),
        GcpResourceMetadata.REGION.key: values.get("region"),
        GcpResourceMetadata.ZONE.key: values.get("zone"),
        **metadata,
    }


def _dict_list(value: Any) -> list[dict[str, Any]]:
    return [item for item in as_list(value) if isinstance(item, dict)]


def _serverless_neg_endpoints(values: dict[str, Any]) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    endpoints.extend(_serverless_neg_endpoint("cloud_run", item) for item in _dict_list(values.get("cloud_run")))
    endpoints.extend(
        _serverless_neg_endpoint("cloud_function", item) for item in _dict_list(values.get("cloud_function"))
    )
    endpoints.extend(_serverless_neg_endpoint("app_engine", item) for item in _dict_list(values.get("app_engine")))
    return [endpoint for endpoint in endpoints if len(endpoint) > 1]


def _serverless_neg_endpoint(platform: str, values: dict[str, Any]) -> dict[str, Any]:
    endpoint = {
        "platform": platform,
        "service": values.get("service"),
        "function": values.get("function"),
        "version": values.get("version"),
        "tag": values.get("tag"),
        "url_mask": values.get("url_mask"),
    }
    return {key: value for key, value in endpoint.items() if value not in (None, "", [], {})}


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


def parse_firewall_policy_allow_rules(values: dict[str, Any]) -> list[SecurityGroupRule]:
    if str(values.get("action") or "").strip().lower() != "allow":
        return []

    match = _firewall_policy_match(values)
    direction = _firewall_policy_direction(values)
    cidr_blocks = _firewall_policy_cidr_blocks(match, direction)
    rules: list[SecurityGroupRule] = []
    for layer4_config in _firewall_policy_layer4_configs(match):
        protocol = str(layer4_config.get("ip_protocol") or layer4_config.get("protocol") or "-1")
        ports = compact(as_list(layer4_config.get("ports")))
        if not ports:
            rules.append(_firewall_rule(direction, protocol, None, None, cidr_blocks))
            continue
        for port in ports:
            from_port, to_port = _parse_port_range(port)
            rules.append(_firewall_rule(direction, protocol, from_port, to_port, cidr_blocks))
    return rules


def _firewall_policy_rule_identifier(resource: TerraformResource) -> str | None:
    values = resource.values
    firewall_policy = first_non_empty(values.get("firewall_policy"))
    priority = first_non_empty(values.get("priority"))
    if firewall_policy and priority:
        return f"{firewall_policy}/rules/{priority}"
    return resource_identifier(resource)


def _firewall_policy_match(values: dict[str, Any]) -> dict[str, Any]:
    return first_item(values.get("match")) or {}


def _firewall_policy_direction(values: dict[str, Any]) -> str:
    return str(values.get("direction") or "INGRESS").strip().lower()


def _firewall_policy_layer4_configs(match: dict[str, Any]) -> list[dict[str, Any]]:
    return _dict_list(match.get("layer4_configs") or match.get("layer4_config"))


def _firewall_policy_source_ranges(match: dict[str, Any]) -> list[str]:
    return compact(as_list(match.get("src_ip_ranges") or match.get("src_ip_range")))


def _firewall_policy_destination_ranges(match: dict[str, Any]) -> list[str]:
    return compact(as_list(match.get("dest_ip_ranges") or match.get("dest_ip_range")))


def _firewall_policy_cidr_blocks(match: dict[str, Any], direction: str) -> list[str]:
    destination_ranges = _firewall_policy_destination_ranges(match)
    if direction == "egress" and destination_ranges:
        return destination_ranges
    source_ranges = _firewall_policy_source_ranges(match)
    if source_ranges:
        return source_ranges
    if direction == "ingress" and not _firewall_policy_has_non_cidr_source(match):
        return ["0.0.0.0/0"]
    return []


def _firewall_policy_has_non_cidr_source(match: dict[str, Any]) -> bool:
    source_scoped_fields = (
        "src_address_groups",
        "src_fqdns",
        "src_region_codes",
        "src_secure_tags",
        "src_threat_intelligences",
    )
    return any(compact(as_list(match.get(field))) for field in source_scoped_fields)


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