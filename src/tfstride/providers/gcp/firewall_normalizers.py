from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, SecurityGroupRule, TerraformResource
from tfstride.providers.gcp.attributes import GcpAttr, GcpValues
from tfstride.providers.gcp.coercion import as_optional_int, first_item
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizer_utils import _gcp_values
from tfstride.providers.gcp.normalizer_common import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_identifier, resource_name


def normalize_compute_firewall(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=resource_identifier(resource),
        vpc_id=values.get(GcpAttr.NETWORK),
        network_rules=parse_firewall_allow_rules(values),
        metadata={
            GcpResourceMetadata.NAME: resource_name(resource),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.NETWORK: values.get(GcpAttr.NETWORK),
            GcpResourceMetadata.FIREWALL_ALLOW: values.get(GcpAttr.ALLOW),
            GcpResourceMetadata.FIREWALL_DENY: values.get(GcpAttr.DENY),
            GcpResourceMetadata.FIREWALL_SOURCE_RANGES: values.get(GcpAttr.SOURCE_RANGES),
            GcpResourceMetadata.FIREWALL_DESTINATION_RANGES: values.get(GcpAttr.DESTINATION_RANGES),
            GcpResourceMetadata.FIREWALL_TARGET_TAGS: values.get(GcpAttr.TARGET_TAGS),
            GcpResourceMetadata.FIREWALL_SOURCE_TAGS: values.get(GcpAttr.SOURCE_TAGS),
            GcpResourceMetadata.FIREWALL_TARGET_SERVICE_ACCOUNTS: values.get(GcpAttr.TARGET_SERVICE_ACCOUNTS),
            GcpResourceMetadata.FIREWALL_SOURCE_SERVICE_ACCOUNTS: values.get(GcpAttr.SOURCE_SERVICE_ACCOUNTS),
            GcpResourceMetadata.FIREWALL_DIRECTION: str(values.get(GcpAttr.DIRECTION) or "INGRESS").lower(),
            GcpResourceMetadata.FIREWALL_PRIORITY: values.get(GcpAttr.PRIORITY),
            GcpResourceMetadata.FIREWALL_DISABLED: values.get(GcpAttr.DISABLED),
        },
    )


def normalize_compute_firewall_policy(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=first_non_empty(
            values.get(GcpAttr.SHORT_NAME), values.get(GcpAttr.NAME), resource_identifier(resource)
        ),
        metadata={
            GcpResourceMetadata.NAME: first_non_empty(values.get(GcpAttr.SHORT_NAME), values.get(GcpAttr.NAME)),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.FIREWALL_POLICY_REFERENCE: values.get(GcpAttr.NAME),
            GcpResourceMetadata.FIREWALL_POLICY_PARENT: values.get(GcpAttr.PARENT),
            "description": values.get(GcpAttr.DESCRIPTION),
            "display_name": values.get(GcpAttr.DISPLAY_NAME),
        },
    )


def normalize_compute_firewall_policy_rule(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    match = _firewall_policy_match(values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=_firewall_policy_rule_identifier(resource),
        network_rules=parse_firewall_policy_rules(values),
        metadata={
            GcpResourceMetadata.NAME: first_non_empty(values.get(GcpAttr.NAME)),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.FIREWALL_POLICY_REFERENCE: values.get(GcpAttr.FIREWALL_POLICY),
            GcpResourceMetadata.FIREWALL_POLICY_ACTION: values.get(GcpAttr.ACTION),
            GcpResourceMetadata.FIREWALL_POLICY_DIRECTION: _firewall_policy_direction(values),
            GcpResourceMetadata.FIREWALL_POLICY_PRIORITY: values.get(GcpAttr.PRIORITY),
            GcpResourceMetadata.FIREWALL_POLICY_MATCH: match,
            GcpResourceMetadata.FIREWALL_SOURCE_RANGES: _firewall_policy_source_ranges(match),
            GcpResourceMetadata.FIREWALL_DESTINATION_RANGES: _firewall_policy_destination_ranges(match),
            GcpResourceMetadata.FIREWALL_POLICY_TARGET_RESOURCES: values.get(GcpAttr.TARGET_RESOURCES),
            GcpResourceMetadata.FIREWALL_POLICY_TARGET_SERVICE_ACCOUNTS: values.get(GcpAttr.TARGET_SERVICE_ACCOUNTS),
            GcpResourceMetadata.FIREWALL_POLICY_DISABLED: values.get(GcpAttr.DISABLED),
            GcpResourceMetadata.FIREWALL_POLICY_ENABLE_LOGGING: values.get(GcpAttr.ENABLE_LOGGING),
            "description": values.get(GcpAttr.DESCRIPTION),
        },
    )


def normalize_compute_firewall_policy_association(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=first_non_empty(
            values.get(GcpAttr.ATTACHMENT_TARGET), values.get(GcpAttr.NAME), resource_identifier(resource)
        ),
        metadata={
            GcpResourceMetadata.NAME: first_non_empty(values.get(GcpAttr.NAME)),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.FIREWALL_POLICY_REFERENCE: values.get(GcpAttr.FIREWALL_POLICY),
            GcpResourceMetadata.FIREWALL_POLICY_ATTACHMENT_TARGET: values.get(GcpAttr.ATTACHMENT_TARGET),
            "display_name": values.get(GcpAttr.DISPLAY_NAME),
        },
    )


def parse_firewall_allow_rules(values: dict[str, Any] | GcpValues) -> list[SecurityGroupRule]:
    gcp_values = _gcp_values(values)
    direction = str(gcp_values.get(GcpAttr.DIRECTION) or "INGRESS").strip().lower()
    cidr_blocks = _firewall_cidr_blocks(gcp_values, direction)
    rules: list[SecurityGroupRule] = []
    for allow in gcp_values.get(GcpAttr.ALLOW):
        allow_values = GcpValues(allow)
        protocol = str(allow_values.get(GcpAttr.PROTOCOL) or "-1")
        ports = allow_values.get(GcpAttr.PORTS)
        if not ports:
            rules.append(_firewall_rule(direction, protocol, None, None, cidr_blocks))
            continue
        for port in ports:
            from_port, to_port = _parse_port_range(port)
            rules.append(_firewall_rule(direction, protocol, from_port, to_port, cidr_blocks))
    return rules


def parse_firewall_policy_allow_rules(values: dict[str, Any] | GcpValues) -> list[SecurityGroupRule]:
    gcp_values = _gcp_values(values)
    if str(gcp_values.get(GcpAttr.ACTION) or "").strip().lower() != "allow":
        return []
    return parse_firewall_policy_rules(gcp_values)


def parse_firewall_policy_rules(
    values: dict[str, Any] | GcpValues,
) -> list[SecurityGroupRule]:
    gcp_values = _gcp_values(values)
    match = _firewall_policy_match(gcp_values)
    direction = _firewall_policy_direction(gcp_values)
    cidr_blocks = _firewall_policy_cidr_blocks(match, direction)
    rules: list[SecurityGroupRule] = []
    for layer4_config in _firewall_policy_layer4_configs(match):
        layer4_values = GcpValues(layer4_config)
        protocol = str(layer4_values.get(GcpAttr.IP_PROTOCOL) or layer4_values.get(GcpAttr.PROTOCOL) or "-1")
        ports = layer4_values.get(GcpAttr.PORTS)
        if not ports:
            rules.append(_firewall_rule(direction, protocol, None, None, cidr_blocks))
            continue
        for port in ports:
            from_port, to_port = _parse_port_range(port)
            rules.append(_firewall_rule(direction, protocol, from_port, to_port, cidr_blocks))
    return rules


def _firewall_policy_rule_identifier(resource: TerraformResource) -> str | None:
    values = GcpValues(resource.values)
    firewall_policy = first_non_empty(values.get(GcpAttr.FIREWALL_POLICY))
    priority = first_non_empty(values.get(GcpAttr.PRIORITY))
    if firewall_policy and priority:
        return f"{firewall_policy}/rules/{priority}"
    return resource_identifier(resource)


def _firewall_policy_match(values: GcpValues) -> dict[str, Any]:
    return first_item(values.get(GcpAttr.MATCH)) or {}


def _firewall_policy_direction(values: GcpValues) -> str:
    return str(values.get(GcpAttr.DIRECTION) or "INGRESS").strip().lower()


def _firewall_policy_layer4_configs(match: dict[str, Any]) -> list[dict[str, Any]]:
    match_values = GcpValues(match)
    return match_values.get(GcpAttr.LAYER4_CONFIGS) or match_values.get(GcpAttr.LAYER4_CONFIG)


def _firewall_policy_source_ranges(match: dict[str, Any]) -> list[str]:
    match_values = GcpValues(match)
    return match_values.get(GcpAttr.SRC_IP_RANGES) or match_values.get(GcpAttr.SRC_IP_RANGE)


def _firewall_policy_destination_ranges(match: dict[str, Any]) -> list[str]:
    match_values = GcpValues(match)
    return match_values.get(GcpAttr.DEST_IP_RANGES) or match_values.get(GcpAttr.DEST_IP_RANGE)


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
    match_values = GcpValues(match)
    source_scoped_fields = (
        GcpAttr.SRC_ADDRESS_GROUPS,
        GcpAttr.SRC_FQDNS,
        GcpAttr.SRC_REGION_CODES,
        GcpAttr.SRC_SECURE_TAGS,
        GcpAttr.SRC_THREAT_INTELLIGENCES,
    )
    return any(match_values.get(field) for field in source_scoped_fields)


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


def _firewall_cidr_blocks(values: GcpValues, direction: str) -> list[str]:
    source_ranges = values.get(GcpAttr.SOURCE_RANGES)
    destination_ranges = values.get(GcpAttr.DESTINATION_RANGES)
    if direction == "egress" and destination_ranges:
        return destination_ranges
    if source_ranges:
        return source_ranges
    source_tags = values.get(GcpAttr.SOURCE_TAGS)
    source_service_accounts = values.get(GcpAttr.SOURCE_SERVICE_ACCOUNTS)
    if direction == "ingress" and not source_tags and not source_service_accounts:
        return ["0.0.0.0/0"]
    return []


def _parse_port_range(value: Any) -> tuple[int | None, int | None]:
    text = str(value).strip()
    if not text:
        return (None, None)
    if "-" not in text:
        port = as_optional_int(text)
        return (port, port)
    start, end = text.split("-", 1)
    return (as_optional_int(start.strip()), as_optional_int(end.strip()))
