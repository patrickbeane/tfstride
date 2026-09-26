"""Known network inputs used by the AWS packet-permission evaluator."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from tfstride.models import TerraformResource
from tfstride.providers.coercion import block_attribute_unknown, unknown_block_at


def network_value(values: Mapping[str, Any], unknown: Any, key: str) -> Any:
    return None if block_attribute_unknown(unknown, key) else values.get(key)


def network_string(values: Mapping[str, Any], unknown: Any, key: str, default: str | None = None) -> str | None:
    if block_attribute_unknown(unknown, key):
        return None
    value = values.get(key, default)
    return value if isinstance(value, str) and value.strip() else None


def network_port(values: Mapping[str, Any], unknown: Any, key: str) -> int | None:
    value = network_value(values, unknown, key)
    return value if type(value) is int and 1 <= value <= 65535 else None


def network_strings(values: Mapping[str, Any], unknown: Any, key: str) -> tuple[list[str], bool]:
    if block_attribute_unknown(unknown, key):
        return [], False
    value = values.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        return [], False
    return sorted(set(value)), True


def network_attachments(resource: TerraformResource, *, ecs: bool = False) -> dict[str, Any]:
    values, unknown = resource.values, resource.unknown_values
    prefix: list[str | int] = []
    if ecs:
        blocks = values.get("network_configuration")
        raw_unknown = unknown.get("network_configuration")
        prefix = ["network_configuration", 0]
        if isinstance(blocks, list) and len(blocks) == 1 and isinstance(blocks[0], dict):
            values, unknown = blocks[0], unknown_block_at(raw_unknown, 0)
        elif isinstance(blocks, dict):
            values, unknown = blocks, raw_unknown
        else:
            values, unknown = {}, True
    groups, groups_complete = network_strings(values, unknown, "security_groups")
    subnets, subnets_complete = network_strings(values, unknown, "subnets")
    return {
        "security_groups": groups,
        "security_groups_complete": groups_complete and bool(groups),
        "security_group_path": [*prefix, "security_groups"],
        "subnets": subnets,
        "subnets_complete": subnets_complete and bool(subnets),
        "subnet_path": [*prefix, "subnets"],
    }


def container_network_inputs(
    resource: TerraformResource, definitions: list[Any], parse_uncertainties: list[str]
) -> dict[str, Any]:
    containers: list[dict[str, Any]] = []
    unknown_definitions = resource.unknown_values.get("container_definitions")
    for index, definition in enumerate(definitions):
        unknown = unknown_block_at(unknown_definitions, index)
        if not isinstance(definition, Mapping) or unknown is True:
            containers.append({"name": None, "port_mappings": [], "complete": False})
            continue
        name = network_string(definition, unknown, "name")
        mappings = network_value(definition, unknown, "portMappings")
        unknown_mappings = cast(dict[str, Any], unknown).get("portMappings") if isinstance(unknown, dict) else None
        records: list[dict[str, Any]] = []
        complete = isinstance(mappings, list)
        if isinstance(mappings, list):
            for position, mapping in enumerate(mappings):
                unknown_mapping = unknown_block_at(unknown_mappings, position)
                if not isinstance(mapping, Mapping) or unknown_mapping is True:
                    complete = False
                    continue
                mapping = cast(Mapping[str, Any], mapping)
                port = network_port(mapping, unknown_mapping, "containerPort")
                host_port = network_port(mapping, unknown_mapping, "hostPort")
                records.append(
                    {
                        "container_port": port,
                        "container_port_omitted": mapping.get("containerPort") is None
                        and not block_attribute_unknown(unknown_mapping, "containerPort"),
                        "container_port_range": network_string(mapping, unknown_mapping, "containerPortRange"),
                        "container_range_omitted": mapping.get("containerPortRange") is None
                        and not block_attribute_unknown(unknown_mapping, "containerPortRange"),
                        "host_port": host_port,
                        "host_port_omitted": "hostPort" not in mapping
                        and not block_attribute_unknown(unknown_mapping, "hostPort"),
                        "protocol": network_string(mapping, unknown_mapping, "protocol", "tcp"),
                    }
                )
        containers.append({"name": name, "port_mappings": records, "complete": complete})
    return {
        "network_mode": network_string(resource.values, resource.unknown_values, "network_mode"),
        "containers": containers,
        "uncertainties": parse_uncertainties,
    }


def security_group_traffic_rules(resource: TerraformResource) -> list[dict[str, Any]]:
    if resource.resource_type == "aws_security_group_rule":
        return [_traffic_rule(resource.values, resource.unknown_values, [], standalone=True)]
    records: list[dict[str, Any]] = []
    for direction in ("ingress", "egress"):
        blocks = resource.values.get(direction, [])
        unknown = resource.unknown_values.get(direction)
        if unknown is True or not isinstance(blocks, list):
            records.append(_traffic_rule({}, True, [direction], direction=direction))
            continue
        for index, block in enumerate(blocks):
            records.append(
                _traffic_rule(
                    block if isinstance(block, Mapping) else {},
                    unknown_block_at(unknown, index) if isinstance(block, Mapping) else True,
                    [direction, index],
                    direction=direction,
                )
            )
        if isinstance(unknown, list) and len(unknown) > len(blocks):
            records.append(_traffic_rule({}, True, [direction], direction=direction))
    return records


def _traffic_rule(
    values: Mapping[str, Any],
    unknown: Any,
    path: list[str | int],
    *,
    direction: str | None = None,
    standalone: bool = False,
) -> dict[str, Any]:
    raw_protocol = network_value(values, unknown, "protocol")
    protocol = str(raw_protocol).lower() if isinstance(raw_protocol, str) or type(raw_protocol) is int else None
    if protocol is not None:
        protocol = {"6": "tcp", "17": "udp", "-1": "all"}.get(protocol, protocol)
    groups, groups_complete = network_strings(values, unknown, "security_groups")
    group_field = "source_security_group_id" if standalone else "security_groups"
    if standalone:
        reference = network_string(values, unknown, group_field)
        groups = [reference] if reference else []
        groups_complete = not block_attribute_unknown(unknown, group_field) and (
            values.get(group_field) is None or reference is not None
        )
    ipv4, ipv4_complete = network_strings(values, unknown, "cidr_blocks")
    ipv6, ipv6_complete = network_strings(values, unknown, "ipv6_cidr_blocks")
    prefixes, prefixes_complete = network_strings(values, unknown, "prefix_list_ids")
    return {
        "path": path,
        "rule_direction": direction or network_string(values, unknown, "type"),
        "protocol": protocol,
        "from_port": network_value(values, unknown, "from_port"),
        "to_port": network_value(values, unknown, "to_port"),
        "cidr_blocks": ipv4,
        "ipv6_cidr_blocks": ipv6,
        "security_groups": groups,
        "security_group_path": [*path, group_field],
        "self": network_value(values, unknown, "self"),
        "selectors_complete": ipv4_complete
        and ipv6_complete
        and groups_complete
        and prefixes_complete
        and not prefixes
        and (values.get("self") is None or type(values.get("self")) is bool)
        and not block_attribute_unknown(unknown, "self"),
    }
