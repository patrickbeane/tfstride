"""Normalized GCP firewall packet scope and unresolved constraints.

Unknown scope is never represented by the wildcard protocol or an omitted port
range. The generic network rules are a projection; these records also retain
constraints that that projection cannot express.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from ipaddress import ip_network
from typing import Any, Literal, TypedDict

from tfstride.models import SecurityGroupRule
from tfstride.providers.coercion import value_is_unknown


class FirewallPortRange(TypedDict):
    from_port: int
    to_port: int


class GcpFirewallMatch(TypedDict):
    path: str
    action: str | None
    rule_direction: str | None
    rule_priority: int | None
    rule_disabled: bool | None
    protocol: str | None
    ports_state: Literal["all", "ranges", "not_applicable", "unknown"]
    port_ranges: list[FirewallPortRange]
    source_ranges: list[str]
    source_ranges_state: Literal["configured", "default", "not_configured", "unknown"]
    destination_ranges: list[str]
    source_constraints: dict[str, Any]
    destination_constraints: dict[str, Any]
    unknown_fields: list[str]
    unsupported_fields: list[str]
    uncertainties: list[str]


_PROTOCOL_NAMES = {
    1: "icmp",
    4: "ipip",
    6: "tcp",
    17: "udp",
    50: "esp",
    51: "ah",
    58: "ipv6-icmp",
    132: "sctp",
}
_PROTOCOL_NUMBERS = {name: number for number, name in _PROTOCOL_NAMES.items()}
_PROTOCOL_NUMBERS["icmpv6"] = 58
_POLICY_SOURCE_FIELDS = (
    "src_address_groups",
    "src_fqdns",
    "src_region_codes",
    "src_secure_tags",
    "src_threat_intelligences",
)
_POLICY_DESTINATION_FIELDS = (
    "dest_address_groups",
    "dest_fqdns",
    "dest_region_codes",
    "dest_threat_intelligences",
)


def normalize_firewall_protocol(value: object) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    text = str(value).strip().lower()
    if text in {"all", "-1"}:
        return "-1"
    if text in _PROTOCOL_NUMBERS:
        return _PROTOCOL_NAMES[_PROTOCOL_NUMBERS[text]]
    number = _bounded_integer(text, 255)
    if number is not None:
        return _PROTOCOL_NAMES.get(number, str(number))
    return None


def parse_firewall_port_range(value: object) -> tuple[int, int] | None:
    """Parse an explicit inclusive range; absence and invalidity are not wildcards."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    parts = [part.strip() for part in str(value).strip().split("-")]
    if len(parts) not in {1, 2} or not all(part.isascii() and part.isdecimal() for part in parts):
        return None
    start, end = _bounded_integer(parts[0], 65535), _bounded_integer(parts[-1], 65535)
    return (start, end) if start is not None and end is not None and start <= end else None


def _bounded_integer(value: object, maximum: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    text = str(value).strip()
    if not text.isascii() or not text.isdecimal():
        return None
    digits = text.lstrip("0") or "0"
    if len(digits) > len(str(maximum)):
        return None
    number = int(digits)
    return number if number <= maximum else None


def normalize_firewall_matches(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None = None,
    *,
    policy: bool = False,
) -> list[GcpFirewallMatch]:
    unknown = unknown_values or {}
    common = _common_match(values, unknown, policy=policy)
    records: list[GcpFirewallMatch] = []
    if not policy:
        for action in ("allow", "deny"):
            for block, flags, path in _blocks(values.get(action), unknown.get(action), action):
                record = deepcopy(common)
                record["action"] = action
                records.append(_layer4_match(record, block, flags, path, policy=False))
        return records

    for match, flags, path in _blocks(values.get("match"), unknown.get("match"), "match", required=True):
        record = deepcopy(common)
        if match is None:
            _issue(record, path, "unknown" if value_is_unknown(flags) else "unsupported")
            record["path"] = path
            records.append(record)
            continue
        _match_scope(record, match, flags, prefix=f"{path}.", policy=True)
        key = _alias_key(match, flags, "layer4_configs", "layer4_config")
        _check_aliases(record, match, flags, "layer4_configs", "layer4_config", f"{path}.")
        for block, block_flags, block_path in _blocks(match.get(key), flags.get(key), f"{path}.{key}", required=True):
            records.append(_layer4_match(deepcopy(record), block, block_flags, block_path, policy=True))
    return records


def _common_match(values: Mapping[str, Any], unknown: Mapping[str, Any], *, policy: bool) -> GcpFirewallMatch:
    record: GcpFirewallMatch = {
        "path": "",
        "action": None,
        "rule_direction": None,
        "rule_priority": None,
        "rule_disabled": None,
        "protocol": None,
        "ports_state": "unknown",
        "port_ranges": [],
        "source_ranges": [],
        "source_ranges_state": "unknown",
        "destination_ranges": [],
        "source_constraints": {},
        "destination_constraints": {},
        "unknown_fields": [],
        "unsupported_fields": [],
        "uncertainties": [],
    }
    direction = _known(record, values, unknown, "direction", default="ingress")
    if isinstance(direction, str) and direction.strip().lower() in {"ingress", "egress"}:
        record["rule_direction"] = direction.strip().lower()
    elif not value_is_unknown(unknown.get("direction")):
        _issue(record, "direction", "unsupported")
    priority = _known(record, values, unknown, "priority", default=1000)
    limit = 2147483647 if policy else 65535
    record["rule_priority"] = _bounded_integer(priority, limit)
    if record["rule_priority"] is None and not value_is_unknown(unknown.get("priority")):
        _issue(record, "priority", "unsupported")
    disabled = _known(record, values, unknown, "disabled", default=False)
    if isinstance(disabled, bool):
        record["rule_disabled"] = disabled
    elif not value_is_unknown(unknown.get("disabled")):
        _issue(record, "disabled", "unsupported")
    if policy:
        action = _known(record, values, unknown, "action")
        if isinstance(action, str) and action.strip().lower() in {"allow", "deny", "goto_next", "go_to_next"}:
            record["action"] = action.strip().lower().replace("go_to_next", "goto_next")
        elif not value_is_unknown(unknown.get("action")):
            _issue(record, "action", "unsupported")
    else:
        _match_scope(record, values, unknown, prefix="", policy=False)
    # Keep unresolved applicability visible even when the legacy typed metadata
    # readers would coerce it into an empty list or a default value.
    for key in (
        ("firewall_policy", "target_resources", "target_service_accounts", "target_secure_tags")
        if policy
        else ("network", "target_tags", "target_service_accounts")
    ):
        value = _known(record, values, unknown, key)
        if value is None:
            continue
        if key == "target_secure_tags" and value:
            _issue(record, key, "unsupported")
        elif key in {"network", "firewall_policy"}:
            if not isinstance(value, str) or not value.strip():
                _issue(record, key, "unsupported")
        elif not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
            _issue(record, key, "unsupported")
    return record


def _match_scope(
    record: GcpFirewallMatch, values: Mapping[str, Any], unknown: Mapping[str, Any], *, prefix: str, policy: bool
) -> None:
    source_key = _alias_key(values, unknown, "src_ip_ranges", "src_ip_range") if policy else "source_ranges"
    destination_key = _alias_key(values, unknown, "dest_ip_ranges", "dest_ip_range") if policy else "destination_ranges"
    source_fields = _POLICY_SOURCE_FIELDS if policy else ("source_tags", "source_service_accounts")
    destination_fields = _POLICY_DESTINATION_FIELDS if policy else ()
    if policy:
        _check_aliases(record, values, unknown, "src_ip_ranges", "src_ip_range", prefix)
        _check_aliases(record, values, unknown, "dest_ip_ranges", "dest_ip_range", prefix)
    source_ranges = _cidrs(record, values, unknown, source_key, prefix)
    record["source_ranges"] = source_ranges
    record["destination_ranges"] = _cidrs(record, values, unknown, destination_key, prefix)
    for key in (*source_fields, *destination_fields):
        value = _known(record, values, unknown, key, prefix=prefix)
        if value:
            constraints = record["source_constraints"] if key in source_fields else record["destination_constraints"]
            constraints[key] = deepcopy(value)
            _issue(record, f"{prefix}{key}", "unsupported")
    source_uncertain = any(
        field.startswith(f"{prefix}{'src_ip_range' if policy else source_key}")
        or ((policy or not source_ranges) and any(field == f"{prefix}{key}" for key in source_fields))
        for field in record["unknown_fields"] + record["unsupported_fields"]
    )
    if source_uncertain:
        record["source_ranges_state"] = "unknown"
    elif source_ranges:
        record["source_ranges_state"] = "configured"
    elif record["rule_direction"] == "ingress":
        record["source_ranges"] = ["0.0.0.0/0"]
        record["source_ranges_state"] = "default"
    else:
        record["source_ranges_state"] = "not_configured"
    # Destination-constrained ingress needs the destination interface/IP match,
    # which the current public-ingress projection cannot establish.
    if record["rule_direction"] == "ingress" and record["destination_ranges"]:
        _issue(record, f"{prefix}{destination_key}", "unsupported")
    if policy:
        modeled = {
            "src_ip_ranges",
            "src_ip_range",
            "dest_ip_ranges",
            "dest_ip_range",
            "layer4_configs",
            "layer4_config",
            *source_fields,
            *destination_fields,
        }
        for key in sorted(set(values) | set(unknown)):
            if key not in modeled and (values.get(key) or value_is_unknown(unknown.get(key))):
                _issue(record, f"{prefix}{key}", "unknown" if value_is_unknown(unknown.get(key)) else "unsupported")


def _alias_key(values: Mapping[str, Any], unknown: Mapping[str, Any], plural: str, singular: str) -> str:
    return plural if values.get(plural) or value_is_unknown(unknown.get(plural)) else singular


def _check_aliases(
    record: GcpFirewallMatch,
    values: Mapping[str, Any],
    unknown: Mapping[str, Any],
    plural: str,
    singular: str,
    prefix: str,
) -> None:
    selected = _alias_key(values, unknown, plural, singular)
    for key in (plural, singular):
        if key != selected and value_is_unknown(unknown.get(key)):
            _issue(record, f"{prefix}{key}", "unknown")
    if values.get(plural) and values.get(singular) and values[plural] != values[singular]:
        _issue(record, f"{prefix}{plural}", "unsupported")
        _issue(record, f"{prefix}{singular}", "unsupported")


def _cidrs(
    record: GcpFirewallMatch, values: Mapping[str, Any], unknown: Mapping[str, Any], key: str, prefix: str
) -> list[str]:
    raw = _known(record, values, unknown, key, prefix=prefix)
    if raw is None:
        return []
    if not isinstance(raw, list):
        _issue(record, f"{prefix}{key}", "unsupported")
        return []
    result: set[str] = set()
    for index, value in enumerate(raw):
        try:
            if not isinstance(value, str) or "/" not in value:
                raise ValueError
            result.add(str(ip_network(value.strip(), strict=False)))
        except ValueError:
            _issue(record, f"{prefix}{key}[{index}]", "unsupported")
    return sorted(result)


def _blocks(
    raw: Any, unknown: Any, path: str, *, required: bool = False
) -> list[tuple[Mapping[str, Any] | None, Mapping[str, Any], str]]:
    if unknown is True:
        return [(None, {"block": True}, path)]
    blocks = raw if isinstance(raw, list) else ([] if raw is None else [raw])
    flags = unknown if isinstance(unknown, list) else ([] if unknown is None or unknown is False else [unknown])
    result: list[tuple[Mapping[str, Any] | None, Mapping[str, Any], str]] = []
    for index in range(max(len(blocks), len(flags), int(required))):
        block = blocks[index] if index < len(blocks) else None
        flag = flags[index] if index < len(flags) else {}
        result.append(
            (
                block if isinstance(block, Mapping) and flag is not True else None,
                flag if isinstance(flag, Mapping) else {"block": flag},
                f"{path}[{index}]",
            )
        )
    return result


def _layer4_match(
    record: GcpFirewallMatch, block: Mapping[str, Any] | None, unknown: Mapping[str, Any], path: str, *, policy: bool
) -> GcpFirewallMatch:
    record["path"] = path
    if block is None:
        _issue(record, path, "unknown" if value_is_unknown(unknown) else "unsupported")
        return record
    key = "ip_protocol" if policy and ("ip_protocol" in block or "ip_protocol" in unknown) else "protocol"
    for field in sorted(set(block) | set(unknown)):
        if field not in {key, "ports"} and (block.get(field) or value_is_unknown(unknown.get(field))):
            _issue(record, f"{path}.{field}", "unknown" if value_is_unknown(unknown.get(field)) else "unsupported")
    raw_protocol = _known(record, block, unknown, key, prefix=f"{path}.")
    record["protocol"] = normalize_firewall_protocol(raw_protocol)
    if record["protocol"] is None and not value_is_unknown(unknown.get(key)):
        _issue(record, f"{path}.{key}", "unsupported")
    ports = _known(record, block, unknown, "ports", prefix=f"{path}.")
    if value_is_unknown(unknown.get("ports")):
        return record
    if ports is None or ports == []:
        if record["protocol"] is not None:
            record["ports_state"] = "all" if record["protocol"] in {"-1", "tcp", "udp"} else "not_applicable"
        return record
    if not isinstance(ports, list) or record["protocol"] not in {"tcp", "udp"}:
        _issue(record, f"{path}.ports", "unsupported")
        return record
    ranges: set[tuple[int, int]] = set()
    for index, value in enumerate(ports):
        interval = parse_firewall_port_range(value)
        if interval is None:
            _issue(record, f"{path}.ports[{index}]", "unsupported")
        else:
            ranges.add(interval)
    record["port_ranges"] = [FirewallPortRange(from_port=start, to_port=end) for start, end in sorted(ranges)]
    if not any(field.startswith(f"{path}.ports") for field in record["unsupported_fields"]):
        record["ports_state"] = "ranges"
    return record


def _known(
    record: GcpFirewallMatch,
    values: Mapping[str, Any],
    unknown: Mapping[str, Any],
    key: str,
    *,
    prefix: str = "",
    default: Any = None,
) -> Any:
    if value_is_unknown(unknown.get(key)):
        _issue(record, f"{prefix}{key}", "unknown")
        return None
    value = values.get(key)
    return default if value is None else value


def _issue(record: GcpFirewallMatch, path: str, state: Literal["unknown", "unsupported"]) -> None:
    fields = record["unknown_fields"] if state == "unknown" else record["unsupported_fields"]
    if path not in fields:
        fields.append(path)
        record["uncertainties"].append(
            f"{path} is unknown after planning"
            if state == "unknown"
            else f"{path} is malformed or not supported by the firewall match model"
        )


def firewall_match_network_rules(record: GcpFirewallMatch) -> list[SecurityGroupRule]:
    """Project only known match scope into the shared, two-valued rule model."""
    protocol = record["protocol"]
    direction = record["rule_direction"]
    if protocol is None or direction is None or record["ports_state"] == "unknown":
        return []
    # Preserve known non-CIDR source rules as non-public generic rules for
    # existing consumers, while retaining their constraints in the match record.
    source_only = bool(record["source_constraints"]) and not record["source_ranges"] and not record["unknown_fields"]
    # VPC source tags/service accounts are alternatives to source CIDRs. Their
    # unresolved contribution cannot narrow an explicitly known CIDR match.
    known_cidr_alternative = record["source_ranges_state"] == "configured" and set(
        record["unknown_fields"] + record["unsupported_fields"]
    ) <= {"source_tags", "source_service_accounts"}
    if record["uncertainties"] and not (
        known_cidr_alternative
        or (
            source_only
            and all(field.rsplit(".", 1)[-1] in record["source_constraints"] for field in record["unsupported_fields"])
        )
    ):
        return []
    cidrs = record["destination_ranges"] if direction == "egress" else record["source_ranges"]
    intervals: list[tuple[int | None, int | None]] = (
        [(item["from_port"], item["to_port"]) for item in record["port_ranges"]]
        if record["ports_state"] == "ranges"
        else [(None, None)]
    )
    return [
        SecurityGroupRule(
            direction=direction,
            protocol=protocol,
            from_port=start,
            to_port=end,
            cidr_blocks=[cidr for cidr in cidrs if ":" not in cidr],
            ipv6_cidr_blocks=[cidr for cidr in cidrs if ":" in cidr],
        )
        for start, end in intervals
    ]
