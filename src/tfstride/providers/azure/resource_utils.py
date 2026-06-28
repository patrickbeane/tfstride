from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from tfstride.models import NormalizedResource, SecurityGroupRule
from tfstride.providers.azure.metadata import AzureResourceMetadata

_AZURE_REFERENCE_SUFFIXES = (".id", ".name")


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def compact_strings(values: Iterable[Any]) -> list[str]:
    compacted: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text or text in seen:
            continue
        compacted.append(text)
        seen.add(text)
    return compacted


def first_non_empty(*values: Any) -> str | None:
    compacted = compact_strings(values)
    return compacted[0] if compacted else None


def value_is_unknown(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, Mapping):
        return any(value_is_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(value_is_unknown(item) for item in value)
    return False


def attribute_unknown(unknown_values: Mapping[str, Any] | None, key: str) -> bool:
    return isinstance(unknown_values, Mapping) and value_is_unknown(unknown_values.get(key))


def first_mapping(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, list) and value and isinstance(value[0], Mapping):
        return value[0]
    return None


def unknown_block_at(value: Any, index: int) -> Any:
    if value is True:
        return True
    if isinstance(value, list) and index < len(value):
        return value[index]
    return None


def block_attribute_unknown(unknown_block: Any, key: str) -> bool:
    if unknown_block is True:
        return True
    if isinstance(unknown_block, Mapping):
        return value_is_unknown(unknown_block.get(key))
    if isinstance(unknown_block, list) and unknown_block:
        first = unknown_block[0]
        return first is True or (isinstance(first, Mapping) and value_is_unknown(first.get(key)))
    return False


def first_block_attribute_unknown(
    unknown_values: Mapping[str, Any] | None,
    block: str,
    key: str,
) -> bool:
    if not isinstance(unknown_values, Mapping):
        return False
    return block_attribute_unknown(unknown_values.get(block), key)


def known_string(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
    *,
    path: str | None = None,
    require_string: bool = False,
) -> str | None:
    display_path = path or key
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{display_path} is unknown after planning")
        return None
    raw = values.get(key)
    if raw is None:
        return None
    if require_string and not isinstance(raw, str):
        uncertainties.append(f"{display_path} has an unrecognized value shape")
        return None
    return first_non_empty(raw)


def known_string_list(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
    *,
    path: str | None = None,
) -> list[str]:
    display_path = path or key
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{display_path} is unknown after planning")
        return []
    return compact_strings(as_list(values.get(key)))


def known_bool(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
    *,
    path: str | None = None,
    allow_string: bool = True,
) -> bool | None:
    display_path = path or key
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{display_path} is unknown after planning")
        return None
    if key not in values or values[key] is None:
        return None
    value = values[key]
    if isinstance(value, bool):
        return value
    if allow_string and isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "enabled", "yes", "on"}:
            return True
        if normalized in {"false", "disabled", "no", "off"}:
            return False
    uncertainties.append(f"{display_path} has an unrecognized value shape")
    return None


def known_block_string(
    values: Mapping[str, Any] | None,
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
    unknown_fields: list[str] | None = None,
) -> str | None:
    if block_attribute_unknown(unknown_block, key):
        uncertainties.append(f"{path}.{key} is unknown after planning")
        if unknown_fields is not None:
            unknown_fields.append(key)
        return None
    return first_non_empty(values.get(key)) if values is not None else None


def known_block_strings(
    values: Mapping[str, Any] | None,
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
    unknown_fields: list[str] | None = None,
) -> list[str]:
    if block_attribute_unknown(unknown_block, key):
        uncertainties.append(f"{path}.{key} is unknown after planning")
        if unknown_fields is not None:
            unknown_fields.append(key)
        return []
    return compact_strings(as_list(values.get(key))) if values is not None else []


def known_block_bool(
    values: Mapping[str, Any] | None,
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
    unknown_fields: list[str] | None = None,
) -> bool | None:
    if block_attribute_unknown(unknown_block, key):
        uncertainties.append(f"{path}.{key} is unknown after planning")
        if unknown_fields is not None:
            unknown_fields.append(key)
        return None
    value = values.get(key) if values is not None else None
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    uncertainties.append(f"{path}.{key} has an unrecognized value shape")
    return None


def known_block_int(
    values: Mapping[str, Any] | None,
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
    unknown_fields: list[str] | None = None,
) -> int | None:
    if block_attribute_unknown(unknown_block, key):
        uncertainties.append(f"{path}.{key} is unknown after planning")
        if unknown_fields is not None:
            unknown_fields.append(key)
        return None
    value = values.get(key) if values is not None else None
    if value is None:
        return None
    if isinstance(value, bool):
        uncertainties.append(f"{path}.{key} has an unrecognized value shape")
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        uncertainties.append(f"{path}.{key} has an unrecognized value shape")
        return None


def tls_version_below_1_2(value: str | None) -> bool:
    if value is None:
        return False
    normalized = value.strip().lower().replace(".", "_").replace("-", "_")
    return normalized in {"tls1_0", "tls1_1", "tlsv1", "tlsv1_0", "tlsv1_1", "1_0", "1_1"}


def azure_reference_key(value: str | None) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if text.startswith("${") and text.endswith("}"):
        text = text[2:-1].strip()
    lowered = text.lower()
    for suffix in _AZURE_REFERENCE_SUFFIXES:
        if lowered.endswith(suffix):
            lowered = lowered[: -len(suffix)]
            break
    return lowered


def azure_resource_references(resource: NormalizedResource) -> tuple[str, ...]:
    references = {
        resource.address,
        f"{resource.address}.id",
        f"{resource.address}.name",
    }
    for value in (
        resource.identifier,
        resource.get_metadata_field(AzureResourceMetadata.NAME),
        resource.get_metadata_field(AzureResourceMetadata.STORAGE_ACCOUNT_ID),
        resource.get_metadata_field(AzureResourceMetadata.KEY_VAULT_ID),
        resource.get_metadata_field(AzureResourceMetadata.CLIENT_ID),
        resource.get_metadata_field(AzureResourceMetadata.PRINCIPAL_ID),
        resource.get_metadata_field(AzureResourceMetadata.PUBLIC_IP_ADDRESS),
    ):
        if value:
            references.add(value)
    return tuple(sorted({azure_reference_key(reference) for reference in references if reference}))


def parse_network_security_rules(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None = None,
) -> tuple[list[SecurityGroupRule], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    allow_rules: list[SecurityGroupRule] = []
    for raw_rule, raw_unknown in _rule_mappings(values, unknown_values):
        record = normalize_network_security_rule_record(raw_rule, raw_unknown)
        records.append(record)
        if record["access"] != "allow" or not _has_known_rule_decision(record):
            continue
        for from_port, to_port in _port_ranges(record["destination_port_ranges"]):
            allow_rules.append(
                SecurityGroupRule(
                    direction=record["rule_direction"],
                    protocol=record["protocol"],
                    from_port=from_port,
                    to_port=to_port,
                    cidr_blocks=list(record["source_cidr_blocks"]),
                    description=record["description"],
                )
            )
    return allow_rules, records


def normalize_network_security_rule_record(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | bool | None = None,
) -> dict[str, Any]:
    source_prefixes = compact_strings(
        [values.get("source_address_prefix"), *as_list(values.get("source_address_prefixes"))]
    )
    destination_prefixes = compact_strings(
        [values.get("destination_address_prefix"), *as_list(values.get("destination_address_prefixes"))]
    )
    destination_ports = compact_strings(
        [values.get("destination_port_range"), *as_list(values.get("destination_port_ranges"))]
    ) or ["*"]
    record = {
        "name": first_non_empty(values.get("name")),
        "rule_priority": _optional_int(values.get("priority")),
        "rule_direction": _direction(values.get("direction")),
        "access": str(values.get("access") or "Allow").strip().lower(),
        "protocol": _protocol(values.get("protocol")),
        "source_address_prefixes": source_prefixes,
        "source_cidr_blocks": _internet_cidr_blocks(source_prefixes),
        "source_port_ranges": compact_strings(
            [values.get("source_port_range"), *as_list(values.get("source_port_ranges"))]
        )
        or ["*"],
        "destination_address_prefixes": destination_prefixes,
        "destination_port_ranges": destination_ports,
        "source_application_security_group_ids": compact_strings(
            as_list(values.get("source_application_security_group_ids"))
        ),
        "destination_application_security_group_ids": compact_strings(
            as_list(values.get("destination_application_security_group_ids"))
        ),
        "description": first_non_empty(values.get("description")),
    }
    unknown_fields = _unknown_decision_fields(unknown_values)
    if unknown_fields:
        record["unknown_decision_fields"] = unknown_fields
    unsupported_fields = _unsupported_decision_fields(record)
    if unsupported_fields:
        record["unsupported_decision_fields"] = unsupported_fields
    return record


def clone_security_group_rules(rules: Iterable[SecurityGroupRule]) -> list[SecurityGroupRule]:
    return [
        SecurityGroupRule(
            direction=rule.direction,
            protocol=rule.protocol,
            from_port=rule.from_port,
            to_port=rule.to_port,
            cidr_blocks=list(rule.cidr_blocks),
            ipv6_cidr_blocks=list(rule.ipv6_cidr_blocks),
            referenced_security_group_ids=list(rule.referenced_security_group_ids),
            description=rule.description,
        )
        for rule in rules
    ]


def _has_known_rule_decision(record: Mapping[str, Any]) -> bool:
    return (
        not record.get("unknown_decision_fields")
        and not record.get("unsupported_decision_fields")
        and record.get("rule_priority") is not None
    )


def _rule_mappings(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None = None,
) -> list[tuple[Mapping[str, Any], Mapping[str, Any] | bool | None]]:
    unknown_values = unknown_values or {}
    if "security_rule" in values:
        unknown_rules = unknown_values.get("security_rule") if isinstance(unknown_values, Mapping) else None
        return [
            (rule, _unknown_rule_at(unknown_rules, index))
            for index, rule in enumerate(as_list(values.get("security_rule")))
            if isinstance(rule, Mapping)
        ]
    return [(values, unknown_values if isinstance(unknown_values, Mapping) else None)]


def _unknown_rule_at(value: Any, index: int) -> Mapping[str, Any] | bool | None:
    if value is True:
        return True
    if isinstance(value, list) and index < len(value):
        item = value[index]
        return item if isinstance(item, Mapping) or item is True else None
    return None


def _unknown_decision_fields(unknown_values: Mapping[str, Any] | bool | None) -> list[str]:
    decision_fields = (
        "priority",
        "direction",
        "access",
        "protocol",
        "source_address_prefix",
        "source_address_prefixes",
        "destination_address_prefix",
        "destination_address_prefixes",
        "destination_port_range",
        "destination_port_ranges",
    )
    if unknown_values is True:
        return list(decision_fields)
    if not isinstance(unknown_values, Mapping):
        return []
    return [field for field in decision_fields if value_is_unknown(unknown_values.get(field))]


def _unsupported_decision_fields(record: Mapping[str, Any]) -> list[str]:
    unsupported: list[str] = []
    if record.get("destination_application_security_group_ids"):
        unsupported.append("destination_application_security_group_ids")
    return unsupported


def _direction(value: Any) -> str:
    return "egress" if str(value or "Inbound").strip().lower() == "outbound" else "ingress"


def _protocol(value: Any) -> str:
    protocol = str(value or "*").strip().lower()
    return "-1" if protocol in {"*", "any"} else protocol


def _internet_cidr_blocks(prefixes: Iterable[str]) -> list[str]:
    cidr_blocks: list[str] = []
    for prefix in prefixes:
        normalized = prefix.strip().lower()
        if normalized in {"*", "internet"}:
            cidr_blocks.extend(("0.0.0.0/0", "::/0"))
        elif "/" in prefix:
            cidr_blocks.append(prefix)
    return compact_strings(cidr_blocks)


def _port_ranges(values: Iterable[str]) -> list[tuple[int | None, int | None]]:
    parsed: list[tuple[int | None, int | None]] = []
    for value in values:
        text = value.strip()
        if text in {"", "*"}:
            parsed.append((0, 65535))
            continue
        if "-" in text:
            start, end = text.split("-", 1)
            parsed.append((_optional_int(start), _optional_int(end)))
            continue
        port = _optional_int(text)
        parsed.append((port, port))
    return parsed or [(None, None)]


def _optional_int(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None
