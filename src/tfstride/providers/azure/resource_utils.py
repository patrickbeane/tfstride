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


def parse_network_security_rules(values: Mapping[str, Any]) -> tuple[list[SecurityGroupRule], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    allow_rules: list[SecurityGroupRule] = []
    for raw_rule in _rule_mappings(values):
        record = normalize_network_security_rule_record(raw_rule)
        records.append(record)
        if record["access"] != "allow":
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


def normalize_network_security_rule_record(values: Mapping[str, Any]) -> dict[str, Any]:
    source_prefixes = compact_strings(
        [values.get("source_address_prefix"), *as_list(values.get("source_address_prefixes"))]
    )
    destination_prefixes = compact_strings(
        [values.get("destination_address_prefix"), *as_list(values.get("destination_address_prefixes"))]
    )
    destination_ports = compact_strings(
        [values.get("destination_port_range"), *as_list(values.get("destination_port_ranges"))]
    ) or ["*"]
    return {
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


def _rule_mappings(values: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if "security_rule" in values:
        return [rule for rule in as_list(values.get("security_rule")) if isinstance(rule, Mapping)]
    return [values]


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
