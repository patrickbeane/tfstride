from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext, AzureResourceIndex
from tfstride.providers.azure.resource_types import AZURE_COMPUTE_RESOURCE_TYPES

_PROTOCOLS = ("tcp", "udp")
_ADMINISTRATIVE_PORTS = (22, 3389)


@dataclass(frozen=True, slots=True)
class _EffectiveIngress:
    protocol: str
    from_port: int
    to_port: int
    network_security_groups: tuple[str, ...]
    rule_descriptions: tuple[str, ...]


class DerivePublicComputeExposureStage:
    name = "derive_public_compute_exposure"

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        for virtual_machine in resources:
            if virtual_machine.resource_type not in AZURE_COMPUTE_RESOURCE_TYPES:
                continue
            facts = azure_facts(virtual_machine)
            if not virtual_machine.public_access_configured:
                facts.set_public_compute_exposure([], [])
                continue
            effective_ingress = _effective_vm_internet_ingress(virtual_machine, context.index)
            exposure_paths = [
                _exposure_path_record(virtual_machine, decision, context.index) for decision in effective_ingress
            ]
            facts.set_public_compute_exposure(
                exposure_paths,
                ["virtual machine has a public IP path and effective subnet/NIC NSG decisions allow internet ingress"]
                if exposure_paths
                else [],
            )


def is_risky_public_compute_path(path: dict[str, Any]) -> bool:
    from_port = _int_value(path.get("from_port"))
    to_port = _int_value(path.get("to_port"))
    if from_port is None or to_port is None:
        return False
    if from_port == 0 and to_port >= 65535:
        return True
    return any(from_port <= port <= to_port for port in _ADMINISTRATIVE_PORTS)


def _effective_vm_internet_ingress(
    virtual_machine: NormalizedResource,
    index: AzureResourceIndex,
) -> tuple[_EffectiveIngress, ...]:
    network_security_groups = _attached_network_security_groups(virtual_machine, index)
    if not network_security_groups:
        return ()
    decisions = _effective_nsg_ingress(network_security_groups[0])
    for network_security_group in network_security_groups[1:]:
        decisions = _intersect_ingress(decisions, _effective_nsg_ingress(network_security_group))
        if not decisions:
            break
    return tuple(decisions)


def _attached_network_security_groups(
    virtual_machine: NormalizedResource,
    index: AzureResourceIndex,
) -> tuple[NormalizedResource, ...]:
    groups: list[NormalizedResource] = []
    seen: set[str] = set()
    for reference in virtual_machine.security_group_ids:
        network_security_group = index.resolve(reference)
        if network_security_group is None or network_security_group.address in seen:
            continue
        seen.add(network_security_group.address)
        groups.append(network_security_group)
    return tuple(groups)


def _effective_nsg_ingress(network_security_group: NormalizedResource) -> list[_EffectiveIngress]:
    records = sorted(
        (
            record
            for record in azure_facts(network_security_group).network_security_rules
            if _is_deterministic_public_ingress_record(record)
        ),
        key=lambda record: (_int_value(record.get("rule_priority")), str(record.get("name") or "")),
    )
    decisions: list[_EffectiveIngress] = []
    for protocol in _PROTOCOLS:
        undecided = [(0, 65535)]
        for record in records:
            if not _record_applies_to_protocol(record, protocol):
                continue
            for rule_start, rule_end in _record_port_ranges(record):
                matched, undecided = _consume_intervals(undecided, rule_start, rule_end)
                if str(record.get("access") or "").lower() != "allow":
                    continue
                description = _describe_nsg_rule(network_security_group, record, protocol, rule_start, rule_end)
                decisions.extend(
                    _EffectiveIngress(
                        protocol=protocol,
                        from_port=start,
                        to_port=end,
                        network_security_groups=(network_security_group.address,),
                        rule_descriptions=(description,),
                    )
                    for start, end in matched
                )
    return decisions


def _intersect_ingress(
    left: list[_EffectiveIngress],
    right: list[_EffectiveIngress],
) -> list[_EffectiveIngress]:
    combined: list[_EffectiveIngress] = []
    for left_decision in left:
        for right_decision in right:
            if left_decision.protocol != right_decision.protocol:
                continue
            start = max(left_decision.from_port, right_decision.from_port)
            end = min(left_decision.to_port, right_decision.to_port)
            if start > end:
                continue
            combined.append(
                _EffectiveIngress(
                    protocol=left_decision.protocol,
                    from_port=start,
                    to_port=end,
                    network_security_groups=tuple(
                        dict.fromkeys((*left_decision.network_security_groups, *right_decision.network_security_groups))
                    ),
                    rule_descriptions=tuple(
                        dict.fromkeys((*left_decision.rule_descriptions, *right_decision.rule_descriptions))
                    ),
                )
            )
    return _merge_adjacent_decisions(combined)


def _merge_adjacent_decisions(decisions: list[_EffectiveIngress]) -> list[_EffectiveIngress]:
    ordered = sorted(
        decisions,
        key=lambda item: (
            item.protocol,
            item.network_security_groups,
            item.rule_descriptions,
            item.from_port,
            item.to_port,
        ),
    )
    merged: list[_EffectiveIngress] = []
    for decision in ordered:
        if not merged:
            merged.append(decision)
            continue
        previous = merged[-1]
        if (
            previous.protocol == decision.protocol
            and previous.network_security_groups == decision.network_security_groups
            and previous.rule_descriptions == decision.rule_descriptions
            and decision.from_port <= previous.to_port + 1
        ):
            merged[-1] = _EffectiveIngress(
                protocol=previous.protocol,
                from_port=previous.from_port,
                to_port=max(previous.to_port, decision.to_port),
                network_security_groups=previous.network_security_groups,
                rule_descriptions=previous.rule_descriptions,
            )
        else:
            merged.append(decision)
    return merged


def _is_deterministic_public_ingress_record(record: dict[str, Any]) -> bool:
    if record.get("unknown_decision_fields") or record.get("unsupported_decision_fields"):
        return False
    if _int_value(record.get("rule_priority")) is None:
        return False
    if record.get("rule_direction") != "ingress":
        return False
    if str(record.get("access") or "").lower() not in {"allow", "deny"}:
        return False
    return _is_public_source(record) and bool(_record_port_ranges(record))


def _exposure_path_record(
    virtual_machine: NormalizedResource,
    decision: _EffectiveIngress,
    index: AzureResourceIndex,
) -> dict[str, Any]:
    facts = azure_facts(virtual_machine)
    public_ip_addresses = []
    for address in facts.resolved_public_ip_addresses:
        public_ip = index.resolve(address)
        value = azure_facts(public_ip).public_ip_address if public_ip is not None else None
        public_ip_addresses.append(f"{address} ({value})" if value else address)
    return {
        "protocol": decision.protocol,
        "from_port": decision.from_port,
        "to_port": decision.to_port,
        "network_interfaces": facts.resolved_network_interface_addresses,
        "public_ip_resources": facts.resolved_public_ip_addresses,
        "public_ips": public_ip_addresses,
        "network_security_groups": list(decision.network_security_groups),
        "network_security_rules": list(decision.rule_descriptions),
    }


def _is_public_source(record: dict[str, Any]) -> bool:
    prefixes = {str(value).strip().lower() for value in record.get("source_address_prefixes", [])}
    return bool(prefixes.intersection({"*", "any", "internet", "0.0.0.0/0", "::/0"}))


def _record_applies_to_protocol(record: dict[str, Any], protocol: str) -> bool:
    rule_protocol = str(record.get("protocol") or "-1").strip().lower()
    return rule_protocol in {"-1", "*", protocol}


def _record_port_ranges(record: dict[str, Any]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for value in record.get("destination_port_ranges", ["*"]):
        text = str(value).strip()
        if text in {"", "*"}:
            ranges.append((0, 65535))
        elif "-" in text:
            start, end = text.split("-", 1)
            start_value = _int_value(start)
            end_value = _int_value(end)
            if start_value is not None and end_value is not None:
                ranges.append((start_value, end_value))
        else:
            port = _int_value(text)
            if port is not None:
                ranges.append((port, port))
    return ranges


def _consume_intervals(
    intervals: list[tuple[int, int]],
    rule_start: int,
    rule_end: int,
) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    matched: list[tuple[int, int]] = []
    remaining: list[tuple[int, int]] = []
    for start, end in intervals:
        overlap_start = max(start, rule_start)
        overlap_end = min(end, rule_end)
        if overlap_start > overlap_end:
            remaining.append((start, end))
            continue
        matched.append((overlap_start, overlap_end))
        if start < overlap_start:
            remaining.append((start, overlap_start - 1))
        if overlap_end < end:
            remaining.append((overlap_end + 1, end))
    return matched, remaining


def _describe_nsg_rule(
    network_security_group: NormalizedResource,
    record: dict[str, Any],
    protocol: str,
    from_port: int,
    to_port: int,
) -> str:
    name = str(record.get("name") or "unnamed-rule")
    priority = record.get("rule_priority")
    priority_text = str(priority) if priority is not None else "unknown"
    port_text = str(from_port) if from_port == to_port else f"{from_port}-{to_port}"
    sources = ", ".join(str(value) for value in record.get("source_address_prefixes", [])) or "unspecified"
    return (
        f"{network_security_group.address} rule {name} priority {priority_text} "
        f"allows {protocol} {port_text} from {sources}"
    )


def _int_value(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None
