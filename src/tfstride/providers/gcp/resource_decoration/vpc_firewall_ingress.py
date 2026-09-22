"""VPC rule precedence over protocol/port subsets of broad internet sources.

Protocol sets are finite (the 256 IP protocol numbers). Ports stay as intervals;
we never enumerate individual ports. Source CIDR subtraction is not modeled:
denies matching only part of an internet source range retain uncertainty for
their protocol/port subset instead of being ignored or treated as global denies.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, replace
from ipaddress import ip_network

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.attributes import GcpAttr
from tfstride.providers.gcp.firewall_ingress_evidence import GcpEffectiveFirewallIngress, describe_effective_ingress
from tfstride.providers.gcp.firewall_matches import (
    GcpFirewallMatch,
    firewall_match_network_rules,
    normalize_firewall_matches,
    normalize_firewall_protocol,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.firewall_decisions import FirewallIngressDecision, FirewallIngressSource
from tfstride.providers.network_ranges import consume_intervals

_ALL_PROTOCOLS = frozenset(range(256))
_PROTOCOL_NAMES = {number: str(normalize_firewall_protocol(number)) for number in _ALL_PROTOCOLS}
_PROTOCOL_NUMBERS = {name: number for number, name in _PROTOCOL_NAMES.items()}
_INTERNET_SOURCES = {4: "0.0.0.0/0", 6: "::/0"}


@dataclass(frozen=True, slots=True)
class _PacketSubset:
    family: int
    protocols: frozenset[int]
    start: int = 0
    end: int = 65535


@dataclass(frozen=True, slots=True)
class _Candidate:
    firewall_address: str
    priority: int
    allows: bool
    scope: _PacketSubset
    match_path: str


@dataclass(frozen=True, slots=True)
class _AllowedSubset:
    candidate: _Candidate
    scope: _PacketSubset


def evaluate_vpc_firewall_ingress(firewalls: tuple[NormalizedResource, ...]) -> FirewallIngressDecision:
    candidates: list[_Candidate] = []
    uncertainties: set[str] = set()
    resources = {resource.address: resource for resource in firewalls}
    for resource in firewalls:
        for match in _firewall_matches(resource):
            if match["rule_direction"] == "egress" or match["rule_disabled"] is True:
                continue
            uncertainties.update(f"{resource.address}: {reason}" for reason in match["uncertainties"])
            candidates.extend(_match_candidates(resource, match, uncertainties))

    undecided = [_PacketSubset(family, _ALL_PROTOCOLS) for family in _INTERNET_SOURCES]
    allowed: list[_AllowedSubset] = []
    for candidate in sorted(candidates, key=_candidate_sort_key):
        # GCP's implied ingress deny has priority 65535. Deny wins a tie, so
        # even an explicit allow at this priority cannot establish ingress.
        if candidate.priority >= 65535:
            continue
        remaining: list[_PacketSubset] = []
        for subset in undecided:
            matched, rest = _consume_subset(subset, candidate.scope)
            remaining.extend(rest)
            if matched is not None and candidate.allows:
                allowed.append(_AllowedSubset(candidate, matched))
        undecided = remaining
        if not undecided:
            break

    by_resource: dict[str, list[GcpEffectiveFirewallIngress]] = defaultdict(list)
    for ingress in _effective_ingress(allowed):
        by_resource[ingress["firewall_address"]].append(ingress)
    sources = tuple(
        FirewallIngressSource(
            resource=resources[address],
            internet_ingress_reasons=tuple(
                describe_effective_ingress(resources[address], ingress) for ingress in paths
            ),
            effective_ingress=tuple(paths),
        )
        for address, paths in sorted(by_resource.items())
    )
    return FirewallIngressDecision(sources=sources, uncertainties=tuple(sorted(uncertainties)))


def _candidate_sort_key(candidate: _Candidate) -> tuple[object, ...]:
    return (
        candidate.priority,
        candidate.allows,
        candidate.firewall_address,
        candidate.scope.family,
        tuple(sorted(candidate.scope.protocols)),
        candidate.scope.start,
        candidate.scope.end,
        candidate.match_path,
    )


def _protocols(protocol: str | None) -> frozenset[int]:
    if protocol is None or protocol == "-1":
        return _ALL_PROTOCOLS
    return frozenset({_PROTOCOL_NUMBERS[protocol]})


def _match_candidates(
    resource: NormalizedResource, match: GcpFirewallMatch, uncertainties: set[str]
) -> list[_Candidate]:
    priority = match["rule_priority"] if match["rule_priority"] is not None else -1
    candidates: list[_Candidate] = []
    covered_families: set[int] = set()
    for rule in firewall_match_network_rules(match):
        for source in (*rule.cidr_blocks, *rule.ipv6_cidr_blocks):
            network = ip_network(source)
            if network.prefixlen != 0:
                continue
            covered_families.add(network.version)
            candidates.append(
                _Candidate(
                    resource.address,
                    priority,
                    match["action"] == "allow",
                    _PacketSubset(
                        network.version,
                        _protocols(rule.protocol),
                        rule.from_port if rule.from_port is not None else 0,
                        rule.to_port if rule.to_port is not None else 65535,
                    ),
                    match["path"],
                )
            )
    if match["action"] == "allow":
        return candidates

    source_alternatives = {"source_tags", "source_service_accounts"}.intersection(
        match["unknown_fields"] + match["unsupported_fields"]
    )
    families = {ip_network(source).version for source in match["source_ranges"]}
    if match["source_ranges_state"] == "unknown" or source_alternatives or not families:
        families = {4, 6}
    unresolved_families = families - covered_families
    if unresolved_families and not match["uncertainties"]:
        uncertainties.add(
            f"{resource.address}: {match['path']} has a partial source CIDR constraint; source-subset precedence is not established"
        )
    ports = (
        [(port["from_port"], port["to_port"]) for port in match["port_ranges"]]
        if match["ports_state"] == "ranges"
        else [(0, 65535)]
    )
    candidates.extend(
        _Candidate(
            resource.address,
            priority,
            False,
            _PacketSubset(family, _protocols(match["protocol"]), start, end),
            match["path"],
        )
        for family in sorted(unresolved_families)
        for start, end in ports
    )
    return candidates


def _consume_subset(subset: _PacketSubset, scope: _PacketSubset) -> tuple[_PacketSubset | None, list[_PacketSubset]]:
    protocols = subset.protocols & scope.protocols
    if subset.family != scope.family or not protocols:
        return None, [subset]
    matched, remaining_ports = consume_intervals([(subset.start, subset.end)], scope.start, scope.end)
    if not matched:
        return None, [subset]
    remaining = [replace(subset, protocols=protocols, start=start, end=end) for start, end in remaining_ports]
    if other_protocols := subset.protocols - protocols:
        remaining.append(replace(subset, protocols=other_protocols))
    start, end = matched[0]
    return replace(subset, protocols=protocols, start=start, end=end), remaining


def _effective_ingress(allowed: list[_AllowedSubset]) -> list[GcpEffectiveFirewallIngress]:
    # Canonicalize coverage per protocol before recombining protocol sets. This
    # makes split/merged input intervals produce equivalent effective scopes.
    by_protocol: dict[tuple[str, int, int, int], list[tuple[int, int, str]]] = defaultdict(list)
    for item in allowed:
        for protocol in item.scope.protocols:
            by_protocol[(item.candidate.firewall_address, item.candidate.priority, item.scope.family, protocol)].append(
                (item.scope.start, item.scope.end, item.candidate.match_path)
            )
    grouped: dict[tuple[str, int, int, int, int], tuple[set[int], set[str]]] = {}
    for (address, priority, family, protocol), intervals in sorted(by_protocol.items()):
        for start, end, paths in _merge_intervals(intervals):
            protocols, match_paths = grouped.setdefault((address, priority, family, start, end), (set(), set()))
            protocols.add(protocol)
            match_paths.update(paths)
    records: dict[tuple[str, int, str, tuple[str, ...], int | None, int | None], GcpEffectiveFirewallIngress] = {}
    for (address, priority, family, start, end), (protocols, paths) in sorted(grouped.items()):
        for protocol, exclusions in _describe_protocols(protocols):
            port_start, port_end = (start, end) if protocol in {"tcp", "udp"} else (None, None)
            key = address, priority, protocol, exclusions, port_start, port_end
            record = records.setdefault(
                key,
                GcpEffectiveFirewallIngress(
                    firewall_address=address,
                    rule_priority=priority,
                    protocol=protocol,
                    excluded_protocols=list(exclusions),
                    from_port=port_start,
                    to_port=port_end,
                    source_ranges=[],
                    match_paths=[],
                ),
            )
            record["source_ranges"] = sorted(set(record["source_ranges"]) | {_INTERNET_SOURCES[family]})
            record["match_paths"] = sorted(set(record["match_paths"]) | paths)
    return sorted(
        records.values(),
        key=lambda record: (
            record["firewall_address"],
            record["protocol"],
            tuple(record["excluded_protocols"]),
            record["from_port"] if record["from_port"] is not None else -1,
            record["to_port"] if record["to_port"] is not None else -1,
            tuple(record["source_ranges"]),
        ),
    )


def _merge_intervals(intervals: Iterable[tuple[int, int, str]]) -> list[tuple[int, int, set[str]]]:
    merged: list[tuple[int, int, set[str]]] = []
    for start, end, path in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            previous_start, previous_end, paths = merged[-1]
            merged[-1] = previous_start, max(previous_end, end), paths | {path}
        else:
            merged.append((start, end, {path}))
    return merged


def _describe_protocols(protocols: set[int]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if len(protocols) > len(_ALL_PROTOCOLS - protocols) + 1:
        return (("-1", tuple(sorted(_PROTOCOL_NAMES[number] for number in _ALL_PROTOCOLS - protocols))),)
    return tuple((_PROTOCOL_NAMES[number], ()) for number in sorted(protocols))


def _firewall_matches(resource: NormalizedResource) -> list[GcpFirewallMatch]:
    if resource.has_metadata_field(GcpResourceMetadata.FIREWALL_MATCHES):
        return resource.get_metadata_field(GcpResourceMetadata.FIREWALL_MATCHES)
    # Directly constructed normalized inventories predate the structured match
    # contract. Parse their deny metadata with the same validated normalizer.
    common = {
        GcpAttr.DIRECTION.key: resource.get_metadata_field(GcpResourceMetadata.FIREWALL_DIRECTION),
        GcpAttr.PRIORITY.key: resource.get_metadata_field(GcpResourceMetadata.FIREWALL_PRIORITY),
        "source_ranges": resource.get_metadata_field(GcpResourceMetadata.FIREWALL_SOURCE_RANGES),
        "source_tags": resource.get_metadata_field(GcpResourceMetadata.FIREWALL_SOURCE_TAGS),
        "source_service_accounts": resource.get_metadata_field(GcpResourceMetadata.FIREWALL_SOURCE_SERVICE_ACCOUNTS),
        "deny": resource.get_metadata_field(GcpResourceMetadata.FIREWALL_DENY),
    }
    matches = normalize_firewall_matches(common)
    for index, rule in enumerate(resource.network_rules):
        ports = None if rule.from_port is None or rule.to_port is None else [f"{rule.from_port}-{rule.to_port}"]
        records = normalize_firewall_matches(
            {
                **common,
                "deny": [],
                GcpAttr.DIRECTION.key: rule.direction,
                "source_ranges": [*rule.cidr_blocks, *rule.ipv6_cidr_blocks],
                "allow": [{"protocol": rule.protocol, "ports": ports}],
            }
        )
        for record in records:
            record["path"] = f"network_rules[{index}]"
        matches.extend(records)
    return matches
