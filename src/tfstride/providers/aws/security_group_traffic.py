"""Evaluate additive AWS security-group permissions with source-aware evidence."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Literal, TypedDict

from tfstride.models import NormalizedResource
from tfstride.providers.aws.reference_resolution import symbolic_reference_target, symbolic_reference_target_records
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.aws.resource_index import AwsResourceIndex, resolve_aws_network_reference
from tfstride.providers.network_ranges import consume_intervals

TrafficState = Literal["allowed", "blocked", "unknown"]


class TrafficDecision(TypedDict):
    state: TrafficState
    evidence: list[dict[str, Any]]
    reasons: list[str]


def traffic_decision(
    state: TrafficState, *reasons: str, evidence: list[dict[str, Any]] | None = None
) -> TrafficDecision:
    return {"state": state, "evidence": evidence or [], "reasons": sorted(set(reasons))}


@dataclass(frozen=True)
class _Attachments:
    groups: tuple[NormalizedResource, ...]
    complete: bool
    reasons: tuple[str, ...]


class AwsSecurityGroupTrafficIndex:
    def __init__(self, index: AwsResourceIndex) -> None:
        self.index = index
        self._attachments: dict[str, _Attachments] = {}
        self._peer_networks: dict[str, tuple[ipaddress.IPv4Network, ...] | None] = {}
        self._rules: dict[str, list[tuple[NormalizedResource, dict[str, Any]]]] = {
            group.address: [(group, rule) for rule in aws_facts(group).security_group_traffic_rules]
            for group in index.security_groups.resources
        }
        self._unresolved_rules: dict[str, list[tuple[NormalizedResource, dict[str, Any]]]] = {}
        for source in sorted(index.resources_by_address.values(), key=lambda item: item.address):
            if source.resource_type != "aws_security_group_rule":
                continue
            reference = aws_facts(source).security_group_id
            group = resolve_aws_network_reference(index.security_groups, reference, source)
            if group is None and not reference:
                group = symbolic_reference_target(
                    source,
                    index,
                    "security_group_id",
                    expected_resource_types={"aws_security_group"},
                    expected_reference_suffixes={".id"},
                )
            records = [(source, rule) for rule in aws_facts(source).security_group_traffic_rules]
            if group is not None:
                self._rules.setdefault(group.address, []).extend(records)
                continue
            candidates = index.security_groups.resolve(reference, source=source).candidates
            if not candidates:
                if reference and (reference.startswith("arn:") or reference.startswith("aws_security_group.")):
                    continue
                candidates = tuple(
                    group
                    for group in index.security_groups.resources
                    if not source.provider_config_key
                    or not group.provider_config_key
                    or source.provider_config_key == group.provider_config_key
                )
            for candidate in candidates:
                self._unresolved_rules.setdefault(candidate.address, []).extend(records)

    def attachments(self, resource: NormalizedResource) -> _Attachments:
        if resource.address in self._attachments:
            return self._attachments[resource.address]
        inputs = aws_facts(resource).network_attachments
        groups: dict[str, NormalizedResource] = {}
        reasons: list[str] = []
        complete = inputs.get("security_groups_complete") is True
        for reference in inputs.get("security_groups", []):
            group = resolve_aws_network_reference(self.index.security_groups, reference, resource)
            if group is None:
                complete = False
                reasons.append(f"{resource.address}: security group {reference} is unresolved or ambiguous")
            else:
                groups[group.address] = group
        if not complete:
            path = tuple(inputs.get("security_group_path", []))
            if path:
                for _, group in symbolic_reference_target_records(
                    resource,
                    self.index,
                    paths=(path,),
                    expected_resource_types={"aws_security_group"},
                    expected_reference_suffixes={".id"},
                ):
                    groups[group.address] = group
            reasons.append(f"{resource.address}: security-group attachments are not completely established")
        result = _Attachments(tuple(groups[key] for key in sorted(groups)), complete, tuple(reasons))
        self._attachments[resource.address] = result
        return result

    def _subnet_ranges(self, resource: NormalizedResource) -> tuple[ipaddress.IPv4Network, ...] | None:
        if resource.address in self._peer_networks:
            return self._peer_networks[resource.address]
        inputs = aws_facts(resource).network_attachments
        networks: list[ipaddress.IPv4Network] = []
        complete = inputs.get("subnets_complete") is True
        for reference in inputs.get("subnets", []):
            subnet = self.index.resolve_subnet(reference, source=resource).selected_candidate
            network = _network(aws_facts(subnet).cidr_block) if subnet is not None else None
            if not isinstance(network, ipaddress.IPv4Network):
                complete = False
            else:
                networks.append(network)
        result = tuple(networks) if complete and networks else None
        self._peer_networks[resource.address] = result
        return result

    def permission(
        self,
        resource: NormalizedResource,
        direction: str,
        port: int,
        *,
        peer: NormalizedResource | None = None,
        internet_versions: tuple[int, ...] = (4,),
    ) -> TrafficDecision:
        attachments = self.attachments(resource)
        reasons = list(attachments.reasons)
        peer_attachments = self.attachments(peer) if peer is not None else None
        allowed: list[dict[str, Any]] = []
        cidr_grants: list[tuple[ipaddress.IPv4Network, dict[str, Any]]] = []
        for group in attachments.groups:
            if not aws_facts(group).security_group_traffic_rules_known:
                reasons.append(f"{group.address}: security-group rule inputs are not established")
            for source, rule in self._unresolved_rules.get(group.address, []):
                if _matches_packet(rule, direction, port) is not False:
                    reasons.append(f"{source.address}: rule attachment to {group.address} is unresolved")
            for source, rule in self._rules.get(group.address, []):
                match = _matches_packet(rule, direction, port)
                if match is False:
                    continue
                if match is None:
                    reasons.append(f"{source.address}: {rule['path']} protocol/port scope is unknown or malformed")
                    continue
                evidence = {
                    "security_group_address": group.address,
                    "rule_source_address": source.address,
                    "rule_path": rule["path"],
                    "rule_direction": direction,
                    "protocol": "tcp",
                    "port": port,
                }
                if not rule["selectors_complete"]:
                    reasons.append(
                        f"{source.address}: {rule['path']} contains unresolved or unsupported address selectors"
                    )
                for cidr, family in [
                    *((cidr, 4) for cidr in rule["cidr_blocks"]),
                    *((cidr, 6) for cidr in rule["ipv6_cidr_blocks"]),
                ]:
                    network = _network(cidr)
                    if network is None or network.version != family:
                        reasons.append(f"{source.address}: CIDR {cidr} is malformed")
                        continue
                    proof = {**evidence, "selector": "cidr", "cidr": str(network)}
                    if peer is None:
                        if network.version not in internet_versions:
                            continue
                        witness = _internet_source(network)
                        if witness is not None:
                            allowed.append({**proof, "internet_source_witness": witness})
                        elif not (
                            network.is_private
                            or network.is_multicast
                            or network.is_reserved
                            or network.is_loopback
                            or network.is_link_local
                        ):
                            reasons.append(f"{source.address}: an internet source in {network} is not established")
                    elif isinstance(network, ipaddress.IPv4Network):
                        if network.prefixlen == 0:
                            allowed.append(proof)
                        else:
                            cidr_grants.append((network, proof))
                if peer_attachments is not None:
                    references = rule["security_groups"]
                    targets: dict[str, NormalizedResource] = {}
                    for reference in references:
                        target = resolve_aws_network_reference(self.index.security_groups, reference, source)
                        if target is None:
                            reasons.append(
                                f"{source.address}: peer security group {reference} is unresolved or ambiguous"
                            )
                        else:
                            targets[target.address] = target
                    for _, target in symbolic_reference_target_records(
                        source,
                        self.index,
                        paths=(tuple(rule["security_group_path"]),),
                        expected_resource_types={"aws_security_group"},
                        expected_reference_suffixes={".id"},
                    ):
                        targets[target.address] = target
                    if rule["self"] is True:
                        targets[group.address] = group
                    matching = sorted(set(targets).intersection(item.address for item in peer_attachments.groups))
                    if matching:
                        allowed.append(
                            {**evidence, "selector": "security_group", "peer_security_group_addresses": matching}
                        )
                    elif targets and not peer_attachments.complete:
                        reasons.extend(peer_attachments.reasons)
        if peer is not None and cidr_grants:
            networks = self._subnet_ranges(peer)
            if networks is None:
                reasons.append(
                    f"{peer.address}: peer addresses/subnet CIDRs are required to evaluate restricted CIDR permissions"
                )
            else:
                remaining = [(int(network.network_address), int(network.broadcast_address)) for network in networks]
                matched_any = False
                for network, _ in cidr_grants:
                    matched, remaining = consume_intervals(
                        remaining, int(network.network_address), int(network.broadcast_address)
                    )
                    matched_any |= bool(matched)
                if not remaining:
                    allowed.extend(
                        {**proof, "peer_subnet_cidrs": [str(network) for network in networks]}
                        for _, proof in cidr_grants
                    )
                elif matched_any:
                    reasons.append(f"{peer.address}: only part of the possible peer address range is permitted")
        if allowed:
            allowed.sort(
                key=lambda item: (
                    item["security_group_address"],
                    item["rule_source_address"],
                    str(item["rule_path"]),
                    item["selector"],
                    item.get("cidr", ""),
                )
            )
            return traffic_decision("allowed", evidence=allowed)
        if reasons or not attachments.groups:
            return traffic_decision(
                "unknown", *reasons, f"{resource.address}: TCP {port} {direction} permission is not established"
            )
        return traffic_decision(
            "blocked", f"{resource.address}: no attached security-group rule permits TCP {port} {direction}"
        )


def _matches_packet(rule: dict[str, Any], direction: str, port: int) -> bool | None:
    if rule["rule_direction"] in {"ingress", "egress"} and rule["rule_direction"] != direction:
        return False
    if rule["rule_direction"] not in {"ingress", "egress"}:
        return None
    protocol = rule["protocol"]
    if protocol == "all":
        return True
    if protocol in {"udp", "icmp", "icmpv6", "1", "58"}:
        return False
    if protocol != "tcp":
        return None
    start, end = rule["from_port"], rule["to_port"]
    if type(start) is not int or type(end) is not int or not 0 <= start <= end <= 65535:
        return None
    return start <= port <= end


def _network(value: object) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.ip_network(value, strict=True)
    except ValueError:
        return None


def _internet_source(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str | None:
    candidates = [network.network_address, network.broadcast_address]
    candidates.append(ipaddress.ip_address("8.8.8.8" if network.version == 4 else "2001:4860:4860::8888"))
    return next(
        (
            str(address)
            for address in candidates
            if address in network and address.is_global and not address.is_multicast
        ),
        None,
    )
