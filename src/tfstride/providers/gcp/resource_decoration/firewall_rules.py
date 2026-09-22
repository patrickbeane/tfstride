from __future__ import annotations

from ipaddress import ip_network

from tfstride.models import SecurityGroupRule
from tfstride.providers.gcp.firewall_matches import normalize_firewall_protocol


def priority_value(value: object, *, default: int = 1000) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except ValueError:
        return default


def firewall_rules_overlap(left: SecurityGroupRule, right: SecurityGroupRule) -> bool:
    if not _firewall_protocols_overlap(left.protocol, right.protocol):
        return False
    left_sources = [*left.cidr_blocks, *left.ipv6_cidr_blocks]
    right_sources = [*right.cidr_blocks, *right.ipv6_cidr_blocks]
    if (
        left_sources
        and right_sources
        and not any(
            ip_network(source, strict=False).overlaps(ip_network(target, strict=False))
            for source in left_sources
            for target in right_sources
        )
    ):
        return False
    left_ports = _firewall_port_range(left)
    right_ports = _firewall_port_range(right)
    if left_ports is None or right_ports is None:
        return True
    left_start, left_end = left_ports
    right_start, right_end = right_ports
    return left_start <= right_end and right_start <= left_end


def _firewall_protocols_overlap(left: str, right: str) -> bool:
    left_protocol = normalize_firewall_protocol(left)
    right_protocol = normalize_firewall_protocol(right)
    return (
        left_protocol is None
        or right_protocol is None
        or left_protocol == "-1"
        or right_protocol == "-1"
        or left_protocol == right_protocol
    )


def _firewall_port_range(rule: SecurityGroupRule) -> tuple[int, int] | None:
    if rule.protocol == "-1" or rule.from_port is None or rule.to_port is None:
        return None
    return (rule.from_port, rule.to_port)
