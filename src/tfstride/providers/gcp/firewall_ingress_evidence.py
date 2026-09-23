from __future__ import annotations

from typing import TypedDict

from tfstride.models import NormalizedResource, SecurityGroupRule
from tfstride.resource_helpers import describe_security_group_rule


class GcpEffectiveFirewallIngress(TypedDict):
    """A definite allowed subset, with a deterministic winning firewall witness."""

    firewall_address: str
    rule_priority: int
    protocol: str
    excluded_protocols: list[str]
    from_port: int | None
    to_port: int | None
    source_ranges: list[str]
    match_paths: list[str]


def effective_ingress_rule(ingress: GcpEffectiveFirewallIngress) -> SecurityGroupRule:
    exclusions = ingress["excluded_protocols"]
    return SecurityGroupRule(
        direction="ingress",
        protocol=ingress["protocol"],
        from_port=ingress["from_port"],
        to_port=ingress["to_port"],
        cidr_blocks=[source for source in ingress["source_ranges"] if ":" not in source],
        ipv6_cidr_blocks=[source for source in ingress["source_ranges"] if ":" in source],
        description=f"excluding protocols {', '.join(exclusions)}" if exclusions else None,
    )


def describe_effective_ingress(resource: NormalizedResource, ingress: GcpEffectiveFirewallIngress) -> str:
    return describe_security_group_rule(resource, effective_ingress_rule(ingress))


def is_risky_effective_ingress(ingress: GcpEffectiveFirewallIngress) -> bool:
    # Non-port protocols remain valid exposure witnesses, but do not establish
    # administrative or unrestricted TCP/UDP port access.
    if ingress["protocol"] == "-1" and {"tcp", "udp"}.issubset(ingress["excluded_protocols"]):
        return False
    rule = effective_ingress_rule(ingress)
    return rule.is_administrative_access() or rule.is_all_ports()
