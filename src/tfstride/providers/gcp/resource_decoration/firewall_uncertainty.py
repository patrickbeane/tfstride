from __future__ import annotations

from ipaddress import ip_network

from tfstride.models import NormalizedResource, SecurityGroupRule
from tfstride.providers.gcp.firewall_matches import GcpFirewallMatch, normalize_firewall_protocol
from tfstride.providers.gcp.metadata import GcpResourceMetadata


def firewall_field_is_uncertain(resource: NormalizedResource, field: str) -> bool:
    return any(
        field in match["unknown_fields"] or field in match["unsupported_fields"]
        for match in resource.get_metadata_field(GcpResourceMetadata.FIREWALL_MATCHES)
    )


def uncertain_firewall_matches(resource: NormalizedResource) -> tuple[GcpFirewallMatch, ...]:
    return tuple(
        match
        for match in resource.get_metadata_field(GcpResourceMetadata.FIREWALL_MATCHES)
        if match["uncertainties"] and match["rule_direction"] != "egress" and match["rule_disabled"] is not True
    )


def firewall_match_may_overlap(match: GcpFirewallMatch, rule: SecurityGroupRule) -> bool:
    """Use known dimensions to exclude disjoint traffic; unknown is not empty."""
    if match["rule_direction"] is not None and match["rule_direction"] != rule.direction:
        return False
    protocol = normalize_firewall_protocol(rule.protocol)
    if (
        match["protocol"] is not None
        and protocol is not None
        and "-1" not in {match["protocol"], protocol}
        and match["protocol"] != protocol
    ):
        return False
    if match["ports_state"] == "ranges" and rule.from_port is not None and rule.to_port is not None:
        if not any(
            port["from_port"] <= rule.to_port and rule.from_port <= port["to_port"] for port in match["port_ranges"]
        ):
            return False
    source_alternatives = {"source_tags", "source_service_accounts"}.intersection(
        match["unknown_fields"] + match["unsupported_fields"]
    )
    if match["source_ranges_state"] in {"configured", "default"} and not source_alternatives:
        sources = [*rule.cidr_blocks, *rule.ipv6_cidr_blocks]
        return any(ip_network(left).overlaps(ip_network(right)) for left in match["source_ranges"] for right in sources)
    return True


def uncertain_match_can_override(
    match: GcpFirewallMatch,
    source: NormalizedResource,
    rule: SecurityGroupRule,
    *,
    same_policy: bool,
    policy_constraint: bool,
) -> bool:
    if match["action"] == "allow" or not firewall_match_may_overlap(match, rule):
        return False
    # Numeric priorities are comparable within a VPC rule set or one policy,
    # never across different policy groups.
    if same_policy or not policy_constraint:
        field = (
            GcpResourceMetadata.FIREWALL_POLICY_PRIORITY if policy_constraint else GcpResourceMetadata.FIREWALL_PRIORITY
        )
        priority = source.get_metadata_field(field)
        source_priority = priority if priority is not None else 1000
        if match["rule_priority"] is not None and match["rule_priority"] > source_priority:
            return False
    return True
