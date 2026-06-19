from __future__ import annotations

from collections.abc import Mapping

from tfstride.models import NormalizedResource, SecurityGroupRule
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.firewall_decisions import (
    FirewallIngressDecision,
    FirewallIngressSource,
)
from tfstride.providers.gcp.resource_decoration.firewall_policy_exposure import (
    firewall_policy_ingress_decision,
)
from tfstride.providers.gcp.resource_decoration.firewall_rules import (
    firewall_rules_overlap,
    parse_firewall_port_range,
    priority_value,
)
from tfstride.providers.gcp.resource_decoration.firewall_targets import (
    instance_service_account_keys,
    service_account_reference_keys,
)
from tfstride.providers.gcp.resource_decoration.network_posture import (
    resource_has_network_reference,
)
from tfstride.providers.gcp.resource_index import GcpResourceIndex
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.resource_helpers import describe_security_group_rule


def derive_public_compute_exposure(resource: NormalizedResource, index: GcpResourceIndex) -> None:
    ingress_decision = _compute_internet_ingress_decision(resource, index)
    gcp_mutations(resource).set_compute_internet_ingress(
        internet_ingress_reasons=ingress_decision.internet_ingress_reasons,
        firewall_addresses=ingress_decision.firewall_addresses,
    )

    public_exposure = bool(resource.public_access_configured and ingress_decision.has_internet_ingress)
    gcp_mutations(resource).set_public_exposure(
        public_exposure,
        reasons=(
            ["compute instance has an external access config and matching firewall rules allow internet ingress"]
            if public_exposure
            else None
        ),
    )


def _compute_internet_ingress_decision(
    resource: NormalizedResource,
    index: GcpResourceIndex,
) -> FirewallIngressDecision:
    policy_decision = firewall_policy_ingress_decision(resource, index)
    if not policy_decision.continues_to_compute_firewalls:
        return FirewallIngressDecision(sources=policy_decision.sources)
    return FirewallIngressDecision(sources=(*_compute_firewall_ingress_sources(resource, index),))


def _compute_firewall_ingress_sources(
    resource: NormalizedResource,
    index: GcpResourceIndex,
) -> tuple[FirewallIngressSource, ...]:
    applicable_firewalls = tuple(
        firewall for firewall in index.firewalls if _firewall_applies_to_instance(firewall, resource, index)
    )
    return tuple(
        source
        for firewall in applicable_firewalls
        for source in (
            _effective_compute_firewall_ingress_source(
                firewall,
                applicable_firewalls,
            ),
        )
        if source is not None
    )


def _effective_compute_firewall_ingress_source(
    firewall: NormalizedResource,
    applicable_firewalls: tuple[NormalizedResource, ...],
) -> FirewallIngressSource | None:
    internet_ingress_reasons = tuple(
        describe_security_group_rule(firewall, allow_rule)
        for allow_rule in _compute_firewall_internet_ingress_rules(firewall)
        if _compute_firewall_allow_rule_is_effective(
            firewall,
            allow_rule,
            applicable_firewalls,
        )
    )
    if not internet_ingress_reasons:
        return None
    return FirewallIngressSource(
        resource=firewall,
        internet_ingress_reasons=internet_ingress_reasons,
    )


def _compute_firewall_allow_rule_is_effective(
    allow_firewall: NormalizedResource,
    allow_rule: SecurityGroupRule,
    applicable_firewalls: tuple[NormalizedResource, ...],
) -> bool:
    allow_priority = _compute_firewall_priority(allow_firewall)
    winning_priority = min(
        _compute_firewall_priority(firewall)
        for firewall in applicable_firewalls
        if _compute_firewall_has_overlapping_internet_rule(firewall, allow_rule)
    )
    if allow_priority != winning_priority:
        return False
    return not any(
        _compute_firewall_priority(firewall) == allow_priority
        and any(
            firewall_rules_overlap(deny_rule, allow_rule)
            for deny_rule in _compute_firewall_internet_deny_rules(firewall)
        )
        for firewall in applicable_firewalls
    )


def _compute_firewall_has_overlapping_internet_rule(
    firewall: NormalizedResource,
    allow_rule: SecurityGroupRule,
) -> bool:
    return any(
        firewall_rules_overlap(candidate_rule, allow_rule)
        for candidate_rule in (
            *_compute_firewall_internet_ingress_rules(firewall),
            *_compute_firewall_internet_deny_rules(firewall),
        )
    )


def _firewall_applies_to_instance(
    firewall: NormalizedResource,
    instance: NormalizedResource,
    index: GcpResourceIndex,
) -> bool:
    if firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_DISABLED):
        return False
    firewall_direction = (
        str(firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_DIRECTION) or "ingress").strip().lower()
    )
    if firewall_direction != "ingress":
        return False
    if not resource_has_network_reference(instance, firewall.vpc_id, index):
        return False

    target_tags = set(firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_TARGET_TAGS))
    if target_tags:
        instance_tags = set(instance.get_metadata_field(GcpResourceMetadata.NETWORK_TAGS))
        if not target_tags.intersection(instance_tags):
            return False

    target_service_accounts = service_account_reference_keys(
        firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_TARGET_SERVICE_ACCOUNTS)
    )
    if target_service_accounts:
        instance_service_accounts = instance_service_account_keys(instance)
        if not target_service_accounts.intersection(instance_service_accounts):
            return False

    return True


def _compute_firewall_internet_ingress_rules(
    firewall: NormalizedResource,
) -> tuple[SecurityGroupRule, ...]:
    return tuple(rule for rule in firewall.network_rules if rule.direction == "ingress" and rule.allows_internet())


def _compute_firewall_internet_deny_rules(
    firewall: NormalizedResource,
) -> tuple[SecurityGroupRule, ...]:
    return tuple(
        rule
        for rule in _metadata_firewall_rules(
            firewall,
            GcpResourceMetadata.FIREWALL_DENY,
        )
        if rule.direction == "ingress" and rule.allows_internet()
    )


def _metadata_firewall_rules(
    firewall: NormalizedResource,
    metadata_field: object,
) -> tuple[SecurityGroupRule, ...]:
    direction = str(firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_DIRECTION) or "ingress").strip().lower()
    cidr_blocks = _firewall_cidr_blocks(firewall, direction)
    rules: list[SecurityGroupRule] = []
    for rule_block in firewall.get_metadata_field(metadata_field):
        if not isinstance(rule_block, Mapping):
            continue
        protocol = str(rule_block.get("protocol") or "-1")
        ports = rule_block.get("ports")
        if not ports:
            rules.append(_firewall_rule(direction, protocol, None, None, cidr_blocks))
            continue
        for port in ports if isinstance(ports, list) else [ports]:
            from_port, to_port = parse_firewall_port_range(port)
            rules.append(_firewall_rule(direction, protocol, from_port, to_port, cidr_blocks))
    return tuple(rules)


def _firewall_rule(
    direction: str,
    protocol: str,
    from_port: int | None,
    to_port: int | None,
    cidr_blocks: list[str],
) -> SecurityGroupRule:
    return SecurityGroupRule(
        direction=direction,
        protocol="-1" if protocol.lower() in {"all", "-1"} else protocol,
        from_port=from_port,
        to_port=to_port,
        cidr_blocks=list(cidr_blocks),
    )


def _firewall_cidr_blocks(firewall: NormalizedResource, direction: str) -> list[str]:
    source_ranges = firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_SOURCE_RANGES)
    destination_ranges = firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_DESTINATION_RANGES)
    if direction == "egress" and destination_ranges:
        return destination_ranges
    if source_ranges:
        return source_ranges
    source_tags = firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_SOURCE_TAGS)
    source_service_accounts = firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_SOURCE_SERVICE_ACCOUNTS)
    if direction == "ingress" and not source_tags and not source_service_accounts:
        return ["0.0.0.0/0"]
    return []


def _compute_firewall_priority(firewall: NormalizedResource) -> int:
    return priority_value(firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_PRIORITY))
