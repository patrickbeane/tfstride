from __future__ import annotations

from dataclasses import dataclass

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.firewall_decisions import FirewallIngressDecision
from tfstride.providers.gcp.resource_decoration.firewall_packet_subsets import (
    AllowedSubset,
    PacketSubset,
    evaluate_firewall_layer,
    firewall_ingress_decision,
    internet_packet_subsets,
)
from tfstride.providers.gcp.resource_decoration.firewall_policy_order import resolve_firewall_policy_order
from tfstride.providers.gcp.resource_decoration.firewall_targets import (
    instance_service_account_keys,
    service_account_reference_keys,
)
from tfstride.providers.gcp.resource_decoration.firewall_uncertainty import firewall_field_is_uncertain
from tfstride.providers.gcp.resource_decoration.network_posture import resource_has_network_reference
from tfstride.providers.gcp.resource_index import GcpResourceIndex


@dataclass(frozen=True, slots=True)
class FirewallPolicyIngressDecision:
    ingress: FirewallIngressDecision
    continuing: tuple[PacketSubset, ...]


def firewall_policy_ingress_decision(
    resource: NormalizedResource,
    index: GcpResourceIndex,
) -> FirewallPolicyIngressDecision:
    order = resolve_firewall_policy_order(
        resource,
        index,
        tuple(
            rule
            for rule in index.firewall_policy_rules
            if _firewall_policy_rule_targets_instance(rule, resource, index)
        ),
    )
    if order.uncertainties:
        return FirewallPolicyIngressDecision(FirewallIngressDecision(sources=(), uncertainties=order.uncertainties), ())

    continuing = internet_packet_subsets()
    allowed: list[AllowedSubset] = []
    uncertainties: set[str] = set()
    for group in order.groups:
        layer = evaluate_firewall_layer(group.rules, continuing, policy=True)
        allowed.extend(layer.allowed)
        uncertainties.update(layer.uncertainties)
        continuing = layer.continuing
        if not continuing:
            break
    rules = tuple(rule for group in order.groups for rule in group.rules)
    return FirewallPolicyIngressDecision(firewall_ingress_decision(rules, tuple(allowed), uncertainties), continuing)


def _firewall_policy_rule_targets_instance(
    policy_rule: NormalizedResource,
    instance: NormalizedResource,
    index: GcpResourceIndex,
) -> bool:
    if policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_DISABLED) and not firewall_field_is_uncertain(
        policy_rule, "disabled"
    ):
        return False
    policy_direction = (
        str(policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_DIRECTION) or "").strip().lower()
    )
    if policy_direction != "ingress" and not firewall_field_is_uncertain(policy_rule, "direction"):
        return False

    target_resources = policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_TARGET_RESOURCES)
    target_resource_applies = bool(target_resources) and any(
        resource_has_network_reference(instance, target_resource, index) for target_resource in target_resources
    )
    if (
        target_resources
        and not target_resource_applies
        and not firewall_field_is_uncertain(policy_rule, "target_resources")
    ):
        return False

    target_service_accounts = service_account_reference_keys(
        policy_rule.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_TARGET_SERVICE_ACCOUNTS)
    )
    if (
        target_service_accounts
        and not target_service_accounts.intersection(instance_service_account_keys(instance))
        and not firewall_field_is_uncertain(policy_rule, "target_service_accounts")
    ):
        return False

    return True
