"""VPC precedence applied to traffic remaining after hierarchical policies."""

from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.resource_decoration.firewall_decisions import FirewallIngressDecision
from tfstride.providers.gcp.resource_decoration.firewall_packet_subsets import (
    PacketSubset,
    evaluate_firewall_layer,
    firewall_ingress_decision,
    internet_packet_subsets,
)


def evaluate_vpc_firewall_ingress(
    firewalls: tuple[NormalizedResource, ...],
    *,
    incoming: tuple[PacketSubset, ...] | None = None,
) -> FirewallIngressDecision:
    layer = evaluate_firewall_layer(
        firewalls, internet_packet_subsets() if incoming is None else incoming, policy=False
    )
    return firewall_ingress_decision(firewalls, layer.allowed, layer.uncertainties)
