from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.firewall_decisions import (
    FirewallIngressDecision,
)
from tfstride.providers.gcp.resource_decoration.firewall_policy_exposure import (
    firewall_policy_ingress_decision,
)
from tfstride.providers.gcp.resource_decoration.firewall_targets import (
    instance_service_account_keys,
    service_account_reference_keys,
)
from tfstride.providers.gcp.resource_decoration.firewall_uncertainty import (
    firewall_field_is_uncertain,
)
from tfstride.providers.gcp.resource_decoration.network_posture import (
    resource_has_network_reference,
)
from tfstride.providers.gcp.resource_decoration.vpc_firewall_ingress import evaluate_vpc_firewall_ingress
from tfstride.providers.gcp.resource_index import GcpResourceIndex
from tfstride.providers.gcp.resource_mutations import gcp_mutations


def derive_public_compute_exposure(resource: NormalizedResource, index: GcpResourceIndex) -> None:
    ingress_decision = _compute_internet_ingress_decision(resource, index)
    gcp_mutations(resource).set_compute_internet_ingress(
        internet_ingress_reasons=ingress_decision.internet_ingress_reasons,
        firewall_addresses=ingress_decision.firewall_addresses,
        uncertainties=ingress_decision.uncertainties,
        effective_ingress=ingress_decision.effective_ingress,
    )

    public_exposure = bool(resource.public_access_configured and ingress_decision.has_internet_ingress)
    gcp_mutations(resource).set_public_exposure(
        public_exposure,
        reasons=(
            ["compute instance has an external access config and matching firewall rules allow internet ingress"]
            if public_exposure
            else []
        ),
    )


def _compute_internet_ingress_decision(
    resource: NormalizedResource,
    index: GcpResourceIndex,
) -> FirewallIngressDecision:
    policy_decision = firewall_policy_ingress_decision(resource, index)
    vpc_decision = evaluate_vpc_firewall_ingress(
        tuple(firewall for firewall in index.firewalls if _firewall_applies_to_instance(firewall, resource, index)),
        incoming=policy_decision.continuing,
    )
    return FirewallIngressDecision(
        sources=tuple(
            sorted(
                (*policy_decision.ingress.sources, *vpc_decision.sources),
                key=lambda source: source.resource.address,
            )
        ),
        uncertainties=tuple(sorted(set(policy_decision.ingress.uncertainties) | set(vpc_decision.uncertainties))),
    )


def _firewall_applies_to_instance(
    firewall: NormalizedResource,
    instance: NormalizedResource,
    index: GcpResourceIndex,
) -> bool:
    if firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_DISABLED) and not firewall_field_is_uncertain(
        firewall, "disabled"
    ):
        return False
    firewall_direction = (
        str(firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_DIRECTION) or "ingress").strip().lower()
    )
    if firewall_direction != "ingress" and not firewall_field_is_uncertain(firewall, "direction"):
        return False
    if not firewall_field_is_uncertain(firewall, "network") and not resource_has_network_reference(
        instance, firewall.vpc_id, index
    ):
        return False

    target_tags = set(firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_TARGET_TAGS))
    if target_tags and not firewall_field_is_uncertain(firewall, "target_tags"):
        instance_tags = set(instance.get_metadata_field(GcpResourceMetadata.NETWORK_TAGS))
        if not target_tags.intersection(instance_tags):
            return False

    target_service_accounts = service_account_reference_keys(
        firewall.get_metadata_field(GcpResourceMetadata.FIREWALL_TARGET_SERVICE_ACCOUNTS)
    )
    if target_service_accounts and not firewall_field_is_uncertain(firewall, "target_service_accounts"):
        instance_service_accounts = instance_service_account_keys(instance)
        if not target_service_accounts.intersection(instance_service_accounts):
            return False

    return True
