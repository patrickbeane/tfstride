from __future__ import annotations

import re
from collections.abc import Mapping

from tfstride.models import NormalizedResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_index import (
    GcpDecorationContext,
    GcpResourceIndex,
    gcp_network_reference_key,
    gcp_resource_references,
)
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_types import (
    GCP_FORWARDING_RULE_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import (
    GCP_NETWORK_REFERENCE_SUFFIXES,
    dedupe,
    gcp_reference_key,
)

_GCP_NETWORK_NAME_PATTERN = re.compile(r"^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_TERRAFORM_REFERENCE_TOKEN_CHARS = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_[]"-')


class DeriveNetworkPostureStage:
    name = "derive_network_posture"

    def apply(self, resources: list[NormalizedResource], context: GcpDecorationContext) -> None:
        index = context.index
        for resource in resources:
            if resource.resource_type == GcpResourceType.COMPUTE_SUBNETWORK:
                _derive_subnetwork_route_posture(resource, index)

        for resource in resources:
            is_network_posture_resource = (
                resource.resource_type == GcpResourceType.COMPUTE_INSTANCE
                or resource.resource_type in GCP_FORWARDING_RULE_RESOURCE_TYPES
            )
            if not is_network_posture_resource:
                continue
            _infer_instance_vpc_id(resource, index)
            _derive_instance_network_posture(resource, index)


def _derive_subnetwork_route_posture(subnetwork: NormalizedResource, index: GcpResourceIndex) -> None:
    has_public_route = any(
        _route_has_internet_gateway(route)
        and not route.get_metadata_field(GcpResourceMetadata.ROUTE_TAGS)
        and _same_network_reference(route.vpc_id, subnetwork.vpc_id, index)
        for route in index.routes
    )
    has_nat_egress = any(_nat_applies_to_subnetwork(router_nat, subnetwork, index) for router_nat in index.router_nats)
    gcp_mutations(subnetwork).set_subnetwork_route_posture(
        has_public_route=has_public_route,
        has_nat_gateway_egress=has_nat_egress,
    )


def _derive_instance_network_posture(resource: NormalizedResource, index: GcpResourceIndex) -> None:
    subnetworks = _resource_subnetworks(resource, index)
    in_public_subnet = any(subnetwork.is_public_subnet for subnetwork in subnetworks)
    has_nat_gateway_egress = any(subnetwork.has_nat_gateway_egress for subnetwork in subnetworks)
    has_public_route = in_public_subnet or any(
        _route_has_internet_gateway(route)
        and _route_tags_apply_to_instance(route, resource)
        and resource_has_network_reference(resource, route.vpc_id, index)
        for route in index.routes
    )
    gcp_mutations(resource).set_instance_network_posture(
        in_public_subnet=in_public_subnet,
        has_nat_gateway_egress=has_nat_gateway_egress,
        has_public_route=has_public_route,
    )


def _resource_subnetworks(resource: NormalizedResource, index: GcpResourceIndex) -> list[NormalizedResource]:
    subnetworks: list[NormalizedResource] = []
    seen: set[str] = set()
    for subnet_reference in resource.subnet_ids:
        subnetwork = index.subnetworks_by_reference.get(
            gcp_reference_key(subnet_reference, GCP_NETWORK_REFERENCE_SUFFIXES)
        )
        if subnetwork is None or subnetwork.address in seen:
            continue
        subnetworks.append(subnetwork)
        seen.add(subnetwork.address)
    return subnetworks


def _infer_instance_vpc_id(resource: NormalizedResource, index: GcpResourceIndex) -> None:
    if resource.vpc_id:
        return
    subnet_network_reference = _unique_network_reference(_subnetwork_vpc_references(resource, index), index)
    if gcp_mutations(resource).infer_vpc_id(subnet_network_reference):
        return
    network_reference = _unique_network_reference(_instance_network_references(resource), index)
    gcp_mutations(resource).infer_vpc_id(network_reference)


def _subnetwork_vpc_references(resource: NormalizedResource, index: GcpResourceIndex) -> list[str]:
    references: list[str] = []
    for subnet_reference in resource.subnet_ids:
        subnetwork = index.subnetworks_by_reference.get(
            gcp_reference_key(subnet_reference, GCP_NETWORK_REFERENCE_SUFFIXES)
        )
        if subnetwork is None:
            continue
        network_reference = _validated_network_reference(subnetwork.vpc_id)
        if network_reference is not None:
            references.append(network_reference)
    return references


def _instance_network_references(resource: NormalizedResource) -> list[str]:
    references: list[str] = []
    for interface in resource.get_metadata_field(GcpResourceMetadata.NETWORK_INTERFACES):
        if not isinstance(interface, Mapping):
            continue
        network = interface.get("network")
        if network in (None, ""):
            continue
        network_reference = _validated_network_reference(network)
        if network_reference is not None:
            references.append(network_reference)
    return dedupe(references)


def _unique_network_reference(references: list[str], index: GcpResourceIndex) -> str | None:
    inferred_reference: str | None = None
    inferred_canonical_reference: str | None = None
    for reference in references:
        canonical_reference = _canonical_network_reference(reference, index)
        if inferred_reference is None:
            inferred_reference = reference
            inferred_canonical_reference = canonical_reference
            continue
        if canonical_reference != inferred_canonical_reference:
            return None
    return inferred_reference


def resource_has_network_reference(
    resource: NormalizedResource,
    network_reference: str | None,
    index: GcpResourceIndex,
) -> bool:
    return any(
        _same_network_reference(candidate, network_reference, index)
        for candidate in _resource_network_references(resource, index)
    )


def _resource_network_references(resource: NormalizedResource, index: GcpResourceIndex) -> list[str]:
    references: list[str] = []
    direct_reference = _validated_network_reference(resource.vpc_id)
    if direct_reference is not None:
        references.append(direct_reference)
    references.extend(_subnetwork_vpc_references(resource, index))
    references.extend(_instance_network_references(resource))
    return dedupe(references)


def _route_has_internet_gateway(route: NormalizedResource) -> bool:
    dest_range = route.get_metadata_field(GcpResourceMetadata.ROUTE_DEST_RANGE)
    next_hop_gateway = route.get_metadata_field(GcpResourceMetadata.ROUTE_NEXT_HOP_GATEWAY)
    if dest_range not in {"0.0.0.0/0", "::/0"} or not next_hop_gateway:
        return False
    return "default-internet-gateway" in next_hop_gateway or "internet" in next_hop_gateway


def _route_tags_apply_to_instance(route: NormalizedResource, instance: NormalizedResource) -> bool:
    route_tags = set(route.get_metadata_field(GcpResourceMetadata.ROUTE_TAGS))
    if not route_tags:
        return False
    instance_tags = set(instance.get_metadata_field(GcpResourceMetadata.NETWORK_TAGS))
    return bool(route_tags.intersection(instance_tags))


def _nat_applies_to_subnetwork(
    router_nat: NormalizedResource,
    subnetwork: NormalizedResource,
    index: GcpResourceIndex,
) -> bool:
    source_mode = str(router_nat.metadata.get("source_subnetwork_ip_ranges_to_nat") or "").upper()
    if source_mode.startswith("ALL_SUBNETWORKS"):
        return any(
            _same_network_reference(network_reference, subnetwork.vpc_id, index)
            for network_reference in _router_nat_network_references(router_nat, index)
        )

    subnetwork_references = set(gcp_resource_references(subnetwork))
    for nat_subnetwork in router_nat.get_metadata_field(GcpResourceMetadata.NAT_SUBNETWORKS):
        reference = nat_subnetwork.get("name") if isinstance(nat_subnetwork, dict) else None
        if reference and gcp_reference_key(str(reference), GCP_NETWORK_REFERENCE_SUFFIXES) in subnetwork_references:
            return True
    return False


def _router_nat_network_references(
    router_nat: NormalizedResource,
    index: GcpResourceIndex,
) -> tuple[str, ...]:
    router_reference = router_nat.get_metadata_field(GcpResourceMetadata.ROUTER_REFERENCE)
    if not router_reference:
        return ()
    router = index.routers_by_reference.get(gcp_reference_key(router_reference, GCP_NETWORK_REFERENCE_SUFFIXES))
    if router is None or not router.vpc_id:
        return ()
    return (router.vpc_id,)


def _same_network_reference(
    left: str | None,
    right: str | None,
    index: GcpResourceIndex | None = None,
) -> bool:
    if not left or not right:
        return False
    return _canonical_network_reference(left, index) == _canonical_network_reference(right, index)


def _canonical_network_reference(value: str, index: GcpResourceIndex | None) -> str:
    reference_key = gcp_reference_key(value, GCP_NETWORK_REFERENCE_SUFFIXES)
    network_key = gcp_network_reference_key(value)
    if index is not None:
        return index.network_references.get(reference_key) or index.network_references.get(network_key) or network_key
    return network_key


def _validated_network_reference(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or any(character.isspace() for character in text):
        return None
    network_key = gcp_network_reference_key(text)
    if _GCP_NETWORK_NAME_PATTERN.fullmatch(network_key):
        return text
    reference_key = gcp_reference_key(text, GCP_NETWORK_REFERENCE_SUFFIXES)
    if _is_terraform_network_reference(reference_key):
        return text
    return None


def _is_terraform_network_reference(value: str) -> bool:
    parts = value.split(".")
    for index, part in enumerate(parts[:-1]):
        if part != GcpResourceType.COMPUTE_NETWORK:
            continue
        resource_name = parts[index + 1]
        return bool(resource_name) and all(token and set(token) <= _TERRAFORM_REFERENCE_TOKEN_CHARS for token in parts)
    return False
