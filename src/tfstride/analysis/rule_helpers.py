from __future__ import annotations

from typing import Protocol

from tfstride.analysis.resource_concepts import is_subnet_resource
from tfstride.models import NormalizedResource
from tfstride.providers.resource_reference_index import ResourceReferenceResolution


class SubnetReferenceResolver(Protocol):
    """Provider-owned, source-aware resolution restricted to subnet resources."""

    def __call__(self, reference: str, *, source: NormalizedResource) -> ResourceReferenceResolution: ...


def subnet_posture(resource: NormalizedResource | None, resolve_subnet: SubnetReferenceResolver) -> list[str]:
    if resource is None:
        return []
    postures: list[str] = []
    seen_subnets: set[str] = set()
    for subnet_id in sorted(set(resource.subnet_ids)):
        resolution = resolve_subnet(subnet_id, source=resource)
        if resolution.state == "ambiguous":
            candidates = ", ".join(sorted(candidate.address for candidate in resolution.candidates))
            postures.append(
                f"{resource.address} subnet reference {subnet_id} is ambiguous in its source context "
                f"(candidates: {candidates}); subnet posture is unknown"
            )
            continue
        subnet = resolution.selected_candidate
        if subnet is None or subnet.provider != resource.provider or not is_subnet_resource(subnet):
            postures.append(
                f"{resource.address} subnet reference {subnet_id} is unresolved in its source context; subnet posture is unknown"
            )
            continue
        if subnet.address in seen_subnets:
            continue
        seen_subnets.add(subnet.address)
        if subnet.is_public_subnet:
            posture = f"{resource.address} sits in public subnet {subnet.address}"
        else:
            posture = f"{resource.address} sits in private subnet {subnet.address}"
        if subnet.has_public_route:
            posture += " with an internet route"
        elif subnet.has_nat_gateway_egress:
            posture += " with NAT-backed egress"
        postures.append(posture)
    if not resource.subnet_ids and resource.in_public_subnet:
        postures.append(
            f"{resource.address} is classified in a public subnet, but no subnet reference is available to verify membership"
        )
    return postures


def join_clauses(clauses: list[str]) -> str:
    if not clauses:
        return "its network controls allow paths that should remain tighter"
    if len(clauses) == 1:
        return clauses[0]
    return f"{', '.join(clauses[:-1])}, and {clauses[-1]}"
