from __future__ import annotations

from tfstride.models import NormalizedResource, ResourceInventory


def subnet_posture(resource: NormalizedResource | None, inventory: ResourceInventory) -> list[str]:
    if resource is None:
        return []
    postures: list[str] = []
    for subnet_id in resource.subnet_ids:
        subnet = inventory.get_by_identifier(subnet_id)
        if subnet is None or subnet.resource_type != "aws_subnet":
            continue
        if subnet.is_public_subnet:
            posture = f"{resource.address} sits in public subnet {subnet.address}"
        else:
            posture = f"{resource.address} sits in private subnet {subnet.address}"
        if subnet.has_public_route:
            posture += " with an internet route"
        elif subnet.has_nat_gateway_egress:
            posture += " with NAT-backed egress"
        postures.append(posture)
    if not postures and resource.in_public_subnet:
        postures.append(f"{resource.address} is classified in a public subnet")
    return postures


def join_clauses(clauses: list[str]) -> str:
    if not clauses:
        return "its network controls allow paths that should remain tighter"
    if len(clauses) == 1:
        return clauses[0]
    return f"{', '.join(clauses[:-1])}, and {clauses[-1]}"