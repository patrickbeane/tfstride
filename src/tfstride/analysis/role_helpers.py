from __future__ import annotations

from tfstride.models import NormalizedResource, ResourceInventory


def build_role_index(inventory: ResourceInventory) -> dict[str, NormalizedResource]:
    index: dict[str, NormalizedResource] = {}
    for role in inventory.by_type("aws_iam_role"):
        if role.arn:
            index[role.arn] = role
        index[role.address] = role
        if role.identifier:
            index[role.identifier] = role
    return index


def resolve_workload_role(
    workload: NormalizedResource,
    role_index: dict[str, NormalizedResource],
) -> NormalizedResource | None:
    for role_arn in workload.attached_role_arns:
        role = role_index.get(role_arn)
        if role is not None:
            return role
    return None