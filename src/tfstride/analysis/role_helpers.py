from __future__ import annotations

from collections.abc import Mapping

from tfstride.models import NormalizedResource


def resolve_workload_role(
    workload: NormalizedResource,
    role_index: Mapping[str, NormalizedResource],
) -> NormalizedResource | None:
    for role_arn in workload.attached_role_arns:
        role = role_index.get(role_arn)
        if role is not None:
            return role
    return None
