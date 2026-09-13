from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.resource_reference_index import ResourceReferenceIndex


def resolve_workload_role(
    workload: NormalizedResource,
    role_index: ResourceReferenceIndex,
) -> NormalizedResource | None:
    for role_arn in workload.attached_role_arns:
        role = role_index.unique_candidate(role_arn)
        if role is not None:
            return role
    return None
