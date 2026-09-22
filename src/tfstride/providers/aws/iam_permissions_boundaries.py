from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.coercion import STATE_NOT_CONFIGURED


def permissions_boundary_uncertainties(role: NormalizedResource, *, authority: str) -> list[str]:
    """Require explicit absence until permissions-boundary policy intersections are modeled."""

    facts = aws_facts(role)
    if facts.iam_permissions_boundary_state == STATE_NOT_CONFIGURED:
        return []

    boundary = facts.iam_permissions_boundary_arn
    if boundary is not None:
        return [
            f"{role.address} has configured permissions boundary {boundary}; "
            f"effective {authority} authority is unresolved because "
            "permissions-boundary policy intersection is not modeled"
        ]

    details = facts.iam_permissions_boundary_uncertainties
    if details:
        return [f"{role.address} permissions-boundary evidence is unresolved: {detail}" for detail in details]
    return [
        f"{role.address} permissions-boundary state is unresolved; effective "
        f"{authority} authority cannot be established"
    ]
