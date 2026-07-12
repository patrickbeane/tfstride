from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.constants import PUBLIC_GCP_IAM_MEMBERS
from tfstride.providers.gcp.resource_decoration.iam import (
    iam_bindings,
    resource_iam_target_reference,
    serverless_iam_resources,
)
from tfstride.providers.gcp.resource_index import GcpResourceIndex, gcp_resource_references
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_utils import (
    GCP_NETWORK_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
)

_SERVERLESS_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker", "roles/cloudfunctions.invoker"})


def derive_public_serverless_exposure(
    resource: NormalizedResource,
    index: GcpResourceIndex,
) -> None:
    public_access_reasons = _serverless_public_access_reasons(
        resource,
        serverless_iam_resources(resource, index),
    )
    if public_access_reasons:
        gcp_mutations(resource).set_public_access_reasons(public_access_reasons)
    public_exposure = bool(resource.public_access_configured and public_access_reasons)
    gcp_mutations(resource).set_public_exposure(
        public_exposure,
        reasons=public_access_reasons if public_exposure else None,
    )


def _serverless_public_access_reasons(
    resource: NormalizedResource,
    iam_resources: tuple[NormalizedResource, ...],
) -> list[str]:
    reasons: list[str] = []
    resource_references = set(gcp_resource_references(resource))
    for iam_resource in iam_resources:
        target_reference = resource_iam_target_reference(iam_resource)
        if (
            not target_reference
            or gcp_reference_key(target_reference, GCP_NETWORK_REFERENCE_SUFFIXES) not in resource_references
        ):
            continue
        for binding in iam_bindings(iam_resource):
            role = str(binding.get("role") or "unknown role")
            if role not in _SERVERLESS_PUBLIC_INVOKER_ROLES:
                continue
            public_members = sorted(member for member in binding_members(binding) if member in PUBLIC_GCP_IAM_MEMBERS)
            for member in public_members:
                reasons.append(f"{iam_resource.address} grants {role} to {member}")
    return dedupe(reasons)
