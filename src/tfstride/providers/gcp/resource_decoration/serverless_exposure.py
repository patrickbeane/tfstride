from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.constants import PUBLIC_GCP_IAM_MEMBERS
from tfstride.providers.gcp.resource_decoration.iam import (
    iam_bindings,
    resolve_resource_iam_target,
    serverless_iam_resources,
)
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpResourceIndex
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_types import GCP_CLOUD_RUN_RESOURCE_TYPES
from tfstride.providers.gcp.resource_utils import binding_members

_CLOUD_RUN_PUBLIC_INVOKER_ROLES = frozenset({"roles/run.invoker", "roles/run.servicesInvoker"})
_CLOUD_FUNCTION_PUBLIC_INVOKER_ROLES = frozenset({"roles/cloudfunctions.invoker"})


def derive_public_serverless_exposure(
    resource: NormalizedResource,
    index: GcpResourceIndex,
) -> None:
    public_access_reasons = _serverless_public_access_reasons(
        resource,
        serverless_iam_resources(resource, index),
        index,
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
    index: GcpResourceIndex,
) -> list[str]:
    reasons: list[str] = []
    if resource.resource_type in GCP_CLOUD_RUN_RESOURCE_TYPES and gcp_facts(resource).cloud_run_invoker_iam_disabled:
        reasons.append(f"{resource.address} disables the Cloud Run Invoker IAM check")
    public_invoker_roles = (
        _CLOUD_RUN_PUBLIC_INVOKER_ROLES
        if resource.resource_type in GCP_CLOUD_RUN_RESOURCE_TYPES
        else _CLOUD_FUNCTION_PUBLIC_INVOKER_ROLES
    )
    for iam_resource in iam_resources:
        if not iam_resource.resource_type.startswith(f"{resource.resource_type}_iam_"):
            continue
        resolution = resolve_resource_iam_target(
            iam_resource,
            index,
            resource_types={resource.resource_type},
        )
        if resolution.selected_candidate is not resource:
            continue
        for binding in iam_bindings(iam_resource):
            if binding.get("condition_state") == "unknown":
                continue
            role = str(binding.get("role") or "unknown role")
            if role not in public_invoker_roles:
                continue
            public_members = sorted(member for member in binding_members(binding) if member in PUBLIC_GCP_IAM_MEMBERS)
            for member in public_members:
                reasons.append(f"{iam_resource.address} grants {role} to {member}")
    return dedupe(reasons)
