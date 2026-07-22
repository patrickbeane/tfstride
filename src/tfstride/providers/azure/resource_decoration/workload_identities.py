from __future__ import annotations

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AzureResourceType


def workload_managed_identities(
    workload: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[list[tuple[NormalizedResource, str]], list[str]]:
    facts = azure_facts(workload)
    identities: list[tuple[NormalizedResource, str]] = []
    uncertainties: list[str] = []
    if facts.has_system_assigned_identity:
        if facts.principal_id:
            identities.append((workload, "system_assigned"))
        else:
            uncertainties.append(f"{workload.address}: system-assigned identity principal_id is unresolved")

    if facts.has_user_assigned_identity:
        if not facts.attached_identity_references:
            uncertainties.append(f"{workload.address}: user-assigned identity references are unresolved")
        for reference in facts.attached_identity_references:
            identity = context.index.resolve(reference)
            if identity is None or identity.resource_type != AzureResourceType.USER_ASSIGNED_IDENTITY:
                uncertainties.append(f"{workload.address}: user-assigned identity {reference} is not modeled")
                continue
            if not azure_facts(identity).principal_id:
                uncertainties.append(f"{workload.address}: {identity.address} principal_id is unresolved")
                continue
            identities.append((identity, "user_assigned"))
    return identities, uncertainties
