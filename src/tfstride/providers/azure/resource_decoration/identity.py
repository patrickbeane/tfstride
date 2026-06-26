from __future__ import annotations

import re
from collections.abc import Iterable

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import (
    AZURE_COMPUTE_RESOURCE_TYPES,
    AzureResourceType,
)

_BROAD_BUILT_IN_ROLE_NAMES = frozenset(
    {
        "contributor",
        "key vault administrator",
        "key vault data access administrator",
        "owner",
        "storage account contributor",
        "storage blob data owner",
        "user access administrator",
    }
)
_SENSITIVE_SCOPE_RESOURCE_TYPES = frozenset(
    {
        AzureResourceType.KEY_VAULT,
        AzureResourceType.KEY_VAULT_CERTIFICATE,
        AzureResourceType.KEY_VAULT_KEY,
        AzureResourceType.KEY_VAULT_SECRET,
        AzureResourceType.STORAGE_ACCOUNT,
        AzureResourceType.STORAGE_CONTAINER,
    }
)
_SUBSCRIPTION_SCOPE_PATTERN = re.compile(r"^/subscriptions/[^/]+/?$", re.IGNORECASE)
_RESOURCE_GROUP_SCOPE_PATTERN = re.compile(r"^/subscriptions/[^/]+/resourcegroups/[^/]+/?$", re.IGNORECASE)


class DecorateManagedIdentityRoleAssignmentsStage:
    name = "decorate_managed_identity_role_assignments"

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        principal_index = _managed_identities_by_principal_id(resources)
        for role_assignment in resources:
            if role_assignment.resource_type != AzureResourceType.ROLE_ASSIGNMENT:
                continue
            self._decorate_role_assignment(role_assignment, context, principal_index)

    def _decorate_role_assignment(
        self,
        role_assignment: NormalizedResource,
        context: AzureDecorationContext,
        principal_index: dict[str, list[NormalizedResource]],
    ) -> None:
        facts = azure_facts(role_assignment)
        scope = facts.role_assignment_scope
        target_resource = context.index.resolve(scope)
        scope_kind = _classify_scope(scope)
        breadth_signals = _breadth_signals(
            role_definition_name=facts.role_definition_name,
            scope_kind=scope_kind,
            target_resource=target_resource,
        )
        facts.set_role_assignment_scope_context(
            scope_kind=scope_kind,
            breadth_signals=breadth_signals,
            target_resource_address=target_resource.address if target_resource else None,
            target_resource_type=target_resource.resource_type if target_resource else None,
        )

        principal_id = facts.principal_id
        if not principal_id:
            return
        matches = principal_index.get(_principal_key(principal_id), [])
        if len(matches) != 1:
            return

        identity = matches[0]
        facts.set_resolved_managed_identity_address(identity.address)
        azure_facts(identity).add_managed_identity_role_assignment(
            _role_assignment_record(
                role_assignment,
                scope_kind=scope_kind,
                breadth_signals=breadth_signals,
                target_resource=target_resource,
            )
        )


def _managed_identities_by_principal_id(
    resources: Iterable[NormalizedResource],
) -> dict[str, list[NormalizedResource]]:
    identities: dict[str, list[NormalizedResource]] = {}
    for resource in resources:
        facts = azure_facts(resource)
        if resource.resource_type == AzureResourceType.USER_ASSIGNED_IDENTITY:
            principal_id = facts.principal_id
        elif resource.resource_type in AZURE_COMPUTE_RESOURCE_TYPES and facts.has_system_assigned_identity:
            principal_id = facts.principal_id
        else:
            continue
        if principal_id:
            identities.setdefault(_principal_key(principal_id), []).append(resource)
    return identities


def _classify_scope(scope: str | None) -> str | None:
    if not scope:
        return None
    normalized = scope.strip().lower()
    if _SUBSCRIPTION_SCOPE_PATTERN.fullmatch(normalized):
        return "subscription"
    if _RESOURCE_GROUP_SCOPE_PATTERN.fullmatch(normalized) or normalized.startswith("azurerm_resource_group."):
        return "resource_group"
    return "resource"


def _breadth_signals(
    *,
    role_definition_name: str | None,
    scope_kind: str | None,
    target_resource: NormalizedResource | None,
) -> list[str]:
    signals: list[str] = []
    if scope_kind == "subscription":
        signals.append("subscription_scope")
    elif scope_kind == "resource_group":
        signals.append("resource_group_scope")
    if _is_broad_builtin_role(role_definition_name):
        signals.append("broad_builtin_role")
    if target_resource is not None and target_resource.resource_type in _SENSITIVE_SCOPE_RESOURCE_TYPES:
        signals.append("sensitive_resource_scope")
    return signals


def _is_broad_builtin_role(role_definition_name: str | None) -> bool:
    if not role_definition_name:
        return False
    return role_definition_name.strip().lower() in _BROAD_BUILT_IN_ROLE_NAMES


def _role_assignment_record(
    role_assignment: NormalizedResource,
    *,
    scope_kind: str | None,
    breadth_signals: list[str],
    target_resource: NormalizedResource | None,
) -> dict[str, object]:
    facts = azure_facts(role_assignment)
    return {
        "source": role_assignment.address,
        "scope": facts.role_assignment_scope,
        "role_definition_name": facts.role_definition_name,
        "role_definition_id": facts.role_definition_id,
        "principal_id": facts.principal_id,
        "principal_type": facts.principal_type,
        "scope_kind": scope_kind,
        "target_resource_address": target_resource.address if target_resource else None,
        "target_resource_type": target_resource.resource_type if target_resource else None,
        "breadth_signals": list(breadth_signals),
    }


def _principal_key(principal_id: str) -> str:
    return principal_id.strip().lower()
