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
        role_definition_index = _custom_role_definitions_by_reference(resources)
        for role_assignment in resources:
            if role_assignment.resource_type != AzureResourceType.ROLE_ASSIGNMENT:
                continue
            self._decorate_role_assignment(role_assignment, context, principal_index, role_definition_index)

    def _decorate_role_assignment(
        self,
        role_assignment: NormalizedResource,
        context: AzureDecorationContext,
        principal_index: dict[str, list[NormalizedResource]],
        role_definition_index: dict[str, list[NormalizedResource]],
    ) -> None:
        facts = azure_facts(role_assignment)
        scope = facts.role_assignment_scope
        target_resource = context.index.resolve(scope)
        scope_kind = _classify_scope(scope)
        role_definition = _resolve_custom_role_definition(facts.role_definition_id, role_definition_index)
        if role_definition is not None:
            facts.set_resolved_role_definition_address(role_definition.address)
        elif _looks_like_role_definition_reference(facts.role_definition_id):
            facts.add_unresolved_resource_reference("role_definition", facts.role_definition_id)
        breadth_signals = _breadth_signals(
            role_definition_name=facts.role_definition_name,
            scope_kind=scope_kind,
            target_resource=target_resource,
            role_definition=role_definition,
        )
        breadth_mitigations = _custom_role_breadth_mitigations(role_definition)
        facts.set_role_assignment_scope_context(
            scope_kind=scope_kind,
            breadth_signals=breadth_signals,
            breadth_mitigations=breadth_mitigations,
            target_resource_address=target_resource.address if target_resource else None,
            target_resource_type=target_resource.resource_type if target_resource else None,
        )
        facts.set_key_vault_role_assignments(
            [
                _role_assignment_record(
                    role_assignment,
                    scope_kind=scope_kind,
                    breadth_signals=breadth_signals,
                    target_resource=target_resource,
                    role_definition=role_definition,
                )
            ]
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
                role_definition=role_definition,
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
    role_definition: NormalizedResource | None,
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
    if role_definition is not None:
        signals.extend(azure_facts(role_definition).role_definition_breadth_signals)
    return list(dict.fromkeys(signals))


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
    role_definition: NormalizedResource | None,
) -> dict[str, object]:
    facts = azure_facts(role_assignment)
    record: dict[str, object] = {
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
    if facts.resolved_role_definition_address:
        record["resolved_role_definition_address"] = facts.resolved_role_definition_address
    if facts.role_assignment_breadth_mitigations:
        record["breadth_mitigations"] = facts.role_assignment_breadth_mitigations
    if role_definition is not None:
        role_definition_facts = azure_facts(role_definition)
        record["role_definition_breadth_signals"] = role_definition_facts.role_definition_breadth_signals
        if role_definition_facts.role_definition_breadth_mitigations:
            record["role_definition_breadth_mitigations"] = role_definition_facts.role_definition_breadth_mitigations
    return record


def _custom_role_breadth_mitigations(role_definition: NormalizedResource | None) -> list[str]:
    if role_definition is None:
        return []
    return azure_facts(role_definition).role_definition_breadth_mitigations


def _custom_role_definitions_by_reference(
    resources: Iterable[NormalizedResource],
) -> dict[str, list[NormalizedResource]]:
    definitions: dict[str, list[NormalizedResource]] = {}
    for resource in resources:
        if resource.resource_type != AzureResourceType.ROLE_DEFINITION:
            continue
        seen: set[str] = set()
        for reference in _role_definition_references(resource):
            key = _role_definition_reference_key(reference)
            if not key or key in seen:
                continue
            seen.add(key)
            definitions.setdefault(key, []).append(resource)
    return definitions


def _resolve_custom_role_definition(
    reference: str | None,
    definitions: dict[str, list[NormalizedResource]],
) -> NormalizedResource | None:
    key = _role_definition_reference_key(reference)
    if not key:
        return None
    matches = definitions.get(key, [])
    if len(matches) != 1:
        return None
    return matches[0]


def _role_definition_references(role_definition: NormalizedResource) -> tuple[str, ...]:
    facts = azure_facts(role_definition)
    references = [
        role_definition.address,
        f"{role_definition.address}.id",
        f"{role_definition.address}.role_definition_id",
        f"{role_definition.address}.role_definition_resource_id",
        role_definition.identifier,
        facts.role_definition_id,
    ]
    return tuple(reference for reference in references if reference)


def _looks_like_role_definition_reference(reference: str | None) -> bool:
    if not reference:
        return False
    normalized = reference.strip().lower()
    return normalized.startswith("azurerm_role_definition.")


def _role_definition_reference_key(reference: str | None) -> str:
    if not reference:
        return ""
    text = reference.strip().lower()
    if text.startswith("${") and text.endswith("}"):
        text = text[2:-1].strip()
    for suffix in (".role_definition_resource_id", ".role_definition_id", ".id"):
        if text.endswith(suffix):
            return text[: -len(suffix)]
    return text


def _principal_key(principal_id: str) -> str:
    return principal_id.strip().lower()
