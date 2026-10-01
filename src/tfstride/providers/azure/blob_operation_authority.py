from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Literal

from tfstride.models import NormalizedResource, TerraformReferenceProvenance, TerraformReferenceResolutionState
from tfstride.providers.azure.arm_scope import (
    assignment_condition_state,
    assignment_field_unknown,
    proven_symbolic_assignment_scope_target,
    resolve_assignment_scope,
    resource_arm_id,
    role_assignable_scope_state,
)
from tfstride.providers.azure.protected_data_evidence import AzureStorageAccessClass
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType

_ACCESS_CLASS_ORDER: tuple[AzureStorageAccessClass, ...] = (
    "read",
    "write",
    "delete",
    "administrative",
)
_BUILT_IN_BLOB_DATA_ROLES: dict[
    str,
    tuple[str, str, tuple[AzureStorageAccessClass, ...]],
] = {
    "storage blob data reader": (
        "Storage Blob Data Reader",
        "blob_data_reader",
        ("read",),
    ),
    "storage blob data contributor": (
        "Storage Blob Data Contributor",
        "blob_data_contributor",
        ("read", "write", "delete"),
    ),
    "storage blob data owner": (
        "Storage Blob Data Owner",
        "blob_data_owner",
        _ACCESS_CLASS_ORDER,
    ),
}
_BUILT_IN_BLOB_DATA_ROLE_IDS: dict[
    str,
    tuple[str, str, tuple[AzureStorageAccessClass, ...]],
] = {
    "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1": _BUILT_IN_BLOB_DATA_ROLES["storage blob data reader"],
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe": _BUILT_IN_BLOB_DATA_ROLES["storage blob data contributor"],
    "b7e6dc6d-f1e8-4753-8033-0f276bb0955b": _BUILT_IN_BLOB_DATA_ROLES["storage blob data owner"],
}
_BLOB_DATA_ACTIONS: tuple[tuple[str, AzureStorageAccessClass], ...] = (
    ("microsoft.storage/storageaccounts/blobservices/containers/blobs/read", "read"),
    ("microsoft.storage/storageaccounts/blobservices/containers/blobs/tags/read", "read"),
    ("microsoft.storage/storageaccounts/blobservices/containers/blobs/filter/action", "read"),
    ("microsoft.storage/storageaccounts/blobservices/containers/blobs/write", "write"),
    ("microsoft.storage/storageaccounts/blobservices/containers/blobs/add/action", "write"),
    ("microsoft.storage/storageaccounts/blobservices/containers/blobs/move/action", "write"),
    ("microsoft.storage/storageaccounts/blobservices/containers/blobs/tags/write", "write"),
    ("microsoft.storage/storageaccounts/blobservices/containers/blobs/delete", "delete"),
    (
        "microsoft.storage/storageaccounts/blobservices/containers/blobs/deleteblobversion/action",
        "delete",
    ),
    (
        "microsoft.storage/storageaccounts/blobservices/containers/blobs/permanentdelete/action",
        "delete",
    ),
    (
        "microsoft.storage/storageaccounts/blobservices/containers/blobs/modifypermissions/action",
        "administrative",
    ),
    (
        "microsoft.storage/storageaccounts/blobservices/containers/blobs/manageownership/action",
        "administrative",
    ),
    (
        "microsoft.storage/storageaccounts/blobservices/containers/blobs/runassuperuser/action",
        "administrative",
    ),
    (
        "microsoft.storage/storageaccounts/blobservices/containers/blobs/immutablestorage/runassuperuser/action",
        "administrative",
    ),
)
_STORAGE_TARGET_TYPES = frozenset(
    {
        AzureResourceType.STORAGE_ACCOUNT,
        AzureResourceType.STORAGE_CONTAINER,
    }
)


@dataclass(frozen=True, slots=True)
class AzureBlobDataGrant:
    role_name: str
    role_kind: str
    access_classes: tuple[AzureStorageAccessClass, ...]
    grant_basis: str
    role_definition_address: str | None = None
    permission_patterns: tuple[str, ...] = ()
    not_permission_patterns: tuple[str, ...] = ()
    matched_data_actions: tuple[str, ...] = ()
    excluded_data_actions: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AzureBlobAuthorityResult:
    """One assignment alternative over one modeled target, never a network proof.

    Conditions and exclusions belong to this grant only. This describes modeled
    RBAC allow authority; it does not claim coverage of Azure deny assignments.
    """

    state: Literal["granted", "conditional", "unknown", "unrelated", "not_granted"]
    principal_id: str
    assignment_address: str
    target_address: str
    grant: AzureBlobDataGrant | None = None
    assignment_scope: str | None = None
    assignment_scope_kind: str | None = None
    condition: str | None = None
    condition_version: str | None = None
    uncertainties: tuple[str, ...] = ()


def evaluate_blob_operation_authority(
    assignment: NormalizedResource,
    target: NormalizedResource,
    context: AzureDecorationContext,
    *,
    principal_id: str,
) -> AzureBlobAuthorityResult:
    """Evaluate the existing Blob operation catalog against an exact target."""
    facts = azure_facts(assignment)

    def result(
        state: Literal["granted", "conditional", "unknown", "unrelated", "not_granted"], reason: str | None = None
    ) -> AzureBlobAuthorityResult:
        # Explicit construction below keeps provider facts separate from path presentation.
        return AzureBlobAuthorityResult(
            state,
            principal_id,
            assignment.address,
            target.address,
            assignment_scope=facts.role_assignment_scope,
            condition=facts.role_assignment_condition,
            condition_version=facts.role_assignment_condition_version,
            uncertainties=(reason,) if reason else (),
        )

    if target.resource_type not in _STORAGE_TARGET_TYPES:
        return result("unrelated")
    if facts.principal_id and facts.principal_id.casefold() != principal_id.casefold():
        return result("unrelated")
    if not facts.principal_id:
        return result("unknown", "principal applicability is unresolved")
    if assignment_field_unknown(assignment, "principal_id"):
        identity = _symbolic_field_target(assignment, "principal_id", (".principal_id",), context)
        if (
            identity is None
            or identity.resource_type
            not in {*AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType.USER_ASSIGNED_IDENTITY}
            or azure_facts(identity).principal_id != facts.principal_id
        ):
            return result("unknown", "principal applicability is unresolved")

    target_id = resource_arm_id(target)
    symbolic_target = proven_symbolic_assignment_scope_target(assignment, context)
    if facts.role_assignment_scope is None and symbolic_target is None:
        return result(
            "unknown", "scope does not resolve to an exact Storage Account or container or established ARM ancestor"
        )
    named_scope = context.index.resolve(facts.role_assignment_scope, source=assignment)
    if named_scope is not None and named_scope.resource_type not in {
        *_STORAGE_TARGET_TYPES,
        "azurerm_resource_group",
        "azurerm_subscription",
        "azurerm_management_group",
    }:
        return result("unrelated")
    scope = resolve_assignment_scope(assignment, context, target_id)
    if (
        target_id is None
        and symbolic_target is not None
        and symbolic_target.address == target.address
        and (facts.role_assignment_scope is None or named_scope is target)
    ):
        scope_kind = "resource"
        arm_scope = None
    elif scope.state == "unrelated":
        return result("unrelated")
    elif (
        target_id is None
        or scope.state != "resolved"
        or scope.scope_type not in {"subscription", "resource_group", "resource"}
    ):
        return result(
            "unknown", "scope does not resolve to an exact Storage Account or container or established ARM ancestor"
        )
    else:
        scope_kind = scope.scope_type
        arm_scope = scope.arm_scope

    grant, uncertainty = blob_data_grant(assignment, context)
    if grant is None:
        return result("unknown" if uncertainty else "not_granted", uncertainty)
    if grant.role_definition_address:
        role = context.index.resources_by_address[grant.role_definition_address]
        assignability = role_assignable_scope_state(role, arm_scope)
        if assignability != "resolved":
            return result("unknown", f"custom role {role.address} assignable-scope compatibility is {assignability}")
    condition_state = assignment_condition_state(assignment)
    if condition_state == "unknown":
        return result("unknown", "condition is unresolved")
    return AzureBlobAuthorityResult(
        "conditional" if condition_state == "configured" else "granted",
        principal_id,
        assignment.address,
        target.address,
        grant,
        facts.role_assignment_scope,
        scope_kind,
        facts.role_assignment_condition,
        facts.role_assignment_condition_version,
    )


def blob_data_grant(
    assignment: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[AzureBlobDataGrant | None, str | None]:
    """Resolve current DataActions; never use cached identity assignment summaries."""
    facts = azure_facts(assignment)
    role_name = facts.role_definition_name
    role_id = facts.role_definition_id
    symbolic_role = None
    if role_id is None and assignment_field_unknown(assignment, "role_definition_name"):
        return None, "role is unresolved"
    if assignment_field_unknown(assignment, "role_definition_id"):
        # Exact symbolic role references remain valid first-plan identities.
        symbolic_role = _symbolic_field_target(
            assignment, "role_definition_id", (".id", ".role_definition_resource_id"), context
        )
        if symbolic_role is None or symbolic_role.resource_type != AzureResourceType.ROLE_DEFINITION:
            return None, "role is unresolved"
        if (
            role_id is not None
            and context.index.resolve(role_id, source=assignment, resource_types={AzureResourceType.ROLE_DEFINITION})
            is not symbolic_role
        ):
            return None, "role identity conflicts with its symbolic reference"
    built_in = _built_in_role(role_name, role_id) if symbolic_role is None else None
    if built_in is not None:
        name, kind, classes = built_in
        return AzureBlobDataGrant(name, kind, classes, "azure_storage_scoped_rbac"), None
    role = symbolic_role or context.index.resolve(
        role_id, source=assignment, resource_types={AzureResourceType.ROLE_DEFINITION}
    )
    if role is None:
        # Unmodeled roles cannot establish any particular Blob operation.
        return None, "role is unresolved"
    role_facts = azure_facts(role)
    if any(
        "data_actions" in value or (value.startswith("permissions") and "." not in value)
        for value in role_facts.role_definition_uncertainties
    ):
        return None, f"custom role {role.address} data actions are unresolved"
    patterns = tuple(value for value in role_facts.role_definition_data_actions if value.strip())
    exclusions = tuple(value for value in role_facts.role_definition_not_data_actions if value.strip())
    matched, excluded = _matched_data_actions(patterns, exclusions)
    if not matched:
        return None, None
    return AzureBlobDataGrant(
        role_name or role_facts.name or role.address,
        "custom",
        _access_classes(matched),
        "azure_custom_role_storage_scoped_rbac",
        role.address,
        patterns,
        exclusions,
        matched,
        excluded,
    ), None


def _symbolic_field_target(
    assignment: NormalizedResource,
    field: str,
    suffixes: tuple[str, ...],
    context: AzureDecorationContext,
) -> NormalizedResource | None:
    resolution = assignment.reference_resolution(field)
    if (
        resolution.state != TerraformReferenceResolutionState.SYMBOLIC
        or resolution.provenance != TerraformReferenceProvenance.CONFIGURATION_REFERENCE
        or len(resolution.targets) != 1
    ):
        return None
    target = resolution.targets[0]
    if target.reference not in {target.address + suffix for suffix in suffixes}:
        return None
    return context.index.resources_by_address.get(target.address)


def _built_in_role(
    role_name: str | None,
    role_definition_id: str | None,
) -> tuple[str, str, tuple[AzureStorageAccessClass, ...]] | None:
    if role_definition_id:
        match = _BUILT_IN_BLOB_DATA_ROLE_IDS.get(role_definition_id.strip().lower().rstrip("/").rsplit("/", 1)[-1])
        return match
    if role_name:
        return _BUILT_IN_BLOB_DATA_ROLES.get(role_name.strip().lower())
    return None


def _matched_data_actions(
    permission_patterns: tuple[str, ...],
    not_permission_patterns: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    matched: list[str] = []
    excluded: list[str] = []
    for action, _access_class in _BLOB_DATA_ACTIONS:
        if not _matches_any(action, permission_patterns):
            continue
        if _matches_any(action, not_permission_patterns):
            excluded.append(action)
        else:
            matched.append(action)
    return tuple(matched), tuple(excluded)


def _access_classes(actions: tuple[str, ...]) -> tuple[AzureStorageAccessClass, ...]:
    classes = {access_class for action, access_class in _BLOB_DATA_ACTIONS if action in actions}
    return tuple(access_class for access_class in _ACCESS_CLASS_ORDER if access_class in classes)


def _matches_any(action: str, patterns: tuple[str, ...]) -> bool:
    normalized_action = action.strip().lower()
    return any(fnmatchcase(normalized_action, pattern.strip().lower()) for pattern in patterns)
