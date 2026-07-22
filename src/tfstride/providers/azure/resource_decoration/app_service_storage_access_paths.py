from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_decoration.workload_identities import workload_managed_identities
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType
from tfstride.providers.coercion import dedupe

_ACCESS_CLASS_ORDER = ("read", "write", "delete", "administrative")
_BUILT_IN_BLOB_DATA_ROLES: dict[str, tuple[str, str, tuple[str, ...]]] = {
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
_BUILT_IN_BLOB_DATA_ROLE_IDS: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1": _BUILT_IN_BLOB_DATA_ROLES["storage blob data reader"],
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe": _BUILT_IN_BLOB_DATA_ROLES["storage blob data contributor"],
    "b7e6dc6d-f1e8-4753-8033-0f276bb0955b": _BUILT_IN_BLOB_DATA_ROLES["storage blob data owner"],
}
_BLOB_DATA_ACTIONS: tuple[tuple[str, str], ...] = (
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
class _StorageDataGrant:
    role_name: str
    role_kind: str
    access_classes: tuple[str, ...]
    grant_basis: str
    role_definition_address: str | None = None
    permission_patterns: tuple[str, ...] = ()
    not_permission_patterns: tuple[str, ...] = ()
    matched_data_actions: tuple[str, ...] = ()
    excluded_data_actions: tuple[str, ...] = ()


class ModelAppServiceStorageAccessPathsStage:
    name = "model_app_service_storage_access_paths"

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        for workload in resources:
            if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
                continue
            paths, uncertainties = _app_service_storage_access_paths(workload, context)
            facts = azure_facts(workload)
            facts.set_app_service_storage_access_paths(paths)
            facts.extend_app_service_storage_access_path_uncertainties(uncertainties)


def _app_service_storage_access_paths(
    workload: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[list[dict[str, Any]], list[str]]:
    workload_facts = azure_facts(workload)
    identities, identity_uncertainties = workload_managed_identities(workload, context)
    uncertainties = [
        *identity_uncertainties,
        *[f"{workload.address}: {value}" for value in workload_facts.managed_identity_uncertainties],
    ]
    paths: list[dict[str, Any]] = []

    for identity, identity_kind in identities:
        identity_facts = azure_facts(identity)
        for assignment in identity_facts.managed_identity_role_assignments:
            assignment_resource = _assignment_resource(assignment, context)
            if assignment_resource is None:
                source = _string_value(assignment.get("source")) or "unknown role assignment"
                uncertainties.append(f"{workload.address}: {source} is not modeled")
                continue
            assignment_facts = azure_facts(assignment_resource)
            if not _same_identifier(assignment_facts.principal_id, identity_facts.principal_id):
                continue
            if _condition_is_unknown(assignment_resource):
                uncertainties.append(f"{workload.address}: {assignment_resource.address} condition is unresolved")
                continue

            grant, grant_uncertainty = _storage_data_grant(assignment, assignment_resource, context)
            if grant_uncertainty:
                uncertainties.append(f"{workload.address}: {assignment_resource.address} {grant_uncertainty}")
            if grant is None:
                continue

            target, target_uncertainty = _exact_storage_target(assignment, assignment_resource, context)
            if target_uncertainty:
                uncertainties.append(f"{workload.address}: {assignment_resource.address} {target_uncertainty}")
            if target is None:
                continue
            paths.append(
                _access_path_record(
                    workload,
                    identity,
                    identity_kind,
                    assignment_resource,
                    target,
                    grant,
                    context,
                )
            )

    return _dedupe_dicts(paths), dedupe(uncertainties)


def _assignment_resource(
    assignment: Mapping[str, Any],
    context: AzureDecorationContext,
) -> NormalizedResource | None:
    resource = context.index.resolve(_string_value(assignment.get("source")))
    if resource is None or resource.resource_type != AzureResourceType.ROLE_ASSIGNMENT:
        return None
    return resource


def _exact_storage_target(
    assignment: Mapping[str, Any],
    assignment_resource: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[NormalizedResource | None, str | None]:
    target_address = _string_value(assignment.get("target_resource_address"))
    target_type = _string_value(assignment.get("target_resource_type"))
    scope_kind = _string_value(assignment.get("scope_kind"))
    if scope_kind != "resource" or target_address is None or target_type not in _STORAGE_TARGET_TYPES:
        scope = azure_facts(assignment_resource).role_assignment_scope or "unknown"
        return None, f"scope {scope} does not resolve to an exact Storage Account or container"

    target = context.index.resolve(target_address)
    if target is None or target.address != target_address or target.resource_type != target_type:
        return None, f"target {target_address} is not an exact modeled Storage Account or container"
    return target, None


def _storage_data_grant(
    assignment: Mapping[str, Any],
    assignment_resource: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[_StorageDataGrant | None, str | None]:
    role_name = _string_value(assignment.get("role_definition_name"))
    role_definition_id = _string_value(assignment.get("role_definition_id"))
    built_in = _built_in_role(role_name, role_definition_id)
    if built_in is not None:
        default_role_name, role_kind, access_classes = built_in
        return (
            _StorageDataGrant(
                role_name=default_role_name,
                role_kind=role_kind,
                access_classes=access_classes,
                grant_basis="azure_storage_scoped_rbac",
            ),
            None,
        )

    assignment_facts = azure_facts(assignment_resource)
    role_definition = context.index.resolve(assignment_facts.resolved_role_definition_address)
    if role_definition is None or role_definition.resource_type != AzureResourceType.ROLE_DEFINITION:
        if role_name is None:
            return None, "role is unresolved"
        return None, None

    role_facts = azure_facts(role_definition)
    if any(
        "data_actions" in value or "not_data_actions" in value for value in role_facts.role_definition_uncertainties
    ):
        return None, f"custom role {role_definition.address} data actions are unresolved"

    permission_patterns = tuple(value for value in role_facts.role_definition_data_actions if value.strip())
    not_permission_patterns = tuple(value for value in role_facts.role_definition_not_data_actions if value.strip())
    matched, excluded = _matched_data_actions(permission_patterns, not_permission_patterns)
    if not matched:
        return None, None
    return (
        _StorageDataGrant(
            role_name=role_name or role_facts.name or role_definition.address,
            role_kind="custom",
            access_classes=_access_classes(matched),
            grant_basis="azure_custom_role_storage_scoped_rbac",
            role_definition_address=role_definition.address,
            permission_patterns=permission_patterns,
            not_permission_patterns=not_permission_patterns,
            matched_data_actions=matched,
            excluded_data_actions=excluded,
        ),
        None,
    )


def _built_in_role(
    role_name: str | None,
    role_definition_id: str | None,
) -> tuple[str, str, tuple[str, ...]] | None:
    if role_definition_id:
        match = _BUILT_IN_BLOB_DATA_ROLE_IDS.get(role_definition_id.strip().lower().rstrip("/").rsplit("/", 1)[-1])
        if match is not None:
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


def _access_classes(actions: tuple[str, ...]) -> tuple[str, ...]:
    classes = {access_class for action, access_class in _BLOB_DATA_ACTIONS if action in actions}
    return tuple(access_class for access_class in _ACCESS_CLASS_ORDER if access_class in classes)


def _matches_any(action: str, patterns: tuple[str, ...]) -> bool:
    normalized_action = action.strip().lower()
    return any(fnmatchcase(normalized_action, pattern.strip().lower()) for pattern in patterns)


def _access_path_record(
    workload: NormalizedResource,
    identity: NormalizedResource,
    identity_kind: str,
    assignment: NormalizedResource,
    target: NormalizedResource,
    grant: _StorageDataGrant,
    context: AzureDecorationContext,
) -> dict[str, Any]:
    identity_facts = azure_facts(identity)
    assignment_facts = azure_facts(assignment)
    storage_account = _storage_account_for_target(target, context)
    condition = assignment_facts.role_assignment_condition
    record: dict[str, Any] = {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "identity_address": identity.address,
        "identity_kind": identity_kind,
        "principal_id": identity_facts.principal_id,
        "credential_context": "workload_runtime",
        "storage_resource_address": target.address,
        "storage_resource_type": target.resource_type,
        "storage_resource_id": target.identifier,
        "storage_account_address": storage_account.address if storage_account else None,
        "storage_account_id": azure_facts(storage_account).storage_account_id if storage_account else None,
        "container_address": target.address if target.resource_type == AzureResourceType.STORAGE_CONTAINER else None,
        "role_assignment_address": assignment.address,
        "role_definition_name": grant.role_name,
        "role_definition_id": assignment_facts.role_definition_id,
        "role_kind": grant.role_kind,
        "access_classes": list(grant.access_classes),
        "grant_basis": grant.grant_basis,
        "evaluation_basis": "modeled_rbac_assignment",
        "resource_scope": (
            "exact_storage_container"
            if target.resource_type == AzureResourceType.STORAGE_CONTAINER
            else "exact_storage_account"
        ),
        "assignment_scope": assignment_facts.role_assignment_scope,
        "assignment_scope_kind": assignment_facts.role_assignment_scope_kind,
        "condition": condition,
        "condition_state": "configured" if condition else "not_configured",
        "access_state": "conditional" if condition else "granted",
        "role_definition_address": grant.role_definition_address,
        "custom_role_data_actions": list(grant.permission_patterns),
        "custom_role_not_data_actions": list(grant.not_permission_patterns),
        "matched_data_actions": list(grant.matched_data_actions),
        "excluded_data_actions": list(grant.excluded_data_actions),
    }
    return record


def _storage_account_for_target(
    target: NormalizedResource,
    context: AzureDecorationContext,
) -> NormalizedResource | None:
    if target.resource_type == AzureResourceType.STORAGE_ACCOUNT:
        return target
    account = context.index.resolve(azure_facts(target).resolved_storage_account_address)
    if account is None or account.resource_type != AzureResourceType.STORAGE_ACCOUNT:
        return None
    return account


def _condition_is_unknown(assignment: NormalizedResource) -> bool:
    return any(
        "condition is unknown" in uncertainty
        for uncertainty in azure_facts(assignment).key_vault_authorization_uncertainties
    )


def _same_identifier(left: str | None, right: str | None) -> bool:
    return bool(left and right and left.strip().lower() == right.strip().lower())


def _string_value(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _dedupe_dicts(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result
