from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.custom_role_index import (
    GcpCustomRoleIndex,
    build_gcp_custom_role_index,
    custom_role_permissions,
)
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import GCP_CLOUD_RUN_RESOURCE_TYPES, GcpResourceType
from tfstride.providers.gcp.resource_utils import GCP_BASIC_IAM_ROLES, binding_members

_ACTIVE_CUSTOM_ROLE_STAGES = frozenset(
    {
        "ALPHA",
        "BETA",
        "DEPRECATED",
        "EAP",
        "GA",
    }
)
_ACCESS_CLASS_ORDER = (
    "read",
    "entity_write",
    "entity_delete",
    "destructive_administration",
    "configuration_administration",
)
_ENTITY_READ_PERMISSIONS = (
    "datastore.entities.get",
    "datastore.entities.list",
)
_ENTITY_LIST_PERMISSIONS = ("datastore.entities.list",)
_ENTITY_WRITE_PERMISSIONS = (
    "datastore.entities.create",
    "datastore.entities.update",
)
_ENTITY_DELETE_PERMISSIONS = ("datastore.entities.delete",)
_CONFIGURATION_PERMISSIONS = (
    "datastore.databases.update",
    "datastore.schemas.create",
    "datastore.schemas.delete",
    "datastore.schemas.update",
)
_DESTRUCTIVE_ADMINISTRATION_PERMISSIONS = (
    "datastore.databases.bulkDelete",
    "datastore.databases.delete",
)
_DATA_USER_PERMISSIONS = (
    *_ENTITY_READ_PERMISSIONS,
    *_ENTITY_WRITE_PERMISSIONS,
    *_ENTITY_DELETE_PERMISSIONS,
)
_EDITOR_PERMISSIONS = (*_DATA_USER_PERMISSIONS, *_CONFIGURATION_PERMISSIONS)
_BULK_TRANSFER_PERMISSIONS = (
    "datastore.databases.export",
    "datastore.databases.import",
)
_ADMIN_PERMISSIONS = (
    *_EDITOR_PERMISSIONS,
    *_DESTRUCTIVE_ADMINISTRATION_PERMISSIONS,
    *_BULK_TRANSFER_PERMISSIONS,
)
_DATABASE_ADMIN_PERMISSIONS = (
    "datastore.databases.bulkDelete",
    *_BULK_TRANSFER_PERMISSIONS,
    *_CONFIGURATION_PERMISSIONS,
)
_BUILT_IN_ROLE_PERMISSIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "roles/datastore.viewer": ("viewer", _ENTITY_READ_PERMISSIONS),
    "roles/datastore.user": ("user", _DATA_USER_PERMISSIONS),
    "roles/datastore.editor": ("editor", _EDITOR_PERMISSIONS),
    "roles/datastore.owner": ("owner", _ADMIN_PERMISSIONS),
    "roles/datastore.admin": ("admin", _ADMIN_PERMISSIONS),
    "roles/datastore.bulkAdmin": (
        "bulk_admin",
        ("datastore.databases.bulkDelete",),
    ),
    "roles/datastore.indexAdmin": ("index_admin", _CONFIGURATION_PERMISSIONS[1:]),
    "roles/datastore.importExportAdmin": (
        "import_export_admin",
        _BULK_TRANSFER_PERMISSIONS,
    ),
    "roles/iam.databasesAdmin": ("database_admin", _DATABASE_ADMIN_PERMISSIONS),
    "roles/viewer": ("viewer", _ENTITY_READ_PERMISSIONS),
    "roles/editor": ("editor", _EDITOR_PERMISSIONS),
    "roles/owner": ("owner", _ADMIN_PERMISSIONS),
    "roles/firebase.admin": ("admin", _ADMIN_PERMISSIONS),
    "roles/firebase.editor": ("firebase_editor", _ENTITY_READ_PERMISSIONS),
    "roles/firebase.viewer": ("firebase_viewer", _ENTITY_LIST_PERMISSIONS),
    "roles/firebase.developAdmin": ("admin", _ADMIN_PERMISSIONS),
    "roles/firebase.developViewer": (
        "firebase_develop_viewer",
        _ENTITY_LIST_PERMISSIONS,
    ),
    "roles/firebaserules.system": ("firebase_rules_system", _DATA_USER_PERMISSIONS),
    "roles/iam.dataScientist": ("data_scientist", _ENTITY_LIST_PERMISSIONS),
    "roles/iam.supportUser": ("support_user", _ENTITY_LIST_PERMISSIONS),
    "roles/iam.securityAdmin": ("security_admin", _ENTITY_LIST_PERMISSIONS),
    "roles/iam.securityReviewer": ("security_reviewer", _ENTITY_LIST_PERMISSIONS),
    "roles/iam.securityAuditor": ("security_auditor", _ENTITY_LIST_PERMISSIONS),
}
# Service-agent roles are intentionally outside this workload-role catalog;
# their cross-service permission surfaces are not stable application contracts.
_PERMISSION_ACCESS_CLASSES: dict[str, tuple[str, ...]] = {
    "datastore.entities.get": ("read",),
    "datastore.entities.list": ("read",),
    "datastore.entities.create": ("entity_write",),
    "datastore.entities.update": ("entity_write",),
    "datastore.entities.delete": ("entity_delete",),
    "datastore.databases.export": ("read",),
    "datastore.databases.import": ("entity_write",),
    "datastore.databases.bulkdelete": (
        "entity_delete",
        "destructive_administration",
    ),
    "datastore.databases.delete": ("destructive_administration",),
    "datastore.databases.update": ("configuration_administration",),
    "datastore.schemas.create": ("configuration_administration",),
    "datastore.schemas.delete": ("configuration_administration",),
    "datastore.schemas.update": ("configuration_administration",),
}


@dataclass(frozen=True, slots=True)
class _FirestoreRoleAccess:
    role_kind: str
    access_classes: tuple[str, ...]
    matched_permissions: tuple[str, ...]
    custom_role_permissions: tuple[str, ...] = ()


class ModelCloudRunFirestoreAccessPathsStage:
    """Model IAM-authorized Cloud Run server/API access to Firestore.

    Firestore Security Rules govern mobile and web client access. They are not
    evaluated for this service-account-authenticated server/API path.
    """

    name = "model_cloud_run_firestore_access_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        del context
        custom_roles = build_gcp_custom_role_index(resources)
        databases = tuple(
            resource for resource in resources if resource.resource_type == GcpResourceType.FIRESTORE_DATABASE
        )
        for workload in resources:
            if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
                continue
            paths, uncertainties = _cloud_run_firestore_access_paths(
                workload,
                databases,
                custom_roles,
            )
            facts = gcp_facts(workload)
            facts.set_cloud_run_firestore_access_paths(paths)
            facts.extend_cloud_run_firestore_access_path_uncertainties(uncertainties)


def _cloud_run_firestore_access_paths(
    workload: NormalizedResource,
    databases: tuple[NormalizedResource, ...],
    custom_roles: GcpCustomRoleIndex,
) -> tuple[list[dict[str, Any]], list[str]]:
    workload_facts = gcp_facts(workload)
    service_account_member = workload_facts.service_account_member
    if not service_account_member:
        return [], [f"{workload.address}: Cloud Run service account is unresolved"]

    paths: list[dict[str, Any]] = []
    uncertainties: list[str] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for database in databases:
        database_facts = gcp_facts(database)
        uncertainties.extend(
            f"{workload.address}: Firestore IAM posture is incomplete: {uncertainty}"
            for uncertainty in database_facts.firestore_iam_posture_uncertainties
        )
        for grant in database_facts.firestore_iam_grants:
            if service_account_member not in binding_members(grant):
                continue
            source = _known_string(grant.get("source"))
            role = _known_string(grant.get("role"))
            if role is None:
                uncertainties.append(
                    f"{workload.address}: {source or database.address} Firestore IAM role is unresolved"
                )
                continue

            lifecycle_issue = _custom_role_lifecycle_issue(
                role,
                custom_roles,
            )
            if lifecycle_issue is not None:
                uncertainties.append(
                    f"{workload.address}: {source or database.address} custom IAM role {role} {lifecycle_issue}"
                )
                continue

            role_access = _role_access(role, custom_roles)
            if role_access is None:
                if _looks_like_custom_role(role) and not _custom_role_is_resolved(role, custom_roles):
                    uncertainties.append(
                        f"{workload.address}: {source or database.address} custom IAM role {role} "
                        "does not resolve to deterministic Firestore permissions"
                    )
                continue

            scope_type = _known_string(grant.get("scope_type"))
            database_resource_name = _known_string(grant.get("database_resource_name"))
            if not _grant_is_exact_for_database(
                database,
                scope_type=scope_type,
                database_resource_name=database_resource_name,
            ):
                uncertainties.append(
                    f"{workload.address}: {source or database.address} Firestore IAM grant scope is unresolved"
                )
                continue

            if scope_type == "database" and role in GCP_BASIC_IAM_ROLES:
                uncertainties.append(
                    f"{workload.address}: {source or database.address} basic IAM role {role} "
                    "cannot use conditional database scope"
                )
                continue

            condition = _condition(grant.get("condition"))
            condition_state = _known_string(grant.get("condition_state"))
            if not _grant_condition_is_deterministic(scope_type, condition, condition_state):
                uncertainties.append(
                    f"{workload.address}: {source or database.address} Firestore IAM condition is unresolved"
                )
                continue

            fingerprint = (
                database.address,
                source or "",
                role,
                scope_type or "",
                json.dumps(condition, sort_keys=True, default=str),
            )
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            paths.append(
                _access_path_record(
                    workload,
                    database,
                    service_account_member,
                    source,
                    role,
                    role_access,
                    grant,
                    scope_type,
                    condition,
                    condition_state,
                )
            )

    paths.sort(
        key=lambda path: (
            str(path["firestore_database_address"]),
            str(path["iam_resource_address"]),
            str(path["role"]),
            str(path["scope_type"]),
        )
    )
    return paths, dedupe(uncertainties)


def _custom_role_lifecycle_issue(
    role: str,
    custom_roles: GcpCustomRoleIndex,
) -> str | None:
    if not _looks_like_custom_role(role):
        return None
    resolution = custom_roles.resolve(role)
    if resolution.state == "ambiguous":
        addresses = ", ".join(candidate.address for candidate in resolution.candidates)
        return f"is ambiguous across {addresses} and does not grant Firestore permissions"
    resource = resolution.selected_candidate
    if resource is None:
        return None

    facts = gcp_facts(resource)
    if facts.custom_role_deleted is True:
        return f"is deleted ({resource.address}) and does not grant Firestore permissions"
    if facts.custom_role_deleted is None:
        return f"has unresolved deletion lifecycle ({resource.address})"

    stage = facts.custom_role_stage.upper() if facts.custom_role_stage is not None else None
    if stage is None:
        return f"has unresolved lifecycle stage ({resource.address})"
    if stage == "DISABLED":
        return f"is disabled ({resource.address}) and does not grant Firestore permissions"
    if stage not in _ACTIVE_CUSTOM_ROLE_STAGES:
        return f"has unsupported lifecycle stage {stage} ({resource.address})"
    return None


def _role_access(
    role: str,
    custom_roles: GcpCustomRoleIndex,
) -> _FirestoreRoleAccess | None:
    built_in = _BUILT_IN_ROLE_PERMISSIONS.get(role)
    if built_in is not None:
        role_kind, permissions = built_in
        matched_permissions = tuple(sorted(set(permissions)))
        return _FirestoreRoleAccess(
            role_kind,
            _access_classes(matched_permissions),
            matched_permissions,
        )

    permissions = custom_role_permissions(role, custom_roles)
    if not permissions:
        return None
    matched_permissions = tuple(sorted(permission for permission in permissions if _permission_classes(permission)))
    if not matched_permissions:
        return None
    return _FirestoreRoleAccess(
        "custom",
        _access_classes(matched_permissions),
        matched_permissions,
        custom_role_permissions=permissions,
    )


def _access_classes(permissions: tuple[str, ...]) -> tuple[str, ...]:
    classes = {access_class for permission in permissions for access_class in _permission_classes(permission)}
    return tuple(access_class for access_class in _ACCESS_CLASS_ORDER if access_class in classes)


def _permission_classes(permission: str) -> tuple[str, ...]:
    normalized = permission.strip().lower()
    if normalized in {"*", "datastore.*"}:
        return _ACCESS_CLASS_ORDER
    if normalized == "datastore.entities.*":
        return ("read", "entity_write", "entity_delete")
    if normalized == "datastore.databases.*":
        return (
            "read",
            "entity_write",
            "entity_delete",
            "destructive_administration",
            "configuration_administration",
        )
    if normalized == "datastore.schemas.*":
        return ("configuration_administration",)
    return _PERMISSION_ACCESS_CLASSES.get(normalized, ())


def _custom_role_is_resolved(
    role: str,
    custom_roles: GcpCustomRoleIndex,
) -> bool:
    return bool(custom_role_permissions(role, custom_roles))


def _grant_is_exact_for_database(
    database: NormalizedResource,
    *,
    scope_type: str | None,
    database_resource_name: str | None,
) -> bool:
    if scope_type not in {"database", "project"}:
        return False
    return database_resource_name is not None and database_resource_name == _database_resource_name(database)


def _database_resource_name(database: NormalizedResource) -> str | None:
    identifier = _known_string(database.identifier)
    if identifier and identifier.startswith("projects/") and "/databases/" in identifier:
        return identifier
    facts = gcp_facts(database)
    project = _known_string(facts.project)
    database_name = _known_string(facts.firestore_database_name)
    if project and database_name and "/" not in database_name:
        return f"projects/{project}/databases/{database_name}"
    return None


def _grant_condition_is_deterministic(
    scope_type: str | None,
    condition: dict[str, Any] | None,
    condition_state: str | None,
) -> bool:
    if scope_type == "database":
        return condition_state == "configured" and condition is not None
    return scope_type == "project" and condition_state == "not_configured" and condition is None


def _access_path_record(
    workload: NormalizedResource,
    database: NormalizedResource,
    service_account_member: str,
    iam_resource_address: str | None,
    role: str,
    role_access: _FirestoreRoleAccess,
    grant: Mapping[str, Any],
    scope_type: str | None,
    condition: dict[str, Any] | None,
    condition_state: str | None,
) -> dict[str, Any]:
    workload_facts = gcp_facts(workload)
    database_facts = gcp_facts(database)
    database_resource_name = _database_resource_name(database)
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "service_account_email": workload_facts.service_account_email,
        "service_account_member": service_account_member,
        "identity_kind": "cloud_run_service_account",
        "credential_context": "workload_runtime",
        "firestore_database_address": database.address,
        "firestore_database_resource_type": database.resource_type,
        "firestore_database_resource_name": database_resource_name,
        "firestore_database_name": database_facts.firestore_database_name,
        "firestore_database_project": database_facts.project,
        "firestore_database_type": database_facts.firestore_database_type,
        "iam_resource_address": iam_resource_address,
        "iam_resource_type": grant.get("source_type"),
        "role": role,
        "role_kind": role_access.role_kind,
        "access_classes": list(role_access.access_classes),
        "custom_role_permissions": list(role_access.custom_role_permissions),
        "matched_permissions": list(role_access.matched_permissions),
        "grant_basis": grant.get("grant_basis"),
        "scope_type": scope_type,
        "scope": grant.get("scope"),
        "resource_scope": "exact_firestore_database" if scope_type == "database" else "firestore_project",
        "condition": condition,
        "condition_state": condition_state,
        "condition_evaluation": ("exact_database_scope_match" if scope_type == "database" else "not_configured"),
        "access_state": "granted",
        "authorization_model": "iam_authorized_server_api",
        "firestore_security_rules_evaluated": False,
        "firestore_security_rules_applicability": "not_in_server_api_authorization_path",
    }


def _condition(value: object) -> dict[str, Any] | None:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    return None


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _looks_like_custom_role(role: str) -> bool:
    return role.startswith(("projects/", "organizations/")) or "iam_custom_role." in role
