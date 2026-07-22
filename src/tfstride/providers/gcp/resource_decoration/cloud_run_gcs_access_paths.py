from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import GCP_CLOUD_RUN_RESOURCE_TYPES, GcpResourceType
from tfstride.providers.gcp.resource_utils import (
    GCP_ROLE_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
)

if TYPE_CHECKING:
    from tfstride.providers.gcp.custom_roles import GcpCustomRoleIndex

_ACCESS_CLASS_ORDER = ("read", "write", "delete", "administrative")
_BUILT_IN_ROLE_ACCESS: dict[str, tuple[str, tuple[str, ...]]] = {
    "roles/storage.objectViewer": ("viewer", ("read",)),
    "roles/storage.objectCreator": ("creator", ("write",)),
    "roles/storage.objectUser": ("user", ("read", "write", "delete")),
    "roles/storage.objectAdmin": ("admin", ("read", "write", "delete")),
    "roles/storage.admin": ("admin", _ACCESS_CLASS_ORDER),
    "roles/editor": ("admin", _ACCESS_CLASS_ORDER),
    "roles/owner": ("admin", _ACCESS_CLASS_ORDER),
}
_READ_PERMISSIONS = frozenset(
    {
        "storage.objects.get",
        "storage.objects.getIamPolicy",
        "storage.objects.list",
    }
)
_WRITE_PERMISSIONS = frozenset(
    {
        "storage.objects.compose",
        "storage.objects.create",
        "storage.objects.move",
        "storage.objects.restore",
        "storage.objects.rewrite",
        "storage.objects.update",
    }
)
_DELETE_PERMISSIONS = frozenset({"storage.objects.delete"})
_ADMIN_PERMISSIONS = frozenset({"storage.objects.setIamPolicy"})


@dataclass(frozen=True, slots=True)
class _GcsRoleAccess:
    role_kind: str
    access_classes: tuple[str, ...]
    custom_role_permissions: tuple[str, ...] = ()
    matched_permissions: tuple[str, ...] = ()


class ModelCloudRunGcsAccessPathsStage:
    name = "model_cloud_run_gcs_access_paths"

    def apply(self, resources: list[NormalizedResource], context: GcpDecorationContext) -> None:
        # Delay this provider-local import to keep normalizer/plugin initialization acyclic.
        from tfstride.providers.gcp.custom_roles import build_gcp_custom_role_index

        del context
        custom_roles = build_gcp_custom_role_index(resources)
        buckets = tuple(resource for resource in resources if resource.resource_type == GcpResourceType.STORAGE_BUCKET)
        for workload in resources:
            if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
                continue
            paths, uncertainties = _cloud_run_gcs_access_paths(workload, buckets, custom_roles)
            facts = gcp_facts(workload)
            facts.set_cloud_run_gcs_access_paths(paths)
            facts.extend_cloud_run_gcs_access_path_uncertainties(uncertainties)


def _cloud_run_gcs_access_paths(
    workload: NormalizedResource,
    buckets: tuple[NormalizedResource, ...],
    custom_roles: GcpCustomRoleIndex,
) -> tuple[list[dict[str, Any]], list[str]]:
    workload_facts = gcp_facts(workload)
    service_account_member = workload_facts.service_account_member
    if not service_account_member:
        return [], [f"{workload.address}: Cloud Run service account is unresolved"]

    paths: list[dict[str, Any]] = []
    uncertainties: list[str] = []
    seen: set[tuple[str, str, str, str]] = set()
    for bucket in buckets:
        for binding in gcp_facts(bucket).bindings:
            if service_account_member not in binding_members(binding):
                continue
            role = _known_string(binding.get("role"))
            source = _known_string(binding.get("source"))
            if role is None or role == "unknown role":
                uncertainties.append(f"{workload.address}: {source or bucket.address} IAM role is unresolved")
                continue
            role_access = _role_access(role, custom_roles)
            if role_access is None:
                if _looks_like_custom_role(role):
                    uncertainties.append(
                        f"{workload.address}: {source or bucket.address} custom IAM role {role} "
                        "does not resolve to deterministic permissions"
                    )
                continue

            condition = _condition(binding.get("condition"))
            fingerprint = (
                bucket.address,
                source or "",
                role,
                json.dumps(condition, sort_keys=True, default=str),
            )
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            paths.append(
                _access_path_record(
                    workload,
                    bucket,
                    service_account_member,
                    source,
                    role,
                    role_access,
                    condition,
                )
            )

    return paths, dedupe(uncertainties)


def _role_access(role: str, custom_roles: GcpCustomRoleIndex) -> _GcsRoleAccess | None:
    built_in = _BUILT_IN_ROLE_ACCESS.get(role)
    if built_in is not None:
        role_kind, access_classes = built_in
        return _GcsRoleAccess(role_kind, access_classes)

    permissions = custom_roles.permissions_by_reference.get(
        gcp_reference_key(role, GCP_ROLE_REFERENCE_SUFFIXES),
        (),
    )
    matched_permissions = tuple(sorted(permission for permission in permissions if _is_gcs_data_permission(permission)))
    if not matched_permissions:
        return None
    return _GcsRoleAccess(
        "custom",
        _custom_access_classes(matched_permissions),
        custom_role_permissions=permissions,
        matched_permissions=matched_permissions,
    )


def _is_gcs_data_permission(permission: str) -> bool:
    return permission in {"*", "storage.*", "storage.objects.*"} or permission.startswith("storage.objects.")


def _custom_access_classes(permissions: tuple[str, ...]) -> tuple[str, ...]:
    wildcard = any(permission in {"*", "storage.*", "storage.objects.*"} for permission in permissions)
    if wildcard:
        return _ACCESS_CLASS_ORDER

    classes: set[str] = set()
    for permission in permissions:
        if permission in _READ_PERMISSIONS:
            classes.add("read")
        if permission in _WRITE_PERMISSIONS:
            classes.add("write")
        if permission in _DELETE_PERMISSIONS:
            classes.add("delete")
        if permission in _ADMIN_PERMISSIONS:
            classes.add("administrative")
    return tuple(access_class for access_class in _ACCESS_CLASS_ORDER if access_class in classes)


def _access_path_record(
    workload: NormalizedResource,
    bucket: NormalizedResource,
    service_account_member: str,
    iam_resource_address: str | None,
    role: str,
    role_access: _GcsRoleAccess,
    condition: dict[str, Any] | None,
) -> dict[str, Any]:
    workload_facts = gcp_facts(workload)
    bucket_facts = gcp_facts(bucket)
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "service_account_email": workload_facts.service_account_email,
        "service_account_member": service_account_member,
        "identity_kind": "cloud_run_service_account",
        "credential_context": "workload_runtime",
        "bucket_address": bucket.address,
        "bucket_name": bucket_facts.bucket_name or bucket.name,
        "bucket_project": bucket_facts.project,
        "iam_resource_address": iam_resource_address,
        "role": role,
        "role_kind": role_access.role_kind,
        "access_classes": list(role_access.access_classes),
        "custom_role_permissions": list(role_access.custom_role_permissions),
        "matched_permissions": list(role_access.matched_permissions),
        "grant_basis": "storage_bucket_iam",
        "resource_scope": "exact_bucket",
        "condition": condition,
        "condition_state": "configured" if condition else "not_configured",
        "access_state": "conditional" if condition else "granted",
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
