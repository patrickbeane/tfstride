"""Evaluate existing bucket IAM grants for a principal and exact modeled targets.

This preserves the bucket-binding evaluator's access classifications. It does
not expand ancestor grants, evaluate IAM denies, or prove network reachability.
Workload identity selection and path/report projection belong to the caller.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, TypedDict

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.protected_data_evidence import GcpGcsAccessClass, GcpGcsAccessState
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.providers.gcp.resource_utils import GCP_ROLE_REFERENCE_SUFFIXES, binding_members, gcp_reference_key

if TYPE_CHECKING:
    from tfstride.providers.gcp.custom_roles import GcpCustomRoleIndex


class GcpGcsBucketGrant(TypedDict):
    principal: str
    bucket_address: str
    bucket_name: str
    bucket_project: str | None
    iam_resource_address: str | None
    role: str
    role_kind: str
    access_classes: list[GcpGcsAccessClass]
    custom_role_permissions: list[str]
    matched_permissions: list[str]
    grant_basis: Literal["storage_bucket_iam"]
    resource_scope: Literal["exact_bucket"]
    condition: dict[str, object] | None
    condition_state: Literal["configured", "not_configured"]
    access_state: GcpGcsAccessState


_ACCESS_CLASS_ORDER: tuple[GcpGcsAccessClass, ...] = (
    "read",
    "write",
    "delete",
    "administrative",
)
_BUILT_IN_ROLE_ACCESS: dict[str, tuple[str, tuple[GcpGcsAccessClass, ...]]] = {
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
    access_classes: tuple[GcpGcsAccessClass, ...]
    custom_role_permissions: tuple[str, ...] = ()
    matched_permissions: tuple[str, ...] = ()


def evaluate_gcs_bucket_grants(
    principal: str,
    buckets: Sequence[NormalizedResource],
    custom_roles: GcpCustomRoleIndex,
) -> tuple[list[GcpGcsBucketGrant], list[str]]:
    """Return matching grant evidence and uncertainty without workload-specific prose.

    Only bindings already resolved onto the supplied buckets are considered.
    Conditions remain separate alternatives; operation classes and permissions
    retain the existing evaluator's meaning rather than implying broader access.
    """
    grants: list[GcpGcsBucketGrant] = []
    uncertainties: list[str] = []
    seen: set[tuple[str, str, str, str]] = set()
    for bucket in buckets:
        if bucket.resource_type != GcpResourceType.STORAGE_BUCKET:
            continue
        for binding in gcp_facts(bucket).bindings:
            if principal not in binding_members(binding):
                continue
            role = _known_string(binding.get("role"))
            source = _known_string(binding.get("source"))
            if role is None or role == "unknown role":
                uncertainties.append(f"{source or bucket.address} IAM role is unresolved")
                continue
            role_access = _role_access(role, custom_roles)
            if role_access is None:
                if _looks_like_custom_role(role):
                    uncertainties.append(
                        f"{source or bucket.address} custom IAM role {role} "
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
            grants.append(
                _grant_record(
                    principal,
                    bucket,
                    source,
                    role,
                    role_access,
                    condition,
                )
            )

    return grants, dedupe(uncertainties)


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


def _custom_access_classes(permissions: tuple[str, ...]) -> tuple[GcpGcsAccessClass, ...]:
    wildcard = any(permission in {"*", "storage.*", "storage.objects.*"} for permission in permissions)
    if wildcard:
        return _ACCESS_CLASS_ORDER

    classes: set[GcpGcsAccessClass] = set()
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


def _grant_record(
    principal: str,
    bucket: NormalizedResource,
    iam_resource_address: str | None,
    role: str,
    role_access: _GcsRoleAccess,
    condition: dict[str, object] | None,
) -> GcpGcsBucketGrant:
    bucket_facts = gcp_facts(bucket)
    return {
        "principal": principal,
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


def _condition(value: object) -> dict[str, object] | None:
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
