"""Evaluate scoped IAM grants and modeled constraints for exact GCS buckets.

Workload identity selection and path/report projection belong to the caller.
An authority result does not establish network reachability or operation success.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Literal, NotRequired, TypedDict, cast

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.custom_role_index import GcpCustomRoleIndex, build_gcp_custom_role_index
from tfstride.providers.gcp.gcs_custom_role_evaluation import assess_inherited_gcs_custom_role
from tfstride.providers.gcp.gcs_grant_constraints import GcsPermissionConstraint, gcs_permission_constraints
from tfstride.providers.gcp.gcs_project_grants import (
    ancestor_grant_candidates,
    bucket_grant_candidates,
    project_grant_candidates,
    project_reference_index,
)
from tfstride.providers.gcp.protected_data_evidence import (
    GcpGcsAccessClass,
    GcpGcsAccessState,
    GcsInheritedCustomRoleEvidence,
)
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpResourceIndex, GcpResourceIndexBuilder
from tfstride.providers.gcp.resource_types import (
    GCP_FOLDER_IAM_RESOURCE_TYPES,
    GCP_ORG_FOLDER_IAM_RESOURCE_TYPES,
    GCP_ORGANIZATION_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import GCP_ROLE_REFERENCE_SUFFIXES, binding_members, gcp_reference_key
from tfstride.providers.resource_reference_index import ResourceReferenceIndex

GCS_ACCESS_IAM_TYPES_BY_BASIS = {
    "storage_bucket_iam": GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES,
    "storage_project_iam": GCP_PROJECT_IAM_RESOURCE_TYPES,
    "storage_folder_iam": GCP_FOLDER_IAM_RESOURCE_TYPES,
    "storage_organization_iam": GCP_ORGANIZATION_IAM_RESOURCE_TYPES,
}


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
    grant_basis: Literal["storage_bucket_iam", "storage_project_iam", "storage_folder_iam", "storage_organization_iam"]
    resource_scope: Literal["exact_bucket"]
    condition: dict[str, object] | None
    condition_state: Literal["configured", "not_configured"]
    access_state: GcpGcsAccessState
    custom_role_evidence: NotRequired[GcsInheritedCustomRoleEvidence]
    grant_project: NotRequired[str]
    grant_scope: NotRequired[str]
    grant_ancestry: NotRequired[list[str]]
    permission_constraints: NotRequired[list[GcsPermissionConstraint]]


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
MODELED_GCS_OBJECT_PERMISSIONS = _READ_PERMISSIONS | _WRITE_PERMISSIONS | _DELETE_PERMISSIONS | _ADMIN_PERMISSIONS


@dataclass(frozen=True, slots=True)
class _GcsRoleAccess:
    role_kind: str
    access_classes: tuple[GcpGcsAccessClass, ...]
    custom_role_permissions: tuple[str, ...] = ()
    matched_permissions: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class GcsGrantConstraintContext:
    """Indexes scoped to one evaluation; callers rebuild after input mutations."""

    resources: tuple[NormalizedResource, ...]
    index: GcpResourceIndex
    projects: ResourceReferenceIndex
    custom_roles: GcpCustomRoleIndex
    deny_policies: tuple[NormalizedResource, ...]

    @classmethod
    def build(cls, resources: Sequence[NormalizedResource]) -> GcsGrantConstraintContext:
        return cls(
            tuple(resources),
            GcpResourceIndexBuilder().build(list(resources)),
            project_reference_index(resources),
            build_gcp_custom_role_index(resources),
            tuple(
                sorted(
                    (item for item in resources if item.resource_type == GcpResourceType.IAM_DENY_POLICY),
                    key=lambda item: item.address,
                )
            ),
        )

    def bindings(self, principal: str, bucket: NormalizedResource) -> tuple[list[dict[str, object]], list[str]]:
        local, local_problems = bucket_grant_candidates(principal, bucket, self.resources, self.index)
        inherited, problems = project_grant_candidates(
            principal, bucket, self.resources, self.projects, self.custom_roles
        )
        ancestors, ancestor_problems = ancestor_grant_candidates(
            principal, bucket, self.resources, self.index, self.custom_roles
        )
        return [*local, *inherited, *ancestors], [*local_problems, *problems, *ancestor_problems]


def evaluate_gcs_operation_constraints(
    principal: str,
    bucket: NormalizedResource,
    source_address: str,
    role: str,
    permission: str,
    context: GcsGrantConstraintContext,
) -> tuple[bool, list[str]]:
    """Require a current scoped grant and compatible denies for a proven role operation.

    The caller must independently establish that this role grants this exact
    permission, including custom-role lifecycle. This query can only constrain
    that proof; an IAM binding by itself never proves a role's permissions.
    """
    bindings, problems = context.bindings(principal, bucket)
    if not any(
        binding.get("source") == source_address
        and binding.get("role") == role
        and binding.get("condition") in (None, {}, [])
        and binding.get("condition_state") in (None, "not_configured")
        for binding in bindings
    ):
        return False, [
            *problems,
            f"{source_address} for {bucket.address}: unconditional scoped grant for {permission} is not established",
        ]
    source = context.index.resources_by_reference.resolve(source_address).selected_candidate
    if (
        source is not None
        and source.resource_type in (GCP_PROJECT_IAM_RESOURCE_TYPES | GCP_ORG_FOLDER_IAM_RESOURCE_TYPES)
        and _looks_like_custom_role(role)
    ):
        assessment = assess_inherited_gcs_custom_role(
            role, source, bucket, context.custom_roles, context.index, context.projects
        )
        if assessment.state != "compatible":
            return False, [f"{source_address} for {bucket.address}: {assessment.reason}"]
        if permission not in assessment.permissions:
            return False, [f"{source_address} for {bucket.address}: custom role does not grant {permission}"]
    decisions = gcs_permission_constraints(
        principal, permission, bucket, context.deny_policies, context.projects, context.index
    )
    if any(decision["state"] == "denied" for decision in decisions):
        return False, []
    return not decisions, [
        f"{decision['policy_address']} for {bucket.address}: {permission}: {decision['reason']}"
        for decision in decisions
    ]


def evaluate_gcs_bucket_grants(
    principal: str,
    buckets: Sequence[NormalizedResource],
    custom_roles: GcpCustomRoleIndex,
    *,
    resources: Sequence[NormalizedResource] = (),
) -> tuple[list[GcpGcsBucketGrant], list[str]]:
    """Return matching grant evidence and uncertainty without workload-specific prose.

    Full inventory inputs supply ancestor grants and deny constraints. Conditions
    remain separate alternatives. Inherited custom roles require grantability and lifecycle proof; basic roles stay unresolved.
    """
    grants: list[GcpGcsBucketGrant] = []
    uncertainties: list[str] = []
    context = GcsGrantConstraintContext.build(resources)
    seen: set[tuple[str, str, str, str]] = set()
    for bucket in buckets:
        if bucket.resource_type != GcpResourceType.STORAGE_BUCKET:
            continue
        bindings, problems = context.bindings(principal, bucket) if resources else (gcp_facts(bucket).bindings, [])
        uncertainties.extend(problems)
        for binding in bindings:
            if principal not in binding_members(binding):
                continue
            role = _known_string(binding.get("role"))
            source = _known_string(binding.get("source"))
            if any(binding.get(f"{field}_state") == "unknown" for field in ("role", "members", "condition")):
                uncertainties.append(f"{source or bucket.address}: IAM grant for {bucket.address} is unresolved")
                continue
            if role is None or role == "unknown role":
                uncertainties.append(f"{source or bucket.address} IAM role is unresolved")
                continue
            project = _known_string(binding.get("grant_project"))
            ancestor_kind = binding.get("grant_scope_kind")
            custom_evidence: GcsInheritedCustomRoleEvidence | None = None
            if (project or ancestor_kind) and role not in _BUILT_IN_ROLE_ACCESS:
                source_resource = context.index.resources_by_reference.resolve(source).selected_candidate
                if source_resource is None:
                    uncertainties.append(f"{source}: custom role grant source is unresolved")
                    continue
                assessment = assess_inherited_gcs_custom_role(
                    role, source_resource, bucket, context.custom_roles, context.index, context.projects
                )
                if assessment.state != "compatible":
                    uncertainties.append(f"{source} for {bucket.address}: {assessment.reason}")
                    continue
                matched = tuple(
                    permission for permission in assessment.permissions if _is_gcs_data_permission(permission)
                )
                role_access = _GcsRoleAccess("custom", _custom_access_classes(matched), assessment.permissions, matched)
                if not role_access.access_classes:
                    continue
                custom_evidence = assessment.evidence
            elif (project or ancestor_kind) and role in {"roles/editor", "roles/owner"}:
                uncertainties.append(
                    f"{source}: inherited basic role {role} is not representable by predefined GCS semantics"
                )
                continue
            else:
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
            constraints: list[GcsPermissionConstraint] = []
            if context.deny_policies:
                # Keep decisions at permission granularity. Denying delete must not
                # erase independent create authority (nor vice versa).
                permissions = _modeled_permissions(role, role_access)
                surviving: list[str] = []
                for permission in permissions:
                    decisions = gcs_permission_constraints(
                        principal, permission, bucket, context.deny_policies, context.projects, context.index
                    )
                    constraints.extend(decisions)
                    if not decisions:
                        surviving.append(permission)
                    elif not any(decision["state"] == "denied" for decision in decisions):
                        uncertainties.extend(
                            f"{decision['policy_address']} for {bucket.address}: {permission}: {decision['reason']}"
                            for decision in decisions
                        )
                if constraints:
                    classes = _custom_access_classes(tuple(surviving))
                    role_access = replace(
                        role_access,
                        access_classes=tuple(value for value in role_access.access_classes if value in classes),
                        matched_permissions=tuple(surviving),
                    )
                    if not role_access.access_classes:
                        continue
            grant = _grant_record(
                principal,
                bucket,
                source,
                role,
                role_access,
                condition,
            )
            if custom_evidence is not None:
                grant["custom_role_evidence"] = custom_evidence
            if project:
                grant["grant_basis"] = "storage_project_iam"
                grant["grant_project"] = project
                if not grant["matched_permissions"]:
                    grant["matched_permissions"] = list(_modeled_permissions(role, role_access))
            if ancestor_kind:
                grant["grant_basis"] = (
                    "storage_folder_iam" if ancestor_kind == "folders" else "storage_organization_iam"
                )
                grant["grant_scope"] = str(binding["grant_scope"])
                grant["grant_ancestry"] = list(cast(list[str], binding["grant_ancestry"]))
                if not grant["matched_permissions"]:
                    grant["matched_permissions"] = list(_modeled_permissions(role, role_access))
            if constraints:
                grant["permission_constraints"] = constraints
            grants.append(grant)

    return grants, dedupe(uncertainties)


def _modeled_permissions(role: str, access: _GcsRoleAccess) -> tuple[str, ...]:
    if access.role_kind == "custom":
        if any(value in {"*", "storage.*", "storage.objects.*"} for value in access.matched_permissions):
            return tuple(sorted(_READ_PERMISSIONS | _WRITE_PERMISSIONS | _DELETE_PERMISSIONS | _ADMIN_PERMISSIONS))
        return access.matched_permissions
    permissions: list[str] = []
    for access_class in access.access_classes:
        if access_class == "read":
            permissions.extend(("storage.objects.get", "storage.objects.list"))
        elif access_class == "write":
            permissions.append("storage.objects.create")
            if role != "roles/storage.objectCreator":
                permissions.append("storage.objects.update")
        elif access_class == "delete":
            permissions.append("storage.objects.delete")
        elif access_class == "administrative":
            permissions.append("storage.objects.setIamPolicy")
    return tuple(sorted(permissions))


def gcs_path_permissions(path: Mapping[str, object]) -> tuple[str, ...]:
    """Read evaluated operation scope without widening role evidence.

    Scope remains available for conditional alternatives. Consumers must also
    establish that the grant is current and unconditional before claiming access.
    """
    matched = path.get("matched_permissions")
    if isinstance(matched, list) and matched:
        permissions = tuple(value for value in matched if isinstance(value, str))
        if any(value in {"*", "storage.*", "storage.objects.*"} for value in permissions):
            return tuple(sorted(_READ_PERMISSIONS | _WRITE_PERMISSIONS | _DELETE_PERMISSIONS | _ADMIN_PERMISSIONS))
        return permissions
    role = path.get("role")
    access = _BUILT_IN_ROLE_ACCESS.get(role) if isinstance(role, str) else None
    if access is None or not isinstance(role, str):
        return ()
    return _modeled_permissions(role, _GcsRoleAccess(*access))


def modeled_gcs_role_permissions(role: str, custom_roles: GcpCustomRoleIndex) -> tuple[str, ...]:
    """Return current modeled GCS operations for one resolved IAM role."""
    access = _role_access(role, custom_roles)
    return _modeled_permissions(role, access) if access is not None else ()


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
