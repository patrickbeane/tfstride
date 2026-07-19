from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.iam_access import GCP_SECRET_ACCESS_ROLES
from tfstride.providers.gcp.iam_inheritance import (
    GCP_IAM_SCOPE_FOLDER,
    GCP_IAM_SCOPE_ORGANIZATION,
    GcpIamInheritanceIndex,
    build_gcp_iam_inheritance_index,
)
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_FOLDER_IAM_RESOURCE_TYPES,
    GCP_ORGANIZATION_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import (
    GCP_ROLE_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
)

if TYPE_CHECKING:
    from tfstride.providers.gcp.custom_roles import GcpCustomRoleIndex

_SECRET_ACCESS_PERMISSION = "secretmanager.versions.access"
_SECRET_RESOURCE_PREFIX = "//secretmanager.googleapis.com/"
_SERVICE_ACCOUNT_DOMAIN = ".gserviceaccount.com"


@dataclass(frozen=True, slots=True)
class _SecretTarget:
    resource_name: str
    project: str
    resource: NormalizedResource | None
    resolution_basis: str


@dataclass(frozen=True, slots=True)
class _GrantScope:
    scope_type: str
    identifier: str
    basis: str


class ModelCloudRunSecretAccessPathsStage:
    name = "model_cloud_run_secret_access_paths"

    def apply(self, resources: list[NormalizedResource], context: GcpDecorationContext) -> None:
        # Delay this provider-local import to keep normalizer/plugin initialization acyclic.
        from tfstride.providers.gcp.custom_roles import build_gcp_custom_role_index

        inheritance = build_gcp_iam_inheritance_index(resources)
        custom_roles = build_gcp_custom_role_index(resources)
        for workload in resources:
            if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
                continue
            paths, uncertainties = _cloud_run_secret_access_paths(
                workload,
                resources,
                context,
                inheritance,
                custom_roles,
            )
            facts = gcp_facts(workload)
            facts.set_cloud_run_secret_access_paths(paths)
            facts.extend_cloud_run_secret_access_path_uncertainties(uncertainties)


def _cloud_run_secret_access_paths(
    workload: NormalizedResource,
    resources: list[NormalizedResource],
    context: GcpDecorationContext,
    inheritance: GcpIamInheritanceIndex,
    custom_roles: GcpCustomRoleIndex,
) -> tuple[list[dict[str, Any]], list[str]]:
    facts = gcp_facts(workload)
    uncertainties: list[str] = []
    service_account_email = facts.service_account_email
    service_account_member = facts.service_account_member
    if not _is_exact_service_account_identity(service_account_email, service_account_member):
        if facts.cloud_run_secret_references:
            uncertainties.append(f"{workload.address}: Cloud Run service account identity is unresolved")
        return [], uncertainties

    targets: list[tuple[Mapping[str, Any], _SecretTarget]] = []
    for reference in facts.cloud_run_secret_references:
        if reference.get("state") != "reference":
            continue
        target = _resolve_secret_target(reference, facts.project, context)
        if target is None:
            uncertainties.append(
                f"{workload.address}: Secret Manager reference at "
                f"{reference.get('secret_reference_path') or reference.get('path') or 'unknown path'} "
                "does not resolve to an exact secret"
            )
            continue
        targets.append((reference, target))

    if not targets:
        return [], dedupe(uncertainties)

    iam_resources = [
        resource
        for resource in resources
        if resource.resource_type
        in (
            GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES
            | GCP_PROJECT_IAM_RESOURCE_TYPES
            | GCP_FOLDER_IAM_RESOURCE_TYPES
            | GCP_ORGANIZATION_IAM_RESOURCE_TYPES
        )
    ]
    paths: list[dict[str, Any]] = []
    seen_paths: set[tuple[str, str, str, str]] = set()
    for reference, target in targets:
        for iam_resource in iam_resources:
            scope, scope_uncertainty = _grant_scope(iam_resource, target, context, inheritance)
            for binding in iam_bindings(iam_resource):
                role = _known_string(binding.get("role"))
                members = binding_members(binding)
                role_kind, permissions = _secret_access_role(role, custom_roles)
                if service_account_member not in members:
                    if role_kind and any(_looks_unresolved_identity(member) for member in members):
                        uncertainties.append(
                            f"{workload.address}: {iam_resource.address} has an unresolved IAM member "
                            f"for {role or 'unknown role'}"
                        )
                    continue
                if role is None:
                    uncertainties.append(f"{workload.address}: {iam_resource.address} IAM role is unresolved")
                    continue
                if role_kind is None:
                    if _looks_like_terraform_reference(role):
                        uncertainties.append(
                            f"{workload.address}: {iam_resource.address} IAM role {role} is unresolved"
                        )
                    continue
                if scope is None:
                    if scope_uncertainty:
                        uncertainties.append(f"{workload.address}: {iam_resource.address}: {scope_uncertainty}")
                    continue

                condition = _condition(binding.get("condition"))
                fingerprint = (
                    target.resource_name,
                    iam_resource.address,
                    role,
                    json.dumps(condition, sort_keys=True, default=str),
                )
                if fingerprint in seen_paths:
                    continue
                seen_paths.add(fingerprint)
                paths.append(
                    _access_path_record(
                        workload,
                        reference,
                        target,
                        service_account_email,
                        service_account_member,
                        iam_resource,
                        role,
                        role_kind,
                        permissions,
                        scope,
                        condition,
                    )
                )

    return paths, dedupe(uncertainties)


def _resolve_secret_target(
    reference: Mapping[str, Any],
    workload_project: str | None,
    context: GcpDecorationContext,
) -> _SecretTarget | None:
    raw_reference = _known_string(reference.get("secret_reference"))
    if raw_reference is None:
        return None

    terraform_reference = _terraform_reference(raw_reference)
    if terraform_reference is not None:
        resource = context.index.resources_by_reference.get(gcp_reference_key(terraform_reference))
        return _target_from_resource(resource, "terraform_reference")

    canonical_name = _canonical_secret_name(raw_reference, workload_project)
    if canonical_name is None:
        return None
    project = _secret_project(canonical_name)
    if project is None:
        return None
    resource = context.index.resources_by_reference.get(gcp_reference_key(canonical_name))
    if resource is not None and resource.resource_type != GcpResourceType.SECRET_MANAGER_SECRET:
        resource = None
    return _SecretTarget(
        resource_name=canonical_name,
        project=project,
        resource=resource,
        resolution_basis="canonical_resource_name",
    )


def _target_from_resource(resource: NormalizedResource | None, basis: str) -> _SecretTarget | None:
    if resource is None or resource.resource_type != GcpResourceType.SECRET_MANAGER_SECRET:
        return None
    facts = gcp_facts(resource)
    canonical_name = _canonical_secret_name(
        facts.resource_name or facts.secret_id,
        facts.project,
    )
    project = _secret_project(canonical_name) if canonical_name else None
    if canonical_name is None or project is None:
        return None
    return _SecretTarget(
        resource_name=canonical_name,
        project=project,
        resource=resource,
        resolution_basis=basis,
    )


def _grant_scope(
    iam_resource: NormalizedResource,
    target: _SecretTarget,
    context: GcpDecorationContext,
    inheritance: GcpIamInheritanceIndex,
) -> tuple[_GrantScope | None, str | None]:
    facts = gcp_facts(iam_resource)
    if iam_resource.resource_type in GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES:
        target_reference = facts.target_reference
        if not target_reference:
            return None, "secret IAM target is unresolved"
        target_resource = _resource_from_reference(target_reference, context)
        if target_resource is not None:
            if target.resource is not None and target_resource.address == target.resource.address:
                return _GrantScope("secret", target.resource_name, "secret_resource_iam"), None
            return None, None
        canonical_name = _canonical_secret_name(target_reference, facts.project)
        if canonical_name is None:
            return None, "secret IAM target is not an exact resource name or in-plan reference"
        if canonical_name == target.resource_name:
            return _GrantScope("secret", canonical_name, "secret_resource_iam"), None
        return None, None

    if iam_resource.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES:
        project = _normalize_project(facts.project)
        if project is None:
            return None, "project IAM scope is unresolved"
        if project == target.project:
            return _GrantScope("project", project, "project_iam"), None
        return None, None

    if iam_resource.resource_type in GCP_FOLDER_IAM_RESOURCE_TYPES:
        return _inherited_scope(iam_resource, target, inheritance, GCP_IAM_SCOPE_FOLDER)
    if iam_resource.resource_type in GCP_ORGANIZATION_IAM_RESOURCE_TYPES:
        return _inherited_scope(iam_resource, target, inheritance, GCP_IAM_SCOPE_ORGANIZATION)
    return None, None


def _inherited_scope(
    iam_resource: NormalizedResource,
    target: _SecretTarget,
    inheritance: GcpIamInheritanceIndex,
    expected_scope_type: str,
) -> tuple[_GrantScope | None, str | None]:
    if target.resource is None:
        return None, f"{expected_scope_type} IAM scope cannot be related without the target secret in the plan"
    for scope in inheritance.scopes_for_iam_resource(iam_resource):
        if scope.scope_type != expected_scope_type:
            continue
        descendants = inheritance.descendant_resources_for_scope(scope)
        if any(resource.address == target.resource.address for resource in descendants):
            return _GrantScope(scope.scope_type, scope.identifier, f"{scope.scope_type}_iam"), None
    if not inheritance.scopes_for_iam_resource(iam_resource):
        return None, f"{expected_scope_type} IAM scope is unresolved"
    return None, None


def _resource_from_reference(
    reference: str,
    context: GcpDecorationContext,
) -> NormalizedResource | None:
    terraform_reference = _terraform_reference(reference)
    key = terraform_reference or reference
    resource = context.index.resources_by_reference.get(gcp_reference_key(key))
    if resource is None or resource.resource_type != GcpResourceType.SECRET_MANAGER_SECRET:
        return None
    return resource


def _secret_access_role(
    role: str | None,
    custom_roles: GcpCustomRoleIndex,
) -> tuple[str | None, tuple[str, ...]]:
    if role is None:
        return None, ()
    if role in GCP_SECRET_ACCESS_ROLES:
        return "built_in", ()
    permissions = custom_roles.permissions_by_reference.get(
        gcp_reference_key(role, GCP_ROLE_REFERENCE_SUFFIXES),
        (),
    )
    if any(fnmatchcase(_SECRET_ACCESS_PERMISSION, permission) for permission in permissions):
        return "custom", permissions
    return None, permissions


def _access_path_record(
    workload: NormalizedResource,
    reference: Mapping[str, Any],
    target: _SecretTarget,
    service_account_email: str,
    service_account_member: str,
    iam_resource: NormalizedResource,
    role: str,
    role_kind: str,
    permissions: tuple[str, ...],
    scope: _GrantScope,
    condition: dict[str, Any],
) -> dict[str, Any]:
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "secret_reference": reference.get("secret_reference"),
        "secret_reference_path": reference.get("secret_reference_path") or reference.get("path"),
        "secret_resource_name": target.resource_name,
        "secret_resource_address": target.resource.address if target.resource else None,
        "secret_target_resolution": "resolved_in_plan" if target.resource else "canonical_name",
        "secret_resolution_basis": target.resolution_basis,
        "secret_version": reference.get("secret_version"),
        "secret_version_state": reference.get("secret_version_state"),
        "version_path": reference.get("version_path"),
        "container_name": reference.get("container_name"),
        "setting_name": reference.get("setting_name"),
        "service_account_email": service_account_email,
        "service_account_member": service_account_member,
        "identity_kind": "cloud_run_service_account",
        "credential_context": "workload_runtime",
        "iam_resource_address": iam_resource.address,
        "iam_resource_type": iam_resource.resource_type,
        "role": role,
        "role_kind": role_kind,
        "custom_role_permissions": list(permissions),
        "grant_scope_type": scope.scope_type,
        "grant_scope": scope.identifier,
        "grant_basis": scope.basis,
        "condition": condition,
        "condition_state": "configured" if condition else "not_configured",
        "access_state": "conditional" if condition else "granted",
    }


def _canonical_secret_name(value: str | None, default_project: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if text.startswith(_SECRET_RESOURCE_PREFIX):
        text = text.removeprefix(_SECRET_RESOURCE_PREFIX)
    parts = [part for part in text.split("/") if part]
    if len(parts) == 4 and parts[0] == "projects" and parts[2] == "secrets":
        if all(_is_exact_path_segment(part) for part in (parts[1], parts[3])):
            return f"projects/{parts[1]}/secrets/{parts[3]}"
        return None
    project = _normalize_project(default_project)
    if len(parts) == 1 and project and _is_exact_path_segment(parts[0]):
        return f"projects/{project}/secrets/{parts[0]}"
    return None


def _secret_project(resource_name: str | None) -> str | None:
    if resource_name is None:
        return None
    parts = resource_name.split("/")
    return parts[1] if len(parts) == 4 and parts[0] == "projects" else None


def _normalize_project(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if text.startswith("projects/"):
        text = text.removeprefix("projects/")
    return text if _is_exact_path_segment(text) else None


def _is_exact_path_segment(value: str) -> bool:
    return (
        bool(value)
        and not _looks_like_terraform_reference(value)
        and not any(character in value for character in "/*?")
    )


def _terraform_reference(value: str) -> str | None:
    text = value.strip()
    if text.startswith("${") and text.endswith("}"):
        text = text[2:-1].strip()
    key = gcp_reference_key(text)
    return key if key.startswith(f"{GcpResourceType.SECRET_MANAGER_SECRET}.") else None


def _is_exact_service_account_identity(email: str | None, member: str | None) -> bool:
    if email is None or member is None or _looks_like_terraform_reference(email):
        return False
    return "@" in email and email.endswith(_SERVICE_ACCOUNT_DOMAIN) and member == f"serviceAccount:{email}"


def _looks_unresolved_identity(value: str) -> bool:
    return "serviceAccount:" in value and _looks_like_terraform_reference(value)


def _looks_like_terraform_reference(value: str) -> bool:
    text = value.strip()
    return "${" in text or ("google_" in text and "." in text and "@" not in text)


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _condition(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): raw for key, raw in value.items() if raw not in (None, "", [])}
