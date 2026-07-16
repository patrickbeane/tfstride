from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.azure.container_registry_references import normalize_container_registry_login_server
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType

_ACR_WRITE_ROLE_KINDS = {
    "acrpush": "writer",
    "container registry repository writer": "writer",
}
_ACR_CONTENT_WRITE_ACTIONS = (
    "microsoft.containerregistry/registries/push/write",
    "microsoft.containerregistry/registries/repositories/content/write",
)


@dataclass(frozen=True, slots=True)
class _AcrWriteGrant:
    role_name: str
    role_kind: str
    grant_basis: str
    role_definition_address: str | None = None
    permission_patterns: tuple[str, ...] = ()
    not_permission_patterns: tuple[str, ...] = ()
    matched_write_actions: tuple[str, ...] = ()


class ModelAppServiceAcrWritePathsStage:
    name = "model_app_service_acr_write_paths"

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        registries_by_login_server = _registries_by_login_server(resources)
        for workload in resources:
            if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
                continue
            paths, uncertainties = _app_service_acr_write_paths(
                workload,
                context,
                registries_by_login_server,
            )
            facts = azure_facts(workload)
            facts.set_acr_write_paths(paths)
            facts.extend_acr_write_path_uncertainties(uncertainties)


def _app_service_acr_write_paths(
    workload: NormalizedResource,
    context: AzureDecorationContext,
    registries_by_login_server: Mapping[str, tuple[NormalizedResource, ...]],
) -> tuple[list[dict[str, Any]], list[str]]:
    facts = azure_facts(workload)
    images = [
        image
        for image in facts.container_image_references
        if image.get("is_resolved") is True
        and isinstance(image.get("container_registry_login_server"), str)
        and image.get("container_registry_login_server")
    ]
    if not images:
        return [], [f"{workload.address}: {value}" for value in facts.container_image_posture_uncertainties]

    identities, identity_uncertainties = _workload_identities(workload, context)
    uncertainties = list(identity_uncertainties)
    paths: list[dict[str, Any]] = []
    for image in images:
        login_server = normalize_container_registry_login_server(image["container_registry_login_server"])
        matches = registries_by_login_server.get(login_server or "", ())
        if len(matches) != 1:
            reason = "is not modeled" if not matches else "matches multiple modeled registries"
            uncertainties.append(f"{workload.address}: ACR login server {login_server or 'unknown'} {reason}")
            continue
        registry = matches[0]
        for identity, identity_kind in identities:
            _append_identity_write_paths(
                paths,
                uncertainties,
                workload=workload,
                image=image,
                registry=registry,
                identity=identity,
                identity_kind=identity_kind,
                context=context,
            )
    return _dedupe_dicts(paths), _dedupe_strings(uncertainties)


def _workload_identities(
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


def _append_identity_write_paths(
    paths: list[dict[str, Any]],
    uncertainties: list[str],
    *,
    workload: NormalizedResource,
    image: Mapping[str, Any],
    registry: NormalizedResource,
    identity: NormalizedResource,
    identity_kind: str,
    context: AzureDecorationContext,
) -> None:
    identity_facts = azure_facts(identity)
    for assignment in identity_facts.managed_identity_role_assignments:
        if assignment.get("target_resource_address") != registry.address or assignment.get("scope_kind") != "resource":
            continue
        assignment_resource = context.index.resolve(_string_value(assignment.get("source")))
        if assignment_resource is None or assignment_resource.resource_type != AzureResourceType.ROLE_ASSIGNMENT:
            uncertainties.append(f"{workload.address}: registry role assignment resource is unresolved")
            continue
        assignment_facts = azure_facts(assignment_resource)
        if assignment_facts.role_assignment_condition:
            uncertainties.append(
                f"{workload.address}: {assignment_resource.address} has a conditional ACR role assignment"
            )
            continue
        if any("condition is unknown" in value for value in assignment_facts.key_vault_authorization_uncertainties):
            uncertainties.append(f"{workload.address}: {assignment_resource.address} condition is unresolved")
            continue
        grant, uncertainty = _acr_write_grant(assignment, assignment_resource, context)
        if uncertainty:
            uncertainties.append(f"{workload.address}: {assignment_resource.address} {uncertainty}")
        if grant is None:
            continue
        registry_facts = azure_facts(registry)
        path = {
            "workload_address": workload.address,
            "workload_type": workload.resource_type,
            "identity_address": identity.address,
            "identity_kind": identity_kind,
            "principal_id": identity_facts.principal_id,
            "image_reference": image.get("raw"),
            "image_reference_path": image.get("path"),
            "image_tag": image.get("tag"),
            "image_digest": image.get("digest"),
            "image_digest_pinned": image.get("digest_pinned"),
            "container_registry_address": registry.address,
            "container_registry_id": registry_facts.container_registry_id,
            "container_registry_login_server": registry_facts.container_registry_login_server,
            "role_assignment_address": assignment_resource.address,
            "role_definition_name": grant.role_name,
            "role_definition_id": assignment.get("role_definition_id"),
            "role_kind": grant.role_kind,
            "grant_basis": grant.grant_basis,
            "registry_scope": "exact_container_registry",
        }
        if grant.role_definition_address:
            path["role_definition_address"] = grant.role_definition_address
            path["permission_patterns"] = list(grant.permission_patterns)
            path["not_permission_patterns"] = list(grant.not_permission_patterns)
            path["matched_write_actions"] = list(grant.matched_write_actions)
        paths.append(path)


def _acr_write_grant(
    assignment: Mapping[str, Any],
    assignment_resource: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[_AcrWriteGrant | None, str | None]:
    role_name = _string_value(assignment.get("role_definition_name"))
    role_kind = _ACR_WRITE_ROLE_KINDS.get((role_name or "").strip().lower())
    if role_kind is not None and role_name is not None:
        return (
            _AcrWriteGrant(
                role_name=role_name,
                role_kind=role_kind,
                grant_basis="azure_registry_scoped_rbac",
            ),
            None,
        )

    assignment_facts = azure_facts(assignment_resource)
    role_definition_address = assignment_facts.resolved_role_definition_address
    role_definition = context.index.resolve(role_definition_address)
    if role_definition is None or role_definition.resource_type != AzureResourceType.ROLE_DEFINITION:
        if not role_name:
            return None, "role is unresolved"
        return None, None

    role_facts = azure_facts(role_definition)
    if any(
        "data_actions" in value or "not_data_actions" in value for value in role_facts.role_definition_uncertainties
    ):
        return None, f"custom role {role_definition.address} data actions are unresolved"

    permission_patterns = tuple(_normalized_actions(role_facts.role_definition_data_actions))
    not_permission_patterns = tuple(_normalized_actions(role_facts.role_definition_not_data_actions))
    matched_write_actions = tuple(
        action
        for action in _ACR_CONTENT_WRITE_ACTIONS
        if _matches_any(action, permission_patterns) and not _matches_any(action, not_permission_patterns)
    )
    if not matched_write_actions:
        return None, None

    return (
        _AcrWriteGrant(
            role_name=role_name or role_facts.name or role_definition.address,
            role_kind="custom_writer",
            grant_basis="azure_custom_role_registry_scoped_rbac",
            role_definition_address=role_definition.address,
            permission_patterns=permission_patterns,
            not_permission_patterns=not_permission_patterns,
            matched_write_actions=matched_write_actions,
        ),
        None,
    )


def _normalized_actions(values: list[str]) -> list[str]:
    return [value.strip().lower() for value in values if value.strip()]


def _matches_any(action: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatchcase(action, pattern) for pattern in patterns)


def _registries_by_login_server(
    resources: list[NormalizedResource],
) -> dict[str, tuple[NormalizedResource, ...]]:
    mutable: dict[str, list[NormalizedResource]] = {}
    for resource in resources:
        if resource.resource_type != AzureResourceType.CONTAINER_REGISTRY:
            continue
        login_server = azure_facts(resource).container_registry_login_server
        if login_server:
            mutable.setdefault(login_server, []).append(resource)
    return {key: tuple(values) for key, values in mutable.items()}


def _string_value(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _dedupe_strings(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _dedupe_dicts(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result
