from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, TypedDict, TypeGuard

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext
from tfstride.providers.gcp.resource_types import (
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_CUSTOM_ROLE_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import (
    GCP_ROLE_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
)
from tfstride.providers.gcp.secret_management_evidence import (
    GcpCloudRunSecretManagementPath,
    GcpSecretManagerGrantBasis,
    GcpSecretManagerIamGrant,
    GcpSecretManagerLifecycleCompatibilityState,
    GcpSecretManagerManagementEffect,
    GcpSecretManagerOperationClass,
    GcpSecretManagerPermission,
    GcpSecretManagerScopeType,
    GcpSecretManagerTargetType,
    GcpSecretManagerVersionEvidence,
)

_SECRET_PATH_PATTERN = re.compile(r"^projects/(?P<project>[^/]+)/secrets/(?P<secret>[^/]+)$")
_VERSION_PATH_PATTERN = re.compile(r"^(?P<secret_path>projects/[^/]+/secrets/[^/]+)/versions/(?P<version>[^/]+)$")
_SERVICE_ACCOUNT_DOMAIN = ".gserviceaccount.com"
_SECRET_VERSION_PARENT_REFERENCE_SUFFIXES = (".id",)
_SECRET_IAM_TARGET_REFERENCE_SUFFIXES = (".secret_id",)

_ADD_PERMISSION: GcpSecretManagerPermission = "secretmanager.versions.add"
_DISABLE_PERMISSION: GcpSecretManagerPermission = "secretmanager.versions.disable"
_DESTROY_PERMISSION: GcpSecretManagerPermission = "secretmanager.versions.destroy"
_DELETE_SECRET_PERMISSION: GcpSecretManagerPermission = "secretmanager.secrets.delete"
_VERSION_PERMISSIONS = frozenset({_DISABLE_PERMISSION, _DESTROY_PERMISSION})
_MANAGEMENT_DEFINITIONS: dict[
    GcpSecretManagerPermission,
    tuple[
        GcpSecretManagerOperationClass,
        GcpSecretManagerManagementEffect,
        GcpSecretManagerTargetType,
    ],
] = {
    _ADD_PERMISSION: ("value_mutation", "tampering", "secret"),
    _DISABLE_PERMISSION: ("version_disruption", "disruption", "secret_version"),
    _DESTROY_PERMISSION: ("version_disruption", "disruption", "secret_version"),
    _DELETE_SECRET_PERMISSION: (
        "destructive_administration",
        "disruption",
        "secret",
    ),
}
_MANAGEMENT_PERMISSIONS = frozenset(_MANAGEMENT_DEFINITIONS)
_PREDEFINED_ROLE_PERMISSIONS: dict[str, tuple[GcpSecretManagerPermission, ...]] = {
    "roles/owner": tuple(_MANAGEMENT_DEFINITIONS),
    "roles/editor": tuple(_MANAGEMENT_DEFINITIONS),
    "roles/secretmanager.admin": tuple(_MANAGEMENT_DEFINITIONS),
    "roles/secretmanager.editor": tuple(_MANAGEMENT_DEFINITIONS),
    "roles/secretmanager.secretVersionAdder": (_ADD_PERMISSION,),
    "roles/secretmanager.secretVersionManager": (
        _ADD_PERMISSION,
        _DISABLE_PERMISSION,
        _DESTROY_PERMISSION,
    ),
}
_QUIET_PREDEFINED_ROLES = frozenset(
    {
        "roles/secretmanager.secretAccessor",
        "roles/secretmanager.viewer",
        "roles/viewer",
    }
)
_IAM_RESOURCE_TYPES = GCP_PROJECT_IAM_RESOURCE_TYPES | GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES


@dataclass(frozen=True, slots=True)
class _RoleResolution:
    role_kind: str
    state: str
    modeled_permissions: tuple[GcpSecretManagerPermission, ...]
    custom_role_permissions: tuple[str, ...] = ()
    role_definition_address: str | None = None


@dataclass(frozen=True, slots=True)
class _CustomRole:
    resource: NormalizedResource
    permissions: tuple[str, ...]
    permissions_state: str


class _ManagementSource(TypedDict):
    source: str
    scope_type: GcpSecretManagerScopeType
    scope: str
    management_mode: str
    roles: list[str]


_ApplicableScopeType = GcpSecretManagerScopeType | Literal["unrelated"]


class NormalizeSecretManagerVersionPostureStage:
    """Resolve modeled SecretVersions to exact modeled parent secrets."""

    name = "normalize_secret_manager_version_posture"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        secrets = tuple(
            resource for resource in resources if resource.resource_type == GcpResourceType.SECRET_MANAGER_SECRET
        )
        for version in resources:
            if version.resource_type != GcpResourceType.SECRET_MANAGER_SECRET_VERSION:
                continue
            _resolve_version_parent(version, secrets, context)


class NormalizeSecretManagerIamPostureStage:
    """Project exact project and secret IAM grants onto modeled secrets."""

    name = "normalize_secret_manager_iam_posture"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        iam_resources = tuple(resource for resource in resources if resource.resource_type in _IAM_RESOURCE_TYPES)
        custom_roles = _custom_roles_by_reference(resources)
        for secret in resources:
            if secret.resource_type != GcpResourceType.SECRET_MANAGER_SECRET:
                continue
            grants, uncertainties = _secret_iam_posture(
                secret,
                iam_resources,
                custom_roles,
                context,
            )
            gcp_facts(secret).set_secret_manager_iam_posture(
                grants=grants,
                uncertainties=uncertainties,
            )


class ModelCloudRunSecretManagementPathsStage:
    """Project deterministic Secret Manager lifecycle authority onto Cloud Run."""

    name = "model_cloud_run_secret_management_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        del context
        secrets = tuple(
            resource for resource in resources if resource.resource_type == GcpResourceType.SECRET_MANAGER_SECRET
        )
        versions = tuple(
            resource
            for resource in resources
            if resource.resource_type == GcpResourceType.SECRET_MANAGER_SECRET_VERSION
        )
        resources_by_address = {resource.address: resource for resource in resources}
        for workload in resources:
            if workload.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES:
                continue
            paths, uncertainties = _cloud_run_secret_management_paths(
                workload,
                secrets,
                versions,
                resources_by_address,
            )
            facts = gcp_facts(workload)
            facts.set_cloud_run_secret_management_paths(paths)
            facts.extend_cloud_run_secret_management_path_uncertainties(uncertainties)


def _resolve_version_parent(
    version: NormalizedResource,
    secrets: Sequence[NormalizedResource],
    context: GcpDecorationContext,
) -> None:
    facts = gcp_facts(version)
    version_path = _exact_version_path(facts.secret_manager_version_reference)
    parent_path = _parent_secret_path(version_path)
    declared_reference = _known_string(facts.secret_manager_version_secret_reference)
    declared_path = _exact_secret_path(declared_reference)
    if declared_path is not None and parent_path is not None and declared_path != parent_path:
        facts.append(
            GcpResourceMetadata.SECRET_MANAGER_VERSION_POSTURE_UNCERTAINTIES,
            "declared secret reference conflicts with version resource ancestry",
        )
        return

    candidates: dict[str, NormalizedResource] = {}
    resolved_parent_address = facts.secret_manager_version_resolved_secret_address
    if resolved_parent_address is not None:
        resolved_parent = next(
            (secret for secret in secrets if secret.address == resolved_parent_address),
            None,
        )
        if resolved_parent is not None:
            candidates[resolved_parent.address] = resolved_parent
    if declared_reference is not None:
        resolved = context.index.resources_by_reference.get(
            gcp_reference_key(
                declared_reference,
                _SECRET_VERSION_PARENT_REFERENCE_SUFFIXES,
            ),
            source=version,
            resource_types={GcpResourceType.SECRET_MANAGER_SECRET},
        )
        if resolved is not None:
            candidates[resolved.address] = resolved
    if parent_path is not None:
        for secret in secrets:
            if _secret_resource_name(secret) == parent_path:
                candidates[secret.address] = secret

    if len(candidates) != 1:
        evidence = ", ".join(sorted(candidates)) or declared_reference or parent_path or "<missing>"
        facts.append(
            GcpResourceMetadata.SECRET_MANAGER_VERSION_POSTURE_UNCERTAINTIES,
            f"exact parent secret ancestry is unresolved from {evidence}",
        )
        return

    parent = next(iter(candidates.values()))
    parent_path = _secret_resource_name(parent)
    if parent_path is None or (version_path is not None and _parent_secret_path(version_path) != parent_path):
        facts.append(
            GcpResourceMetadata.SECRET_MANAGER_VERSION_POSTURE_UNCERTAINTIES,
            "version resource name conflicts with resolved parent secret ancestry",
        )
        return

    facts.set(
        GcpResourceMetadata.SECRET_MANAGER_VERSION_RESOLVED_SECRET_ADDRESS,
        parent.address,
    )
    facts.set(
        GcpResourceMetadata.SECRET_MANAGER_VERSION_POSTURE_UNCERTAINTIES,
        [
            uncertainty
            for uncertainty in facts.secret_manager_version_posture_uncertainties
            if uncertainty != "secret is unknown after planning"
        ],
    )
    if not facts.project and gcp_facts(parent).project:
        facts.set(GcpResourceMetadata.PROJECT, gcp_facts(parent).project)


def _secret_iam_posture(
    secret: NormalizedResource,
    iam_resources: Sequence[NormalizedResource],
    custom_roles: Mapping[str, _CustomRole],
    context: GcpDecorationContext,
) -> tuple[list[GcpSecretManagerIamGrant], list[str]]:
    secret_path = _secret_resource_name(secret)
    project = _project_from_secret_path(secret_path)
    if secret_path is None or project is None:
        return [], [f"{secret.address}: exact Secret Manager ancestry is unresolved"]

    grants: list[GcpSecretManagerIamGrant] = []
    management_sources: list[_ManagementSource] = []
    uncertainties: list[str] = []
    for iam_resource in iam_resources:
        scope_type, scope = _applicable_scope(
            iam_resource,
            secret,
            secret_path,
            project,
            context,
        )
        if scope_type == "unrelated":
            continue
        if scope_type is None or scope is None:
            uncertainties.append(f"{iam_resource.address}: IAM scope is unresolved for {secret_path}")
            continue

        iam_facts = gcp_facts(iam_resource)
        source_bindings = iam_bindings(iam_resource)
        management_mode = _management_mode(iam_resource)
        management_sources.append(
            {
                "source": iam_resource.address,
                "scope_type": scope_type,
                "scope": scope,
                "management_mode": management_mode,
                "roles": sorted(
                    {role for binding in source_bindings if (role := _known_string(binding.get("role"))) is not None}
                ),
            }
        )
        policy_state = iam_facts.iam_policy_data_state
        if iam_resource.resource_type.endswith("_iam_policy") and policy_state != "configured":
            uncertainties.append(
                f"{iam_resource.address}: IAM policy_data is {policy_state or 'unresolved'} for {secret_path}"
            )
            continue

        for binding in source_bindings:
            role = _known_string(binding.get("role"))
            members = binding_members(binding)
            members_state = _binding_members_state(binding)
            if role is None:
                uncertainties.append(f"{iam_resource.address}: IAM role is unresolved for {secret_path}")
                continue
            if not members and members_state != "unknown":
                uncertainties.append(f"{iam_resource.address}: IAM members are unresolved for {secret_path}")
                continue

            role_resolution = _resolve_role(role, custom_roles)
            if _role_is_quiet(role_resolution):
                continue
            if role_resolution.state not in {"resolved", "modeled_subset"}:
                uncertainties.append(
                    f"{iam_resource.address}: permissions for IAM role {role} are "
                    f"{role_resolution.state} for {secret_path}"
                )
            if members_state == "unknown":
                uncertainties.append(f"{iam_resource.address}: IAM members are unresolved for {secret_path}")

            condition_state = _condition_state(binding)
            if condition_state == "unknown":
                uncertainties.append(
                    f"{iam_resource.address}: IAM condition applicability to {secret_path} is unknown after planning"
                )
            permissions_are_deterministic = role_resolution.state in {"resolved", "modeled_subset"} and bool(
                role_resolution.modeled_permissions
            )
            authorization_state = (
                "unknown"
                if not permissions_are_deterministic or condition_state == "unknown" or members_state == "unknown"
                else "conditional"
                if condition_state == "configured"
                else "granted"
            )
            grant: GcpSecretManagerIamGrant = {
                "role": role,
                "role_kind": role_resolution.role_kind,
                "role_resolution_state": role_resolution.state,
                "modeled_secret_permissions": list(role_resolution.modeled_permissions),
                "scope_effective_permissions": list(role_resolution.modeled_permissions),
                "members": members,
                "source": iam_resource.address,
                "source_type": iam_resource.resource_type,
                "scope_type": scope_type,
                "scope": scope,
                "source_scope_reference": (
                    iam_facts.project if scope_type == "project" else iam_facts.target_reference
                ),
                "project": project,
                "secret_address": secret.address,
                "secret_resource_name": secret_path,
                "condition_state": condition_state,
                "authorization_state": authorization_state,
                "management_mode": management_mode,
                "management_state": "unambiguous",
                "grant_basis": _grant_basis(scope_type),
            }
            if role_resolution.custom_role_permissions:
                grant["custom_role_permissions"] = list(role_resolution.custom_role_permissions)
            if role_resolution.role_definition_address is not None:
                grant["role_definition_address"] = role_resolution.role_definition_address
            condition = _mapping_copy(binding.get("condition"))
            if condition is not None:
                grant["condition"] = condition
            if policy_state is not None:
                grant["policy_data_state"] = policy_state
            if members_state == "unknown":
                grant["members_state"] = "unknown"
            grants.append(grant)

    grants = _dedupe_grants(grants)
    _apply_management_ambiguity(
        grants,
        management_sources,
        uncertainties,
        secret_path,
    )
    grants.sort(key=_grant_sort_key)
    return grants, dedupe(uncertainties)


def _cloud_run_secret_management_paths(
    workload: NormalizedResource,
    secrets: Sequence[NormalizedResource],
    versions: Sequence[NormalizedResource],
    resources_by_address: Mapping[str, NormalizedResource],
) -> tuple[list[GcpCloudRunSecretManagementPath], list[str]]:
    workload_facts = gcp_facts(workload)
    service_account_email = workload_facts.service_account_email
    service_account_member = workload_facts.service_account_member
    if (
        service_account_email is None
        or service_account_member is None
        or not _is_exact_service_account_identity(
            service_account_email,
            service_account_member,
        )
    ):
        return [], [f"{workload.address}: Cloud Run service account identity is unresolved"]

    paths: list[GcpCloudRunSecretManagementPath] = []
    uncertainties: list[str] = []
    seen: set[tuple[str, str, str, str]] = set()
    for secret in secrets:
        secret_path = _secret_resource_name(secret)
        project = _project_from_secret_path(secret_path)
        if secret_path is None or project is None:
            uncertainties.append(
                f"{workload.address}: Secret Manager secret {secret.address} has unresolved exact ancestry"
            )
            continue

        secret_facts = gcp_facts(secret)
        version_records = _secret_version_records(secret, secret_path, versions)
        runtime_may_manage_versions = False
        evaluated_sources: set[str] = set()
        for grant in secret_facts.secret_manager_iam_grants:
            source = grant["source"]
            members_unknown = grant.get("members_state") == "unknown"
            member_matches = service_account_member in grant["members"]
            if not member_matches and not members_unknown:
                continue
            evaluated_sources.add(source)

            permissions = _management_permissions(grant["scope_effective_permissions"])
            role_state = grant["role_resolution_state"]
            if member_matches and (
                any(permission in _VERSION_PERMISSIONS for permission in permissions)
                or role_state not in {"resolved", "modeled_subset"}
            ):
                runtime_may_manage_versions = True
            if members_unknown and (permissions or role_state not in {"resolved", "modeled_subset"}):
                runtime_may_manage_versions = True

            if not permissions:
                if role_state not in {"resolved", "modeled_subset"}:
                    uncertainties.append(
                        f"{workload.address}: {source} Secret Manager role "
                        f"permissions are unresolved for {secret.address}"
                    )
                continue
            if (
                not member_matches
                or grant["authorization_state"] != "granted"
                or grant["management_state"] != "unambiguous"
                or grant["condition_state"] != "not_configured"
                or not _grant_is_current(
                    grant,
                    secret,
                    secret_path,
                    project,
                    resources_by_address,
                )
            ):
                uncertainties.append(
                    f"{workload.address}: {source} Secret Manager lifecycle "
                    f"authority is unresolved for {secret.address}"
                )
                continue

            for permission in permissions:
                definition = _MANAGEMENT_DEFINITIONS[permission]
                targets = _management_targets(
                    permission,
                    secret,
                    secret_path,
                    version_records,
                )
                for target in targets:
                    compatibility = target[5]
                    if compatibility == "incompatible":
                        continue
                    if compatibility == "unknown":
                        uncertainties.append(
                            f"{workload.address}: lifecycle compatibility for {permission} on {target[1]} is unresolved"
                        )
                        continue
                    fingerprint = (
                        permission,
                        target[1],
                        source,
                        grant["role"],
                    )
                    if fingerprint in seen:
                        continue
                    seen.add(fingerprint)
                    paths.append(
                        _management_path_record(
                            workload,
                            service_account_email,
                            service_account_member,
                            permission,
                            definition,
                            target,
                            secret,
                            secret_path,
                            project,
                            grant,
                        )
                    )

        if runtime_may_manage_versions:
            modeled_version_addresses = {record["version_address"] for record in version_records}
            uncertainties.extend(
                f"{workload.address}: Secret Manager version {version.address} "
                "has unresolved exact identity or secret ancestry for lifecycle paths"
                for version in versions
                if version.address not in modeled_version_addresses
                and (
                    _version_may_belong_to_secret(version, secret_path)
                    or gcp_facts(version).secret_manager_version_resolved_secret_address == secret.address
                )
            )
        uncertainties.extend(
            _applicable_posture_uncertainties(
                workload,
                secret,
                service_account_member,
                evaluated_sources,
                resources_by_address,
            )
        )

    paths.sort(
        key=lambda path: (
            path["operation"],
            path["target_address"],
            path["iam_resource_address"],
            path["role"],
        )
    )
    return paths, dedupe(uncertainties)


_ManagementTarget = tuple[
    GcpSecretManagerTargetType,
    str,
    str,
    str,
    GcpSecretManagerVersionEvidence | None,
    GcpSecretManagerLifecycleCompatibilityState,
]


def _management_targets(
    permission: GcpSecretManagerPermission,
    secret: NormalizedResource,
    secret_path: str,
    versions: Sequence[GcpSecretManagerVersionEvidence],
) -> list[_ManagementTarget]:
    if permission in {_ADD_PERMISSION, _DELETE_SECRET_PERMISSION}:
        return [
            (
                "secret",
                secret.address,
                secret.resource_type,
                secret_path,
                None,
                "not_applicable",
            )
        ]
    return [
        (
            "secret_version",
            version["version_address"],
            version["version_resource_type"],
            version["version_resource_name"],
            version,
            _version_lifecycle_compatibility(
                permission,
                version["lifecycle_state"],
            ),
        )
        for version in versions
    ]


def _management_path_record(
    workload: NormalizedResource,
    service_account_email: str,
    service_account_member: str,
    permission: GcpSecretManagerPermission,
    definition: tuple[
        GcpSecretManagerOperationClass,
        GcpSecretManagerManagementEffect,
        GcpSecretManagerTargetType,
    ],
    target: _ManagementTarget,
    secret: NormalizedResource,
    secret_path: str,
    project: str,
    grant: GcpSecretManagerIamGrant,
) -> GcpCloudRunSecretManagementPath:
    version = target[4]
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "service_account_email": service_account_email,
        "service_account_member": service_account_member,
        "identity_kind": "cloud_run_service_account",
        "credential_context": "workload_runtime",
        "operation": permission,
        "operation_class": definition[0],
        "management_effect": definition[1],
        "matched_permissions": [permission],
        "target_type": target[0],
        "target_address": target[1],
        "target_resource_type": target[2],
        "target_resource_name": target[3],
        "target_model_evidence_addresses": [target[1]],
        "secret_address": secret.address,
        "secret_resource_name": secret_path,
        "secret_project": project,
        "secret_version": version.copy() if version is not None else None,
        "version_destroy_ttl": gcp_facts(secret).secret_manager_version_destroy_ttl,
        "recovery_evidence_scope": "secret_version_destruction_delay",
        "lifecycle_compatibility_state": target[5],
        "iam_resource_address": grant["source"],
        "iam_resource_type": grant["source_type"],
        "role": grant["role"],
        "role_kind": grant["role_kind"],
        "role_resolution_state": grant["role_resolution_state"],
        "modeled_secret_permissions": list(grant["modeled_secret_permissions"]),
        "custom_role_permissions": list(grant.get("custom_role_permissions", [])),
        "role_definition_address": grant.get("role_definition_address"),
        "scope_effective_permissions": list(grant["scope_effective_permissions"]),
        "grant_members": list(grant["members"]),
        "grant_basis": grant["grant_basis"],
        "scope_type": grant["scope_type"],
        "scope": grant["scope"],
        "source_scope_reference": grant["source_scope_reference"],
        "management_mode": grant["management_mode"],
        "management_state": grant["management_state"],
        "condition": _mapping_copy(grant.get("condition")),
        "condition_state": grant["condition_state"],
        "authorization_state": "granted",
        "authorization_model": "secret_manager_iam",
        "iam_scope_is_secret_version": False,
        "iam_grant_record": grant.copy(),
    }


def _secret_version_records(
    secret: NormalizedResource,
    secret_path: str,
    versions: Sequence[NormalizedResource],
) -> list[GcpSecretManagerVersionEvidence]:
    records: list[GcpSecretManagerVersionEvidence] = []
    for version in versions:
        facts = gcp_facts(version)
        if facts.secret_manager_version_resolved_secret_address != secret.address:
            continue
        version_path = _exact_version_path(facts.secret_manager_version_reference or version.identifier)
        if version_path is None:
            continue
        match = _VERSION_PATH_PATTERN.fullmatch(version_path)
        if match is None or match.group("secret_path") != secret_path:
            continue
        version_number = facts.secret_manager_version_number
        if version_number is None or version_number != match.group("version"):
            continue
        record: GcpSecretManagerVersionEvidence = {
            "version_address": version.address,
            "version_resource_type": version.resource_type,
            "version_resource_name": version_path,
            "version_number": version_number,
            "version_state": facts.secret_manager_version_lifecycle_state,
            "secret_address": secret.address,
            "secret_resource_name": secret_path,
            "resolved_secret_address": secret.address,
            "lifecycle_state": (facts.secret_manager_version_lifecycle_state or "unknown"),
            "deletion_policy": facts.secret_manager_version_deletion_policy,
            "posture_uncertainties": list(facts.secret_manager_version_posture_uncertainties),
        }
        records.append(record)
    records.sort(
        key=lambda record: (
            record["version_resource_name"],
            record["version_address"],
        )
    )
    return records


def _version_lifecycle_compatibility(
    permission: GcpSecretManagerPermission,
    lifecycle_state: str,
) -> GcpSecretManagerLifecycleCompatibilityState:
    if lifecycle_state == "unknown":
        return "unknown"
    if permission == _DISABLE_PERMISSION:
        return "compatible" if lifecycle_state == "enabled" else "incompatible"
    if permission == _DESTROY_PERMISSION:
        return "compatible" if lifecycle_state in {"enabled", "disabled"} else "incompatible"
    return "not_applicable"


def _grant_is_current(
    grant: GcpSecretManagerIamGrant,
    secret: NormalizedResource,
    secret_path: str,
    project: str,
    resources_by_address: Mapping[str, NormalizedResource],
) -> bool:
    source = resources_by_address.get(grant["source"])
    if (
        source is None
        or source.resource_type != grant["source_type"]
        or grant["secret_address"] != secret.address
        or grant["secret_resource_name"] != secret_path
        or grant["project"] != project
        or grant["scope_effective_permissions"] != grant["modeled_secret_permissions"]
        or grant not in gcp_facts(secret).secret_manager_iam_grants
    ):
        return False
    if grant["scope_type"] == "project":
        return (
            grant["scope"] == project
            and grant["grant_basis"] == "project_iam"
            and source.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES
        )
    return (
        grant["scope"] == secret_path
        and grant["grant_basis"] == "secret_resource_iam"
        and source.resource_type in GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES
    )


def _applicable_posture_uncertainties(
    workload: NormalizedResource,
    secret: NormalizedResource,
    service_account_member: str,
    evaluated_sources: set[str],
    resources_by_address: Mapping[str, NormalizedResource],
) -> list[str]:
    result: list[str] = []
    for uncertainty in gcp_facts(secret).secret_manager_iam_posture_uncertainties:
        source_address = uncertainty.partition(":")[0]
        if source_address in evaluated_sources:
            continue
        source = resources_by_address.get(source_address)
        if source is None:
            continue
        bindings = iam_bindings(source)
        applies = any(
            service_account_member in binding_members(binding) or _binding_members_state(binding) == "unknown"
            for binding in bindings
        )
        policy_unknown = (
            source.resource_type.endswith("_iam_policy") and gcp_facts(source).iam_policy_data_state != "configured"
        )
        if applies or policy_unknown:
            result.append(
                f"{workload.address}: Secret Manager IAM posture for {secret.address} is incomplete: {uncertainty}"
            )
    return result


def _applicable_scope(
    iam_resource: NormalizedResource,
    secret: NormalizedResource,
    secret_path: str,
    project: str,
    context: GcpDecorationContext,
) -> tuple[_ApplicableScopeType | None, str | None]:
    facts = gcp_facts(iam_resource)
    if facts.iam_scope_reference_state in {"unknown", "not_configured"}:
        return None, None
    if iam_resource.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES:
        iam_project = _normalize_project(facts.project)
        if iam_project is None:
            return None, None
        return ("project", project) if iam_project == project else ("unrelated", None)

    target_reference = _known_string(facts.target_reference)
    if target_reference is None:
        return None, None
    target_key = gcp_reference_key(
        target_reference,
        _SECRET_IAM_TARGET_REFERENCE_SUFFIXES,
    )
    resolved = context.index.resources_by_reference.get(
        target_key,
        source=iam_resource,
        resource_types={GcpResourceType.SECRET_MANAGER_SECRET},
    )
    if resolved is not None:
        return (
            ("secret", secret_path)
            if resolved.address == secret.address and resolved.resource_type == GcpResourceType.SECRET_MANAGER_SECRET
            else ("unrelated", None)
        )
    exact_target = _exact_secret_path(target_reference)
    if exact_target is not None:
        return ("secret", secret_path) if exact_target == secret_path else ("unrelated", None)
    return None, None


def _resolve_role(
    role: str,
    custom_roles: Mapping[str, _CustomRole],
) -> _RoleResolution:
    predefined = _PREDEFINED_ROLE_PERMISSIONS.get(role)
    if predefined is not None:
        return _RoleResolution("predefined", "modeled_subset", predefined)
    if role in _QUIET_PREDEFINED_ROLES:
        return _RoleResolution("predefined", "resolved", ())
    if not _looks_like_custom_role(role):
        return _RoleResolution("predefined", "unmodeled", ())

    custom = custom_roles.get(gcp_reference_key(role, GCP_ROLE_REFERENCE_SUFFIXES))
    if custom is None:
        return _RoleResolution("custom", "external_or_unresolved", ())
    if custom.permissions_state != "configured":
        return _RoleResolution(
            "custom",
            custom.permissions_state or "unknown",
            (),
            role_definition_address=custom.resource.address,
        )
    permissions = tuple(_management_permissions(custom.permissions))
    return _RoleResolution(
        "custom",
        "resolved",
        permissions,
        custom_role_permissions=custom.permissions,
        role_definition_address=custom.resource.address,
    )


def _role_is_quiet(resolution: _RoleResolution) -> bool:
    return resolution.state == "resolved" and not resolution.modeled_permissions


def _apply_management_ambiguity(
    grants: list[GcpSecretManagerIamGrant],
    sources: Sequence[_ManagementSource],
    uncertainties: list[str],
    secret_path: str,
) -> None:
    scope_set: set[tuple[GcpSecretManagerScopeType, str]] = {
        (source["scope_type"], source["scope"]) for source in sources
    }
    scopes = sorted(scope_set)
    for scope_type, scope in scopes:
        scoped = [source for source in sources if source["scope_type"] == scope_type and source["scope"] == scope]
        policy_sources = {source["source"] for source in scoped if source["management_mode"] == "authoritative_policy"}
        other_sources = {source["source"] for source in scoped if source["management_mode"] != "authoritative_policy"}
        if len(policy_sources) > 1 or (policy_sources and other_sources):
            _mark_ambiguous(grants, scope_type, scope)
            uncertainties.append(
                f"effective IAM at {scope_type} scope {scope} for {secret_path} "
                "is ambiguous because authoritative policy and other Terraform "
                "IAM managers overlap"
            )
            continue

        roles = sorted({role for source in scoped for role in source["roles"]})
        for role in roles:
            binding_sources = {
                source["source"]
                for source in scoped
                if source["management_mode"] == "authoritative_role_binding" and role in source["roles"]
            }
            member_sources = {
                source["source"]
                for source in scoped
                if source["management_mode"] == "additive_member" and role in source["roles"]
            }
            if len(binding_sources) <= 1 and not (binding_sources and member_sources):
                continue
            _mark_ambiguous(grants, scope_type, scope, role)
            uncertainties.append(
                f"effective IAM membership for role {role} at {scope_type} "
                f"scope {scope} for {secret_path} is ambiguous because "
                "authoritative role bindings overlap with another Terraform "
                "IAM manager"
            )


def _mark_ambiguous(
    grants: list[GcpSecretManagerIamGrant],
    scope_type: GcpSecretManagerScopeType,
    scope: str,
    role: str | None = None,
) -> None:
    for grant in grants:
        if grant["scope_type"] != scope_type or grant["scope"] != scope:
            continue
        if role is not None and grant["role"] != role:
            continue
        grant["management_state"] = "ambiguous"
        if grant["authorization_state"] != "unknown":
            grant["authorization_state"] = "ambiguous"


def _custom_roles_by_reference(
    resources: Sequence[NormalizedResource],
) -> Mapping[str, _CustomRole]:
    result: dict[str, _CustomRole] = {}
    for resource in resources:
        if resource.resource_type not in GCP_CUSTOM_ROLE_RESOURCE_TYPES:
            continue
        facts = gcp_facts(resource)
        custom = _CustomRole(
            resource=resource,
            permissions=tuple(sorted(set(facts.custom_role_permissions))),
            permissions_state=facts.custom_role_permissions_state or "unknown",
        )
        references: set[str | None] = {
            resource.address,
            f"{resource.address}.id",
            f"{resource.address}.name",
            f"{resource.address}.role_id",
            resource.identifier,
            facts.resource_name,
            facts.custom_role_id,
        }
        if facts.project and facts.custom_role_id:
            references.add(f"projects/{facts.project}/roles/{facts.custom_role_id}")
        if facts.organization_id and facts.custom_role_id:
            references.add(f"organizations/{facts.organization_id}/roles/{facts.custom_role_id}")
        for reference in references:
            if reference:
                result.setdefault(
                    gcp_reference_key(
                        reference.strip(),
                        GCP_ROLE_REFERENCE_SUFFIXES,
                    ),
                    custom,
                )
    return result


def _secret_resource_name(secret: NormalizedResource) -> str | None:
    facts = gcp_facts(secret)
    for value in (facts.resource_name, secret.identifier):
        path = _exact_secret_path(value)
        if path is not None:
            return path
    project = _normalize_project(facts.project)
    secret_id = _known_string(facts.secret_id)
    if project is not None and secret_id is not None and "/" not in secret_id:
        return f"projects/{project}/secrets/{secret_id}"
    return None


def _version_may_belong_to_secret(
    version: NormalizedResource,
    secret_path: str,
) -> bool:
    facts = gcp_facts(version)
    version_path = _exact_version_path(facts.secret_manager_version_reference)
    if version_path is not None:
        return _parent_secret_path(version_path) == secret_path
    reference = _exact_secret_path(facts.secret_manager_version_secret_reference)
    return reference == secret_path


def _management_permissions(
    permissions: Sequence[str],
) -> list[GcpSecretManagerPermission]:
    return [permission for permission in permissions if _is_management_permission(permission)]


def _is_management_permission(
    value: str,
) -> TypeGuard[GcpSecretManagerPermission]:
    return value in _MANAGEMENT_PERMISSIONS


def _is_exact_service_account_identity(
    email: str | None,
    member: str | None,
) -> bool:
    return bool(
        email
        and member == f"serviceAccount:{email}"
        and "@" in email
        and email.endswith(_SERVICE_ACCOUNT_DOMAIN)
        and "${" not in email
        and not ("google_" in email and "." in email)
    )


def _condition_state(binding: Mapping[str, Any]) -> str:
    if binding.get("condition_state") == "unknown":
        return "unknown"
    condition = binding.get("condition")
    return "configured" if isinstance(condition, Mapping) and condition else "not_configured"


def _binding_members_state(binding: Mapping[str, Any]) -> str:
    return "unknown" if binding.get("members_state") == "unknown" else "configured"


def _management_mode(resource: NormalizedResource) -> str:
    if resource.resource_type.endswith("_iam_policy"):
        return "authoritative_policy"
    if resource.resource_type.endswith("_iam_binding"):
        return "authoritative_role_binding"
    return "additive_member"


def _grant_basis(
    scope_type: GcpSecretManagerScopeType,
) -> GcpSecretManagerGrantBasis:
    return "project_iam" if scope_type == "project" else "secret_resource_iam"


def _grant_sort_key(
    grant: GcpSecretManagerIamGrant,
) -> tuple[str, str, str, str, tuple[str, ...]]:
    return (
        grant["scope_type"],
        grant["scope"],
        grant["source"],
        grant["role"],
        tuple(grant["members"]),
    )


def _dedupe_grants(
    grants: Sequence[GcpSecretManagerIamGrant],
) -> list[GcpSecretManagerIamGrant]:
    result: list[GcpSecretManagerIamGrant] = []
    for grant in grants:
        if grant not in result:
            result.append(grant)
    return result


def _looks_like_custom_role(role: str) -> bool:
    return role.startswith(("projects/", "organizations/")) or "iam_custom_role." in role


def _normalize_project(value: object) -> str | None:
    text = _known_string(value)
    if text is None:
        return None
    parts = [part for part in text.split("/") if part]
    if len(parts) == 2 and parts[0] == "projects":
        return parts[1]
    return text if "/" not in text else None


def _exact_secret_path(value: object) -> str | None:
    text = _known_string(value)
    if text is None:
        return None
    normalized = text.rstrip("/")
    return normalized if _SECRET_PATH_PATTERN.fullmatch(normalized) is not None else None


def _exact_version_path(value: object) -> str | None:
    text = _known_string(value)
    if text is None:
        return None
    normalized = text.rstrip("/")
    return normalized if _VERSION_PATH_PATTERN.fullmatch(normalized) is not None else None


def _parent_secret_path(version_path: str | None) -> str | None:
    if version_path is None:
        return None
    match = _VERSION_PATH_PATTERN.fullmatch(version_path)
    return match.group("secret_path") if match is not None else None


def _project_from_secret_path(value: str | None) -> str | None:
    if value is None:
        return None
    match = _SECRET_PATH_PATTERN.fullmatch(value)
    return match.group("project") if match is not None else None


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _mapping_copy(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    return {str(key): item for key, item in value.items()}
