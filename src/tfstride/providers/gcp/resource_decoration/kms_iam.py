from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, TypedDict

from tfstride.models import NormalizedResource
from tfstride.providers.coercion import dedupe
from tfstride.providers.gcp.custom_role_index import GcpCustomRoleIndex, build_gcp_custom_role_index
from tfstride.providers.gcp.kms_evidence import (
    GcpKmsGrantBasis,
    GcpKmsIamGrant,
    GcpKmsKeyRingIamGrant,
    GcpKmsScopeType,
)
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings, resolve_resource_iam_target
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext, GcpResourceIndex
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_types import (
    GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES,
    GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GcpResourceType,
)
from tfstride.providers.gcp.resource_utils import (
    GCP_NETWORK_REFERENCE_SUFFIXES,
    binding_members,
    gcp_reference_key,
    is_gcp_terraform_resource_address,
)

_PREDEFINED_KMS_ROLE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "roles/cloudkms.admin": (
        "cloudkms.cryptoKeys.create",
        "cloudkms.cryptoKeys.delete",
        "cloudkms.cryptoKeys.get",
        "cloudkms.cryptoKeys.getIamPolicy",
        "cloudkms.cryptoKeys.list",
        "cloudkms.cryptoKeys.setIamPolicy",
        "cloudkms.cryptoKeys.update",
        "cloudkms.cryptoKeyVersions.create",
        "cloudkms.cryptoKeyVersions.delete",
        "cloudkms.cryptoKeyVersions.destroy",
        "cloudkms.cryptoKeyVersions.get",
        "cloudkms.cryptoKeyVersions.list",
        "cloudkms.cryptoKeyVersions.restore",
        "cloudkms.cryptoKeyVersions.trustedImportExport",
        "cloudkms.cryptoKeyVersions.update",
        "cloudkms.cryptoKeyVersions.useToDecryptViaDelegation",
        "cloudkms.cryptoKeyVersions.useToEncryptViaDelegation",
        "cloudkms.keyRings.create",
        "cloudkms.keyRings.createTagBinding",
        "cloudkms.keyRings.deleteTagBinding",
        "cloudkms.keyRings.get",
        "cloudkms.keyRings.getIamPolicy",
        "cloudkms.keyRings.list",
        "cloudkms.keyRings.listEffectiveTags",
        "cloudkms.keyRings.listTagBindings",
        "cloudkms.keyRings.setIamPolicy",
    ),
    "roles/cloudkms.cryptoKeyEncrypterDecrypter": (
        "cloudkms.cryptoKeyVersions.useToDecrypt",
        "cloudkms.cryptoKeyVersions.useToEncrypt",
    ),
    "roles/cloudkms.cryptoKeyDecrypter": ("cloudkms.cryptoKeyVersions.useToDecrypt",),
    "roles/cloudkms.cryptoKeyEncrypter": ("cloudkms.cryptoKeyVersions.useToEncrypt",),
    "roles/cloudkms.cryptoKeyDecrypterViaDelegation": ("cloudkms.cryptoKeyVersions.useToDecryptViaDelegation",),
    "roles/cloudkms.cryptoKeyEncrypterDecrypterViaDelegation": (
        "cloudkms.cryptoKeyVersions.useToDecryptViaDelegation",
        "cloudkms.cryptoKeyVersions.useToEncryptViaDelegation",
    ),
    "roles/cloudkms.cryptoKeyEncrypterViaDelegation": ("cloudkms.cryptoKeyVersions.useToEncryptViaDelegation",),
    "roles/cloudkms.cryptoOperator": (
        "cloudkms.cryptoKeyVersions.useToDecapsulate",
        "cloudkms.cryptoKeyVersions.useToDecrypt",
        "cloudkms.cryptoKeyVersions.useToEncrypt",
        "cloudkms.cryptoKeyVersions.useToSign",
        "cloudkms.cryptoKeyVersions.useToVerify",
        "cloudkms.cryptoKeyVersions.viewPublicKey",
    ),
    "roles/cloudkms.decapsulator": (
        "cloudkms.cryptoKeyVersions.useToDecapsulate",
        "cloudkms.cryptoKeyVersions.viewPublicKey",
    ),
    "roles/cloudkms.importer": (
        "cloudkms.cryptoKeyVersions.trustedImportExport",
        "cloudkms.importJobs.create",
        "cloudkms.importJobs.get",
        "cloudkms.importJobs.list",
        "cloudkms.importJobs.useToImport",
    ),
    "roles/cloudkms.publicKeyViewer": ("cloudkms.cryptoKeyVersions.viewPublicKey",),
    "roles/cloudkms.signer": ("cloudkms.cryptoKeyVersions.useToSign",),
    "roles/cloudkms.signerVerifier": (
        "cloudkms.cryptoKeyVersions.useToSign",
        "cloudkms.cryptoKeyVersions.useToVerify",
        "cloudkms.cryptoKeyVersions.viewPublicKey",
    ),
    "roles/cloudkms.verifier": (
        "cloudkms.cryptoKeyVersions.useToVerify",
        "cloudkms.cryptoKeyVersions.viewPublicKey",
    ),
    "roles/cloudkms.viewer": (
        "cloudkms.cryptoKeys.get",
        "cloudkms.cryptoKeys.list",
        "cloudkms.cryptoKeyVersions.get",
        "cloudkms.cryptoKeyVersions.list",
        "cloudkms.keyRings.get",
        "cloudkms.keyRings.list",
    ),
    "roles/cloudkms.expertPqcSigner": ("cloudkms.cryptoKeyVersions.managePqcSign",),
    "roles/cloudkms.expertRawAesCbc": ("cloudkms.cryptoKeyVersions.manageRawAesCbcKeys",),
    "roles/cloudkms.expertRawAesCtr": ("cloudkms.cryptoKeyVersions.manageRawAesCtrKeys",),
    "roles/cloudkms.expertRawPKCS1": ("cloudkms.cryptoKeyVersions.manageRawPKCS1Keys",),
}


@dataclass(frozen=True, slots=True)
class _RoleResolution:
    role_kind: str
    state: str
    modeled_kms_permissions: tuple[str, ...]
    custom_role_permissions: tuple[str, ...] = ()
    role_definition_address: str | None = None


class _ManagementSource(TypedDict):
    source: str
    scope_type: GcpKmsScopeType
    scope: str
    management_mode: str
    roles: list[str]


_ApplicableScopeType = GcpKmsScopeType | Literal["unrelated"]
_KEY_RING_PATH_PATTERN = re.compile(r"^projects/[^/]+/locations/[^/]+/keyRings/[^/]+$")


_GRANT_BASIS_BY_SCOPE: dict[GcpKmsScopeType, GcpKmsGrantBasis] = {
    "project": "project_iam",
    "key_ring": "key_ring_iam",
    "crypto_key": "crypto_key_iam",
}


class NormalizeKmsIamPostureStage:
    """Project exact Cloud KMS IAM grants onto key rings and keys."""

    name = "normalize_kms_iam_posture"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: GcpDecorationContext,
    ) -> None:
        iam_resources = tuple(
            resource
            for resource in resources
            if resource.resource_type
            in (
                GCP_PROJECT_IAM_RESOURCE_TYPES
                | GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES
                | GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES
            )
        )
        custom_roles = build_gcp_custom_role_index(resources)
        for key_ring in resources:
            if key_ring.resource_type != GcpResourceType.KMS_KEY_RING:
                continue
            grants, uncertainties = _kms_key_ring_iam_posture(
                key_ring,
                iam_resources,
                custom_roles,
                context,
            )
            gcp_mutations(key_ring).set_kms_key_ring_iam_posture(
                grants=grants,
                uncertainties=uncertainties,
            )

        for key in resources:
            if key.resource_type != GcpResourceType.KMS_CRYPTO_KEY:
                continue
            grants, uncertainties = _kms_iam_posture(
                key,
                iam_resources,
                custom_roles,
                context,
            )
            gcp_mutations(key).set_kms_iam_posture(
                grants=grants,
                uncertainties=uncertainties,
            )


def _kms_key_ring_iam_posture(
    key_ring_resource: NormalizedResource,
    iam_resources: tuple[NormalizedResource, ...],
    custom_roles: GcpCustomRoleIndex,
    context: GcpDecorationContext,
) -> tuple[list[GcpKmsKeyRingIamGrant], list[str]]:
    key_ring = _key_ring_resource_path(key_ring_resource)
    project = _project_from_path(key_ring)
    if key_ring is None or project is None:
        return [], [f"{key_ring_resource.address}: exact Cloud KMS key-ring ancestry is unresolved"]

    grants: list[GcpKmsKeyRingIamGrant] = []
    management_sources: list[_ManagementSource] = []
    uncertainties: list[str] = []
    for iam_resource in iam_resources:
        scope_type, scope = _applicable_key_ring_scope(
            iam_resource,
            key_ring_resource,
            key_ring,
            project,
            context,
        )
        if scope_type == "unrelated":
            continue
        if scope_type is None or scope is None:
            uncertainties.append(f"{iam_resource.address}: IAM scope is unresolved for {key_ring}")
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
                f"{iam_resource.address}: IAM policy_data is {policy_state or 'unresolved'} for {key_ring}"
            )
            continue

        for binding in source_bindings:
            if binding.get("role_state") == "unknown":
                uncertainties.append(f"{iam_resource.address}: IAM role is unresolved for {key_ring}")
                continue
            if binding.get("members_state") == "unknown":
                uncertainties.append(f"{iam_resource.address}: IAM members are unresolved for {key_ring}")
                continue

            role = _known_string(binding.get("role"))
            members = binding_members(binding)
            if role is None or not members:
                uncertainties.append(f"{iam_resource.address}: IAM role or members are unresolved for {key_ring}")
                continue

            role_resolution = _resolve_role(role, custom_roles)
            if not _role_may_affect_kms(role_resolution):
                continue
            if role_resolution.state not in {
                "resolved",
                "modeled_subset",
            }:
                uncertainties.append(
                    f"{iam_resource.address}: permissions for IAM role "
                    f"{role} are {role_resolution.state} for {key_ring}"
                )

            scope_effective_permissions = _scope_effective_permissions(
                role_resolution.modeled_kms_permissions,
                scope_type,
            )
            condition_state = _condition_state(binding)
            if condition_state == "unknown":
                uncertainties.append(
                    f"{iam_resource.address}: IAM condition applicability to {key_ring} is unknown after planning"
                )

            permissions_are_deterministic = role_resolution.state in {"resolved", "modeled_subset"} and bool(
                scope_effective_permissions
            )
            authorization_state = (
                "unknown"
                if (not permissions_are_deterministic or condition_state == "unknown")
                else "conditional"
                if condition_state == "configured"
                else "granted"
            )
            grant: GcpKmsKeyRingIamGrant = {
                "role": role,
                "role_kind": role_resolution.role_kind,
                "role_resolution_state": role_resolution.state,
                "modeled_kms_permissions": list(role_resolution.modeled_kms_permissions),
                "scope_effective_permissions": list(scope_effective_permissions),
                "members": members,
                "source": iam_resource.address,
                "source_type": iam_resource.resource_type,
                "scope_type": scope_type,
                "scope": scope,
                "source_scope_reference": (
                    iam_facts.project if scope_type == "project" else iam_facts.target_reference
                ),
                "project": project,
                "key_ring": key_ring,
                "condition_state": condition_state,
                "authorization_state": authorization_state,
                "management_mode": management_mode,
                "management_state": "unambiguous",
                "grant_basis": _GRANT_BASIS_BY_SCOPE[scope_type],
            }
            if role_resolution.custom_role_permissions:
                grant["custom_role_permissions"] = list(role_resolution.custom_role_permissions)
            if role_resolution.role_definition_address:
                grant["role_definition_address"] = role_resolution.role_definition_address
            condition = binding.get("condition")
            if isinstance(condition, Mapping) and condition:
                grant["condition"] = dict(condition)
            if policy_state:
                grant["policy_data_state"] = policy_state
            grants.append(grant)

    grants = _dedupe_key_ring_grants(grants)
    _apply_key_ring_management_ambiguity(
        grants,
        management_sources,
        uncertainties,
        key_ring,
    )
    grants.sort(
        key=lambda grant: (
            str(grant["scope_type"]),
            str(grant["scope"]),
            str(grant["source"]),
            str(grant["role"]),
            tuple(str(member) for member in grant["members"]),
        )
    )
    return grants, dedupe(uncertainties)


def _kms_iam_posture(
    key: NormalizedResource,
    iam_resources: tuple[NormalizedResource, ...],
    custom_roles: GcpCustomRoleIndex,
    context: GcpDecorationContext,
) -> tuple[list[GcpKmsIamGrant], list[str]]:
    key_path = _key_path(key)
    key_ring = _key_ring(key_path, gcp_facts(key).kms_key_ring)
    project = _project_from_path(key_path or key_ring)
    if key_path is None or key_ring is None or project is None:
        return [], [f"{key.address}: exact Cloud KMS key ancestry is unresolved"]

    grants: list[GcpKmsIamGrant] = []
    management_sources: list[_ManagementSource] = []
    uncertainties: list[str] = []
    for iam_resource in iam_resources:
        scope_type, scope = _applicable_scope(
            iam_resource,
            key,
            key_path,
            key_ring,
            project,
            context,
        )
        if scope_type == "unrelated":
            continue
        if scope_type is None or scope is None:
            uncertainties.append(f"{iam_resource.address}: IAM scope is unresolved for {key_path}")
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
                f"{iam_resource.address}: IAM policy_data is {policy_state or 'unresolved'} for {key_path}"
            )
            continue

        for binding in source_bindings:
            if binding.get("role_state") == "unknown":
                uncertainties.append(f"{iam_resource.address}: IAM role is unresolved for {key_path}")
                continue
            if binding.get("members_state") == "unknown":
                uncertainties.append(f"{iam_resource.address}: IAM members are unresolved for {key_path}")
                continue

            role = _known_string(binding.get("role"))
            members = binding_members(binding)
            if role is None or not members:
                uncertainties.append(f"{iam_resource.address}: IAM role or members are unresolved for {key_path}")
                continue

            role_resolution = _resolve_role(role, custom_roles)
            if not _role_may_affect_kms(role_resolution):
                continue
            if role_resolution.state not in {"resolved", "modeled_subset"}:
                uncertainties.append(
                    f"{iam_resource.address}: permissions for IAM role {role} are "
                    f"{role_resolution.state} for {key_path}"
                )

            scope_effective_permissions = _scope_effective_permissions(
                role_resolution.modeled_kms_permissions,
                scope_type,
            )
            condition_state = _condition_state(binding)
            if condition_state == "unknown":
                uncertainties.append(
                    f"{iam_resource.address}: IAM condition applicability to {key_path} is unknown after planning"
                )

            permissions_are_deterministic = role_resolution.state in {
                "resolved",
                "modeled_subset",
            } and bool(scope_effective_permissions)
            authorization_state = (
                "unknown"
                if not permissions_are_deterministic or condition_state == "unknown"
                else "conditional"
                if condition_state == "configured"
                else "granted"
            )
            grant: GcpKmsIamGrant = {
                "role": role,
                "role_kind": role_resolution.role_kind,
                "role_resolution_state": role_resolution.state,
                "modeled_kms_permissions": list(role_resolution.modeled_kms_permissions),
                "scope_effective_permissions": list(scope_effective_permissions),
                "members": members,
                "source": iam_resource.address,
                "source_type": iam_resource.resource_type,
                "scope_type": scope_type,
                "scope": scope,
                "source_scope_reference": (
                    iam_facts.project if scope_type == "project" else iam_facts.target_reference
                ),
                "project": project,
                "key_ring": key_ring,
                "crypto_key": key_path,
                "crypto_key_address": key.address,
                "condition_state": condition_state,
                "authorization_state": authorization_state,
                "management_mode": management_mode,
                "management_state": "unambiguous",
                "grant_basis": _GRANT_BASIS_BY_SCOPE[scope_type],
            }
            if role_resolution.custom_role_permissions:
                grant["custom_role_permissions"] = list(role_resolution.custom_role_permissions)
            if role_resolution.role_definition_address:
                grant["role_definition_address"] = role_resolution.role_definition_address
            condition = binding.get("condition")
            if isinstance(condition, Mapping) and condition:
                grant["condition"] = dict(condition)
            if policy_state:
                grant["policy_data_state"] = policy_state
            grants.append(grant)

    grants = _dedupe_grants(grants)
    _apply_management_ambiguity(
        grants,
        management_sources,
        uncertainties,
        key_path,
    )
    grants.sort(
        key=lambda grant: (
            str(grant["scope_type"]),
            str(grant["scope"]),
            str(grant["source"]),
            str(grant["role"]),
            tuple(str(member) for member in grant["members"]),
        )
    )
    return grants, dedupe(uncertainties)


def kms_key_ring_iam_target_applies_to_key(
    iam_resource: NormalizedResource,
    key: NormalizedResource,
    index: GcpResourceIndex,
) -> bool:
    target_reference = gcp_facts(iam_resource).target_reference
    if target_reference is None:
        return False

    resolution = resolve_resource_iam_target(
        iam_resource,
        index,
        resource_types={GcpResourceType.KMS_KEY_RING},
    )
    if resolution.state == "ambiguous":
        return False

    key_path = _key_path(key)
    key_ring = _key_ring(key_path, gcp_facts(key).kms_key_ring)
    if key_ring is None:
        return False

    selected = resolution.selected_candidate
    if selected is not None:
        selected_references = _reference_keys(
            selected.address,
            selected.identifier,
            _key_ring_resource_path(selected),
            gcp_facts(selected).kms_key_ring,
        )
        key_references = _reference_keys(key_ring, gcp_facts(key).kms_key_ring)
        return bool(selected_references.intersection(key_references))

    target_key = gcp_reference_key(target_reference, GCP_NETWORK_REFERENCE_SUFFIXES)
    if not _is_exact_kms_key_ring_reference(target_key):
        return False
    return target_key in _reference_keys(key_ring, gcp_facts(key).kms_key_ring)


def _reference_keys(*values: object) -> set[str]:
    references: set[str] = set()
    for value in values:
        text = _known_string(value)
        if text is not None:
            references.add(gcp_reference_key(text, GCP_NETWORK_REFERENCE_SUFFIXES))
    return references


def _is_exact_kms_key_ring_reference(reference: str) -> bool:
    if _KEY_RING_PATH_PATTERN.fullmatch(reference.rstrip("/")) is not None:
        return True
    return is_gcp_terraform_resource_address(reference) and (
        reference.startswith("google_kms_key_ring.") or ".google_kms_key_ring." in reference
    )


def _applicable_scope(
    iam_resource: NormalizedResource,
    key: NormalizedResource,
    key_path: str,
    key_ring: str,
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

    target_reference = facts.target_reference
    if target_reference is None:
        return None, None
    if iam_resource.resource_type in GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES:
        return (
            ("key_ring", key_ring)
            if kms_key_ring_iam_target_applies_to_key(iam_resource, key, context.index)
            else ("unrelated", None)
        )

    resolution = resolve_resource_iam_target(
        iam_resource,
        context.index,
        resource_types={GcpResourceType.KMS_CRYPTO_KEY},
    )
    resolved = resolution.selected_candidate
    if resolved is None:
        return (None, None) if resolution.state == "ambiguous" else ("unrelated", None)
    return (
        ("crypto_key", key_path)
        if resolved.address == key.address and resolved.resource_type == GcpResourceType.KMS_CRYPTO_KEY
        else ("unrelated", None)
    )


def _applicable_key_ring_scope(
    iam_resource: NormalizedResource,
    key_ring_resource: NormalizedResource,
    key_ring: str,
    project: str,
    context: GcpDecorationContext,
) -> tuple[_ApplicableScopeType | None, str | None]:
    facts = gcp_facts(iam_resource)
    if iam_resource.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES:
        if facts.iam_scope_reference_state in {
            "unknown",
            "not_configured",
        }:
            return None, None
        iam_project = _normalize_project(facts.project)
        if iam_project is None:
            return None, None
        return ("project", project) if iam_project == project else ("unrelated", None)

    if iam_resource.resource_type not in GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES:
        return "unrelated", None
    if facts.iam_scope_reference_state in {
        "unknown",
        "not_configured",
    }:
        return None, None
    target_reference = facts.target_reference
    if target_reference is None:
        return None, None
    resolution = resolve_resource_iam_target(
        iam_resource,
        context.index,
        resource_types={GcpResourceType.KMS_KEY_RING},
    )
    resolved = resolution.selected_candidate
    if resolved is None:
        return (None, None) if resolution.state == "ambiguous" else ("unrelated", None)
    return (
        ("key_ring", key_ring)
        if resolved.address == key_ring_resource.address and resolved.resource_type == GcpResourceType.KMS_KEY_RING
        else ("unrelated", None)
    )


def _resolve_role(
    role: str,
    custom_roles: GcpCustomRoleIndex,
) -> _RoleResolution:
    predefined = _PREDEFINED_KMS_ROLE_PERMISSIONS.get(role)
    if predefined is not None:
        return _RoleResolution("predefined", "modeled_subset", predefined)

    if not _looks_like_custom_role(role):
        return _RoleResolution("predefined", "unmodeled", ())

    resolution = custom_roles.resolve(role)
    custom = resolution.selected_candidate
    if custom is None:
        state = "ambiguous" if resolution.state == "ambiguous" else "external_or_unresolved"
        return _RoleResolution("custom", state, ())

    facts = gcp_facts(custom)
    permissions_state = facts.custom_role_permissions_state or "unknown"
    if permissions_state != "configured":
        return _RoleResolution(
            "custom",
            permissions_state,
            (),
            role_definition_address=custom.address,
        )
    permissions = tuple(sorted(set(facts.custom_role_permissions)))
    kms_permissions = tuple(permission for permission in permissions if permission.startswith("cloudkms."))
    return _RoleResolution(
        "custom",
        "resolved",
        kms_permissions,
        custom_role_permissions=permissions,
        role_definition_address=custom.address,
    )


def _role_may_affect_kms(resolution: _RoleResolution) -> bool:
    if resolution.role_kind == "custom":
        return resolution.state != "resolved" or bool(resolution.modeled_kms_permissions)
    return True


def _scope_effective_permissions(
    permissions: tuple[str, ...],
    scope_type: GcpKmsScopeType,
) -> tuple[str, ...]:
    if scope_type in {"project", "key_ring"}:
        return permissions
    return tuple(
        permission
        for permission in permissions
        if permission.startswith(
            (
                "cloudkms.cryptoKeys.",
                "cloudkms.cryptoKeyVersions.",
            )
        )
    )


def _management_mode(resource: NormalizedResource) -> str:
    if resource.resource_type.endswith("_iam_policy"):
        return "authoritative_policy"
    if resource.resource_type.endswith("_iam_binding"):
        return "authoritative_role_binding"
    return "additive_member"


def _apply_management_ambiguity(
    grants: list[GcpKmsIamGrant],
    management_sources: list[_ManagementSource],
    uncertainties: list[str],
    key_path: str,
) -> None:
    scopes: set[tuple[GcpKmsScopeType, str]] = {
        (source["scope_type"], source["scope"]) for source in management_sources
    }
    for scope_type, scope in sorted(scopes):
        sources = [
            source for source in management_sources if source["scope_type"] == scope_type and source["scope"] == scope
        ]
        policy_sources: set[str] = {
            str(source["source"]) for source in sources if source["management_mode"] == "authoritative_policy"
        }
        other_sources: set[str] = {
            str(source["source"]) for source in sources if source["management_mode"] != "authoritative_policy"
        }
        if len(policy_sources) > 1 or (policy_sources and other_sources):
            _mark_ambiguous(
                grants,
                scope_type=scope_type,
                scope=scope,
            )
            uncertainties.append(
                f"effective IAM at {scope_type} scope {scope} for {key_path} is "
                "ambiguous because authoritative policy and other Terraform IAM "
                "managers overlap"
            )
            continue

        roles: list[str] = sorted({role for source in sources for role in source["roles"]})
        for role in roles:
            binding_sources: set[str] = {
                str(source["source"])
                for source in sources
                if source["management_mode"] == "authoritative_role_binding" and role in source["roles"]
            }
            member_sources: set[str] = {
                str(source["source"])
                for source in sources
                if source["management_mode"] == "additive_member" and role in source["roles"]
            }
            if len(binding_sources) <= 1 and not (binding_sources and member_sources):
                continue
            _mark_ambiguous(
                grants,
                scope_type=scope_type,
                scope=scope,
                role=role,
            )
            uncertainties.append(
                f"effective IAM membership for role {role} at {scope_type} scope "
                f"{scope} for {key_path} is ambiguous because authoritative role "
                "bindings overlap with another Terraform IAM manager"
            )


def _mark_ambiguous(
    grants: list[GcpKmsIamGrant],
    *,
    scope_type: GcpKmsScopeType,
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


def _apply_key_ring_management_ambiguity(
    grants: list[GcpKmsKeyRingIamGrant],
    management_sources: list[_ManagementSource],
    uncertainties: list[str],
    key_ring: str,
) -> None:
    scopes: set[tuple[GcpKmsScopeType, str]] = {
        (source["scope_type"], source["scope"]) for source in management_sources
    }
    for scope_type, scope in sorted(scopes):
        sources = [
            source for source in management_sources if source["scope_type"] == scope_type and source["scope"] == scope
        ]
        policy_sources = {source["source"] for source in sources if source["management_mode"] == "authoritative_policy"}
        other_sources = {source["source"] for source in sources if source["management_mode"] != "authoritative_policy"}
        if len(policy_sources) > 1 or (policy_sources and other_sources):
            _mark_key_ring_ambiguous(
                grants,
                scope_type=scope_type,
                scope=scope,
            )
            uncertainties.append(
                f"effective IAM at {scope_type} scope {scope} for "
                f"{key_ring} is ambiguous because authoritative policy and "
                "other Terraform IAM managers overlap"
            )
            continue

        roles = sorted({role for source in sources for role in source["roles"]})
        for role in roles:
            binding_sources = {
                source["source"]
                for source in sources
                if source["management_mode"] == "authoritative_role_binding" and role in source["roles"]
            }
            member_sources = {
                source["source"]
                for source in sources
                if source["management_mode"] == "additive_member" and role in source["roles"]
            }
            if len(binding_sources) <= 1 and not (binding_sources and member_sources):
                continue
            _mark_key_ring_ambiguous(
                grants,
                scope_type=scope_type,
                scope=scope,
                role=role,
            )
            uncertainties.append(
                f"effective IAM membership for role {role} at "
                f"{scope_type} scope {scope} for {key_ring} is ambiguous "
                "because authoritative role bindings overlap with another "
                "Terraform IAM manager"
            )


def _mark_key_ring_ambiguous(
    grants: list[GcpKmsKeyRingIamGrant],
    *,
    scope_type: GcpKmsScopeType,
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


def _condition_state(binding: Mapping[str, Any]) -> str:
    if binding.get("condition_state") == "unknown":
        return "unknown"
    condition = binding.get("condition")
    return "configured" if isinstance(condition, Mapping) and condition else "not_configured"


def _key_ring_resource_path(
    key_ring_resource: NormalizedResource,
) -> str | None:
    facts = gcp_facts(key_ring_resource)
    for value in (facts.kms_key_ring, key_ring_resource.identifier):
        text = _known_string(value)
        if text and _KEY_RING_PATH_PATTERN.fullmatch(text.rstrip("/")) is not None:
            return text.rstrip("/")
    return None


def _key_path(key: NormalizedResource) -> str | None:
    facts = gcp_facts(key)
    for value in (facts.kms_crypto_key_reference, key.identifier):
        text = _known_string(value)
        if text and "/cryptoKeys/" in text and text.startswith("projects/"):
            return text.rstrip("/")
    key_ring = _known_string(facts.kms_key_ring)
    key_name = _known_string(facts.resource_name)
    if key_ring and key_name and "/" not in key_name:
        return f"{key_ring.rstrip('/')}/cryptoKeys/{key_name}"
    return None


def _key_ring(key_path: str | None, value: object) -> str | None:
    text = _known_string(value)
    if text and "/keyRings/" in text:
        return text.rstrip("/")
    if key_path and "/cryptoKeys/" in key_path:
        return key_path.rsplit("/cryptoKeys/", 1)[0]
    return None


def _project_from_path(value: str | None) -> str | None:
    if value is None:
        return None
    parts = [part for part in value.split("/") if part]
    if len(parts) >= 2 and parts[0] == "projects":
        return parts[1]
    return None


def _normalize_project(value: object) -> str | None:
    text = _known_string(value)
    if text is None:
        return None
    parts = [part for part in text.split("/") if part]
    if len(parts) == 2 and parts[0] == "projects":
        return parts[1]
    return text if "/" not in text else None


def _looks_like_custom_role(role: str) -> bool:
    return role.startswith(("projects/", "organizations/")) or "iam_custom_role." in role


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _dedupe_key_ring_grants(
    grants: list[GcpKmsKeyRingIamGrant],
) -> list[GcpKmsKeyRingIamGrant]:
    deduped: list[GcpKmsKeyRingIamGrant] = []
    for grant in grants:
        if grant not in deduped:
            deduped.append(grant)
    return deduped


def _dedupe_grants(grants: list[GcpKmsIamGrant]) -> list[GcpKmsIamGrant]:
    deduped: list[GcpKmsIamGrant] = []
    for grant in grants:
        if grant not in deduped:
            deduped.append(grant)
    return deduped
