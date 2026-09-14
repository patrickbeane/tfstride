from __future__ import annotations

from collections.abc import Iterable, Mapping

from tfstride.identity import (
    AssignmentScopeKind,
    PrincipalType,
    PrivilegeCategory,
    PrivilegeConfidence,
    PrivilegedAccessGrant,
    PrivilegedAccessPosture,
    PrivilegedAssignmentScope,
    PrivilegedPrincipal,
)
from tfstride.models import NormalizedResource
from tfstride.providers.coercion import append_unique, dedupe
from tfstride.providers.gcp.custom_role_index import GcpCustomRoleIndex, custom_role_permissions
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.iam import iam_bindings, resource_iam_target_reference
from tfstride.providers.gcp.resource_types import (
    GCP_FOLDER_IAM_RESOURCE_TYPES,
    GCP_ORGANIZATION_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES,
)

_GCP_PROVIDER = "gcp"

_PROJECT_ROLE_CATEGORIES: dict[str, tuple[PrivilegeCategory, ...]] = {
    "roles/owner": (
        PrivilegeCategory.FULL_ADMIN,
        PrivilegeCategory.IAM_ADMIN,
        PrivilegeCategory.POLICY_ADMIN,
    ),
    "roles/editor": (
        PrivilegeCategory.COMPUTE_ADMIN,
        PrivilegeCategory.NETWORK_ADMIN,
        PrivilegeCategory.DATA_ADMIN,
    ),
    "roles/iam.serviceAccountTokenCreator": (PrivilegeCategory.PRIVILEGE_ESCALATION,),
    "roles/iam.serviceAccountUser": (PrivilegeCategory.PRIVILEGE_ESCALATION,),
    "roles/iam.serviceAccountAdmin": (
        PrivilegeCategory.IAM_ADMIN,
        PrivilegeCategory.PRIVILEGE_ESCALATION,
    ),
    "roles/iam.securityAdmin": (
        PrivilegeCategory.IAM_ADMIN,
        PrivilegeCategory.POLICY_ADMIN,
    ),
    "roles/resourcemanager.iam.projectIamAdmin": (
        PrivilegeCategory.IAM_ADMIN,
        PrivilegeCategory.POLICY_ADMIN,
    ),
}
_ORG_FOLDER_ROLE_CATEGORIES: dict[str, tuple[PrivilegeCategory, ...]] = {
    **_PROJECT_ROLE_CATEGORIES,
    "roles/accesscontextmanager.policyAdmin": (PrivilegeCategory.POLICY_ADMIN,),
    "roles/billing.admin": (PrivilegeCategory.POLICY_ADMIN,),
    "roles/iam.organizationRoleAdmin": (
        PrivilegeCategory.IAM_ADMIN,
        PrivilegeCategory.ROLE_ASSIGNMENT,
    ),
    "roles/orgpolicy.policyAdmin": (PrivilegeCategory.POLICY_ADMIN,),
    "roles/resourcemanager.folderAdmin": (
        PrivilegeCategory.IAM_ADMIN,
        PrivilegeCategory.COMPUTE_ADMIN,
    ),
    "roles/resourcemanager.organizationAdmin": (
        PrivilegeCategory.IAM_ADMIN,
        PrivilegeCategory.COMPUTE_ADMIN,
    ),
    "roles/resourcemanager.iam.projectCreator": (PrivilegeCategory.COMPUTE_ADMIN,),
    "roles/resourcemanager.iam.projectDeleter": (PrivilegeCategory.COMPUTE_ADMIN,),
}
_SERVICE_ACCOUNT_ROLE_CATEGORIES: dict[str, tuple[PrivilegeCategory, ...]] = {
    "roles/iam.serviceAccountAdmin": (
        PrivilegeCategory.IAM_ADMIN,
        PrivilegeCategory.PRIVILEGE_ESCALATION,
    ),
    "roles/iam.serviceAccountTokenCreator": (PrivilegeCategory.PRIVILEGE_ESCALATION,),
    "roles/iam.serviceAccountUser": (PrivilegeCategory.PRIVILEGE_ESCALATION,),
}

_DATA_ADMIN_ROLE_PREFIXES = (
    "roles/bigquery.",
    "roles/cloudsql.",
    "roles/pubsub.",
    "roles/storage.",
)
_SECRETS_ADMIN_ROLE_PREFIXES = ("roles/secretmanager.",)
_KEY_ADMIN_ROLE_PREFIXES = ("roles/cloudkms.",)
_COMPUTE_ADMIN_ROLE_PREFIXES = (
    "roles/cloudbuild.",
    "roles/cloudfunctions.",
    "roles/compute.",
    "roles/container.",
    "roles/run.",
)
_NETWORK_ADMIN_ROLE_PREFIXES = ("roles/compute.network", "roles/compute.security", "roles/dns.")
_AUDIT_ADMIN_ROLE_PREFIXES = (
    "roles/cloudasset.",
    "roles/logging.",
    "roles/monitoring.",
    "roles/securitycenter.",
)


def build_gcp_privileged_access_posture(
    resource: NormalizedResource,
    *,
    custom_roles: GcpCustomRoleIndex | None = None,
) -> PrivilegedAccessPosture:
    if resource.provider != _GCP_PROVIDER:
        return PrivilegedAccessPosture(provider=_GCP_PROVIDER)

    grants: list[PrivilegedAccessGrant] = []
    unresolved: list[str] = []
    for binding in iam_bindings(resource):
        role = _known_string(binding.get("role"))
        members = _binding_members(binding)
        if role is None:
            unresolved.append(f"{resource.address}: missing IAM role")
            continue
        if not members:
            unresolved.append(f"{resource.address}: role {role} has no deterministic members")
            continue
        categories, confidence, permission_patterns, role_uncertainties = _role_privilege_posture(
            resource,
            role,
            custom_roles,
        )
        unresolved.extend(role_uncertainties)
        if not categories:
            continue
        for member in members:
            grants.append(
                _grant_for_binding(
                    resource,
                    binding,
                    role=role,
                    member=member,
                    categories=categories,
                    confidence=confidence,
                    permission_patterns=permission_patterns,
                )
            )

    return PrivilegedAccessPosture(provider=_GCP_PROVIDER, grants=tuple(grants), unresolved_assignments=unresolved)


def serialize_privileged_access_posture(posture: PrivilegedAccessPosture) -> list[dict[str, object]]:
    return [_serialize_grant(grant) for grant in posture.grants]


def deserialize_privileged_access_grants(records: Iterable[dict[str, object]]) -> tuple[PrivilegedAccessGrant, ...]:
    grants: list[PrivilegedAccessGrant] = []
    for record in records:
        grants.append(
            PrivilegedAccessGrant(
                provider=_record_string(record, "provider") or _GCP_PROVIDER,
                principal=PrivilegedPrincipal(
                    principal_type=_record_string(record, "principal_type") or PrincipalType.UNKNOWN,
                    identifier=_record_string(record, "principal_identifier"),
                    display_name=_record_string(record, "principal_display_name"),
                    source_address=_record_string(record, "principal_source_address"),
                ),
                assignment_scope=PrivilegedAssignmentScope(
                    scope_kind=_record_string(record, "scope_kind") or AssignmentScopeKind.UNKNOWN,
                    value=_record_string(record, "scope_value"),
                    source_address=_record_string(record, "scope_source_address"),
                ),
                privilege_categories=tuple(_record_string_list(record, "privilege_categories")),
                confidence=_record_string(record, "confidence") or PrivilegeConfidence.HIGH,
                assignment_source_address=_record_string(record, "assignment_source_address"),
                role_name=_record_string(record, "role_name"),
                role_id=_record_string(record, "role_id"),
                permission_patterns=tuple(_record_string_list(record, "permission_patterns")),
                evidence=tuple(_record_string_list(record, "evidence")),
                uncertainties=tuple(_record_string_list(record, "uncertainties")),
            )
        )
    return tuple(grants)


def _grant_for_binding(
    resource: NormalizedResource,
    binding: Mapping[str, object],
    *,
    role: str,
    member: str,
    categories: tuple[PrivilegeCategory, ...],
    confidence: PrivilegeConfidence,
    permission_patterns: tuple[str, ...],
) -> PrivilegedAccessGrant:
    condition = binding.get("condition") if isinstance(binding.get("condition"), dict) else None
    return PrivilegedAccessGrant(
        provider=_GCP_PROVIDER,
        principal=PrivilegedPrincipal(
            principal_type=_principal_type(member),
            identifier=member,
            display_name=member,
            source_address=resource.address,
        ),
        assignment_scope=_assignment_scope(resource),
        privilege_categories=categories,
        confidence=confidence,
        assignment_source_address=resource.address,
        role_name=role,
        role_id=role,
        permission_patterns=permission_patterns,
        evidence=tuple(_binding_evidence(resource, role, member, condition)),
    )


def _role_privilege_posture(
    resource: NormalizedResource,
    role: str,
    custom_roles: GcpCustomRoleIndex | None,
) -> tuple[tuple[PrivilegeCategory, ...], PrivilegeConfidence, tuple[str, ...], tuple[str, ...]]:
    if custom_roles is not None:
        resolution = custom_roles.resolve(role)
        if resolution.state == "ambiguous":
            addresses = ", ".join(candidate.address for candidate in resolution.candidates)
            return (
                (),
                PrivilegeConfidence.LOW,
                (),
                (f"{resource.address}: custom role {role} is ambiguous across {addresses}",),
            )
        permissions = custom_role_permissions(role, custom_roles)
        if permissions:
            categories = _permission_categories(permissions)
            return categories, PrivilegeConfidence.HIGH, tuple(_privileged_permissions(permissions)), ()
    if _looks_like_custom_role(role):
        return (), PrivilegeConfidence.LOW, (), (f"{resource.address}: custom role {role} was not resolved",)

    normalized = role.strip()
    categories = _predefined_role_categories(resource, normalized)
    if categories:
        return categories, PrivilegeConfidence.HIGH, (normalized,), ()
    inferred_categories = _admin_role_categories(normalized)
    if inferred_categories:
        return inferred_categories, PrivilegeConfidence.MEDIUM, (normalized,), ()
    return (), PrivilegeConfidence.LOW, (), ()


def _predefined_role_categories(resource: NormalizedResource, role: str) -> tuple[PrivilegeCategory, ...]:
    if resource.resource_type in GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES:
        return _SERVICE_ACCOUNT_ROLE_CATEGORIES.get(role, ())
    if resource.resource_type in GCP_ORGANIZATION_IAM_RESOURCE_TYPES | GCP_FOLDER_IAM_RESOURCE_TYPES:
        return _ORG_FOLDER_ROLE_CATEGORIES.get(role, ())
    if resource.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES:
        return _PROJECT_ROLE_CATEGORIES.get(role, ())
    return _resource_role_categories(role)


def _resource_role_categories(role: str) -> tuple[PrivilegeCategory, ...]:
    if role in _PROJECT_ROLE_CATEGORIES:
        return _PROJECT_ROLE_CATEGORIES[role]
    categories: list[PrivilegeCategory] = []
    if role.startswith(_DATA_ADMIN_ROLE_PREFIXES) and (role.endswith(".admin") or role.endswith(".dataOwner")):
        categories.append(PrivilegeCategory.DATA_ADMIN)
    if role.startswith(_SECRETS_ADMIN_ROLE_PREFIXES) and role.endswith(".admin"):
        categories.append(PrivilegeCategory.SECRETS_ADMIN)
    if role.startswith(_KEY_ADMIN_ROLE_PREFIXES) and role.endswith(".admin"):
        categories.append(PrivilegeCategory.KEY_ADMIN)
    return tuple(categories)


def _admin_role_categories(role: str) -> tuple[PrivilegeCategory, ...]:
    if not role.startswith("roles/") or "admin" not in role.rsplit("/", 1)[-1].lower():
        return ()
    categories: list[PrivilegeCategory] = []
    if role.startswith(_DATA_ADMIN_ROLE_PREFIXES):
        categories.append(PrivilegeCategory.DATA_ADMIN)
    elif role.startswith(_SECRETS_ADMIN_ROLE_PREFIXES):
        categories.append(PrivilegeCategory.SECRETS_ADMIN)
    elif role.startswith(_KEY_ADMIN_ROLE_PREFIXES):
        categories.append(PrivilegeCategory.KEY_ADMIN)
    elif role.startswith(_NETWORK_ADMIN_ROLE_PREFIXES):
        categories.append(PrivilegeCategory.NETWORK_ADMIN)
    elif role.startswith(_AUDIT_ADMIN_ROLE_PREFIXES):
        categories.append(PrivilegeCategory.AUDIT_ADMIN)
    elif role.startswith(_COMPUTE_ADMIN_ROLE_PREFIXES):
        categories.append(PrivilegeCategory.COMPUTE_ADMIN)
    else:
        categories.append(PrivilegeCategory.IAM_ADMIN)
    return tuple(categories)


def _permission_categories(permissions: tuple[str, ...]) -> tuple[PrivilegeCategory, ...]:
    categories: list[PrivilegeCategory] = []
    for permission in permissions:
        normalized = permission.strip()
        if not normalized:
            continue
        if normalized == "*":
            append_unique(categories, PrivilegeCategory.FULL_ADMIN)
        if normalized.endswith(".setIamPolicy") or normalized.startswith("resourcemanager.iam."):
            append_unique(categories, PrivilegeCategory.IAM_ADMIN)
            append_unique(categories, PrivilegeCategory.POLICY_ADMIN)
        if normalized.startswith("iam.roles."):
            append_unique(categories, PrivilegeCategory.IAM_ADMIN)
            append_unique(categories, PrivilegeCategory.ROLE_ASSIGNMENT)
        if normalized.startswith("iam.serviceAccounts."):
            append_unique(categories, PrivilegeCategory.PRIVILEGE_ESCALATION)
        if normalized.startswith(("storage.", "bigquery.", "cloudsql.", "pubsub.")):
            append_unique(categories, PrivilegeCategory.DATA_ADMIN)
        if normalized.startswith("secretmanager."):
            append_unique(categories, PrivilegeCategory.SECRETS_ADMIN)
        if normalized.startswith("cloudkms."):
            append_unique(categories, PrivilegeCategory.KEY_ADMIN)
        if normalized.startswith(("compute.", "container.", "run.", "cloudfunctions.", "cloudbuild.")):
            append_unique(categories, PrivilegeCategory.COMPUTE_ADMIN)
        if normalized.startswith(("logging.", "monitoring.", "cloudasset.", "securitycenter.")):
            append_unique(categories, PrivilegeCategory.AUDIT_ADMIN)
    return tuple(categories)


def _privileged_permissions(permissions: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for permission in permissions:
        if _permission_categories((permission,)):
            values.append(permission)
    return dedupe(values)


def _assignment_scope(resource: NormalizedResource) -> PrivilegedAssignmentScope:
    if resource.resource_type in GCP_PROJECT_IAM_RESOURCE_TYPES:
        return PrivilegedAssignmentScope(
            AssignmentScopeKind.PROJECT, value=_get_string(resource, GcpResourceMetadata.PROJECT)
        )
    if resource.resource_type in GCP_ORGANIZATION_IAM_RESOURCE_TYPES:
        return PrivilegedAssignmentScope(
            AssignmentScopeKind.ORGANIZATION,
            value=_get_string(resource, GcpResourceMetadata.ORGANIZATION_ID),
        )
    if resource.resource_type in GCP_FOLDER_IAM_RESOURCE_TYPES:
        return PrivilegedAssignmentScope(
            AssignmentScopeKind.FOLDER, value=_get_string(resource, GcpResourceMetadata.FOLDER_ID)
        )
    target = resource_iam_target_reference(resource)
    return PrivilegedAssignmentScope(AssignmentScopeKind.RESOURCE, value=target, source_address=resource.address)


def _principal_type(member: str) -> PrincipalType:
    if member in {"allUsers", "allAuthenticatedUsers"}:
        return PrincipalType.ANY
    if member.startswith("user:"):
        return PrincipalType.HUMAN_USER
    if member.startswith(("group:", "domain:")):
        return PrincipalType.GROUP
    if member.startswith("serviceAccount:"):
        return PrincipalType.SERVICE_ACCOUNT
    if member.startswith(("principal://", "principalSet://")):
        return PrincipalType.WORKLOAD
    return PrincipalType.UNKNOWN


def _binding_members(binding: Mapping[str, object]) -> list[str]:
    members = binding.get("members")
    if isinstance(members, list | tuple):
        return [_known for member in members if (_known := _known_string(member))]
    member = _known_string(members)
    return [member] if member else []


def _binding_evidence(
    resource: NormalizedResource,
    role: str,
    member: str,
    condition: object | None,
) -> list[str]:
    values = [
        f"source={resource.address}",
        f"role={role}",
        f"member={member}",
    ]
    scope = _assignment_scope(resource)
    values.append(f"scope_kind={scope.scope_kind.value}")
    if scope.value:
        values.append(f"scope_value={scope.value}")
    if isinstance(condition, Mapping):
        expression = _known_string(condition.get("expression"))
        if expression:
            values.append(f"condition_expression={expression}")
    return values


def _serialize_grant(grant: PrivilegedAccessGrant) -> dict[str, object]:
    return {
        "provider": grant.provider,
        "principal_type": grant.principal.principal_type.value,
        "principal_identifier": grant.principal.identifier,
        "principal_display_name": grant.principal.display_name,
        "principal_source_address": grant.principal.source_address,
        "scope_kind": grant.assignment_scope.scope_kind.value,
        "scope_value": grant.assignment_scope.value,
        "scope_source_address": grant.assignment_scope.source_address,
        "privilege_categories": [category.value for category in grant.privilege_categories],
        "confidence": grant.confidence.value,
        "assignment_source_address": grant.assignment_source_address,
        "role_name": grant.role_name,
        "role_id": grant.role_id,
        "permission_patterns": list(grant.permission_patterns),
        "evidence": list(grant.evidence),
        "uncertainties": list(grant.uncertainties),
    }


def _record_string(record: Mapping[str, object], key: str) -> str | None:
    value = record.get(key)
    return _known_string(value)


def _record_string_list(record: Mapping[str, object], key: str) -> list[str]:
    value = record.get(key)
    if not isinstance(value, list | tuple):
        return []
    return [normalized for item in value if (normalized := _known_string(item))]


def _known_string(value: object) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _get_string(resource: NormalizedResource, field: object) -> str | None:
    return _known_string(resource.get_metadata_field(field))


def _looks_like_custom_role(role: str) -> bool:
    return "/roles/" in role and not role.startswith("roles/")
