from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Literal

from tfstride.models import NormalizedResource
from tfstride.providers.azure.arm_control_plane_authorization import azure_arm_scope_contains
from tfstride.providers.azure.key_vault_evidence import (
    AzureKeyVaultAuthorizationGrant,
    AzureKeyVaultAuthorizationModel,
    AzureKeyVaultGrantScopeType,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.coercion import dedupe

_MANAGEMENT_GROUP_SCOPE_PATTERN = re.compile(
    r"^/providers/Microsoft\.Management/managementGroups/(?P<name>[^/]+)/?\Z",
    re.IGNORECASE,
)
_SUBSCRIPTION_SCOPE_PATTERN = re.compile(
    r"^/subscriptions/(?P<subscription>[^/]+)/?\Z",
    re.IGNORECASE,
)
_RESOURCE_GROUP_SCOPE_PATTERN = re.compile(
    r"^/subscriptions/(?P<subscription>[^/]+)/resourceGroups/(?P<resource_group>[^/]+)/?\Z",
    re.IGNORECASE,
)
_VAULT_ARM_ID_PATTERN = re.compile(
    r"^/subscriptions/(?P<subscription>[^/]+)/resourceGroups/(?P<resource_group>[^/]+)/"
    r"providers/Microsoft\.KeyVault/vaults/(?P<vault>[^/]+)/?\Z",
    re.IGNORECASE,
)

_ACCESS_CLASS_ORDER = (
    "metadata_read",
    "cryptographic_use",
    "key_backup",
    "key_release",
    "key_recovery",
    "key_management",
    "destructive_administration",
)


@dataclass(frozen=True, slots=True)
class _KeyOperation:
    name: str
    data_action: str
    access_classes: tuple[str, ...]


_KEY_OPERATIONS = (
    _KeyOperation(
        "read",
        "Microsoft.KeyVault/vaults/keys/read",
        ("metadata_read",),
    ),
    _KeyOperation(
        "create",
        "Microsoft.KeyVault/vaults/keys/create/action",
        ("key_management",),
    ),
    _KeyOperation(
        "import",
        "Microsoft.KeyVault/vaults/keys/import/action",
        ("key_management",),
    ),
    _KeyOperation(
        "update",
        "Microsoft.KeyVault/vaults/keys/update/action",
        ("key_management",),
    ),
    _KeyOperation(
        "recover",
        "Microsoft.KeyVault/vaults/keys/recover/action",
        ("key_recovery", "key_management"),
    ),
    _KeyOperation(
        "restore",
        "Microsoft.KeyVault/vaults/keys/restore/action",
        ("key_recovery", "key_management"),
    ),
    _KeyOperation(
        "delete",
        "Microsoft.KeyVault/vaults/keys/delete",
        ("destructive_administration",),
    ),
    _KeyOperation(
        "backup",
        "Microsoft.KeyVault/vaults/keys/backup/action",
        ("key_backup",),
    ),
    _KeyOperation(
        "purge",
        "Microsoft.KeyVault/vaults/keys/purge/action",
        ("destructive_administration",),
    ),
    _KeyOperation(
        "encrypt",
        "Microsoft.KeyVault/vaults/keys/encrypt/action",
        ("cryptographic_use",),
    ),
    _KeyOperation(
        "decrypt",
        "Microsoft.KeyVault/vaults/keys/decrypt/action",
        ("cryptographic_use",),
    ),
    _KeyOperation(
        "wrap",
        "Microsoft.KeyVault/vaults/keys/wrap/action",
        ("cryptographic_use",),
    ),
    _KeyOperation(
        "unwrap",
        "Microsoft.KeyVault/vaults/keys/unwrap/action",
        ("cryptographic_use",),
    ),
    _KeyOperation(
        "sign",
        "Microsoft.KeyVault/vaults/keys/sign/action",
        ("cryptographic_use",),
    ),
    _KeyOperation(
        "verify",
        "Microsoft.KeyVault/vaults/keys/verify/action",
        ("cryptographic_use",),
    ),
    _KeyOperation(
        "release",
        "Microsoft.KeyVault/vaults/keys/release/action",
        ("key_release",),
    ),
    _KeyOperation(
        "rotate",
        "Microsoft.KeyVault/vaults/keys/rotate/action",
        ("key_management",),
    ),
    _KeyOperation(
        "get_rotation_policy",
        "Microsoft.KeyVault/vaults/keyrotationpolicies/read",
        ("metadata_read",),
    ),
    _KeyOperation(
        "set_rotation_policy",
        "Microsoft.KeyVault/vaults/keyrotationpolicies/write",
        ("key_management",),
    ),
)

_ACCESS_POLICY_PERMISSION_OPERATIONS: dict[str, tuple[str, ...]] = {
    "get": ("read",),
    "list": ("list",),
    "create": ("create",),
    "import": ("import",),
    "update": ("update",),
    "recover": ("recover",),
    "restore": ("restore",),
    "delete": ("delete",),
    "backup": ("backup",),
    "purge": ("purge",),
    "encrypt": ("encrypt",),
    "decrypt": ("decrypt",),
    "wrapkey": ("wrap",),
    "unwrapkey": ("unwrap",),
    "sign": ("sign",),
    "verify": ("verify",),
    "release": ("release",),
    "rotate": ("rotate",),
    "getrotationpolicy": ("get_rotation_policy",),
    "setrotationpolicy": ("set_rotation_policy",),
}
_ACCESS_POLICY_OPERATION_ORDER = (
    "read",
    "list",
    *(operation.name for operation in _KEY_OPERATIONS if operation.name != "read"),
)
_OPERATION_ACCESS_CLASSES: dict[str, tuple[str, ...]] = {
    **{operation.name: operation.access_classes for operation in _KEY_OPERATIONS},
    "list": ("metadata_read",),
}


@dataclass(frozen=True, slots=True)
class _BuiltInRole:
    name: str
    role_id: str
    data_actions: tuple[str, ...]


_BUILT_IN_ROLES = (
    _BuiltInRole(
        "Key Vault Administrator",
        "00482a5a-887f-4fb3-b363-3b7fe8e74483",
        ("Microsoft.KeyVault/vaults/*",),
    ),
    _BuiltInRole(
        "Key Vault Certificate User",
        "db79e9a7-68ee-4b58-9aeb-b90e7c24fcba",
        ("Microsoft.KeyVault/vaults/keys/read",),
    ),
    _BuiltInRole(
        "Key Vault Crypto Officer",
        "14b46e9e-c2b7-41b4-b07b-48a6ebf60603",
        (
            "Microsoft.KeyVault/vaults/keys/*",
            "Microsoft.KeyVault/vaults/keyrotationpolicies/*",
        ),
    ),
    _BuiltInRole(
        "Key Vault Crypto Service Encryption User",
        "e147488a-f6f5-4113-8e2d-b22465e65bf6",
        (
            "Microsoft.KeyVault/vaults/keys/read",
            "Microsoft.KeyVault/vaults/keys/wrap/action",
            "Microsoft.KeyVault/vaults/keys/unwrap/action",
        ),
    ),
    _BuiltInRole(
        "Key Vault Crypto Service Release User",
        "08bbd89e-9f13-488c-ac41-acfcb10c90ab",
        ("Microsoft.KeyVault/vaults/keys/release/action",),
    ),
    _BuiltInRole(
        "Key Vault Crypto User",
        "12338af0-0e69-4776-bea7-57ae8d297424",
        (
            "Microsoft.KeyVault/vaults/keys/read",
            "Microsoft.KeyVault/vaults/keys/update/action",
            "Microsoft.KeyVault/vaults/keys/backup/action",
            "Microsoft.KeyVault/vaults/keys/encrypt/action",
            "Microsoft.KeyVault/vaults/keys/decrypt/action",
            "Microsoft.KeyVault/vaults/keys/wrap/action",
            "Microsoft.KeyVault/vaults/keys/unwrap/action",
            "Microsoft.KeyVault/vaults/keys/sign/action",
            "Microsoft.KeyVault/vaults/keys/verify/action",
        ),
    ),
    _BuiltInRole(
        "Key Vault Reader",
        "21090545-7ca7-4776-b22c-e363652d74d2",
        (
            "Microsoft.KeyVault/vaults/*/read",
            "Microsoft.KeyVault/vaults/secrets/readMetadata/action",
        ),
    ),
)
_BUILT_IN_ROLES_BY_ID = {role.role_id.casefold(): role for role in _BUILT_IN_ROLES}
_BUILT_IN_ROLES_BY_NAME = {role.name.casefold(): role for role in _BUILT_IN_ROLES}
_KNOWN_NON_KEY_ROLE_NAMES = frozenset(
    {
        "contributor",
        "key vault certificates officer",
        "key vault contributor",
        "key vault data access administrator",
        "key vault purge operator",
        "key vault secrets officer",
        "key vault secrets user",
        "owner",
        "reader",
        "user access administrator",
    }
)


@dataclass(frozen=True, slots=True)
class _RoleResolution:
    role_kind: str
    state: str
    data_actions: tuple[str, ...]
    not_data_actions: tuple[str, ...] = ()
    role_definition_address: str | None = None
    assignable_scope_state: str = "not_applicable"


_AssignmentScopeType = AzureKeyVaultGrantScopeType | Literal["unrelated", "unknown", "invalid"]


@dataclass(frozen=True, slots=True)
class _AssignmentScopeResolution:
    scope_type: _AssignmentScopeType
    state: str
    arm_scope: str | None = None


class NormalizeKeyVaultKeyAuthorizationPostureStage:
    """Project exact legacy-policy and RBAC key authority onto Key Vault keys."""

    name = "normalize_key_vault_key_authorization_posture"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        assignments = tuple(
            resource for resource in resources if resource.resource_type == AzureResourceType.ROLE_ASSIGNMENT
        )
        for key in resources:
            if key.resource_type != AzureResourceType.KEY_VAULT_KEY:
                continue
            grants, uncertainties = _key_authorization_posture(
                key,
                assignments,
                context,
            )
            azure_facts(key).set_key_vault_key_authorization_posture(
                grants=grants,
                uncertainties=uncertainties,
            )


def _key_authorization_posture(
    key: NormalizedResource,
    assignments: tuple[NormalizedResource, ...],
    context: AzureDecorationContext,
) -> tuple[list[AzureKeyVaultAuthorizationGrant], list[str]]:
    key_facts = azure_facts(key)
    if key_facts.key_vault_key_identity_state != "resolved":
        return [], [f"{key.address}: exact Key Vault key identity is unresolved"]

    vault = context.index.resolve(
        key_facts.resolved_key_vault_address,
        source=key,
        resource_types={AzureResourceType.KEY_VAULT},
    )
    if vault is None or vault.resource_type != AzureResourceType.KEY_VAULT:
        return [], [f"{key.address}: exact parent Key Vault is unresolved"]
    vault_facts = azure_facts(vault)

    authorization_model = _authorization_model(vault_facts.rbac_authorization_enabled)
    authorization_model_unknown = authorization_model == "unknown"
    uncertainties: list[str] = []
    grants: list[AzureKeyVaultAuthorizationGrant] = []
    if authorization_model in {"access_policy", "unknown"}:
        policy_grants, policy_uncertainties = _access_policy_grants(
            key,
            vault,
            model_unknown=authorization_model_unknown,
        )
        grants.extend(policy_grants)
        uncertainties.extend(policy_uncertainties)
    if authorization_model in {"azure_rbac", "unknown"}:
        rbac_grants, rbac_uncertainties = _rbac_grants(
            key,
            vault,
            assignments,
            context,
            model_unknown=authorization_model_unknown,
        )
        grants.extend(rbac_grants)
        uncertainties.extend(rbac_uncertainties)
    if authorization_model_unknown:
        uncertainties.append(f"{vault.address}: Key Vault authorization model is unknown after planning")

    grants = _dedupe_dicts(grants)
    grants.sort(
        key=lambda grant: (
            str(grant.get("grant_scope_type")),
            str(grant.get("grant_source_address")),
            str(grant.get("principal_id")),
            str(grant.get("role_definition_id")),
        )
    )
    return grants, dedupe(uncertainties)


def _authorization_model(
    rbac_enabled: bool | None,
) -> AzureKeyVaultAuthorizationModel | Literal["unknown"]:
    if rbac_enabled is True:
        return "azure_rbac"
    if rbac_enabled is False:
        return "access_policy"
    return "unknown"


def _access_policy_grants(
    key: NormalizedResource,
    vault: NormalizedResource,
    *,
    model_unknown: bool,
) -> tuple[list[AzureKeyVaultAuthorizationGrant], list[str]]:
    vault_facts = azure_facts(vault)
    policies = vault_facts.key_vault_access_policies
    management_modes: set[str] = {
        str(policy.get("management_mode")) for policy in policies if policy.get("management_mode")
    }
    management_ambiguous = {
        "inline_access_policy",
        "standalone_access_policy",
    }.issubset(management_modes)
    uncertainties = [
        f"{vault.address}: {value}"
        for value in vault_facts.key_vault_authorization_uncertainties
        if "access_policy" in value or "key_permissions" in value
    ]
    if management_ambiguous:
        uncertainties.append(
            f"{vault.address}: effective access policies are ambiguous because inline and "
            "standalone Terraform access-policy managers overlap"
        )

    grants: list[AzureKeyVaultAuthorizationGrant] = []
    for policy in policies:
        permission_state = _known_string(policy.get("key_permissions_state")) or (
            "configured" if _string_values(policy.get("key_permissions")) else "not_configured"
        )
        permissions = tuple(_string_values(policy.get("key_permissions")))
        unknown_permissions = permission_state == "unknown"
        unknown_permission_names = sorted(
            permission for permission in permissions if permission not in _known_access_policy_permissions()
        )
        if unknown_permission_names:
            unknown_permissions = True
            uncertainties.append(
                f"{policy.get('source') or vault.address}: unrecognized Key Vault key permissions "
                f"{','.join(unknown_permission_names)}"
            )
        operations = () if unknown_permissions else _operations_for_access_policy(permissions)
        if not operations and not unknown_permissions:
            continue

        principal_state = _known_string(policy.get("principal_state")) or (
            "resolved" if policy.get("tenant_id") and policy.get("object_id") else "not_configured"
        )
        authorization_state = "granted"
        if model_unknown or unknown_permissions or principal_state != "resolved":
            authorization_state = "unknown"
        elif management_ambiguous:
            authorization_state = "ambiguous"
        grants.append(
            {
                "grant_kind": "access_policy",
                "grant_source_address": policy.get("source") or vault.address,
                "grant_basis": "key_vault_access_policy",
                "authorization_model": "access_policy",
                "authorization_model_state": "unknown" if model_unknown else "active",
                "authorization_state": authorization_state,
                "management_mode": policy.get("management_mode") or "unknown",
                "management_state": "ambiguous" if management_ambiguous else "unambiguous",
                "grant_scope_type": "vault",
                "grant_scope": vault_facts.key_vault_id or vault.address,
                "key_vault_address": vault.address,
                "key_vault_id": vault_facts.key_vault_id,
                "key_address": key.address,
                "key_uri": azure_facts(key).key_vault_key_uri,
                "key_versionless_uri": azure_facts(key).key_vault_key_versionless_uri,
                "key_resource_id": azure_facts(key).key_vault_key_versionless_resource_id,
                "principal_id": policy.get("object_id"),
                "principal_type": "entra_object",
                "tenant_id": policy.get("tenant_id"),
                "application_id": policy.get("application_id"),
                "principal_state": principal_state,
                "key_permissions": list(permissions),
                "key_permissions_state": permission_state,
                "matched_operations": list(operations),
                "access_classes": _access_classes(operations),
                "condition": None,
                "condition_state": "not_configured",
                "condition_applicability_state": "not_configured",
            }
        )
    return grants, uncertainties


def _rbac_grants(
    key: NormalizedResource,
    vault: NormalizedResource,
    assignments: tuple[NormalizedResource, ...],
    context: AzureDecorationContext,
    *,
    model_unknown: bool,
) -> tuple[list[AzureKeyVaultAuthorizationGrant], list[str]]:
    grants: list[AzureKeyVaultAuthorizationGrant] = []
    uncertainties: list[str] = []
    for assignment in assignments:
        scope_resolution = _assignment_scope(assignment, key, vault, context)
        scope_type = scope_resolution.scope_type
        scope_state = scope_resolution.state
        if scope_type == "unrelated":
            continue
        if scope_type == "unknown":
            uncertainties.append(
                f"{assignment.address}: role assignment scope is unresolved and may affect {key.address}"
            )
            continue
        if scope_type == "invalid":
            uncertainties.append(
                f"{assignment.address}: role assignment scope is not a valid Key Vault RBAC "
                f"parent, vault, or versionless key ARM scope for {key.address}"
            )
            continue

        if scope_state == "unknown":
            uncertainties.append(
                f"{assignment.address}: {scope_type} scope inheritance cannot be proven for {key.address}"
            )

        assignment_facts = azure_facts(assignment)
        role = _resolve_role(
            assignment,
            context,
            scope_resolution.arm_scope,
        )
        if role is None:
            continue
        matched_actions = _matched_data_actions(role.data_actions, role.not_data_actions)
        if role.state == "resolved" and not matched_actions:
            continue
        excluded_actions = _excluded_data_actions(role.data_actions, role.not_data_actions)
        operations = _operations_for_data_actions(matched_actions)
        condition_state = _condition_state(assignment)
        condition_applicability_state = _condition_applicability_state(
            condition_state,
        )
        principal_state = "resolved" if assignment_facts.principal_id else "unknown"
        grant_evidence_complete = (
            not model_unknown
            and scope_state == "resolved"
            and role.state in {"modeled_subset", "resolved"}
            and role.assignable_scope_state in {"not_applicable", "resolved"}
            and principal_state == "resolved"
            and bool(operations)
        )
        if not grant_evidence_complete:
            authorization_state = "unknown"
        elif condition_applicability_state == "not_configured":
            authorization_state = "granted"
        elif condition_applicability_state == "applicable":
            authorization_state = "conditional"
        else:
            authorization_state = "unknown"
        if role.state not in {"modeled_subset", "resolved"}:
            uncertainties.append(f"{assignment.address}: role permissions are {role.state} for {key.address}")
        if role.assignable_scope_state not in {"not_applicable", "resolved"}:
            uncertainties.append(
                f"{assignment.address}: custom-role assignable scope is {role.assignable_scope_state} for {key.address}"
            )
        if principal_state == "unknown":
            uncertainties.append(f"{assignment.address}: role assignment principal is unresolved for {key.address}")
        if condition_state == "unknown":
            uncertainties.append(f"{assignment.address}: role assignment condition is unresolved for {key.address}")
        elif condition_applicability_state == "unsupported":
            uncertainties.append(
                f"{assignment.address}: role assignment condition applicability is unsupported "
                f"for Key Vault key data actions on {key.address}"
            )

        grant: AzureKeyVaultAuthorizationGrant = {
            "grant_kind": "rbac",
            "grant_source_address": assignment.address,
            "grant_basis": "azure_rbac_assignment",
            "authorization_model": "azure_rbac",
            "authorization_model_state": "unknown" if model_unknown else "active",
            "authorization_state": authorization_state,
            "grant_scope_type": scope_type,
            "grant_scope": assignment_facts.role_assignment_scope,
            "scope_resolution_state": scope_state,
            "key_vault_address": vault.address,
            "key_vault_id": azure_facts(vault).key_vault_id,
            "key_address": key.address,
            "key_uri": azure_facts(key).key_vault_key_uri,
            "key_versionless_uri": azure_facts(key).key_vault_key_versionless_uri,
            "key_resource_id": azure_facts(key).key_vault_key_versionless_resource_id,
            "principal_id": assignment_facts.principal_id,
            "principal_type": assignment_facts.principal_type,
            "principal_state": principal_state,
            "role_definition_name": assignment_facts.role_definition_name,
            "role_definition_id": assignment_facts.role_definition_id,
            "role_kind": role.role_kind,
            "role_resolution_state": role.state,
            "role_definition_address": role.role_definition_address,
            "role_data_actions": list(role.data_actions),
            "role_not_data_actions": list(role.not_data_actions),
            "matched_data_actions": list(matched_actions),
            "excluded_data_actions": list(excluded_actions),
            "matched_operations": list(operations),
            "access_classes": _access_classes(operations),
            "assignable_scope_compatibility_state": role.assignable_scope_state,
            "condition": assignment_facts.role_assignment_condition,
            "condition_version": assignment_facts.role_assignment_condition_version,
            "condition_state": condition_state,
            "condition_applicability_state": condition_applicability_state,
        }
        grants.append(grant)
    return grants, uncertainties


def _assignment_scope(
    assignment: NormalizedResource,
    key: NormalizedResource,
    vault: NormalizedResource,
    context: AzureDecorationContext,
) -> _AssignmentScopeResolution:
    scope = azure_facts(assignment).role_assignment_scope
    if scope is None:
        return _AssignmentScopeResolution(
            "unknown" if _assignment_field_unknown(assignment, "scope") else "unrelated",
            "unknown" if _assignment_field_unknown(assignment, "scope") else "not_configured",
        )

    normalized_scope = scope.strip().rstrip("/")
    if _MANAGEMENT_GROUP_SCOPE_PATTERN.fullmatch(normalized_scope):
        return _AssignmentScopeResolution(
            "management_group",
            "unknown",
            normalized_scope,
        )
    if normalized_scope.casefold().startswith("azurerm_management_group."):
        return _AssignmentScopeResolution("management_group", "unknown")

    vault_arm_id = _canonical_vault_arm_id(key, vault)
    vault_subscription_scope, vault_resource_group_scope = _vault_parent_scopes(
        vault_arm_id,
    )

    if _SUBSCRIPTION_SCOPE_PATTERN.fullmatch(normalized_scope):
        if vault_subscription_scope is None:
            return _AssignmentScopeResolution(
                "subscription",
                "unknown",
                normalized_scope,
            )
        return _AssignmentScopeResolution(
            "subscription" if _same_scope(normalized_scope, vault_subscription_scope) else "unrelated",
            "resolved",
            normalized_scope,
        )

    if _RESOURCE_GROUP_SCOPE_PATTERN.fullmatch(normalized_scope):
        if vault_resource_group_scope is None:
            return _AssignmentScopeResolution(
                "resource_group",
                "unknown",
                normalized_scope,
            )
        return _AssignmentScopeResolution(
            "resource_group" if _same_scope(normalized_scope, vault_resource_group_scope) else "unrelated",
            "resolved",
            normalized_scope,
        )
    if normalized_scope.casefold().startswith("azurerm_resource_group."):
        return _AssignmentScopeResolution("resource_group", "unknown")

    if vault_arm_id is not None and _same_scope(normalized_scope, vault_arm_id):
        return _AssignmentScopeResolution("vault", "resolved", vault_arm_id)
    key_arm_id = azure_facts(key).key_vault_key_versionless_resource_id
    if key_arm_id is not None and _same_scope(normalized_scope, key_arm_id):
        return _AssignmentScopeResolution("key", "resolved", key_arm_id)

    resolved = context.index.resolve(
        scope,
        source=assignment,
        resource_types={AzureResourceType.KEY_VAULT, AzureResourceType.KEY_VAULT_KEY},
    )
    if resolved is None:
        return _AssignmentScopeResolution("unrelated", "external_or_unresolved")
    if resolved.address == vault.address:
        return (
            _AssignmentScopeResolution("vault", "resolved", vault_arm_id)
            if _valid_vault_scope(scope, vault)
            else _AssignmentScopeResolution("invalid", "invalid")
        )
    if resolved.resource_type != AzureResourceType.KEY_VAULT_KEY:
        return _AssignmentScopeResolution("unrelated", "resolved")
    if resolved.address != key.address:
        return _AssignmentScopeResolution("unrelated", "resolved")
    return (
        _AssignmentScopeResolution("key", "resolved", key_arm_id)
        if _valid_key_scope(scope, key)
        else _AssignmentScopeResolution("invalid", "invalid")
    )


def _canonical_vault_arm_id(
    key: NormalizedResource,
    vault: NormalizedResource,
) -> str | None:
    vault_id = _known_string(azure_facts(vault).key_vault_id)
    if vault_id is not None and _VAULT_ARM_ID_PATTERN.fullmatch(vault_id.strip().rstrip("/")):
        return vault_id.strip().rstrip("/")

    key_id = _known_string(azure_facts(key).key_vault_key_versionless_resource_id)
    if key_id is None or "/keys/" not in key_id.casefold():
        return None
    candidate = key_id[: key_id.casefold().rfind("/keys/")]
    return candidate if _VAULT_ARM_ID_PATTERN.fullmatch(candidate) else None


def _vault_parent_scopes(
    vault_arm_id: str | None,
) -> tuple[str | None, str | None]:
    if vault_arm_id is None:
        return None, None
    match = _VAULT_ARM_ID_PATTERN.fullmatch(vault_arm_id)
    if match is None:
        return None, None
    subscription_id = match.group("subscription")
    resource_group_name = match.group("resource_group")
    subscription_scope = f"/subscriptions/{subscription_id}"
    resource_group_scope = f"{subscription_scope}/resourceGroups/{resource_group_name}"
    return subscription_scope, resource_group_scope


def _same_scope(left: str, right: str) -> bool:
    return left.strip().casefold().rstrip("/") == right.strip().casefold().rstrip("/")


def _valid_vault_scope(scope: str, vault: NormalizedResource) -> bool:
    normalized = scope.strip().casefold()
    vault_id = azure_facts(vault).key_vault_id
    if vault_id and normalized.rstrip("/") == vault_id.strip().casefold().rstrip("/"):
        return True
    return normalized in {
        f"{vault.address}.id".casefold(),
        f"${{{vault.address}.id}}".casefold(),
    }


def _valid_key_scope(scope: str, key: NormalizedResource) -> bool:
    normalized = scope.strip().casefold()
    key_id = azure_facts(key).key_vault_key_versionless_resource_id
    if key_id and normalized.rstrip("/") == key_id.strip().casefold().rstrip("/"):
        return True
    return normalized in {
        f"{key.address}.resource_versionless_id".casefold(),
        f"${{{key.address}.resource_versionless_id}}".casefold(),
    }


def _resolve_role(
    assignment: NormalizedResource,
    context: AzureDecorationContext,
    assignment_arm_scope: str | None,
) -> _RoleResolution | None:
    facts = azure_facts(assignment)
    role_id = _known_string(facts.role_definition_id)
    role_name = _known_string(facts.role_definition_name)
    if role_id is not None:
        built_in = _BUILT_IN_ROLES_BY_ID.get(_role_id(role_id))
        if built_in is not None:
            return _RoleResolution(
                role_kind="built_in",
                state="modeled_subset",
                data_actions=built_in.data_actions,
            )
        custom = context.index.resolve(
            facts.resolved_role_definition_address,
            source=assignment,
            resource_types={AzureResourceType.ROLE_DEFINITION},
        )
        if custom is not None and custom.resource_type == AzureResourceType.ROLE_DEFINITION:
            return _custom_role_resolution(custom, assignment_arm_scope)
        return _RoleResolution("unknown", "external_or_unresolved", ())

    if _assignment_field_unknown(assignment, "role_definition_id"):
        return _RoleResolution("unknown", "unresolved", ())
    if role_name is None or _assignment_field_unknown(
        assignment,
        "role_definition_name",
    ):
        return _RoleResolution("unknown", "unresolved", ())
    built_in = _BUILT_IN_ROLES_BY_NAME.get(role_name.casefold())
    if built_in is not None:
        return _RoleResolution(
            role_kind="built_in",
            state="modeled_subset",
            data_actions=built_in.data_actions,
        )
    if role_name.casefold() in _KNOWN_NON_KEY_ROLE_NAMES:
        return None
    return _RoleResolution("unknown", "unresolved", ())


def _custom_role_resolution(
    role_definition: NormalizedResource,
    assignment_arm_scope: str | None,
) -> _RoleResolution:
    facts = azure_facts(role_definition)
    permission_uncertain = any(
        "permissions" in value or "data_actions" in value or "not_data_actions" in value
        for value in facts.role_definition_uncertainties
    )
    assignable_scope_state = _assignable_scope_state(
        role_definition,
        assignment_arm_scope,
    )
    if permission_uncertain:
        return _RoleResolution(
            role_kind="custom",
            state="unknown",
            data_actions=(),
            role_definition_address=role_definition.address,
            assignable_scope_state=assignable_scope_state,
        )
    return _RoleResolution(
        role_kind="custom",
        state="resolved",
        data_actions=tuple(_string_values(facts.role_definition_data_actions)),
        not_data_actions=tuple(_string_values(facts.role_definition_not_data_actions)),
        role_definition_address=role_definition.address,
        assignable_scope_state=assignable_scope_state,
    )


def _assignable_scope_state(
    role_definition: NormalizedResource,
    assignment_arm_scope: str | None,
) -> str:
    role_facts = azure_facts(role_definition)
    if any("assignable_scopes" in value for value in role_facts.role_definition_uncertainties):
        return "unknown"
    scopes = role_facts.role_definition_assignable_scopes
    if not scopes:
        return "unknown"
    if assignment_arm_scope is None:
        return "unknown"
    return (
        "resolved"
        if any(azure_arm_scope_contains(scope, assignment_arm_scope) for scope in scopes)
        else "outside_assignable_scope"
    )


def _condition_state(assignment: NormalizedResource) -> str:
    facts = azure_facts(assignment)
    if _assignment_field_unknown(
        assignment,
        "condition",
    ) or _assignment_field_unknown(assignment, "condition_version"):
        return "unknown"
    if facts.role_assignment_condition:
        return "configured"
    if facts.role_assignment_condition_version:
        return "unknown"
    return "not_configured"


def _condition_applicability_state(condition_state: str) -> str:
    if condition_state == "not_configured":
        return "not_configured"
    if condition_state == "configured":
        return "unsupported"
    return "unknown"


def _assignment_field_unknown(
    assignment: NormalizedResource,
    field: str,
) -> bool:
    prefix = f"{field} is unknown"
    return any(value.startswith(prefix) for value in azure_facts(assignment).key_vault_authorization_uncertainties)


def _matched_data_actions(
    data_actions: tuple[str, ...],
    not_data_actions: tuple[str, ...],
) -> tuple[str, ...]:
    return tuple(
        operation.data_action
        for operation in _KEY_OPERATIONS
        if _matches_any(operation.data_action, data_actions)
        and not _matches_any(operation.data_action, not_data_actions)
    )


def _excluded_data_actions(
    data_actions: tuple[str, ...],
    not_data_actions: tuple[str, ...],
) -> tuple[str, ...]:
    return tuple(
        operation.data_action
        for operation in _KEY_OPERATIONS
        if _matches_any(operation.data_action, data_actions) and _matches_any(operation.data_action, not_data_actions)
    )


def _matches_any(action: str, patterns: tuple[str, ...]) -> bool:
    normalized_action = action.casefold()
    return any(fnmatchcase(normalized_action, pattern.strip().casefold()) for pattern in patterns if pattern.strip())


def _operations_for_data_actions(actions: tuple[str, ...]) -> tuple[str, ...]:
    matched = set(actions)
    return tuple(operation.name for operation in _KEY_OPERATIONS if operation.data_action in matched)


def _operations_for_access_policy(permissions: tuple[str, ...]) -> tuple[str, ...]:
    matched = {
        operation
        for permission in permissions
        for operation in _ACCESS_POLICY_PERMISSION_OPERATIONS.get(
            permission.casefold(),
            (),
        )
    }
    return tuple(operation for operation in _ACCESS_POLICY_OPERATION_ORDER if operation in matched)


def _known_access_policy_permissions() -> frozenset[str]:
    return frozenset(_ACCESS_POLICY_PERMISSION_OPERATIONS)


def _access_classes(operations: tuple[str, ...]) -> list[str]:
    classes = {
        access_class for operation in operations for access_class in _OPERATION_ACCESS_CLASSES.get(operation, ())
    }
    return [access_class for access_class in _ACCESS_CLASS_ORDER if access_class in classes]


def _role_id(value: str) -> str:
    return value.strip().casefold().rstrip("/").rsplit("/", 1)[-1]


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _string_values(value: object) -> list[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return []
    return sorted({str(item).strip().casefold() for item in value if isinstance(item, str) and item.strip()})


def _dedupe_dicts(
    values: list[AzureKeyVaultAuthorizationGrant],
) -> list[AzureKeyVaultAuthorizationGrant]:
    result: list[AzureKeyVaultAuthorizationGrant] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result
