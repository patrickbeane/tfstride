from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Literal

from tfstride.models import NormalizedResource
from tfstride.providers.azure.arm_control_plane_authorization import azure_arm_scope_contains
from tfstride.providers.azure.key_vault_evidence import (
    AzureKeyVaultAuthorizationModel,
    AzureKeyVaultGrantScopeType,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.secret_management_evidence import (
    AzureKeyVaultSecretAuthorizationGrant,
    AzureKeyVaultSecretGrantOperation,
)
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
_SECRET_ARM_ID_PATTERN = re.compile(
    r"^/subscriptions/(?P<subscription>[^/]+)/resourceGroups/(?P<resource_group>[^/]+)/"
    r"providers/Microsoft\.KeyVault/vaults/(?P<vault>[^/]+)/secrets/(?P<secret>[^/]+)/?\Z",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class _SecretOperation:
    name: AzureKeyVaultSecretGrantOperation
    data_action: str


_SECRET_OPERATIONS = (
    _SecretOperation(
        "set",
        "Microsoft.KeyVault/vaults/secrets/setSecret/action",
    ),
    _SecretOperation(
        "delete",
        "Microsoft.KeyVault/vaults/secrets/delete",
    ),
    _SecretOperation(
        "purge",
        "Microsoft.KeyVault/vaults/secrets/purge/action",
    ),
)
_ACCESS_POLICY_PERMISSION_OPERATIONS: dict[
    str,
    tuple[AzureKeyVaultSecretGrantOperation, ...],
] = {
    "set": ("set",),
    "delete": ("delete",),
    "purge": ("purge",),
}
_KNOWN_ACCESS_POLICY_PERMISSIONS = frozenset(
    {
        "backup",
        "delete",
        "get",
        "list",
        "purge",
        "recover",
        "restore",
        "set",
    }
)


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
        "Key Vault Secrets Officer",
        "b86a8fe4-44ce-4948-aee5-eccb2c155cd7",
        ("Microsoft.KeyVault/vaults/secrets/*",),
    ),
    _BuiltInRole(
        "Key Vault Secrets User",
        "4633458b-17de-408a-b874-0445c86b69e6",
        (),
    ),
    _BuiltInRole(
        "Key Vault Reader",
        "21090545-7ca7-4776-b22c-e363652d74d2",
        (),
    ),
)
_BUILT_IN_ROLES_BY_ID = {role.role_id.casefold(): role for role in _BUILT_IN_ROLES}
_BUILT_IN_ROLES_BY_NAME = {role.name.casefold(): role for role in _BUILT_IN_ROLES}
_KNOWN_NON_SECRET_ROLE_NAMES = frozenset(
    {
        "contributor",
        "key vault certificates officer",
        "key vault contributor",
        "key vault crypto officer",
        "key vault crypto service encryption user",
        "key vault crypto service release user",
        "key vault crypto user",
        "key vault data access administrator",
        "key vault purge operator",
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


_AssignmentScopeType = (
    AzureKeyVaultGrantScopeType
    | Literal[
        "unrelated",
        "unknown",
        "invalid",
    ]
)


@dataclass(frozen=True, slots=True)
class _AssignmentScopeResolution:
    scope_type: _AssignmentScopeType
    state: str
    arm_scope: str | None = None


class NormalizeKeyVaultSecretAuthorizationPostureStage:
    """Project exact legacy-policy and RBAC authority onto Key Vault secrets."""

    name = "normalize_key_vault_secret_authorization_posture"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        assignments = tuple(
            resource for resource in resources if resource.resource_type == AzureResourceType.ROLE_ASSIGNMENT
        )
        for secret in resources:
            if secret.resource_type != AzureResourceType.KEY_VAULT_SECRET:
                continue
            grants, uncertainties = _secret_authorization_posture(
                secret,
                assignments,
                context,
            )
            azure_facts(secret).set_key_vault_secret_authorization_posture(
                grants=grants,
                uncertainties=uncertainties,
            )


def _secret_authorization_posture(
    secret: NormalizedResource,
    assignments: tuple[NormalizedResource, ...],
    context: AzureDecorationContext,
) -> tuple[list[AzureKeyVaultSecretAuthorizationGrant], list[str]]:
    secret_facts = azure_facts(secret)
    if _known_string(secret_facts.key_vault_secret_versionless_uri) is None:
        return [], [f"{secret.address}: exact Key Vault secret identity is unresolved"]

    vault = context.index.resolve(
        secret_facts.resolved_key_vault_address,
        source=secret,
        resource_types={AzureResourceType.KEY_VAULT},
    )
    if vault is None or vault.resource_type != AzureResourceType.KEY_VAULT:
        return [], [f"{secret.address}: exact parent Key Vault is unresolved"]
    vault_facts = azure_facts(vault)

    authorization_model = _authorization_model(vault_facts.rbac_authorization_enabled)
    model_unknown = authorization_model == "unknown"
    grants: list[AzureKeyVaultSecretAuthorizationGrant] = []
    uncertainties: list[str] = []
    if authorization_model in {"access_policy", "unknown"}:
        policy_grants, policy_uncertainties = _access_policy_grants(
            secret,
            vault,
            model_unknown=model_unknown,
        )
        grants.extend(policy_grants)
        uncertainties.extend(policy_uncertainties)
    if authorization_model in {"azure_rbac", "unknown"}:
        rbac_grants, rbac_uncertainties = _rbac_grants(
            secret,
            vault,
            assignments,
            context,
            model_unknown=model_unknown,
        )
        grants.extend(rbac_grants)
        uncertainties.extend(rbac_uncertainties)
    if model_unknown:
        uncertainties.append(f"{vault.address}: Key Vault authorization model is unknown after planning")

    grants = _dedupe_grants(grants)
    grants.sort(
        key=lambda grant: (
            grant["grant_scope_type"],
            grant["grant_source_address"],
            grant.get("principal_id") or "",
            grant.get("role_definition_id") or "",
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
    secret: NormalizedResource,
    vault: NormalizedResource,
    *,
    model_unknown: bool,
) -> tuple[list[AzureKeyVaultSecretAuthorizationGrant], list[str]]:
    vault_facts = azure_facts(vault)
    policies = vault_facts.key_vault_access_policies
    management_modes = {
        mode for policy in policies if (mode := _known_string(policy.get("management_mode"))) is not None
    }
    management_ambiguous = {
        "inline_access_policy",
        "standalone_access_policy",
    }.issubset(management_modes)
    uncertainties = [
        f"{vault.address}: {value}"
        for value in vault_facts.key_vault_authorization_uncertainties
        if "access_policy" in value or "secret_permissions" in value
    ]
    if management_ambiguous:
        uncertainties.append(
            f"{vault.address}: effective access policies are ambiguous because inline and "
            "standalone Terraform access-policy managers overlap"
        )

    secret_facts = azure_facts(secret)
    vault_arm_id = _canonical_vault_arm_id(secret, vault)
    secret_arm_id = _canonical_secret_arm_id(secret)
    grants: list[AzureKeyVaultSecretAuthorizationGrant] = []
    for policy in policies:
        permission_state = _known_string(policy.get("secret_permissions_state")) or (
            "configured" if _string_values(policy.get("secret_permissions")) else "not_configured"
        )
        permissions = tuple(_string_values(policy.get("secret_permissions")))
        permissions_unknown = permission_state == "unknown"
        unknown_names = sorted(
            permission for permission in permissions if permission not in _KNOWN_ACCESS_POLICY_PERMISSIONS
        )
        if unknown_names:
            permissions_unknown = True
            uncertainties.append(
                f"{policy.get('source') or vault.address}: unrecognized Key Vault secret "
                f"permissions {','.join(unknown_names)}"
            )
        operations = () if permissions_unknown else _operations_for_access_policy(permissions)
        if not operations and not permissions_unknown:
            continue

        principal_state = _known_string(policy.get("principal_state")) or (
            "resolved" if policy.get("tenant_id") and policy.get("object_id") else "not_configured"
        )
        authorization_state = "granted"
        if model_unknown or permissions_unknown or principal_state != "resolved":
            authorization_state = "unknown"
        elif management_ambiguous:
            authorization_state = "ambiguous"

        grant: AzureKeyVaultSecretAuthorizationGrant = {
            "grant_kind": "access_policy",
            "grant_source_address": _known_string(policy.get("source")) or vault.address,
            "grant_basis": "key_vault_access_policy",
            "authorization_model": "access_policy",
            "authorization_model_state": "unknown" if model_unknown else "active",
            "authorization_state": authorization_state,
            "management_mode": _known_string(policy.get("management_mode")) or "unknown",
            "management_state": ("ambiguous" if management_ambiguous else "unambiguous"),
            "grant_scope_type": "vault",
            "grant_scope": vault_arm_id or vault.address,
            "key_vault_address": vault.address,
            "key_vault_id": vault_arm_id,
            "secret_address": secret.address,
            "secret_uri": secret_facts.key_vault_secret_uri,
            "secret_versionless_uri": (secret_facts.key_vault_secret_versionless_uri or ""),
            "secret_resource_id": secret_arm_id,
            "secret_version": secret_facts.key_vault_secret_version,
            "principal_id": _known_string(policy.get("object_id")),
            "principal_type": "entra_object",
            "tenant_id": policy.get("tenant_id"),
            "application_id": policy.get("application_id"),
            "principal_state": principal_state,
            "secret_permissions": list(permissions),
            "secret_permissions_state": permission_state,
            "matched_operations": list(operations),
            "condition": None,
            "condition_state": "not_configured",
            "condition_applicability_state": "not_configured",
        }
        grants.append(grant)
    return grants, uncertainties


def _rbac_grants(
    secret: NormalizedResource,
    vault: NormalizedResource,
    assignments: tuple[NormalizedResource, ...],
    context: AzureDecorationContext,
    *,
    model_unknown: bool,
) -> tuple[list[AzureKeyVaultSecretAuthorizationGrant], list[str]]:
    grants: list[AzureKeyVaultSecretAuthorizationGrant] = []
    uncertainties: list[str] = []
    secret_facts = azure_facts(secret)
    vault_arm_id = _canonical_vault_arm_id(secret, vault)
    secret_arm_id = _canonical_secret_arm_id(secret)
    for assignment in assignments:
        scope_resolution = _assignment_scope(
            assignment,
            secret,
            vault,
            context,
        )
        scope_type = scope_resolution.scope_type
        scope_state = scope_resolution.state
        if scope_type == "unrelated":
            continue
        if scope_type == "unknown":
            uncertainties.append(
                f"{assignment.address}: role assignment scope is unresolved and may affect {secret.address}"
            )
            continue
        if scope_type == "invalid":
            uncertainties.append(
                f"{assignment.address}: role assignment scope is not a valid Key Vault RBAC "
                f"parent, vault, or versionless secret ARM scope for {secret.address}"
            )
            continue
        if scope_state == "unknown":
            uncertainties.append(
                f"{assignment.address}: {scope_type} scope inheritance cannot be proven for {secret.address}"
            )

        assignment_facts = azure_facts(assignment)
        role = _resolve_role(
            assignment,
            context,
            scope_resolution.arm_scope,
        )
        if role is None:
            continue
        matched_actions = _matched_data_actions(
            role.data_actions,
            role.not_data_actions,
        )
        if role.state in {"modeled_subset", "resolved"} and not matched_actions:
            continue
        excluded_actions = _excluded_data_actions(
            role.data_actions,
            role.not_data_actions,
        )
        operations = _operations_for_data_actions(matched_actions)
        condition_state = _condition_state(assignment)
        condition_applicability_state = _condition_applicability_state(condition_state)
        principal_state = "resolved" if assignment_facts.principal_id else "unknown"
        evidence_complete = (
            not model_unknown
            and scope_state == "resolved"
            and role.state in {"modeled_subset", "resolved"}
            and role.assignable_scope_state in {"not_applicable", "resolved"}
            and principal_state == "resolved"
            and bool(operations)
        )
        if not evidence_complete:
            authorization_state = "unknown"
        elif condition_applicability_state == "not_configured":
            authorization_state = "granted"
        elif condition_applicability_state == "applicable":
            authorization_state = "conditional"
        else:
            authorization_state = "unknown"

        if role.state not in {"modeled_subset", "resolved"}:
            uncertainties.append(f"{assignment.address}: role permissions are {role.state} for {secret.address}")
        if role.assignable_scope_state not in {"not_applicable", "resolved"}:
            uncertainties.append(
                f"{assignment.address}: custom-role assignable scope is "
                f"{role.assignable_scope_state} for {secret.address}"
            )
        if principal_state == "unknown":
            uncertainties.append(f"{assignment.address}: role assignment principal is unresolved for {secret.address}")
        if condition_state == "unknown":
            uncertainties.append(f"{assignment.address}: role assignment condition is unresolved for {secret.address}")
        elif condition_applicability_state == "unsupported":
            uncertainties.append(
                f"{assignment.address}: role assignment condition applicability is "
                f"unsupported for Key Vault secret data actions on {secret.address}"
            )

        grant: AzureKeyVaultSecretAuthorizationGrant = {
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
            "key_vault_id": vault_arm_id,
            "secret_address": secret.address,
            "secret_uri": secret_facts.key_vault_secret_uri,
            "secret_versionless_uri": (secret_facts.key_vault_secret_versionless_uri or ""),
            "secret_resource_id": secret_arm_id,
            "secret_version": secret_facts.key_vault_secret_version,
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
    secret: NormalizedResource,
    vault: NormalizedResource,
    context: AzureDecorationContext,
) -> _AssignmentScopeResolution:
    facts = azure_facts(assignment)
    scope = _known_string(facts.role_assignment_scope)
    target_address = _known_string(facts.role_assignment_target_resource_address)
    vault_arm_id = _canonical_vault_arm_id(secret, vault)
    secret_arm_id = _canonical_secret_arm_id(secret)

    if scope is None:
        if target_address == vault.address and vault_arm_id is not None:
            return _AssignmentScopeResolution("vault", "resolved", vault_arm_id)
        if target_address == secret.address and secret_arm_id is not None:
            return _AssignmentScopeResolution(
                "secret",
                "resolved",
                secret_arm_id,
            )
        unknown = _assignment_field_unknown(assignment, "scope")
        return _AssignmentScopeResolution(
            "unknown" if unknown else "unrelated",
            "unknown" if unknown else "not_configured",
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

    subscription_scope, resource_group_scope = _vault_parent_scopes(vault_arm_id)
    if _SUBSCRIPTION_SCOPE_PATTERN.fullmatch(normalized_scope):
        if subscription_scope is None:
            return _AssignmentScopeResolution(
                "subscription",
                "unknown",
                normalized_scope,
            )
        return _AssignmentScopeResolution(
            ("subscription" if _same_scope(normalized_scope, subscription_scope) else "unrelated"),
            "resolved",
            normalized_scope,
        )
    if _RESOURCE_GROUP_SCOPE_PATTERN.fullmatch(normalized_scope):
        if resource_group_scope is None:
            return _AssignmentScopeResolution(
                "resource_group",
                "unknown",
                normalized_scope,
            )
        return _AssignmentScopeResolution(
            ("resource_group" if _same_scope(normalized_scope, resource_group_scope) else "unrelated"),
            "resolved",
            normalized_scope,
        )
    if normalized_scope.casefold().startswith("azurerm_resource_group."):
        return _AssignmentScopeResolution("resource_group", "unknown")

    if vault_arm_id is not None and _same_scope(normalized_scope, vault_arm_id):
        return _AssignmentScopeResolution("vault", "resolved", vault_arm_id)
    if secret_arm_id is not None and _same_scope(normalized_scope, secret_arm_id):
        return _AssignmentScopeResolution("secret", "resolved", secret_arm_id)

    resolved = context.index.resolve(
        scope,
        source=assignment,
        resource_types={AzureResourceType.KEY_VAULT, AzureResourceType.KEY_VAULT_SECRET},
    )
    if resolved is None and target_address is not None:
        resolved = context.index.resources_by_address.get(target_address)
    if resolved is None:
        if normalized_scope.casefold().startswith("azurerm_key_vault_secret."):
            return _AssignmentScopeResolution("invalid", "invalid")
        return _AssignmentScopeResolution("unrelated", "external_or_unresolved")
    if resolved.address == vault.address:
        return (
            _AssignmentScopeResolution("vault", "resolved", vault_arm_id)
            if _valid_vault_scope(scope, vault)
            else _AssignmentScopeResolution("invalid", "invalid")
        )
    if resolved.resource_type != AzureResourceType.KEY_VAULT_SECRET:
        return _AssignmentScopeResolution("unrelated", "resolved")
    if resolved.address != secret.address:
        return _AssignmentScopeResolution("unrelated", "resolved")
    return (
        _AssignmentScopeResolution("secret", "resolved", secret_arm_id)
        if _valid_secret_scope(scope, secret)
        else _AssignmentScopeResolution("invalid", "invalid")
    )


def _canonical_vault_arm_id(
    secret: NormalizedResource,
    vault: NormalizedResource,
) -> str | None:
    vault_id = _known_string(azure_facts(vault).key_vault_id)
    if vault_id is not None:
        normalized = vault_id.strip().rstrip("/")
        if _VAULT_ARM_ID_PATTERN.fullmatch(normalized):
            return normalized

    secret_id = _canonical_secret_arm_id(secret)
    if secret_id is None:
        return None
    marker = "/secrets/"
    index = secret_id.casefold().rfind(marker)
    if index < 0:
        return None
    candidate = secret_id[:index]
    return candidate if _VAULT_ARM_ID_PATTERN.fullmatch(candidate) else None


def _canonical_secret_arm_id(secret: NormalizedResource) -> str | None:
    value = _known_string(azure_facts(secret).key_vault_secret_resource_id)
    if value is None:
        return None
    normalized = value.strip().rstrip("/")
    return normalized if _SECRET_ARM_ID_PATTERN.fullmatch(normalized) else None


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
    normalized = scope.strip().casefold().rstrip("/")
    vault_id = _known_string(azure_facts(vault).key_vault_id)
    if vault_id is not None and normalized == vault_id.casefold().rstrip("/"):
        return True
    return normalized in {
        f"{vault.address}.id".casefold(),
        f"${{{vault.address}.id}}".casefold(),
    }


def _valid_secret_scope(scope: str, secret: NormalizedResource) -> bool:
    normalized = scope.strip().casefold().rstrip("/")
    secret_id = _canonical_secret_arm_id(secret)
    if secret_id is not None and normalized == secret_id.casefold().rstrip("/"):
        return True
    return normalized in {
        f"{secret.address}.resource_versionless_id".casefold(),
        f"${{{secret.address}.resource_versionless_id}}".casefold(),
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
        if role_name is not None and role_name.casefold() in _KNOWN_NON_SECRET_ROLE_NAMES:
            return None
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
    if role_name.casefold() in _KNOWN_NON_SECRET_ROLE_NAMES:
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
    facts = azure_facts(role_definition)
    if any("assignable_scopes" in value for value in facts.role_definition_uncertainties):
        return "unknown"
    scopes = facts.role_definition_assignable_scopes
    if not scopes or assignment_arm_scope is None:
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
        for operation in _SECRET_OPERATIONS
        if _matches_any(operation.data_action, data_actions)
        and not _matches_any(operation.data_action, not_data_actions)
    )


def _excluded_data_actions(
    data_actions: tuple[str, ...],
    not_data_actions: tuple[str, ...],
) -> tuple[str, ...]:
    return tuple(
        operation.data_action
        for operation in _SECRET_OPERATIONS
        if _matches_any(operation.data_action, data_actions) and _matches_any(operation.data_action, not_data_actions)
    )


def _matches_any(action: str, patterns: tuple[str, ...]) -> bool:
    normalized_action = action.casefold()
    return any(fnmatchcase(normalized_action, pattern.strip().casefold()) for pattern in patterns if pattern.strip())


def _operations_for_data_actions(
    actions: tuple[str, ...],
) -> tuple[AzureKeyVaultSecretGrantOperation, ...]:
    matched = set(actions)
    return tuple(operation.name for operation in _SECRET_OPERATIONS if operation.data_action in matched)


def _operations_for_access_policy(
    permissions: tuple[str, ...],
) -> tuple[AzureKeyVaultSecretGrantOperation, ...]:
    matched = {
        operation
        for permission in permissions
        for operation in _ACCESS_POLICY_PERMISSION_OPERATIONS.get(permission, ())
    }
    return tuple(operation.name for operation in _SECRET_OPERATIONS if operation.name in matched)


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
    return sorted({item.strip().casefold() for item in value if isinstance(item, str) and item.strip()})


def _dedupe_grants(
    values: list[AzureKeyVaultSecretAuthorizationGrant],
) -> list[AzureKeyVaultSecretAuthorizationGrant]:
    result: list[AzureKeyVaultSecretAuthorizationGrant] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result
