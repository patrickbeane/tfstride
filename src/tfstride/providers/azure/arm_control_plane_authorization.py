from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Literal

from tfstride.models import (
    NormalizedResource,
    TerraformReferenceProvenance,
    TerraformReferenceResolutionState,
)
from tfstride.providers.azure.arm_control_plane_evidence import (
    AzureArmControlPlaneAuthorityState,
    AzureArmControlPlaneGrant,
    AzureArmDelegationConstraintKind,
    AzureArmRoleDefinitionConditionState,
    AzureArmScopeType,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType

_SUBSCRIPTION_SCOPE_PATTERN = re.compile(r"^/subscriptions/[^/]+$", re.IGNORECASE)
_RESOURCE_GROUP_SCOPE_PATTERN = re.compile(
    r"^/subscriptions/[^/]+/resourcegroups/[^/]+$",
    re.IGNORECASE,
)
_MANAGEMENT_GROUP_SCOPE_PATTERN = re.compile(
    r"^/providers/microsoft\.management/managementgroups/[^/]+$",
    re.IGNORECASE,
)

_KEY_VAULT_DATA_ROLE_IDS = (
    "00482a5a-887f-4fb3-b363-3b7fe8e74483",
    "a4417e6f-fecd-4de8-b567-7b0420556985",
    "14b46e9e-c2b7-41b4-b07b-48a6ebf60603",
    "e147488a-f6f5-4113-8e2d-b22465e65bf6",
    "12338af0-0e69-4776-bea7-57ae8d297424",
    "21090545-7ca7-4776-b22c-e363652d74d2",
    "b86a8fe4-44ce-4948-aee5-eccb2c155cd7",
    "4633458b-17de-408a-b874-0445c86b69e6",
)


@dataclass(frozen=True, slots=True)
class _BuiltInControlPlaneRole:
    name: str
    role_id: str
    actions: tuple[str, ...]
    not_actions: tuple[str, ...] = ()
    role_definition_condition_state: AzureArmRoleDefinitionConditionState = "not_configured"
    delegation_constraint_kind: AzureArmDelegationConstraintKind = "none"
    allowed_role_definition_ids: tuple[str, ...] = ()


_BUILT_IN_CONTROL_PLANE_ROLES = (
    _BuiltInControlPlaneRole(
        "Owner",
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        ("*",),
    ),
    _BuiltInControlPlaneRole(
        "Contributor",
        "b24988ac-6180-42a0-ab88-20f7382dd24c",
        ("*",),
        (
            "Microsoft.Authorization/*/Delete",
            "Microsoft.Authorization/*/Write",
            "Microsoft.Authorization/elevateAccess/Action",
        ),
    ),
    _BuiltInControlPlaneRole(
        "Monitoring Contributor",
        "749f88d5-cbae-40b8-bcfc-e573ddc772fa",
        ("Microsoft.Insights/DiagnosticSettings/*",),
    ),
    _BuiltInControlPlaneRole(
        "Storage Account Contributor",
        "17d1049b-9a84-46fb-8f53-869881c3d3ab",
        (
            "Microsoft.Authorization/*/read",
            "Microsoft.Insights/alertRules/*",
            "Microsoft.Insights/diagnosticSettings/*",
            "Microsoft.Network/virtualNetworks/subnets/joinViaServiceEndpoint/action",
            "Microsoft.ResourceHealth/availabilityStatuses/read",
            "Microsoft.Resources/deployments/*",
            "Microsoft.Resources/subscriptions/resourceGroups/read",
            "Microsoft.Storage/storageAccounts/*",
            "Microsoft.Support/*",
        ),
    ),
    _BuiltInControlPlaneRole(
        "Storage Blob Data Contributor",
        "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
        (
            "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
            "Microsoft.Storage/storageAccounts/blobServices/containers/read",
            "Microsoft.Storage/storageAccounts/blobServices/containers/write",
            "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action",
        ),
    ),
    _BuiltInControlPlaneRole(
        "Storage Blob Data Owner",
        "b7e6dc6d-f1e8-4753-8033-0f276bb0955b",
        (
            "Microsoft.Storage/storageAccounts/blobServices/containers/*",
            "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action",
        ),
    ),
    _BuiltInControlPlaneRole(
        "Cosmos DB Operator",
        "230815da-be43-4aae-9cb4-875f7bd000aa",
        (
            "Microsoft.DocumentDb/databaseAccounts/*",
            "Microsoft.Insights/alertRules/*",
            "Microsoft.Authorization/*/read",
            "Microsoft.ResourceHealth/availabilityStatuses/read",
            "Microsoft.Resources/deployments/*",
            "Microsoft.Resources/subscriptions/resourceGroups/read",
            "Microsoft.Support/*",
            "Microsoft.Network/virtualNetworks/subnets/joinViaServiceEndpoint/action",
        ),
        (
            "Microsoft.DocumentDB/databaseAccounts/copyJobs/*",
            "Microsoft.DocumentDB/databaseAccounts/dataTransferJobs/*",
            "Microsoft.DocumentDB/databaseAccounts/readonlyKeys/*",
            "Microsoft.DocumentDB/databaseAccounts/regenerateKey/*",
            "Microsoft.DocumentDB/databaseAccounts/listKeys/*",
            "Microsoft.DocumentDB/databaseAccounts/listConnectionStrings/*",
            "Microsoft.DocumentDB/databaseAccounts/sqlRoleDefinitions/write",
            "Microsoft.DocumentDB/databaseAccounts/sqlRoleDefinitions/delete",
            "Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/write",
            "Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/delete",
            "Microsoft.DocumentDB/databaseAccounts/mongodbRoleDefinitions/write",
            "Microsoft.DocumentDB/databaseAccounts/mongodbRoleDefinitions/delete",
            "Microsoft.DocumentDB/databaseAccounts/mongodbUserDefinitions/write",
            "Microsoft.DocumentDB/databaseAccounts/mongodbUserDefinitions/delete",
            "Microsoft.DocumentDB/databaseAccounts/tableRoleAssignments/write",
            "Microsoft.DocumentDB/databaseAccounts/tableRoleAssignments/delete",
            "Microsoft.DocumentDB/databaseAccounts/tableRoleDefinitions/write",
            "Microsoft.DocumentDB/databaseAccounts/tableRoleDefinitions/delete",
            "Microsoft.DocumentDB/databaseAccounts/gremlinRoleAssignments/write",
            "Microsoft.DocumentDB/databaseAccounts/gremlinRoleAssignments/delete",
            "Microsoft.DocumentDB/databaseAccounts/gremlinRoleDefinitions/write",
            "Microsoft.DocumentDB/databaseAccounts/gremlinRoleDefinitions/delete",
            "Microsoft.DocumentDB/databaseAccounts/cassandraRoleAssignments/write",
            "Microsoft.DocumentDB/databaseAccounts/cassandraRoleAssignments/delete",
            "Microsoft.DocumentDB/databaseAccounts/cassandraRoleDefinitions/write",
            "Microsoft.DocumentDB/databaseAccounts/cassandraRoleDefinitions/delete",
            "Microsoft.DocumentDB/databaseAccounts/mongoMIRoleAssignments/write",
            "Microsoft.DocumentDB/databaseAccounts/mongoMIRoleAssignments/delete",
            "Microsoft.DocumentDB/databaseAccounts/mongoMIRoleDefinitions/write",
            "Microsoft.DocumentDB/databaseAccounts/mongoMIRoleDefinitions/delete",
        ),
    ),
    _BuiltInControlPlaneRole(
        "DocumentDB Account Contributor",
        "5bd9cd88-fe45-4216-938b-f97437e15450",
        (
            "Microsoft.Authorization/*/read",
            "Microsoft.DocumentDb/databaseAccounts/*",
            "Microsoft.Insights/alertRules/*",
            "Microsoft.ResourceHealth/availabilityStatuses/read",
            "Microsoft.Resources/deployments/*",
            "Microsoft.Resources/subscriptions/resourceGroups/read",
            "Microsoft.Support/*",
            "Microsoft.Network/virtualNetworks/subnets/joinViaServiceEndpoint/action",
        ),
    ),
    _BuiltInControlPlaneRole(
        "Role Based Access Control Administrator",
        "f58310d9-a9f6-439a-9e8d-f62e7b41a168",
        ("Microsoft.Authorization/roleAssignments/write",),
    ),
    _BuiltInControlPlaneRole(
        "User Access Administrator",
        "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
        ("Microsoft.Authorization/*",),
    ),
    _BuiltInControlPlaneRole(
        "Key Vault Contributor",
        "f25e0fa2-a7c8-4377-a976-54943a77a395",
        ("Microsoft.KeyVault/*",),
        (
            "Microsoft.KeyVault/locations/deletedVaults/purge/action",
            "Microsoft.KeyVault/hsmPools/*",
            "Microsoft.KeyVault/managedHsms/*",
        ),
    ),
    _BuiltInControlPlaneRole(
        "Key Vault Data Access Administrator",
        "8b54135c-b56d-4d72-a534-26097cfdc8d8",
        (
            "Microsoft.Authorization/roleAssignments/write",
            "Microsoft.Authorization/roleAssignments/delete",
        ),
        role_definition_condition_state="configured",
        delegation_constraint_kind="allowed_role_definition_ids",
        allowed_role_definition_ids=_KEY_VAULT_DATA_ROLE_IDS,
    ),
    _BuiltInControlPlaneRole(
        "Reader",
        "acdd72a7-3385-48ef-bd42-f606fba81ae7",
        (),
    ),
    _BuiltInControlPlaneRole(
        "Key Vault Administrator",
        "00482a5a-887f-4fb3-b363-3b7fe8e74483",
        (),
    ),
    _BuiltInControlPlaneRole(
        "Key Vault Crypto Officer",
        "14b46e9e-c2b7-41b4-b07b-48a6ebf60603",
        (),
    ),
    _BuiltInControlPlaneRole(
        "Key Vault Crypto Service Encryption User",
        "e147488a-f6f5-4113-8e2d-b22465e65bf6",
        (),
    ),
    _BuiltInControlPlaneRole(
        "Key Vault Crypto Service Release User",
        "08bbd89e-9f13-488c-ac41-acfcb10c90ab",
        (),
    ),
    _BuiltInControlPlaneRole(
        "Key Vault Crypto User",
        "12338af0-0e69-4776-bea7-57ae8d297424",
        (),
    ),
    _BuiltInControlPlaneRole(
        "Key Vault Reader",
        "21090545-7ca7-4776-b22c-e363652d74d2",
        (),
    ),
)
_BUILT_IN_CONTROL_PLANE_ROLES_BY_ID = {role.role_id.casefold(): role for role in _BUILT_IN_CONTROL_PLANE_ROLES}
_BUILT_IN_CONTROL_PLANE_ROLES_BY_NAME = {role.name.casefold(): role for role in _BUILT_IN_CONTROL_PLANE_ROLES}


@dataclass(frozen=True, slots=True)
class _RoleResolution:
    role_kind: str
    state: str
    actions: tuple[str, ...]
    not_actions: tuple[str, ...] = ()
    role_definition_address: str | None = None
    assignable_scope_state: str = "not_applicable"
    role_definition_condition_state: AzureArmRoleDefinitionConditionState = "not_configured"
    delegation_constraint_kind: AzureArmDelegationConstraintKind = "none"
    allowed_role_definition_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _ScopeResolution:
    state: Literal["resolved", "unknown", "unrelated", "invalid"]
    scope_type: AzureArmScopeType | None = None
    arm_scope: str | None = None


@dataclass(frozen=True, slots=True)
class AzureArmControlPlaneAuthorityResult:
    state: AzureArmControlPlaneAuthorityState
    grant: AzureArmControlPlaneGrant | None = None
    uncertainties: tuple[str, ...] = ()


def model_arm_control_plane_action_authority(
    assignment: NormalizedResource,
    context: AzureDecorationContext,
    *,
    principal_id: str,
    target_arm_id: str,
    requested_actions: tuple[str, ...],
) -> AzureArmControlPlaneAuthorityResult:
    """Evaluate modeled ARM allow authority without claiming deny-assignment coverage."""

    normalized_target = _arm_id(target_arm_id)
    if normalized_target is None or not requested_actions:
        return AzureArmControlPlaneAuthorityResult(
            "unknown",
            uncertainties=(f"{assignment.address}: exact ARM target or requested actions are unresolved",),
        )

    facts = azure_facts(assignment)
    assignment_principal = _known_string(facts.principal_id)
    if assignment_principal is not None and assignment_principal.casefold() != principal_id.casefold():
        return AzureArmControlPlaneAuthorityResult("unrelated")

    scope = _assignment_scope(assignment, context, normalized_target)
    if scope.state == "unrelated":
        return AzureArmControlPlaneAuthorityResult("unrelated")

    role = _resolve_role(assignment, context, scope.arm_scope)
    matched_actions, excluded_actions = _matched_actions(
        requested_actions,
        role.actions,
        role.not_actions,
    )
    role_may_match = bool(matched_actions) or role.state not in {"resolved", "modeled_subset"}
    if not role_may_match:
        return AzureArmControlPlaneAuthorityResult("not_granted")

    if assignment_principal is None:
        return AzureArmControlPlaneAuthorityResult(
            "unknown",
            uncertainties=(
                f"{assignment.address}: principal applicability is unresolved for modeled ARM action authority",
            ),
        )
    if scope.state != "resolved" or scope.scope_type is None or scope.arm_scope is None:
        return AzureArmControlPlaneAuthorityResult(
            "unknown",
            uncertainties=(
                f"{assignment.address}: assignment scope applicability is unresolved for modeled ARM action authority",
            ),
        )
    if role.state not in {"resolved", "modeled_subset"}:
        return AzureArmControlPlaneAuthorityResult(
            "unknown",
            uncertainties=(f"{assignment.address}: control-plane role resolution is {role.state}",),
        )
    if role.assignable_scope_state not in {"resolved", "not_applicable"}:
        return AzureArmControlPlaneAuthorityResult(
            "unknown",
            uncertainties=(
                f"{assignment.address}: custom-role assignable-scope compatibility is {role.assignable_scope_state}",
            ),
        )

    condition_state = assignment_condition_state(assignment)
    if condition_state != "not_configured":
        return AzureArmControlPlaneAuthorityResult(
            "unknown",
            uncertainties=(f"{assignment.address}: assignment condition state is {condition_state}",),
        )
    if not matched_actions:
        return AzureArmControlPlaneAuthorityResult("not_granted")

    grant: AzureArmControlPlaneGrant = {
        "source_address": assignment.address,
        "principal_id": facts.principal_id,
        "principal_type": facts.principal_type,
        "principal_state": "resolved",
        "assignment_scope_type": scope.scope_type,
        "assignment_scope": facts.role_assignment_scope,
        "assignment_scope_arm_id": scope.arm_scope,
        "assignment_scope_state": "resolved",
        "target_arm_id": normalized_target,
        "role_definition_name": facts.role_definition_name,
        "role_definition_id": facts.role_definition_id,
        "role_definition_address": role.role_definition_address,
        "role_kind": role.role_kind,
        "role_resolution_state": role.state,
        "role_actions": list(role.actions),
        "role_not_actions": list(role.not_actions),
        "requested_actions": list(requested_actions),
        "matched_actions": list(matched_actions),
        "excluded_actions": list(excluded_actions),
        "assignable_scope_compatibility_state": role.assignable_scope_state,
        "assignment_condition": facts.role_assignment_condition,
        "assignment_condition_version": facts.role_assignment_condition_version,
        "assignment_condition_state": "not_configured",
        "role_definition_condition_state": role.role_definition_condition_state,
        "delegation_constraint_kind": role.delegation_constraint_kind,
        "allowed_role_definition_ids": list(role.allowed_role_definition_ids),
        "authorization_state": "granted",
        "deny_assignments_evaluated": False,
        "evaluation_basis": "modeled_arm_control_plane_authority",
    }
    return AzureArmControlPlaneAuthorityResult("granted", grant=grant)


def azure_arm_scope_contains(parent: str, child: str) -> bool:
    normalized_parent = parent.strip().casefold().rstrip("/")
    normalized_child = child.strip().casefold().rstrip("/")
    if normalized_parent == "":
        normalized_parent = "/"
    if normalized_parent == "/":
        return True
    if not normalized_parent.startswith("/") or not normalized_child.startswith("/"):
        return False
    return normalized_child == normalized_parent or normalized_child.startswith(f"{normalized_parent}/")


def _assignment_scope(
    assignment: NormalizedResource,
    context: AzureDecorationContext,
    target_arm_id: str,
) -> _ScopeResolution:
    facts = azure_facts(assignment)
    raw_scope = _known_string(facts.role_assignment_scope)
    if raw_scope is None:
        if _assignment_field_unknown(assignment, "scope"):
            return _ScopeResolution("unknown")
        target_address = _known_string(facts.role_assignment_target_resource_address)
        target = context.index.resources_by_address.get(target_address or "")
        arm_scope = _resource_arm_id(target) if target is not None else None
    else:
        arm_scope = _arm_id(raw_scope)
        if arm_scope is None:
            target = _proven_symbolic_assignment_scope_target(
                assignment,
                context,
            )
            arm_scope = _resource_arm_id(target) if target is not None else None

    if arm_scope is None:
        return _ScopeResolution("unknown")
    scope_type = _scope_type(arm_scope)
    if scope_type is None:
        return _ScopeResolution("invalid")
    if scope_type == "management_group" and not azure_arm_scope_contains(
        arm_scope,
        target_arm_id,
    ):
        return _ScopeResolution("unknown", scope_type, arm_scope)
    if not azure_arm_scope_contains(arm_scope, target_arm_id):
        return _ScopeResolution("unrelated", scope_type, arm_scope)
    return _ScopeResolution("resolved", scope_type, arm_scope)


def _proven_symbolic_assignment_scope_target(
    assignment: NormalizedResource,
    context: AzureDecorationContext,
) -> NormalizedResource | None:
    facts = azure_facts(assignment)
    target_address = _known_string(facts.role_assignment_target_resource_address)
    if target_address is None:
        return None

    resolution = assignment.reference_resolution("scope")
    if (
        resolution.state != TerraformReferenceResolutionState.SYMBOLIC
        or resolution.provenance != TerraformReferenceProvenance.CONFIGURATION_REFERENCE
        or len(resolution.targets) != 1
    ):
        return None

    resolved_target = resolution.targets[0]
    if resolved_target.address != target_address:
        return None
    target = context.index.resources_by_address.get(target_address)
    if target is None or not _valid_symbolic_assignment_scope_reference(
        target,
        resolved_target.reference,
    ):
        return None
    return target


def _valid_symbolic_assignment_scope_reference(
    target: NormalizedResource,
    reference: str,
) -> bool:
    normalized = reference.casefold()
    if target.resource_type in {
        AzureResourceType.KEY_VAULT_KEY,
        AzureResourceType.KEY_VAULT_SECRET,
    }:
        return normalized.endswith(".resource_versionless_id")
    if target.resource_type == AzureResourceType.STORAGE_CONTAINER:
        return normalized.endswith(".resource_manager_id")
    return normalized.endswith(".id")


def _resolve_role(
    assignment: NormalizedResource,
    context: AzureDecorationContext,
    assignment_arm_scope: str | None,
) -> _RoleResolution:
    facts = azure_facts(assignment)
    role_id = _known_string(facts.role_definition_id)
    role_name = _known_string(facts.role_definition_name)
    if role_id is not None:
        built_in = _BUILT_IN_CONTROL_PLANE_ROLES_BY_ID.get(_role_id(role_id))
        if built_in is not None:
            return _built_in_role_resolution(built_in)
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
    if role_name is None or _assignment_field_unknown(assignment, "role_definition_name"):
        return _RoleResolution("unknown", "unresolved", ())
    built_in = _BUILT_IN_CONTROL_PLANE_ROLES_BY_NAME.get(role_name.casefold())
    if built_in is not None:
        return _built_in_role_resolution(built_in)
    return _RoleResolution("unknown", "unresolved", ())


def _built_in_role_resolution(role: _BuiltInControlPlaneRole) -> _RoleResolution:
    return _RoleResolution(
        role_kind="built_in",
        state="modeled_subset",
        actions=role.actions,
        not_actions=role.not_actions,
        role_definition_condition_state=role.role_definition_condition_state,
        delegation_constraint_kind=role.delegation_constraint_kind,
        allowed_role_definition_ids=role.allowed_role_definition_ids,
    )


def _custom_role_resolution(
    role_definition: NormalizedResource,
    assignment_arm_scope: str | None,
) -> _RoleResolution:
    facts = azure_facts(role_definition)
    permission_uncertain = any(
        value == "permissions is unknown after planning"
        or ".actions is unknown" in value
        or ".not_actions is unknown" in value
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
            actions=(),
            role_definition_address=role_definition.address,
            assignable_scope_state=assignable_scope_state,
        )
    return _RoleResolution(
        role_kind="custom",
        state="resolved",
        actions=tuple(_string_values(facts.role_definition_actions)),
        not_actions=tuple(_string_values(facts.role_definition_not_actions)),
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


def _matched_actions(
    requested_actions: tuple[str, ...],
    actions: tuple[str, ...],
    not_actions: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    matched = tuple(
        action
        for action in requested_actions
        if _matches_any(action, actions) and not _matches_any(action, not_actions)
    )
    excluded = tuple(
        action for action in requested_actions if _matches_any(action, actions) and _matches_any(action, not_actions)
    )
    return matched, excluded


def assignment_condition_state(assignment: NormalizedResource) -> str:
    facts = azure_facts(assignment)
    if _assignment_field_unknown(assignment, "condition") or _assignment_field_unknown(
        assignment,
        "condition_version",
    ):
        return "unknown"
    if facts.role_assignment_condition:
        return "configured"
    if facts.role_assignment_condition_version:
        return "unknown"
    return "not_configured"


def _assignment_field_unknown(assignment: NormalizedResource, field: str) -> bool:
    prefix = f"{field} is unknown"
    return any(value.startswith(prefix) for value in azure_facts(assignment).key_vault_authorization_uncertainties)


def _scope_type(value: str) -> AzureArmScopeType | None:
    if _MANAGEMENT_GROUP_SCOPE_PATTERN.fullmatch(value):
        return "management_group"
    if _SUBSCRIPTION_SCOPE_PATTERN.fullmatch(value):
        return "subscription"
    if _RESOURCE_GROUP_SCOPE_PATTERN.fullmatch(value):
        return "resource_group"
    if _arm_id(value) is not None:
        return "resource"
    return None


def _resource_arm_id(resource: NormalizedResource) -> str | None:
    facts = azure_facts(resource)
    if resource.resource_type in AZURE_APP_SERVICE_RESOURCE_TYPES:
        value = facts.app_service_id
    elif resource.resource_type == AzureResourceType.STORAGE_ACCOUNT:
        value = facts.storage_account_id
    elif resource.resource_type == AzureResourceType.STORAGE_CONTAINER:
        value = facts.storage_container_resource_manager_id
    elif resource.resource_type == AzureResourceType.KEY_VAULT:
        value = facts.key_vault_id
    elif resource.resource_type == AzureResourceType.KEY_VAULT_KEY:
        value = facts.key_vault_key_versionless_resource_id
    elif resource.resource_type == AzureResourceType.SERVICE_BUS_NAMESPACE:
        value = facts.service_bus_namespace_id
    elif resource.resource_type in {
        AzureResourceType.SERVICE_BUS_QUEUE,
        AzureResourceType.SERVICE_BUS_TOPIC,
        AzureResourceType.SERVICE_BUS_SUBSCRIPTION,
    }:
        value = facts.service_bus_entity_id
    elif resource.resource_type == AzureResourceType.COSMOSDB_ACCOUNT:
        value = facts.cosmosdb_account_id
    elif resource.resource_type == AzureResourceType.COSMOSDB_SQL_DATABASE:
        value = facts.cosmosdb_sql_database_id
    elif resource.resource_type == AzureResourceType.COSMOSDB_SQL_CONTAINER:
        value = facts.cosmosdb_sql_container_id
    elif resource.resource_type == AzureResourceType.COSMOSDB_SQL_ROLE_DEFINITION:
        value = facts.cosmosdb_sql_role_definition_resource_id
    else:
        value = resource.identifier
    return _arm_id(value) or _arm_id(resource.identifier)


def _arm_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().rstrip("/")
    if "|" in normalized:
        return None
    lowered = normalized.casefold()
    if lowered == "/" or lowered.startswith("/subscriptions/") or lowered.startswith("/providers/"):
        return normalized
    return None


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
    return sorted({item.strip() for item in value if isinstance(item, str) and item.strip()})


def _matches_any(action: str, patterns: tuple[str, ...]) -> bool:
    normalized_action = action.casefold()
    return any(fnmatchcase(normalized_action, pattern.strip().casefold()) for pattern in patterns if pattern.strip())
