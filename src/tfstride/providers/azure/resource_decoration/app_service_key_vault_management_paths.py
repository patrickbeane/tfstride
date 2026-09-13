from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Literal, TypedDict, TypeGuard

from tfstride.models import NormalizedResource
from tfstride.providers.azure.arm_control_plane_authorization import (
    AzureArmControlPlaneAuthorityResult,
    model_arm_control_plane_action_authority,
)
from tfstride.providers.azure.arm_control_plane_evidence import AzureArmControlPlaneGrant
from tfstride.providers.azure.key_vault_evidence import (
    AzureAppServiceKeyVaultManagementPath,
    AzureKeyVaultAuthorizationGrant,
    AzureKeyVaultAuthorizationModel,
    AzureKeyVaultDelegationMechanism,
    AzureKeyVaultManagementOperation,
    AzureKeyVaultManagementOperationClass,
    AzureKeyVaultPathScopeType,
    AzureKeyVaultRuntimeIdentityKind,
)
from tfstride.providers.azure.resource_decoration.workload_identities import workload_managed_identities
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType
from tfstride.providers.coercion import dedupe

_KEY_MANAGEMENT_OPERATIONS = frozenset({"update", "delete", "purge"})
_RBAC_ASSIGNMENT_WRITE = "Microsoft.Authorization/roleAssignments/write"
_VAULT_WRITE = "Microsoft.KeyVault/vaults/write"
_ACCESS_POLICIES_WRITE = "Microsoft.KeyVault/vaults/accessPolicies/write"
_LEGACY_ACCESS_POLICY_ACTIONS = (_VAULT_WRITE, _ACCESS_POLICIES_WRITE)
_SUPPORTED_DATA_GRANT_SCOPES = frozenset({"subscription", "resource_group", "vault", "key"})


@dataclass(frozen=True, slots=True)
class _RuntimeIdentity:
    resource: NormalizedResource
    kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str


class _ManagementPathIdentityAndTarget(TypedDict):
    workload_address: str
    workload_type: str
    identity_address: str
    identity_kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str
    credential_context: Literal["workload_runtime"]
    key_vault_address: str
    key_vault_id: str
    key_address: str | None
    key_resource_type: str | None
    key_name: str | None
    key_uri: str | None
    key_versionless_uri: str | None
    key_resource_id: str | None
    key_versionless_resource_id: str | None
    key_version: str | None
    target_address: str
    target_resource_id: str


class ModelAppServiceKeyVaultManagementPathsStage:
    """Project exact Key Vault administration onto App Service runtime identities."""

    name = "model_app_service_key_vault_management_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        keys = tuple(resource for resource in resources if resource.resource_type == AzureResourceType.KEY_VAULT_KEY)
        vaults = tuple(resource for resource in resources if resource.resource_type == AzureResourceType.KEY_VAULT)
        assignments = tuple(
            resource for resource in resources if resource.resource_type == AzureResourceType.ROLE_ASSIGNMENT
        )
        for workload in resources:
            if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
                continue
            paths, uncertainties = _app_service_key_vault_management_paths(
                workload,
                keys,
                vaults,
                assignments,
                context,
            )
            facts = azure_facts(workload)
            facts.set_app_service_key_vault_management_paths(paths)
            facts.extend_app_service_key_vault_management_path_uncertainties(uncertainties)


def _app_service_key_vault_management_paths(
    workload: NormalizedResource,
    keys: Sequence[NormalizedResource],
    vaults: Sequence[NormalizedResource],
    assignments: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> tuple[list[AzureAppServiceKeyVaultManagementPath], list[str]]:
    identities, identity_uncertainties = workload_managed_identities(workload, context)
    uncertainties = [
        *identity_uncertainties,
        *[f"{workload.address}: {value}" for value in azure_facts(workload).managed_identity_uncertainties],
    ]
    runtime_identities = tuple(
        _RuntimeIdentity(identity, kind, principal_id)
        for identity, kind in identities
        if _is_runtime_identity_kind(kind)
        and (principal_id := _known_string(azure_facts(identity).principal_id)) is not None
    )
    if not runtime_identities:
        return [], dedupe(uncertainties)

    paths: list[AzureAppServiceKeyVaultManagementPath] = []
    keys_by_vault: dict[str, list[NormalizedResource]] = {}
    for key in keys:
        key_facts = azure_facts(key)
        if key_facts.key_vault_key_identity_state != "resolved":
            if _key_authorization_may_match_runtime(key, runtime_identities, context):
                uncertainties.append(
                    f"{workload.address}: Key Vault key {key.address} has unresolved exact identity "
                    "for management paths"
                )
            continue
        vault = context.index.resolve(
            key_facts.resolved_key_vault_address,
            source=key,
            resource_types={AzureResourceType.KEY_VAULT},
        )
        if vault is None or vault.resource_type != AzureResourceType.KEY_VAULT:
            if _key_authorization_may_match_runtime(key, runtime_identities, context):
                uncertainties.append(
                    f"{workload.address}: Key Vault key {key.address} has unresolved vault ancestry "
                    "for management paths"
                )
            continue
        keys_by_vault.setdefault(vault.address, []).append(key)
        key_paths, key_uncertainties = _key_lifecycle_paths(
            workload,
            runtime_identities,
            key,
            vault,
            context,
        )
        paths.extend(key_paths)
        uncertainties.extend(key_uncertainties)

    for vault in vaults:
        delegation_paths, delegation_uncertainties = _delegation_paths(
            workload,
            runtime_identities,
            vault,
            tuple(keys_by_vault.get(vault.address, ())),
            assignments,
            context,
        )
        paths.extend(delegation_paths)
        uncertainties.extend(delegation_uncertainties)

    paths = _dedupe_paths(paths)
    paths.sort(
        key=lambda path: (
            path["management_effect"],
            path["target_address"],
            path["operation"],
            path["identity_address"],
            ",".join(path["grant_source_addresses"]),
        )
    )
    return paths, dedupe(uncertainties)


def _key_lifecycle_paths(
    workload: NormalizedResource,
    identities: Sequence[_RuntimeIdentity],
    key: NormalizedResource,
    vault: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[list[AzureAppServiceKeyVaultManagementPath], list[str]]:
    key_facts = azure_facts(key)
    vault_facts = azure_facts(vault)
    uncertainties: list[str] = []
    grants_by_identity: dict[str, dict[str, list[AzureKeyVaultAuthorizationGrant]]] = {
        identity.resource.address: {operation: [] for operation in _KEY_MANAGEMENT_OPERATIONS}
        for identity in identities
    }
    identity_by_principal = {identity.principal_id.casefold(): identity for identity in identities}
    uncertain_sources: set[str] = set()

    for grant in key_facts.key_vault_key_authorization_grants:
        source = grant["grant_source_address"]
        principal_id = _known_string(grant.get("principal_id"))
        operations = set(_string_values(grant.get("matched_operations"))) & _KEY_MANAGEMENT_OPERATIONS
        operations_unknown = _data_grant_operations_unresolved(grant)
        if principal_id is None:
            if operations or operations_unknown:
                uncertain_sources.add(source)
                uncertainties.append(
                    f"{workload.address}: {source} principal applicability is unresolved for "
                    f"Key Vault management on {key.address}"
                )
            continue
        identity = identity_by_principal.get(principal_id.casefold())
        if identity is None:
            continue
        if not operations:
            if operations_unknown:
                uncertain_sources.add(source)
                uncertainties.append(
                    f"{workload.address}: {source} Key Vault management operations are unresolved "
                    f"for runtime principal {principal_id} on {key.address}"
                )
            continue
        if not _data_grant_is_deterministic(grant, key, vault, context):
            uncertain_sources.add(source)
            uncertainties.append(
                f"{workload.address}: {source} has non-deterministic Key Vault management authority "
                f"for runtime principal {principal_id} on {key.address} "
                f"(authorization_state={grant.get('authorization_state') or 'unknown'}, "
                f"authorization_model_state={grant.get('authorization_model_state') or 'unknown'}, "
                f"condition_state={grant.get('condition_state') or 'unknown'})"
            )
            continue
        for operation in operations:
            grants_by_identity[identity.resource.address][operation].append(grant)

    for uncertainty in key_facts.key_vault_key_authorization_uncertainties:
        source = uncertainty.partition(":")[0]
        source_grants = [
            grant for grant in key_facts.key_vault_key_authorization_grants if grant["grant_source_address"] == source
        ]
        if source_grants and source not in uncertain_sources:
            continue
        if not source_grants and not _uncertainty_source_may_match(source, identities, context):
            continue
        uncertainties.append(
            f"{workload.address}: Key Vault authorization posture for {key.address} is incomplete: {uncertainty}"
        )

    paths: list[AzureAppServiceKeyVaultManagementPath] = []
    for identity in identities:
        operation_grants = grants_by_identity[identity.resource.address]
        update_grants = operation_grants["update"]
        delete_grants = operation_grants["delete"]
        purge_grants = operation_grants["purge"]
        if update_grants:
            paths.append(
                _data_plane_management_path(
                    workload,
                    identity,
                    key,
                    vault,
                    "update",
                    ("update",),
                    update_grants,
                    lifecycle_state="compatible",
                )
            )
        if delete_grants:
            paths.append(
                _data_plane_management_path(
                    workload,
                    identity,
                    key,
                    vault,
                    "delete",
                    ("delete",),
                    delete_grants,
                    lifecycle_state="compatible",
                )
            )
        if delete_grants and purge_grants:
            if vault_facts.purge_protection_enabled is False:
                paths.append(
                    _data_plane_management_path(
                        workload,
                        identity,
                        key,
                        vault,
                        "delete_plus_purge",
                        ("delete", "purge"),
                        [*delete_grants, *purge_grants],
                        lifecycle_state="compatible",
                    )
                )
            elif vault_facts.purge_protection_enabled is None:
                uncertainties.append(
                    f"{workload.address}: Key Vault {vault.address} purge protection is unresolved, "
                    f"so delete-plus-purge compatibility for {key.address} is unknown"
                )
    return paths, uncertainties


def _delegation_paths(
    workload: NormalizedResource,
    identities: Sequence[_RuntimeIdentity],
    vault: NormalizedResource,
    keys: Sequence[NormalizedResource],
    assignments: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> tuple[list[AzureAppServiceKeyVaultManagementPath], list[str]]:
    vault_facts = azure_facts(vault)
    vault_id = _known_string(vault_facts.key_vault_id)
    if vault_id is None:
        return [], [
            f"{workload.address}: Key Vault {vault.address} has unresolved exact ARM identity for delegation paths"
        ]

    authorization_model = _authorization_model(vault_facts.rbac_authorization_enabled)
    grants_by_path: dict[
        tuple[str, AzureKeyVaultManagementOperation, str],
        list[AzureArmControlPlaneGrant],
    ] = {}
    uncertainties: list[str] = []

    for identity in identities:
        for assignment in assignments:
            if authorization_model == "azure_rbac":
                _collect_rbac_delegation_authority(
                    workload,
                    identity,
                    vault,
                    keys,
                    assignment,
                    context,
                    grants_by_path,
                    uncertainties,
                )
                _collect_vault_authority(
                    workload,
                    identity,
                    vault,
                    assignment,
                    context,
                    operation="authorization_model_mutation",
                    requested_actions=(_VAULT_WRITE,),
                    grants_by_path=grants_by_path,
                    uncertainties=uncertainties,
                )
            elif authorization_model == "access_policy":
                _collect_vault_authority(
                    workload,
                    identity,
                    vault,
                    assignment,
                    context,
                    operation="legacy_access_policy_mutation",
                    requested_actions=_LEGACY_ACCESS_POLICY_ACTIONS,
                    grants_by_path=grants_by_path,
                    uncertainties=uncertainties,
                )
            else:
                _collect_unknown_model_authority(
                    workload,
                    identity,
                    vault,
                    keys,
                    assignment,
                    context,
                    uncertainties,
                )

    if authorization_model == "unknown":
        return [], uncertainties

    paths: list[AzureAppServiceKeyVaultManagementPath] = []
    for (identity_address, operation, target_address), grants in grants_by_path.items():
        identity = next(value for value in identities if value.resource.address == identity_address)
        target = context.index.resources_by_address.get(target_address)
        if target is None:
            continue
        paths.append(
            _control_plane_management_path(
                workload,
                identity,
                vault,
                target,
                authorization_model,
                operation,
                grants,
            )
        )
    return paths, uncertainties


def _collect_rbac_delegation_authority(
    workload: NormalizedResource,
    identity: _RuntimeIdentity,
    vault: NormalizedResource,
    keys: Sequence[NormalizedResource],
    assignment: NormalizedResource,
    context: AzureDecorationContext,
    grants_by_path: dict[
        tuple[str, AzureKeyVaultManagementOperation, str],
        list[AzureArmControlPlaneGrant],
    ],
    uncertainties: list[str],
) -> None:
    vault_id = _known_string(azure_facts(vault).key_vault_id)
    if vault_id is None:
        return
    vault_result = model_arm_control_plane_action_authority(
        assignment,
        context,
        principal_id=identity.principal_id,
        target_arm_id=vault_id,
        requested_actions=(_RBAC_ASSIGNMENT_WRITE,),
    )
    if _record_control_result(
        workload,
        identity,
        vault,
        "rbac_role_assignment_management",
        vault_result,
        grants_by_path,
        uncertainties,
    ):
        return

    for key in keys:
        key_id = _known_string(azure_facts(key).key_vault_key_versionless_resource_id)
        if key_id is None:
            continue
        result = model_arm_control_plane_action_authority(
            assignment,
            context,
            principal_id=identity.principal_id,
            target_arm_id=key_id,
            requested_actions=(_RBAC_ASSIGNMENT_WRITE,),
        )
        grant = result.grant
        if grant is not None and grant["assignment_scope_arm_id"].casefold() != key_id.casefold():
            continue
        _record_control_result(
            workload,
            identity,
            key,
            "rbac_role_assignment_management",
            result,
            grants_by_path,
            uncertainties,
        )


def _collect_vault_authority(
    workload: NormalizedResource,
    identity: _RuntimeIdentity,
    vault: NormalizedResource,
    assignment: NormalizedResource,
    context: AzureDecorationContext,
    *,
    operation: AzureKeyVaultManagementOperation,
    requested_actions: tuple[str, ...],
    grants_by_path: dict[
        tuple[str, AzureKeyVaultManagementOperation, str],
        list[AzureArmControlPlaneGrant],
    ],
    uncertainties: list[str],
) -> None:
    vault_id = _known_string(azure_facts(vault).key_vault_id)
    if vault_id is None:
        return
    result = model_arm_control_plane_action_authority(
        assignment,
        context,
        principal_id=identity.principal_id,
        target_arm_id=vault_id,
        requested_actions=requested_actions,
    )
    _record_control_result(
        workload,
        identity,
        vault,
        operation,
        result,
        grants_by_path,
        uncertainties,
    )


def _collect_unknown_model_authority(
    workload: NormalizedResource,
    identity: _RuntimeIdentity,
    vault: NormalizedResource,
    keys: Sequence[NormalizedResource],
    assignment: NormalizedResource,
    context: AzureDecorationContext,
    uncertainties: list[str],
) -> None:
    vault_id = _known_string(azure_facts(vault).key_vault_id)
    if vault_id is None:
        return
    results = [
        model_arm_control_plane_action_authority(
            assignment,
            context,
            principal_id=identity.principal_id,
            target_arm_id=vault_id,
            requested_actions=(
                _RBAC_ASSIGNMENT_WRITE,
                _VAULT_WRITE,
                _ACCESS_POLICIES_WRITE,
            ),
        )
    ]
    for key in keys:
        key_id = _known_string(azure_facts(key).key_vault_key_versionless_resource_id)
        if key_id is None:
            continue
        results.append(
            model_arm_control_plane_action_authority(
                assignment,
                context,
                principal_id=identity.principal_id,
                target_arm_id=key_id,
                requested_actions=(_RBAC_ASSIGNMENT_WRITE,),
            )
        )
    if any(result.state == "granted" for result in results):
        uncertainties.append(
            f"{workload.address}: Key Vault {vault.address} authorization model is unresolved "
            f"for modeled ARM authority from {assignment.address} to runtime principal "
            f"{identity.principal_id}"
        )
    uncertainties.extend(
        f"{workload.address}: {uncertainty}" for result in results for uncertainty in result.uncertainties
    )


def _record_control_result(
    workload: NormalizedResource,
    identity: _RuntimeIdentity,
    target: NormalizedResource,
    operation: AzureKeyVaultManagementOperation,
    result: AzureArmControlPlaneAuthorityResult,
    grants_by_path: dict[
        tuple[str, AzureKeyVaultManagementOperation, str],
        list[AzureArmControlPlaneGrant],
    ],
    uncertainties: list[str],
) -> bool:
    if result.state == "unknown":
        uncertainties.extend(f"{workload.address}: {uncertainty}" for uncertainty in result.uncertainties)
        return False
    if result.grant is None:
        return False
    key = (identity.resource.address, operation, target.address)
    grants_by_path.setdefault(key, []).append(result.grant)
    return True


def _data_plane_management_path(
    workload: NormalizedResource,
    identity: _RuntimeIdentity,
    key: NormalizedResource,
    vault: NormalizedResource,
    operation: AzureKeyVaultManagementOperation,
    step_operations: Sequence[str],
    grants: Sequence[AzureKeyVaultAuthorizationGrant],
    *,
    lifecycle_state: Literal["compatible"],
) -> AzureAppServiceKeyVaultManagementPath:
    key_facts = azure_facts(key)
    vault_facts = azure_facts(vault)
    target_resource_id = _known_string(key_facts.key_vault_key_versionless_resource_id)
    vault_id = _known_string(vault_facts.key_vault_id)
    if target_resource_id is None or vault_id is None:
        raise ValueError("deterministic Key Vault management path requires exact key and vault resource IDs")
    operation_class: AzureKeyVaultManagementOperationClass = (
        "configuration_administration" if operation == "update" else "destructive_administration"
    )
    return {
        **_path_identity_and_target(
            workload,
            identity,
            vault,
            key,
            target_resource_id,
        ),
        "operation": operation,
        "step_operations": list(step_operations),
        "operation_class": operation_class,
        "management_effect": "disruption",
        "target_type": "key",
        "authorization_basis": "key_vault_data_plane_grant",
        "authorization_model": grants[0]["authorization_model"],
        "authorization_model_state": "active",
        "authorization_state": "granted",
        "delegation_mechanism": "not_applicable",
        "grant_source_addresses": sorted({grant["grant_source_address"] for grant in grants}),
        "scope_types": _ordered_scope_types(grant["grant_scope_type"] for grant in grants),
        "scopes": sorted({scope for grant in grants if (scope := _known_string(grant.get("grant_scope"))) is not None}),
        "scope_arm_ids": sorted(
            {scope for grant in grants if (scope := _data_grant_scope_arm_id(grant, key, vault)) is not None}
        ),
        "data_plane_grants": _dedupe_grants(grants),
        "control_plane_grants": [],
        "purge_protection_enabled": vault_facts.purge_protection_enabled,
        "recovery_uncertainties": list(vault_facts.key_vault_recovery_uncertainties),
        "lifecycle_compatibility_state": lifecycle_state,
        "authorization_model_transition": None,
        "evaluation_basis": "modeled_key_vault_key_authorization",
    }


def _control_plane_management_path(
    workload: NormalizedResource,
    identity: _RuntimeIdentity,
    vault: NormalizedResource,
    target: NormalizedResource,
    authorization_model: AzureKeyVaultAuthorizationModel,
    operation: AzureKeyVaultManagementOperation,
    grants: Sequence[AzureArmControlPlaneGrant],
) -> AzureAppServiceKeyVaultManagementPath:
    vault_facts = azure_facts(vault)
    vault_id = _known_string(vault_facts.key_vault_id)
    if vault_id is None:
        raise ValueError("deterministic Key Vault delegation path requires an exact vault resource ID")
    key = target if target.resource_type == AzureResourceType.KEY_VAULT_KEY else None
    target_resource_id = (
        _known_string(azure_facts(key).key_vault_key_versionless_resource_id) if key is not None else vault_id
    )
    if target_resource_id is None:
        raise ValueError("deterministic Key Vault delegation path requires an exact target resource ID")
    mechanism = _delegation_mechanism(operation)
    scope_types = _control_scope_types(grants, key, vault)
    return {
        **_path_identity_and_target(
            workload,
            identity,
            vault,
            key,
            target_resource_id,
        ),
        "operation": operation,
        "step_operations": sorted({action for grant in grants for action in grant["matched_actions"]}),
        "operation_class": "authorization_administration",
        "management_effect": "delegation",
        "target_type": "key" if key is not None else "vault",
        "authorization_basis": "azure_control_plane_role_assignment",
        "authorization_model": authorization_model,
        "authorization_model_state": "active",
        "authorization_state": "granted",
        "delegation_mechanism": mechanism,
        "grant_source_addresses": sorted({grant["source_address"] for grant in grants}),
        "scope_types": scope_types,
        "scopes": sorted(
            {scope for grant in grants if (scope := _known_string(grant.get("assignment_scope"))) is not None}
        ),
        "scope_arm_ids": sorted({grant["assignment_scope_arm_id"] for grant in grants}),
        "data_plane_grants": [],
        "control_plane_grants": _dedupe_control_grants(grants),
        "purge_protection_enabled": vault_facts.purge_protection_enabled,
        "recovery_uncertainties": list(vault_facts.key_vault_recovery_uncertainties),
        "lifecycle_compatibility_state": "not_applicable",
        "authorization_model_transition": (
            "azure_rbac_to_access_policy" if operation == "authorization_model_mutation" else None
        ),
        "evaluation_basis": "modeled_arm_control_plane_authority",
    }


def _control_scope_types(
    grants: Sequence[AzureArmControlPlaneGrant],
    key: NormalizedResource | None,
    vault: NormalizedResource,
) -> list[AzureKeyVaultPathScopeType]:
    values: list[AzureKeyVaultPathScopeType] = []
    vault_id = _known_string(azure_facts(vault).key_vault_id)
    key_id = _known_string(azure_facts(key).key_vault_key_versionless_resource_id) if key is not None else None
    for grant in grants:
        scope_type = grant["assignment_scope_type"]
        scope_arm_id = grant["assignment_scope_arm_id"]
        if scope_type == "subscription":
            values.append("subscription")
        elif scope_type == "resource_group":
            values.append("resource_group")
        elif key_id is not None and scope_arm_id.casefold() == key_id.casefold():
            values.append("key")
        elif vault_id is not None and scope_arm_id.casefold() == vault_id.casefold():
            values.append("vault")
    return _ordered_scope_types(values)


def _delegation_mechanism(
    operation: AzureKeyVaultManagementOperation,
) -> AzureKeyVaultDelegationMechanism:
    if operation == "rbac_role_assignment_management":
        return "azure_rbac_role_assignment"
    if operation == "legacy_access_policy_mutation":
        return "legacy_access_policy"
    if operation == "authorization_model_mutation":
        return "authorization_model_transition"
    raise ValueError(f"unsupported Key Vault delegation operation: {operation}")


def _path_identity_and_target(
    workload: NormalizedResource,
    identity: _RuntimeIdentity,
    vault: NormalizedResource,
    key: NormalizedResource | None,
    target_resource_id: str,
) -> _ManagementPathIdentityAndTarget:
    vault_facts = azure_facts(vault)
    key_facts = azure_facts(key) if key is not None else None
    vault_id = _known_string(vault_facts.key_vault_id)
    if vault_id is None:
        raise ValueError("deterministic Key Vault management path requires an exact vault resource ID")
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "identity_address": identity.resource.address,
        "identity_kind": identity.kind,
        "principal_id": identity.principal_id,
        "credential_context": "workload_runtime",
        "key_vault_address": vault.address,
        "key_vault_id": vault_id,
        "key_address": key.address if key is not None else None,
        "key_resource_type": key.resource_type if key is not None else None,
        "key_name": key_facts.key_vault_key_name if key_facts is not None else None,
        "key_uri": key_facts.key_vault_key_uri if key_facts is not None else None,
        "key_versionless_uri": key_facts.key_vault_key_versionless_uri if key_facts is not None else None,
        "key_resource_id": key_facts.key_vault_key_resource_id if key_facts is not None else None,
        "key_versionless_resource_id": (
            key_facts.key_vault_key_versionless_resource_id if key_facts is not None else None
        ),
        "key_version": key_facts.key_vault_key_version if key_facts is not None else None,
        "target_address": key.address if key is not None else vault.address,
        "target_resource_id": target_resource_id,
    }


def _data_grant_is_deterministic(
    grant: AzureKeyVaultAuthorizationGrant,
    key: NormalizedResource,
    vault: NormalizedResource,
    context: AzureDecorationContext,
) -> bool:
    source = context.index.resources_by_address.get(grant["grant_source_address"])
    if source is None:
        return False
    if grant.get("key_address") != key.address or grant.get("key_vault_address") != vault.address:
        return False
    if (
        grant.get("authorization_state") != "granted"
        or grant.get("authorization_model_state") != "active"
        or grant.get("principal_state") != "resolved"
        or grant.get("condition_state") != "not_configured"
        or grant.get("grant_scope_type") not in _SUPPORTED_DATA_GRANT_SCOPES
    ):
        return False
    if grant["grant_kind"] == "access_policy":
        return bool(
            source.resource_type in {AzureResourceType.KEY_VAULT, AzureResourceType.KEY_VAULT_ACCESS_POLICY}
            and grant.get("authorization_model") == "access_policy"
            and grant.get("management_state") == "unambiguous"
            and grant.get("grant_scope_type") == "vault"
        )
    if grant["grant_kind"] == "rbac":
        return bool(
            source.resource_type == AzureResourceType.ROLE_ASSIGNMENT
            and grant.get("authorization_model") == "azure_rbac"
            and grant.get("scope_resolution_state") == "resolved"
            and grant.get("condition_applicability_state") == "not_configured"
        )
    return False


def _data_grant_scope_arm_id(
    grant: AzureKeyVaultAuthorizationGrant,
    key: NormalizedResource,
    vault: NormalizedResource,
) -> str | None:
    scope_type = grant["grant_scope_type"]
    if scope_type == "key":
        return _known_string(azure_facts(key).key_vault_key_versionless_resource_id)
    vault_id = _known_string(azure_facts(vault).key_vault_id)
    if scope_type == "vault":
        return vault_id
    if vault_id is None:
        return None
    parts = vault_id.strip().rstrip("/").split("/")
    if len(parts) < 5 or parts[1].casefold() != "subscriptions" or parts[3].casefold() != "resourcegroups":
        return None
    if scope_type == "subscription":
        return f"/subscriptions/{parts[2]}"
    if scope_type == "resource_group":
        return f"/subscriptions/{parts[2]}/resourceGroups/{parts[4]}"
    return None


def _key_authorization_may_match_runtime(
    key: NormalizedResource,
    identities: Sequence[_RuntimeIdentity],
    context: AzureDecorationContext,
) -> bool:
    principal_ids = {identity.principal_id.casefold() for identity in identities}
    facts = azure_facts(key)
    for grant in facts.key_vault_key_authorization_grants:
        if not (set(_string_values(grant.get("matched_operations"))) & _KEY_MANAGEMENT_OPERATIONS):
            continue
        principal = _known_string(grant.get("principal_id"))
        if principal is None or principal.casefold() in principal_ids:
            return True
    return any(
        _uncertainty_source_may_match(uncertainty.partition(":")[0], identities, context)
        for uncertainty in facts.key_vault_key_authorization_uncertainties
    )


def _uncertainty_source_may_match(
    source_address: str,
    identities: Sequence[_RuntimeIdentity],
    context: AzureDecorationContext,
) -> bool:
    source = context.index.resources_by_address.get(source_address)
    if source is None:
        return True
    principal = _known_string(azure_facts(source).principal_id)
    return principal is None or principal.casefold() in {identity.principal_id.casefold() for identity in identities}


def _data_grant_operations_unresolved(grant: AzureKeyVaultAuthorizationGrant) -> bool:
    return bool(
        grant.get("key_permissions_state") == "unknown"
        or grant.get("role_resolution_state") not in {None, "resolved", "modeled_subset"}
    )


def _authorization_model(value: bool | None) -> AzureKeyVaultAuthorizationModel | Literal["unknown"]:
    if value is True:
        return "azure_rbac"
    if value is False:
        return "access_policy"
    return "unknown"


def _ordered_scope_types(values: Iterable[object]) -> list[AzureKeyVaultPathScopeType]:
    present = {value for value in values if _is_path_scope_type(value)}
    return [scope_type for scope_type in ("subscription", "resource_group", "vault", "key") if scope_type in present]


def _dedupe_grants(
    values: Sequence[AzureKeyVaultAuthorizationGrant],
) -> list[AzureKeyVaultAuthorizationGrant]:
    result: list[AzureKeyVaultAuthorizationGrant] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _dedupe_control_grants(
    values: Sequence[AzureArmControlPlaneGrant],
) -> list[AzureArmControlPlaneGrant]:
    result: list[AzureArmControlPlaneGrant] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _dedupe_paths(
    values: Sequence[AzureAppServiceKeyVaultManagementPath],
) -> list[AzureAppServiceKeyVaultManagementPath]:
    result: list[AzureAppServiceKeyVaultManagementPath] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _string_values(value: object) -> list[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return []
    return sorted({item.strip() for item in value if isinstance(item, str) and item.strip()})


def _is_runtime_identity_kind(value: str) -> TypeGuard[AzureKeyVaultRuntimeIdentityKind]:
    return value in {"system_assigned", "user_assigned"}


def _is_path_scope_type(value: object) -> TypeGuard[AzureKeyVaultPathScopeType]:
    return value in {"subscription", "resource_group", "vault", "key"}
