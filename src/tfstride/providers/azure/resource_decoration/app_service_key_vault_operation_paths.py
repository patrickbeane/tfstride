from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, TypeGuard

from tfstride.models import NormalizedResource
from tfstride.providers.azure.key_vault_evidence import (
    AzureAppServiceKeyVaultOperationPath,
    AzureKeyVaultAuthorizationGrant,
    AzureKeyVaultGrantScopeType,
    AzureKeyVaultOperation,
    AzureKeyVaultOperationClass,
    AzureKeyVaultPathScopeType,
    AzureKeyVaultRuntimeIdentityKind,
)
from tfstride.providers.azure.resource_decoration.workload_identities import workload_managed_identities
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType
from tfstride.providers.coercion import dedupe

_RELEVANT_OPERATIONS: frozenset[AzureKeyVaultOperation] = frozenset({"decrypt", "unwrap", "sign"})
_KEY_OPT_BY_OPERATION: dict[AzureKeyVaultOperation, str] = {
    "decrypt": "decrypt",
    "unwrap": "unwrapKey",
    "sign": "sign",
}
_OPERATION_CLASS: dict[AzureKeyVaultOperation, AzureKeyVaultOperationClass] = {
    "decrypt": "plaintext_recovery",
    "unwrap": "plaintext_recovery",
    "sign": "authenticator_generation",
}
_SUPPORTED_SCOPE_TYPES: frozenset[AzureKeyVaultPathScopeType] = frozenset(
    {"subscription", "resource_group", "vault", "key"}
)
_VAULT_ID_PATTERN = re.compile(
    r"^(?P<subscription>/subscriptions/[^/]+)"
    r"(?P<resource_group>/resourceGroups/[^/]+)"
    r"/providers/Microsoft\.KeyVault/vaults/[^/]+$",
    re.IGNORECASE,
)


class ModelAppServiceKeyVaultOperationPathsStage:
    """Project deterministic Key Vault key operations onto App Service runtimes."""

    name = "model_app_service_key_vault_operation_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        keys = tuple(resource for resource in resources if resource.resource_type == AzureResourceType.KEY_VAULT_KEY)
        for workload in resources:
            if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
                continue
            paths, uncertainties = _app_service_key_vault_operation_paths(
                workload,
                keys,
                context,
            )
            facts = azure_facts(workload)
            facts.set_app_service_key_vault_operation_paths(paths)
            facts.extend_app_service_key_vault_operation_path_uncertainties(uncertainties)


def _app_service_key_vault_operation_paths(
    workload: NormalizedResource,
    keys: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> tuple[list[AzureAppServiceKeyVaultOperationPath], list[str]]:
    workload_facts = azure_facts(workload)
    identities, identity_uncertainties = workload_managed_identities(workload, context)
    uncertainties: list[str] = [
        *identity_uncertainties,
        *[f"{workload.address}: {value}" for value in workload_facts.managed_identity_uncertainties],
    ]
    if not identities:
        return [], dedupe(uncertainties)

    identity_principals: set[str] = {
        principal.casefold()
        for identity, _ in identities
        if (principal := _known_string(azure_facts(identity).principal_id)) is not None
    }
    paths: list[AzureAppServiceKeyVaultOperationPath] = []
    for key in keys:
        key_facts = azure_facts(key)
        if key_facts.key_vault_key_identity_state != "resolved":
            if key_facts.key_vault_key_authorization_grants or key_facts.key_vault_key_authorization_uncertainties:
                uncertainties.append(f"{workload.address}: Key Vault key {key.address} has unresolved exact identity")
            continue

        vault = context.index.resolve(
            key_facts.resolved_key_vault_address,
            source=key,
            resource_types={AzureResourceType.KEY_VAULT},
        )
        if vault is None or vault.resource_type != AzureResourceType.KEY_VAULT:
            uncertainties.append(f"{workload.address}: Key Vault key {key.address} has unresolved vault ancestry")
            continue

        key_operations = _normalized_key_operations(key_facts.key_vault_key_ops)
        key_operations_unknown = any(
            "key_opts is unknown" in value for value in key_facts.key_vault_key_posture_uncertainties
        )
        supported_operations: frozenset[AzureKeyVaultOperation] = frozenset(
            operation for operation, key_opt in _KEY_OPT_BY_OPERATION.items() if key_opt.casefold() in key_operations
        )
        if not key_operations_unknown and not supported_operations:
            continue

        grants_by_source = _grants_by_source(key_facts.key_vault_key_authorization_grants)
        uncertain_sources: set[str] = set()

        for grant in key_facts.key_vault_key_authorization_grants:
            source_address = grant["grant_source_address"]
            source = source_address or key.address
            principal_id = _known_string(grant.get("principal_id"))
            grant_operations = _string_values(grant.get("matched_operations"))
            relevant_operations: tuple[AzureKeyVaultOperation, ...] = tuple(
                operation for operation in grant_operations if _is_relevant_operation(operation)
            )
            candidate_operations: tuple[AzureKeyVaultOperation, ...] = (
                relevant_operations
                if key_operations_unknown
                else tuple(operation for operation in relevant_operations if operation in supported_operations)
            )
            grant_operations_unknown = _grant_operations_are_unresolved(grant)
            unresolved_operations_may_matter = bool(
                grant_operations_unknown and (key_operations_unknown or supported_operations)
            )

            if principal_id is None:
                if candidate_operations or unresolved_operations_may_matter:
                    uncertain_sources.add(source)
                    uncertainties.append(
                        f"{workload.address}: {source} principal applicability is unresolved for "
                        f"Key Vault key {key.address}"
                    )
                continue
            matching_identities: list[tuple[NormalizedResource, AzureKeyVaultRuntimeIdentityKind]] = [
                (identity, identity_kind)
                for identity, identity_kind in identities
                if _is_runtime_identity_kind(identity_kind)
                and _same_identifier(azure_facts(identity).principal_id, principal_id)
            ]
            if not matching_identities:
                continue

            if not candidate_operations:
                if unresolved_operations_may_matter:
                    uncertain_sources.add(source)
                    uncertainties.append(
                        f"{workload.address}: {source} Key Vault key operations are unresolved "
                        f"for runtime principal {principal_id} on {key.address}"
                    )
                continue

            if key_operations_unknown:
                uncertain_sources.add(source)
                uncertainties.append(
                    f"{workload.address}: Key Vault key {key.address} key_opts are unresolved for "
                    f"{','.join(candidate_operations)}"
                )
                continue

            for operation in candidate_operations:
                for identity, identity_kind in matching_identities:
                    scope_type = grant["grant_scope_type"]
                    if not _is_supported_scope_type(scope_type):
                        continue
                    if not _grant_is_deterministic(grant, key, vault, context):
                        uncertain_sources.add(source)
                        uncertainties.append(
                            f"{workload.address}: {source} has non-deterministic {operation} "
                            f"authority for runtime principal {principal_id} on {key.address} "
                            f"(authorization_state={grant.get('authorization_state') or 'unknown'}, "
                            f"authorization_model_state="
                            f"{grant.get('authorization_model_state') or 'unknown'}, "
                            f"condition_state={grant.get('condition_state') or 'unknown'})"
                        )
                        continue
                    paths.append(
                        _operation_path_record(
                            workload,
                            identity,
                            identity_kind,
                            key,
                            vault,
                            operation,
                            scope_type,
                            grant,
                        )
                    )

        for uncertainty in key_facts.key_vault_key_authorization_uncertainties:
            source = uncertainty.partition(":")[0]
            source_grants = grants_by_source.get(source, ())
            if source_grants and source not in uncertain_sources:
                continue
            if not source_grants and not _uncertainty_source_may_match(
                source,
                identity_principals,
                context,
            ):
                continue
            uncertainties.append(
                f"{workload.address}: Key Vault authorization posture for {key.address} is incomplete: {uncertainty}"
            )

    paths = _dedupe_dicts(paths)
    paths.sort(
        key=lambda path: (
            str(path["key_address"]),
            str(path["operation_class"]),
            str(path["operation"]),
            str(path["grant_source_address"]),
            str(path["identity_address"]),
        )
    )
    return paths, dedupe(uncertainties)


def _operation_path_record(
    workload: NormalizedResource,
    identity: NormalizedResource,
    identity_kind: AzureKeyVaultRuntimeIdentityKind,
    key: NormalizedResource,
    vault: NormalizedResource,
    operation: AzureKeyVaultOperation,
    scope_type: AzureKeyVaultPathScopeType,
    grant: AzureKeyVaultAuthorizationGrant,
) -> AzureAppServiceKeyVaultOperationPath:
    key_facts = azure_facts(key)
    vault_facts = azure_facts(vault)
    source_address = grant["grant_source_address"]
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "identity_address": identity.address,
        "identity_kind": identity_kind,
        "principal_id": azure_facts(identity).principal_id,
        "credential_context": "workload_runtime",
        "key_address": key.address,
        "key_resource_type": key.resource_type,
        "key_vault_address": vault.address,
        "key_vault_id": vault_facts.key_vault_id,
        "key_name": key_facts.key_vault_key_name,
        "key_type": key_facts.key_vault_key_type,
        "key_operations": list(key_facts.key_vault_key_ops),
        "key_identity_state": key_facts.key_vault_key_identity_state,
        "key_uri": key_facts.key_vault_key_uri,
        "key_versionless_uri": key_facts.key_vault_key_versionless_uri,
        "key_resource_id": key_facts.key_vault_key_resource_id,
        "key_versionless_resource_id": key_facts.key_vault_key_versionless_resource_id,
        "key_version": key_facts.key_vault_key_version,
        "operation": operation,
        "operation_class": _OPERATION_CLASS[operation],
        "matched_key_operation": _KEY_OPT_BY_OPERATION[operation],
        "grant_kind": grant["grant_kind"],
        "grant_basis": grant["grant_basis"],
        "grant_source_address": source_address,
        "grant_source_type": _grant_source_type(source_address, grant, vault),
        "scope_type": scope_type,
        "scope": grant["grant_scope"],
        "scope_arm_id": _scope_arm_id(grant, key, vault),
        "authorization_model": grant["authorization_model"],
        "authorization_model_state": grant["authorization_model_state"],
        "authorization_state": grant["authorization_state"],
        "management_mode": grant.get("management_mode"),
        "management_state": grant.get("management_state"),
        "role_definition_name": grant.get("role_definition_name"),
        "role_definition_id": grant.get("role_definition_id"),
        "role_definition_address": grant.get("role_definition_address"),
        "role_kind": grant.get("role_kind"),
        "role_resolution_state": grant.get("role_resolution_state"),
        "matched_data_actions": list(_string_values(grant.get("matched_data_actions"))),
        "key_permissions": list(_string_values(grant.get("key_permissions"))),
        "condition": _mapping_copy(grant.get("condition")),
        "condition_state": grant["condition_state"],
        "condition_applicability_state": grant["condition_applicability_state"],
        "evaluation_basis": "modeled_key_vault_key_authorization",
        "authorization_grant_record": grant.copy(),
    }


def _grant_is_deterministic(
    grant: AzureKeyVaultAuthorizationGrant,
    key: NormalizedResource,
    vault: NormalizedResource,
    context: AzureDecorationContext,
) -> bool:
    grant_kind = grant["grant_kind"]
    source_address = grant["grant_source_address"]
    source = context.index.resources_by_address.get(source_address)
    if source is None or grant.get("key_address") != key.address:
        return False
    if grant.get("key_vault_address") != vault.address:
        return False
    if grant.get("authorization_state") != "granted":
        return False
    if grant.get("authorization_model_state") != "active":
        return False
    if grant.get("principal_state") != "resolved":
        return False
    if grant.get("condition_state") != "not_configured":
        return False
    if grant.get("grant_scope_type") not in _SUPPORTED_SCOPE_TYPES:
        return False

    if grant_kind == "access_policy":
        return bool(
            source.resource_type in {AzureResourceType.KEY_VAULT, AzureResourceType.KEY_VAULT_ACCESS_POLICY}
            and grant.get("authorization_model") == "access_policy"
            and grant.get("management_state") == "unambiguous"
            and grant.get("grant_scope_type") == "vault"
        )
    if grant_kind == "rbac":
        return bool(
            source.resource_type == AzureResourceType.ROLE_ASSIGNMENT
            and grant.get("authorization_model") == "azure_rbac"
            and grant.get("scope_resolution_state") == "resolved"
            and grant.get("condition_applicability_state") == "not_configured"
        )
    return False


def _scope_arm_id(
    grant: AzureKeyVaultAuthorizationGrant,
    key: NormalizedResource,
    vault: NormalizedResource,
) -> str | None:
    scope_type = grant["grant_scope_type"]
    vault_id = _known_string(azure_facts(vault).key_vault_id)
    if scope_type == "key":
        return azure_facts(key).key_vault_key_versionless_resource_id
    if scope_type == "vault":
        return vault_id
    if vault_id is None:
        return None
    match = _VAULT_ID_PATTERN.fullmatch(vault_id.rstrip("/"))
    if match is None:
        return None
    if scope_type == "subscription":
        return match.group("subscription")
    if scope_type == "resource_group":
        return f"{match.group('subscription')}{match.group('resource_group')}"
    return None


def _grant_source_type(
    source_address: str,
    grant: AzureKeyVaultAuthorizationGrant,
    vault: NormalizedResource,
) -> str | None:
    if source_address == vault.address:
        return vault.resource_type
    if grant.get("grant_kind") == "rbac":
        return AzureResourceType.ROLE_ASSIGNMENT
    if grant.get("grant_kind") == "access_policy":
        return AzureResourceType.KEY_VAULT_ACCESS_POLICY
    return None


def _uncertainty_source_may_match(
    source_address: str,
    identity_principals: set[str],
    context: AzureDecorationContext,
) -> bool:
    source = context.index.resources_by_address.get(source_address)
    if source is None:
        return True
    source_facts = azure_facts(source)
    principal = _known_string(source_facts.principal_id)
    return principal is None or principal.casefold() in identity_principals


def _grants_by_source(
    grants: Sequence[AzureKeyVaultAuthorizationGrant],
) -> dict[str, tuple[AzureKeyVaultAuthorizationGrant, ...]]:
    grouped: dict[str, list[AzureKeyVaultAuthorizationGrant]] = {}
    for grant in grants:
        source = _known_string(grant.get("grant_source_address"))
        if source is not None:
            grouped.setdefault(source, []).append(grant)
    return {source: tuple(values) for source, values in grouped.items()}


def _grant_operations_are_unresolved(grant: AzureKeyVaultAuthorizationGrant) -> bool:
    return bool(
        grant.get("key_permissions_state") == "unknown"
        or grant.get("role_resolution_state") not in {None, "resolved", "modeled_subset"}
    )


def _normalized_key_operations(values: Sequence[str]) -> set[str]:
    return {value.strip().casefold() for value in values if value.strip()}


def _same_identifier(left: str | None, right: str | None) -> bool:
    return bool(left and right and left.strip().casefold() == right.strip().casefold())


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _string_values(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item.strip() for item in value if isinstance(item, str) and item.strip())


def _is_relevant_operation(value: str) -> TypeGuard[AzureKeyVaultOperation]:
    return value in _RELEVANT_OPERATIONS


def _is_runtime_identity_kind(value: str) -> TypeGuard[AzureKeyVaultRuntimeIdentityKind]:
    return value in {"system_assigned", "user_assigned"}


def _is_supported_scope_type(
    value: AzureKeyVaultGrantScopeType,
) -> TypeGuard[AzureKeyVaultPathScopeType]:
    return value in _SUPPORTED_SCOPE_TYPES


def _mapping_copy(value: object) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    return dict(value)


def _dedupe_dicts(
    values: list[AzureAppServiceKeyVaultOperationPath],
) -> list[AzureAppServiceKeyVaultOperationPath]:
    result: list[AzureAppServiceKeyVaultOperationPath] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result
