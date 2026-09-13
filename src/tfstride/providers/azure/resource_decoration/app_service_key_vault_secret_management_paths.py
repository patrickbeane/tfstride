from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Literal, TypeGuard

from tfstride.models import NormalizedResource
from tfstride.providers.azure.key_vault_evidence import (
    AzureKeyVaultAuthorizationModel,
    AzureKeyVaultPathScopeType,
    AzureKeyVaultRuntimeIdentityKind,
)
from tfstride.providers.azure.resource_decoration.workload_identities import (
    workload_managed_identities,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import (
    AZURE_APP_SERVICE_RESOURCE_TYPES,
    AzureResourceType,
)
from tfstride.providers.azure.secret_management_evidence import (
    AzureAppServiceKeyVaultSecretManagementPath,
    AzureKeyVaultSecretAuthorizationGrant,
    AzureKeyVaultSecretGrantOperation,
    AzureKeyVaultSecretManagementEffect,
    AzureKeyVaultSecretManagementOperation,
    AzureKeyVaultSecretOperationClass,
)
from tfstride.providers.coercion import dedupe

_SECRET_MANAGEMENT_OPERATIONS = frozenset({"set", "delete", "purge"})
_SUPPORTED_DATA_GRANT_SCOPES = frozenset({"subscription", "resource_group", "vault", "secret"})
_VAULT_ARM_ID_PATTERN = re.compile(
    r"^/subscriptions/[^/]+/resourceGroups/[^/]+/"
    r"providers/Microsoft\.KeyVault/vaults/[^/]+/?\Z",
    re.IGNORECASE,
)
_SECRET_ARM_ID_PATTERN = re.compile(
    r"^/subscriptions/[^/]+/resourceGroups/[^/]+/"
    r"providers/Microsoft\.KeyVault/vaults/[^/]+/secrets/[^/]+/?\Z",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class _RuntimeIdentity:
    resource: NormalizedResource
    kind: AzureKeyVaultRuntimeIdentityKind
    principal_id: str


class ModelAppServiceKeyVaultSecretManagementPathsStage:
    """Project exact Key Vault secret lifecycle authority onto App Service."""

    name = "model_app_service_key_vault_secret_management_paths"

    def apply(
        self,
        resources: list[NormalizedResource],
        context: AzureDecorationContext,
    ) -> None:
        secrets = tuple(
            resource for resource in resources if resource.resource_type == AzureResourceType.KEY_VAULT_SECRET
        )
        for workload in resources:
            if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
                continue
            paths, uncertainties = _app_service_secret_management_paths(
                workload,
                secrets,
                context,
            )
            facts = azure_facts(workload)
            facts.set_app_service_key_vault_secret_management_paths(paths)
            facts.extend_app_service_key_vault_secret_management_path_uncertainties(uncertainties)


def _app_service_secret_management_paths(
    workload: NormalizedResource,
    secrets: Sequence[NormalizedResource],
    context: AzureDecorationContext,
) -> tuple[list[AzureAppServiceKeyVaultSecretManagementPath], list[str]]:
    identities, identity_uncertainties = workload_managed_identities(
        workload,
        context,
    )
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

    paths: list[AzureAppServiceKeyVaultSecretManagementPath] = []
    for secret in secrets:
        secret_facts = azure_facts(secret)
        vault = context.index.resolve(
            secret_facts.resolved_key_vault_address,
            source=secret,
            resource_types={AzureResourceType.KEY_VAULT},
        )
        if vault is None or vault.resource_type != AzureResourceType.KEY_VAULT:
            if _authorization_may_match_runtime(
                secret,
                runtime_identities,
                context,
            ):
                uncertainties.append(
                    f"{workload.address}: Key Vault secret {secret.address} has "
                    "unresolved vault ancestry for lifecycle paths"
                )
            continue
        if not _has_exact_path_identity(secret, vault):
            if _authorization_may_match_runtime(
                secret,
                runtime_identities,
                context,
            ):
                uncertainties.append(
                    f"{workload.address}: Key Vault secret {secret.address} has "
                    "unresolved exact identity for lifecycle paths"
                )
            continue
        secret_paths, secret_uncertainties = _secret_lifecycle_paths(
            workload,
            runtime_identities,
            secret,
            vault,
            context,
        )
        paths.extend(secret_paths)
        uncertainties.extend(secret_uncertainties)

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


def _secret_lifecycle_paths(
    workload: NormalizedResource,
    identities: Sequence[_RuntimeIdentity],
    secret: NormalizedResource,
    vault: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[list[AzureAppServiceKeyVaultSecretManagementPath], list[str]]:
    secret_facts = azure_facts(secret)
    vault_facts = azure_facts(vault)
    uncertainties: list[str] = []
    grants_by_identity: dict[
        str,
        dict[str, list[AzureKeyVaultSecretAuthorizationGrant]],
    ] = {
        identity.resource.address: {operation: [] for operation in _SECRET_MANAGEMENT_OPERATIONS}
        for identity in identities
    }
    identity_by_principal = {identity.principal_id.casefold(): identity for identity in identities}
    uncertain_sources: set[str] = set()

    for grant in secret_facts.key_vault_secret_authorization_grants:
        source = grant["grant_source_address"]
        principal_id = _known_string(grant.get("principal_id"))
        operations = set(_string_values(grant.get("matched_operations"))) & _SECRET_MANAGEMENT_OPERATIONS
        operations_unknown = _grant_operations_unresolved(grant)
        if principal_id is None:
            if operations or operations_unknown:
                uncertain_sources.add(source)
                uncertainties.append(
                    f"{workload.address}: {source} principal applicability is "
                    f"unresolved for Key Vault secret lifecycle authority on "
                    f"{secret.address}"
                )
            continue
        identity = identity_by_principal.get(principal_id.casefold())
        if identity is None:
            continue
        if not operations:
            if operations_unknown:
                uncertain_sources.add(source)
                uncertainties.append(
                    f"{workload.address}: {source} Key Vault secret lifecycle "
                    f"operations are unresolved for runtime principal "
                    f"{principal_id} on {secret.address}"
                )
            continue
        if not _grant_is_deterministic(
            grant,
            secret,
            vault,
            context,
        ):
            uncertain_sources.add(source)
            uncertainties.append(
                f"{workload.address}: {source} has non-deterministic Key Vault "
                f"secret lifecycle authority for runtime principal {principal_id} "
                f"on {secret.address} "
                f"(authorization_state={grant.get('authorization_state') or 'unknown'}, "
                f"authorization_model_state="
                f"{grant.get('authorization_model_state') or 'unknown'}, "
                f"condition_state={grant.get('condition_state') or 'unknown'})"
            )
            continue
        for operation in operations:
            grants_by_identity[identity.resource.address][operation].append(grant)

    for uncertainty in secret_facts.key_vault_secret_authorization_uncertainties:
        source = uncertainty.partition(":")[0]
        source_grants = [
            grant
            for grant in secret_facts.key_vault_secret_authorization_grants
            if grant["grant_source_address"] == source
        ]
        if source_grants and source not in uncertain_sources:
            continue
        if not source_grants and not _uncertainty_source_may_match(
            source,
            identities,
            context,
        ):
            continue
        uncertainties.append(
            f"{workload.address}: Key Vault secret authorization posture for "
            f"{secret.address} is incomplete: {uncertainty}"
        )

    paths: list[AzureAppServiceKeyVaultSecretManagementPath] = []
    for identity in identities:
        operation_grants = grants_by_identity[identity.resource.address]
        set_grants = operation_grants["set"]
        delete_grants = operation_grants["delete"]
        purge_grants = operation_grants["purge"]
        if set_grants:
            paths.append(
                _management_path(
                    workload,
                    identity,
                    secret,
                    vault,
                    "set",
                    ("set",),
                    set_grants,
                )
            )
        if delete_grants:
            paths.append(
                _management_path(
                    workload,
                    identity,
                    secret,
                    vault,
                    "delete",
                    ("delete",),
                    delete_grants,
                )
            )
        if delete_grants and purge_grants:
            if vault_facts.purge_protection_enabled is False:
                paths.append(
                    _management_path(
                        workload,
                        identity,
                        secret,
                        vault,
                        "delete_plus_purge",
                        ("delete", "purge"),
                        [*delete_grants, *purge_grants],
                    )
                )
            elif vault_facts.purge_protection_enabled is None:
                uncertainties.append(
                    f"{workload.address}: Key Vault {vault.address} purge "
                    "protection is unresolved, so delete-plus-purge "
                    f"compatibility for {secret.address} is unknown"
                )
    return paths, uncertainties


def _management_path(
    workload: NormalizedResource,
    identity: _RuntimeIdentity,
    secret: NormalizedResource,
    vault: NormalizedResource,
    operation: AzureKeyVaultSecretManagementOperation,
    step_operations: Sequence[AzureKeyVaultSecretGrantOperation],
    grants: Sequence[AzureKeyVaultSecretAuthorizationGrant],
) -> AzureAppServiceKeyVaultSecretManagementPath:
    secret_facts = azure_facts(secret)
    vault_facts = azure_facts(vault)
    vault_id = _canonical_vault_arm_id(secret, vault)
    secret_name = _known_string(secret_facts.key_vault_secret_name)
    secret_versionless_uri = _known_string(secret_facts.key_vault_secret_versionless_uri)
    target_resource_id = _canonical_secret_arm_id(secret)
    if vault_id is None or secret_name is None or secret_versionless_uri is None or target_resource_id is None:
        raise ValueError("deterministic Key Vault secret lifecycle path requires exact vault and secret identities")
    operation_class: AzureKeyVaultSecretOperationClass = (
        "value_mutation" if operation == "set" else "destructive_administration"
    )
    management_effect: AzureKeyVaultSecretManagementEffect = "tampering" if operation == "set" else "disruption"
    authorization_model: AzureKeyVaultAuthorizationModel = grants[0]["authorization_model"]
    return {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "identity_address": identity.resource.address,
        "identity_kind": identity.kind,
        "principal_id": identity.principal_id,
        "credential_context": "workload_runtime",
        "key_vault_address": vault.address,
        "key_vault_id": vault_id,
        "secret_address": secret.address,
        "secret_resource_type": secret.resource_type,
        "secret_name": secret_name,
        "secret_uri": secret_facts.key_vault_secret_uri,
        "secret_versionless_uri": secret_versionless_uri,
        "secret_resource_id": target_resource_id,
        "secret_version": secret_facts.key_vault_secret_version,
        "operation": operation,
        "step_operations": list(step_operations),
        "operation_class": operation_class,
        "management_effect": management_effect,
        "target_type": "secret",
        "target_address": secret.address,
        "target_resource_id": target_resource_id,
        "authorization_model": authorization_model,
        "authorization_model_state": "active",
        "authorization_state": "granted",
        "grant_source_addresses": sorted({grant["grant_source_address"] for grant in grants}),
        "scope_types": _ordered_scope_types(grant["grant_scope_type"] for grant in grants),
        "scopes": sorted({scope for grant in grants if (scope := _known_string(grant.get("grant_scope"))) is not None}),
        "scope_arm_ids": sorted(
            {scope for grant in grants if (scope := _grant_scope_arm_id(grant, secret, vault)) is not None}
        ),
        "data_plane_grants": _dedupe_grants(grants),
        "purge_protection_enabled": vault_facts.purge_protection_enabled,
        "recovery_uncertainties": list(vault_facts.key_vault_recovery_uncertainties),
        "lifecycle_compatibility_state": "compatible",
        "condition": None,
        "condition_state": "not_configured",
        "evaluation_basis": "modeled_key_vault_secret_authorization",
    }


def _has_exact_path_identity(
    secret: NormalizedResource,
    vault: NormalizedResource,
) -> bool:
    secret_facts = azure_facts(secret)
    return bool(
        _canonical_vault_arm_id(secret, vault)
        and _known_string(secret_facts.key_vault_secret_name)
        and _known_string(secret_facts.key_vault_secret_versionless_uri)
        and _canonical_secret_arm_id(secret)
    )


def _grant_is_deterministic(
    grant: AzureKeyVaultSecretAuthorizationGrant,
    secret: NormalizedResource,
    vault: NormalizedResource,
    context: AzureDecorationContext,
) -> bool:
    source = context.index.resources_by_address.get(grant["grant_source_address"])
    if source is None:
        return False
    secret_facts = azure_facts(secret)
    vault_facts = azure_facts(vault)
    vault_id = _canonical_vault_arm_id(secret, vault)
    secret_id = _canonical_secret_arm_id(secret)
    if (
        grant["secret_address"] != secret.address
        or grant["key_vault_address"] != vault.address
        or not _same_optional_identifier(
            grant["key_vault_id"],
            vault_id,
        )
        or not _same_optional_identifier(
            grant["secret_uri"],
            secret_facts.key_vault_secret_uri,
        )
        or not _same_identifier(
            grant["secret_versionless_uri"],
            secret_facts.key_vault_secret_versionless_uri,
        )
        or not _same_optional_identifier(
            grant["secret_resource_id"],
            secret_id,
        )
        or not _same_optional_identifier(
            grant["secret_version"],
            secret_facts.key_vault_secret_version,
        )
    ):
        return False
    if (
        grant["authorization_state"] != "granted"
        or grant["authorization_model_state"] != "active"
        or grant["principal_state"] != "resolved"
        or grant["condition_state"] != "not_configured"
        or grant["grant_scope_type"] not in _SUPPORTED_DATA_GRANT_SCOPES
    ):
        return False

    active_model = _authorization_model(vault_facts.rbac_authorization_enabled)
    if grant["authorization_model"] != active_model:
        return False
    if grant["grant_kind"] == "access_policy":
        return bool(
            source.resource_type
            in {
                AzureResourceType.KEY_VAULT,
                AzureResourceType.KEY_VAULT_ACCESS_POLICY,
            }
            and grant["authorization_model"] == "access_policy"
            and grant.get("management_state") == "unambiguous"
            and grant["grant_scope_type"] == "vault"
        )
    if grant["grant_kind"] == "rbac":
        source_facts = azure_facts(source)
        return bool(
            source.resource_type == AzureResourceType.ROLE_ASSIGNMENT
            and grant["authorization_model"] == "azure_rbac"
            and grant.get("scope_resolution_state") == "resolved"
            and grant["condition_applicability_state"] == "not_configured"
            and _same_identifier(
                grant["principal_id"],
                source_facts.principal_id,
            )
            and _same_optional_identifier(
                grant["condition"],
                source_facts.role_assignment_condition,
            )
        )
    return False


def _grant_scope_arm_id(
    grant: AzureKeyVaultSecretAuthorizationGrant,
    secret: NormalizedResource,
    vault: NormalizedResource,
) -> str | None:
    scope_type = grant["grant_scope_type"]
    if scope_type == "secret":
        return _canonical_secret_arm_id(secret)
    vault_id = _canonical_vault_arm_id(secret, vault)
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


def _canonical_vault_arm_id(
    secret: NormalizedResource,
    vault: NormalizedResource,
) -> str | None:
    value = _known_string(azure_facts(vault).key_vault_id)
    if value is not None:
        normalized = value.rstrip("/")
        if _VAULT_ARM_ID_PATTERN.fullmatch(normalized):
            return normalized
    secret_id = _canonical_secret_arm_id(secret)
    if secret_id is None:
        return None
    candidate = secret_id[: secret_id.casefold().rfind("/secrets/")]
    return candidate if _VAULT_ARM_ID_PATTERN.fullmatch(candidate) else None


def _canonical_secret_arm_id(secret: NormalizedResource) -> str | None:
    value = _known_string(azure_facts(secret).key_vault_secret_resource_id)
    if value is None:
        return None
    normalized = value.rstrip("/")
    return normalized if _SECRET_ARM_ID_PATTERN.fullmatch(normalized) else None


def _authorization_may_match_runtime(
    secret: NormalizedResource,
    identities: Sequence[_RuntimeIdentity],
    context: AzureDecorationContext,
) -> bool:
    principal_ids = {identity.principal_id.casefold() for identity in identities}
    facts = azure_facts(secret)
    for grant in facts.key_vault_secret_authorization_grants:
        operations = set(_string_values(grant.get("matched_operations"))) & _SECRET_MANAGEMENT_OPERATIONS
        if not operations and not _grant_operations_unresolved(grant):
            continue
        principal = _known_string(grant.get("principal_id"))
        if principal is None or principal.casefold() in principal_ids:
            return True
    return any(
        _uncertainty_source_may_match(
            uncertainty.partition(":")[0],
            identities,
            context,
        )
        for uncertainty in facts.key_vault_secret_authorization_uncertainties
    )


def _uncertainty_source_may_match(
    source_address: str,
    identities: Sequence[_RuntimeIdentity],
    context: AzureDecorationContext,
) -> bool:
    source = context.index.resources_by_address.get(source_address)
    if source is None:
        return True
    if source.resource_type != AzureResourceType.ROLE_ASSIGNMENT:
        return True
    principal = _known_string(azure_facts(source).principal_id)
    return principal is None or principal.casefold() in {identity.principal_id.casefold() for identity in identities}


def _grant_operations_unresolved(
    grant: AzureKeyVaultSecretAuthorizationGrant,
) -> bool:
    return bool(
        grant.get("secret_permissions_state") == "unknown"
        or grant.get("role_resolution_state") not in {None, "resolved", "modeled_subset"}
    )


def _authorization_model(
    value: bool | None,
) -> AzureKeyVaultAuthorizationModel | Literal["unknown"]:
    if value is True:
        return "azure_rbac"
    if value is False:
        return "access_policy"
    return "unknown"


def _ordered_scope_types(
    values: Iterable[object],
) -> list[AzureKeyVaultPathScopeType]:
    present = {value for value in values if _is_path_scope_type(value)}
    return [
        scope_type
        for scope_type in (
            "subscription",
            "resource_group",
            "vault",
            "secret",
        )
        if scope_type in present
    ]


def _dedupe_grants(
    values: Sequence[AzureKeyVaultSecretAuthorizationGrant],
) -> list[AzureKeyVaultSecretAuthorizationGrant]:
    result: list[AzureKeyVaultSecretAuthorizationGrant] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _dedupe_paths(
    values: Sequence[AzureAppServiceKeyVaultSecretManagementPath],
) -> list[AzureAppServiceKeyVaultSecretManagementPath]:
    result: list[AzureAppServiceKeyVaultSecretManagementPath] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result


def _same_identifier(left: object, right: object) -> bool:
    left_value = _known_string(left)
    right_value = _known_string(right)
    return bool(left_value and right_value and left_value.casefold().rstrip("/") == right_value.casefold().rstrip("/"))


def _same_optional_identifier(left: object, right: object) -> bool:
    left_value = _known_string(left)
    right_value = _known_string(right)
    if left_value is None or right_value is None:
        return left_value is right_value
    return left_value.casefold().rstrip("/") == right_value.casefold().rstrip("/")


def _known_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _string_values(value: object) -> list[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return []
    return sorted({item.strip() for item in value if isinstance(item, str) and item.strip()})


def _is_runtime_identity_kind(
    value: str,
) -> TypeGuard[AzureKeyVaultRuntimeIdentityKind]:
    return value in {"system_assigned", "user_assigned"}


def _is_path_scope_type(
    value: object,
) -> TypeGuard[AzureKeyVaultPathScopeType]:
    return value in {"subscription", "resource_group", "vault", "secret"}
