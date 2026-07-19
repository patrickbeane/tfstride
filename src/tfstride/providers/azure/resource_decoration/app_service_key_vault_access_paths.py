from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from tfstride.models import NormalizedResource
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_index import AzureDecorationContext
from tfstride.providers.azure.resource_types import AZURE_APP_SERVICE_RESOURCE_TYPES, AzureResourceType
from tfstride.providers.azure.resource_utils import azure_reference_key, azure_resource_references
from tfstride.providers.coercion import dedupe

_KEY_VAULT_SECRET_READ_ROLE_NAMES = frozenset(
    {
        "key vault administrator",
        "key vault secrets officer",
        "key vault secrets user",
    }
)
_KEY_VAULT_SECRET_GET_ACTION = "microsoft.keyvault/vaults/secrets/getsecret/action"


@dataclass(frozen=True, slots=True)
class _ReferenceIdentity:
    resource: NormalizedResource
    kind: str
    resolution_basis: str


@dataclass(frozen=True, slots=True)
class _SecretTarget:
    vault: NormalizedResource
    secret: NormalizedResource | None
    resolution_basis: str


class ModelAppServiceKeyVaultAccessPathsStage:
    name = "model_app_service_key_vault_access_paths"

    def apply(self, resources: list[NormalizedResource], context: AzureDecorationContext) -> None:
        vaults_by_uri = _vaults_by_uri(resources)
        secrets_by_uri = _secrets_by_uri(resources)
        for workload in resources:
            if workload.resource_type not in AZURE_APP_SERVICE_RESOURCE_TYPES:
                continue
            paths, uncertainties = _app_service_key_vault_access_paths(
                workload,
                context,
                vaults_by_uri,
                secrets_by_uri,
            )
            facts = azure_facts(workload)
            facts.set_app_service_key_vault_access_paths(paths)
            facts.extend_app_service_key_vault_access_path_uncertainties(uncertainties)


def _app_service_key_vault_access_paths(
    workload: NormalizedResource,
    context: AzureDecorationContext,
    vaults_by_uri: Mapping[str, tuple[NormalizedResource, ...]],
    secrets_by_uri: Mapping[str, tuple[NormalizedResource, ...]],
) -> tuple[list[dict[str, Any]], list[str]]:
    facts = azure_facts(workload)
    references = [
        reference for reference in facts.app_service_secret_references if _is_exact_secret_reference(reference)
    ]
    uncertainties = _reference_uncertainties(workload, facts.app_service_secret_references)
    if not references:
        return [], dedupe(uncertainties)

    identity, identity_uncertainties = _reference_identity(workload, context)
    uncertainties.extend(identity_uncertainties)
    if identity is None:
        return [], dedupe(uncertainties)

    paths: list[dict[str, Any]] = []
    for reference in references:
        target, target_uncertainties = _secret_target(
            workload,
            reference,
            vaults_by_uri,
            secrets_by_uri,
        )
        uncertainties.extend(target_uncertainties)
        if target is None:
            continue

        grants, grant_uncertainties = _access_grants(identity, target, context)
        uncertainties.extend(f"{workload.address}: {value}" for value in grant_uncertainties)
        paths.extend(_access_path_record(workload, reference, identity, target, grant) for grant in grants)

    return _dedupe_dicts(paths), dedupe(uncertainties)


def _reference_identity(
    workload: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[_ReferenceIdentity | None, list[str]]:
    facts = azure_facts(workload)
    explicit_reference = facts.app_service_key_vault_reference_identity_id
    if explicit_reference:
        identity = context.index.resolve(explicit_reference)
        if identity is None or identity.resource_type != AzureResourceType.USER_ASSIGNED_IDENTITY:
            return None, [f"{workload.address}: Key Vault reference identity {explicit_reference} is not modeled"]
        if not _is_exact_user_assigned_identity_reference(explicit_reference, identity):
            return None, [
                f"{workload.address}: Key Vault reference identity {explicit_reference} is not an exact "
                "user-assigned identity resource reference"
            ]
        if not azure_facts(identity).principal_id:
            return None, [f"{workload.address}: {identity.address} principal_id is unresolved"]
        return (
            _ReferenceIdentity(
                resource=identity,
                kind="user_assigned",
                resolution_basis="key_vault_reference_identity_id",
            ),
            [],
        )

    if any(
        "key_vault_reference_identity_id is unknown" in uncertainty
        for uncertainty in facts.app_service_secret_posture_uncertainties
    ):
        return None, [f"{workload.address}: key_vault_reference_identity_id is unknown after planning"]

    if not facts.has_system_assigned_identity:
        return None, [f"{workload.address}: no deterministic Key Vault reference identity is configured"]
    if not facts.principal_id:
        return None, [f"{workload.address}: system-assigned identity principal_id is unresolved"]
    return (
        _ReferenceIdentity(
            resource=workload,
            kind="system_assigned",
            resolution_basis="system_assigned_identity",
        ),
        [],
    )


def _secret_target(
    workload: NormalizedResource,
    reference: Mapping[str, Any],
    vaults_by_uri: Mapping[str, tuple[NormalizedResource, ...]],
    secrets_by_uri: Mapping[str, tuple[NormalizedResource, ...]],
) -> tuple[_SecretTarget | None, list[str]]:
    vault_uri = _string_value(reference.get("key_vault_uri"))
    if vault_uri is None:
        return None, [f"{workload.address}: Key Vault reference does not expose an exact vault URI"]
    vault_matches = vaults_by_uri.get(_uri_key(vault_uri), ())
    if len(vault_matches) != 1:
        reason = "is not modeled" if not vault_matches else "matches multiple modeled vaults"
        return None, [f"{workload.address}: Key Vault URI {vault_uri} {reason}"]

    secret, resolution_basis, uncertainty = _resolved_secret(reference, secrets_by_uri)
    uncertainties = [f"{workload.address}: {uncertainty}"] if uncertainty else []
    if secret is not None and azure_facts(secret).resolved_key_vault_address != vault_matches[0].address:
        return None, [f"{workload.address}: resolved secret does not belong to Key Vault URI {vault_uri}"]
    return (
        _SecretTarget(
            vault=vault_matches[0],
            secret=secret,
            resolution_basis=resolution_basis,
        ),
        uncertainties,
    )


def _resolved_secret(
    reference: Mapping[str, Any],
    secrets_by_uri: Mapping[str, tuple[NormalizedResource, ...]],
) -> tuple[NormalizedResource | None, str, str | None]:
    secret_uri = _string_value(reference.get("key_vault_secret_uri"))
    versionless_uri = _string_value(reference.get("key_vault_secret_versionless_uri"))
    candidates = (
        (secret_uri, "versioned_secret_uri"),
        (versionless_uri, "versionless_secret_uri"),
    )
    for uri, basis in candidates:
        if uri is None:
            continue
        matches = secrets_by_uri.get(_uri_key(uri), ())
        if len(matches) == 1:
            return matches[0], basis, None
        if len(matches) > 1:
            return None, "exact_secret_uri", f"Key Vault secret URI {uri} matches multiple modeled secrets"
    return None, "exact_secret_uri", None


def _access_grants(
    identity: _ReferenceIdentity,
    target: _SecretTarget,
    context: AzureDecorationContext,
) -> tuple[list[dict[str, Any]], list[str]]:
    vault_facts = azure_facts(target.vault)
    if vault_facts.rbac_authorization_enabled is True:
        return _rbac_grants(identity, target, context)
    if vault_facts.rbac_authorization_enabled is False:
        return _access_policy_grants(identity, target)
    return [], [f"{target.vault.address}: Key Vault authorization model is unknown"]


def _access_policy_grants(
    identity: _ReferenceIdentity,
    target: _SecretTarget,
) -> tuple[list[dict[str, Any]], list[str]]:
    identity_facts = azure_facts(identity.resource)
    principal_id = identity_facts.principal_id
    if principal_id is None:
        return [], [f"{identity.resource.address}: principal_id is unresolved"]

    vault_facts = azure_facts(target.vault)
    grants: list[dict[str, Any]] = []
    for policy in vault_facts.key_vault_access_policies:
        if not _same_identifier(_string_value(policy.get("object_id")), principal_id):
            continue
        permissions = _normalized_strings(policy.get("secret_permissions"))
        if not permissions.intersection({"get", "all", "*"}):
            continue
        grants.append(
            {
                "grant_kind": "access_policy",
                "grant_source_address": _string_value(policy.get("source")) or target.vault.address,
                "grant_scope_type": "vault",
                "grant_scope": vault_facts.key_vault_id or vault_facts.key_vault_uri,
                "grant_basis": "key_vault_access_policy",
                "secret_permissions": sorted(permissions),
                "condition": None,
                "condition_state": "not_configured",
                "access_state": "granted",
            }
        )
    uncertainties = [
        f"{target.vault.address}: {value}"
        for value in vault_facts.key_vault_authorization_uncertainties
        if "access_policy" in value or "secret_permissions" in value
    ]
    return grants, uncertainties


def _rbac_grants(
    identity: _ReferenceIdentity,
    target: _SecretTarget,
    context: AzureDecorationContext,
) -> tuple[list[dict[str, Any]], list[str]]:
    identity_facts = azure_facts(identity.resource)
    grants: list[dict[str, Any]] = []
    uncertainties: list[str] = []
    for assignment in identity_facts.managed_identity_role_assignments:
        source = _string_value(assignment.get("source"))
        assignment_resource = context.index.resolve(source)
        if assignment_resource is None or assignment_resource.resource_type != AzureResourceType.ROLE_ASSIGNMENT:
            if source:
                uncertainties.append(f"role assignment {source} is not modeled")
            continue
        assignment_facts = azure_facts(assignment_resource)
        if not _same_identifier(assignment_facts.principal_id, identity_facts.principal_id):
            continue
        scope_type = _assignment_scope_type(assignment_resource, target)
        if scope_type is None:
            continue
        if any("condition is unknown" in value for value in assignment_facts.key_vault_authorization_uncertainties):
            uncertainties.append(f"{assignment_resource.address} condition is unknown after planning")
            continue

        role, role_uncertainty = _secret_read_role(assignment_resource, context)
        if role_uncertainty:
            uncertainties.append(f"{assignment_resource.address} {role_uncertainty}")
        if role is None:
            continue
        condition = assignment_facts.role_assignment_condition
        grants.append(
            {
                "grant_kind": "rbac",
                "grant_source_address": assignment_resource.address,
                "grant_scope_type": scope_type,
                "grant_scope": assignment_facts.role_assignment_scope,
                "grant_basis": "azure_rbac_assignment",
                "role_definition_name": assignment_facts.role_definition_name,
                "role_definition_id": assignment_facts.role_definition_id,
                "role_kind": role["role_kind"],
                "custom_role_address": role.get("custom_role_address"),
                "custom_role_data_actions": role.get("data_actions", []),
                "custom_role_not_data_actions": role.get("not_data_actions", []),
                "condition": condition,
                "condition_state": "configured" if condition else "not_configured",
                "access_state": "conditional" if condition else "granted",
            }
        )
    return grants, uncertainties


def _assignment_scope_type(assignment: NormalizedResource, target: _SecretTarget) -> str | None:
    facts = azure_facts(assignment)
    scope_key = azure_reference_key(facts.role_assignment_scope)
    if target.secret is not None and scope_key in azure_resource_references(target.secret):
        return "secret"
    if scope_key in azure_resource_references(target.vault):
        return "vault"
    if facts.role_assignment_scope_kind not in {"subscription", "resource_group"}:
        return None
    scope = _string_value(facts.role_assignment_scope)
    vault_id = azure_facts(target.vault).key_vault_id
    if scope is None or vault_id is None or not _absolute_scope_contains(scope, vault_id):
        return None
    return facts.role_assignment_scope_kind


def _secret_read_role(
    assignment: NormalizedResource,
    context: AzureDecorationContext,
) -> tuple[dict[str, Any] | None, str | None]:
    facts = azure_facts(assignment)
    role_name = _string_value(facts.role_definition_name)
    if role_name and role_name.lower() in _KEY_VAULT_SECRET_READ_ROLE_NAMES:
        return {"role_kind": "built_in"}, None

    role_definition = context.index.resolve(facts.resolved_role_definition_address)
    if role_definition is None or role_definition.resource_type != AzureResourceType.ROLE_DEFINITION:
        if role_name is None:
            return None, "role is unresolved"
        return None, None
    role_facts = azure_facts(role_definition)
    if any(
        "data_actions" in value or "not_data_actions" in value for value in role_facts.role_definition_uncertainties
    ):
        return None, f"custom role {role_definition.address} data actions are unresolved"

    data_actions = tuple(_normalized_strings(role_facts.role_definition_data_actions))
    not_data_actions = tuple(_normalized_strings(role_facts.role_definition_not_data_actions))
    if not any(fnmatchcase(_KEY_VAULT_SECRET_GET_ACTION, pattern) for pattern in data_actions):
        return None, None
    if any(fnmatchcase(_KEY_VAULT_SECRET_GET_ACTION, pattern) for pattern in not_data_actions):
        return None, None
    return (
        {
            "role_kind": "custom",
            "custom_role_address": role_definition.address,
            "data_actions": list(data_actions),
            "not_data_actions": list(not_data_actions),
        },
        None,
    )


def _access_path_record(
    workload: NormalizedResource,
    reference: Mapping[str, Any],
    identity: _ReferenceIdentity,
    target: _SecretTarget,
    grant: Mapping[str, Any],
) -> dict[str, Any]:
    workload_facts = azure_facts(workload)
    identity_facts = azure_facts(identity.resource)
    vault_facts = azure_facts(target.vault)
    record = {
        "workload_address": workload.address,
        "workload_type": workload.resource_type,
        "secret_reference": reference.get("reference"),
        "secret_reference_path": reference.get("path"),
        "setting_name": reference.get("setting_name"),
        "key_vault_address": target.vault.address,
        "key_vault_id": vault_facts.key_vault_id,
        "key_vault_uri": vault_facts.key_vault_uri,
        "secret_resource_address": target.secret.address if target.secret else None,
        "secret_target_resolution": "resolved_in_plan" if target.secret else "exact_secret_uri",
        "secret_resolution_basis": target.resolution_basis,
        "secret_uri": reference.get("key_vault_secret_uri"),
        "secret_versionless_uri": reference.get("key_vault_secret_versionless_uri"),
        "secret_name": reference.get("key_vault_secret_name"),
        "secret_version": reference.get("key_vault_secret_version"),
        "secret_version_state": reference.get("secret_version_state"),
        "identity_address": identity.resource.address,
        "identity_kind": identity.kind,
        "identity_resolution_basis": identity.resolution_basis,
        "key_vault_reference_identity_id": workload_facts.app_service_key_vault_reference_identity_id,
        "principal_id": identity_facts.principal_id,
        "client_id": identity_facts.client_id,
        "credential_context": "app_service_key_vault_reference",
        **dict(grant),
    }
    return record


def _vaults_by_uri(resources: list[NormalizedResource]) -> dict[str, tuple[NormalizedResource, ...]]:
    return _resources_by_uris(
        resources,
        AzureResourceType.KEY_VAULT,
        lambda resource: (azure_facts(resource).key_vault_uri,),
    )


def _secrets_by_uri(resources: list[NormalizedResource]) -> dict[str, tuple[NormalizedResource, ...]]:
    return _resources_by_uris(
        resources,
        AzureResourceType.KEY_VAULT_SECRET,
        lambda resource: (
            azure_facts(resource).key_vault_secret_uri,
            azure_facts(resource).key_vault_secret_versionless_uri,
        ),
    )


def _resources_by_uris(
    resources: list[NormalizedResource],
    resource_type: str,
    uri_factory: Callable[[NormalizedResource], tuple[str | None, ...]],
) -> dict[str, tuple[NormalizedResource, ...]]:
    mutable: dict[str, list[NormalizedResource]] = {}
    for resource in resources:
        if resource.resource_type != resource_type:
            continue
        for uri in uri_factory(resource):
            if uri:
                mutable.setdefault(_uri_key(uri), []).append(resource)
    result: dict[str, tuple[NormalizedResource, ...]] = {}
    for key, values in mutable.items():
        unique: list[NormalizedResource] = []
        for value in values:
            if value not in unique:
                unique.append(value)
        result[key] = tuple(unique)
    return result


def _is_exact_secret_reference(reference: Mapping[str, Any]) -> bool:
    return (
        reference.get("state") == "reference"
        and reference.get("reference_kind") == "key_vault_secret_uri"
        and reference.get("is_resolved") is True
        and reference.get("target_resolution") == "resolved"
        and _string_value(reference.get("key_vault_uri")) is not None
        and _string_value(reference.get("key_vault_secret_versionless_uri")) is not None
    )


def _reference_uncertainties(
    workload: NormalizedResource,
    references: list[dict[str, Any]],
) -> list[str]:
    return [
        f"{workload.address}: {reference.get('unresolved_reason')}"
        for reference in references
        if reference.get("state") == "reference"
        and reference.get("is_resolved") is False
        and reference.get("unresolved_reason")
    ]


def _absolute_scope_contains(scope: str, resource_id: str) -> bool:
    normalized_scope = scope.strip().lower().rstrip("/")
    normalized_resource = resource_id.strip().lower().rstrip("/")
    return normalized_scope.startswith("/subscriptions/") and normalized_resource.startswith(f"{normalized_scope}/")


def _is_exact_user_assigned_identity_reference(
    reference: str,
    identity: NormalizedResource,
) -> bool:
    reference_key = azure_reference_key(reference)
    if reference_key == azure_reference_key(identity.address):
        return True
    identifier = identity.identifier.strip()
    normalized_identifier = identifier.lower()
    return (
        normalized_identifier.startswith("/subscriptions/")
        and "/providers/microsoft.managedidentity/userassignedidentities/" in normalized_identifier
        and reference_key == azure_reference_key(identifier)
    )


def _same_identifier(left: str | None, right: str | None) -> bool:
    return bool(left and right and left.strip().lower() == right.strip().lower())


def _normalized_strings(value: object) -> set[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return set()
    return {item.strip().lower() for item in value if isinstance(item, str) and item.strip()}


def _string_value(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _uri_key(value: str) -> str:
    return value.strip().rstrip("/").lower()


def _dedupe_dicts(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for value in values:
        if value not in result:
            result.append(value)
    return result
