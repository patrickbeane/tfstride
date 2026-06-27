from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.rbac_breadth import classify_role_definition_breadth
from tfstride.providers.azure.resource_utils import (
    as_list,
    compact_strings,
    first_mapping,
    first_non_empty,
    known_block_string,
    known_block_strings,
    known_string,
    known_string_list,
    value_is_unknown,
)

AZURE_PROVIDER = "azure"
_USER_ASSIGNED_IDENTITY_TYPE = "UserAssigned"


def normalize_user_assigned_identity(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    principal_id = known_string(values, resource.unknown_values, "principal_id", uncertainties)
    client_id = known_string(values, resource.unknown_values, "client_id", uncertainties)
    tenant_id = known_string(values, resource.unknown_values, "tenant_id", uncertainties)
    identity_id = None if resource.unknown_values.get("id") is True else first_non_empty(values.get("id"))
    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
        AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
        AzureResourceMetadata.IDENTITY_TYPE: _USER_ASSIGNED_IDENTITY_TYPE,
        AzureResourceMetadata.PRINCIPAL_ID: principal_id,
        AzureResourceMetadata.CLIENT_ID: client_id,
        AzureResourceMetadata.TENANT_ID: tenant_id,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.MANAGED_IDENTITY_UNCERTAINTIES] = uncertainties

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=identity_id or client_id or principal_id or resource.address,
        metadata=metadata,
    )


def normalize_role_definition(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    role_name = known_string(values, resource.unknown_values, "name", uncertainties)
    role_definition_id = (
        known_string(values, resource.unknown_values, "role_definition_id", uncertainties)
        or known_string(values, resource.unknown_values, "role_definition_resource_id", uncertainties)
        or known_string(values, resource.unknown_values, "id", uncertainties)
    )
    scope = known_string(values, resource.unknown_values, "scope", uncertainties)
    assignable_scopes = known_string_list(values, resource.unknown_values, "assignable_scopes", uncertainties)
    permissions = _role_definition_permission_records(resource, values, uncertainties)
    actions = _permission_values(permissions, "actions")
    not_actions = _permission_values(permissions, "not_actions")
    data_actions = _permission_values(permissions, "data_actions")
    not_data_actions = _permission_values(permissions, "not_data_actions")
    breadth = classify_role_definition_breadth(
        actions=actions,
        not_actions=not_actions,
        data_actions=data_actions,
        not_data_actions=not_data_actions,
    )
    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: role_name,
        AzureResourceMetadata.ROLE_DEFINITION_ID: role_definition_id,
        AzureResourceMetadata.ROLE_DEFINITION_SCOPE: scope,
        AzureResourceMetadata.ROLE_DEFINITION_ASSIGNABLE_SCOPES: assignable_scopes,
        AzureResourceMetadata.ROLE_DEFINITION_ACTIONS: actions,
        AzureResourceMetadata.ROLE_DEFINITION_NOT_ACTIONS: not_actions,
        AzureResourceMetadata.ROLE_DEFINITION_DATA_ACTIONS: data_actions,
        AzureResourceMetadata.ROLE_DEFINITION_NOT_DATA_ACTIONS: not_data_actions,
        AzureResourceMetadata.ROLE_DEFINITION_BREADTH_SIGNALS: list(breadth.signals),
        AzureResourceMetadata.ROLE_DEFINITION_BREADTH_MITIGATIONS: list(breadth.mitigations),
        AzureResourceMetadata.ROLE_DEFINITION_PERMISSIONS: permissions,
        AzureResourceMetadata.CUSTOM_ROLE_DEFINITION: True,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.ROLE_DEFINITION_UNCERTAINTIES] = uncertainties

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(role_definition_id, role_name, resource.address),
        metadata=metadata,
    )


def normalize_role_assignment(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    scope = known_string(values, resource.unknown_values, "scope", uncertainties)
    role_definition_name = known_string(values, resource.unknown_values, "role_definition_name", uncertainties)
    role_definition_id = known_string(values, resource.unknown_values, "role_definition_id", uncertainties)
    principal_id = known_string(values, resource.unknown_values, "principal_id", uncertainties)
    principal_type = known_string(values, resource.unknown_values, "principal_type", uncertainties)
    assignment = {
        "source": resource.address,
        "scope": scope,
        "role_definition_name": role_definition_name,
        "role_definition_id": role_definition_id,
        "principal_id": principal_id,
        "principal_type": principal_type,
    }
    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get("id"), resource.address),
        metadata={
            AzureResourceMetadata.ROLE_ASSIGNMENT_SCOPE: scope,
            AzureResourceMetadata.ROLE_DEFINITION_NAME: role_definition_name,
            AzureResourceMetadata.ROLE_DEFINITION_ID: role_definition_id,
            AzureResourceMetadata.PRINCIPAL_ID: principal_id,
            AzureResourceMetadata.PRINCIPAL_TYPE: principal_type,
            AzureResourceMetadata.KEY_VAULT_ROLE_ASSIGNMENTS: [assignment],
            AzureResourceMetadata.KEY_VAULT_AUTHORIZATION_UNCERTAINTIES: uncertainties,
        },
    )


def managed_identity_metadata(resource: TerraformResource) -> dict[Any, Any]:
    identity = first_mapping(resource.values.get("identity"))
    identity_unknown = resource.unknown_values.get("identity")
    if identity is None and identity_unknown is None:
        return {}

    uncertainties: list[str] = []
    if identity_unknown is True:
        return {AzureResourceMetadata.MANAGED_IDENTITY_UNCERTAINTIES: ["identity is unknown after planning"]}

    identity_type = known_block_string(identity, identity_unknown, "type", uncertainties, path="identity")
    principal_id = known_block_string(identity, identity_unknown, "principal_id", uncertainties, path="identity")
    client_id = known_block_string(identity, identity_unknown, "client_id", uncertainties, path="identity")
    tenant_id = known_block_string(identity, identity_unknown, "tenant_id", uncertainties, path="identity")
    attached_identity_references = known_block_strings(
        identity, identity_unknown, "identity_ids", uncertainties, path="identity"
    )
    metadata: dict[Any, Any] = {
        AzureResourceMetadata.IDENTITY_TYPE: identity_type,
        AzureResourceMetadata.PRINCIPAL_ID: principal_id,
        AzureResourceMetadata.CLIENT_ID: client_id,
        AzureResourceMetadata.TENANT_ID: tenant_id,
        AzureResourceMetadata.ATTACHED_IDENTITY_REFERENCES: attached_identity_references,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.MANAGED_IDENTITY_UNCERTAINTIES] = uncertainties
    return metadata


def _role_definition_permission_records(
    resource: TerraformResource,
    values: Mapping[str, Any],
    uncertainties: list[str],
) -> list[dict[str, Any]]:
    raw_unknown = resource.unknown_values.get("permissions")
    if raw_unknown is True:
        uncertainties.append("permissions is unknown after planning")
        return []

    permission_values = as_list(values.get("permissions"))
    unknown_values = as_list(raw_unknown) if raw_unknown is not None else []
    records: list[dict[str, Any]] = []
    for index, permission in enumerate(permission_values):
        if not isinstance(permission, Mapping):
            if permission is not None:
                uncertainties.append(f"permissions[{index}] has an unrecognized value shape")
            continue
        unknown_permission = unknown_values[index] if index < len(unknown_values) else None
        if unknown_permission is True:
            uncertainties.append(f"permissions[{index}] is unknown after planning")
            continue
        records.append(
            {
                "actions": _permission_strings(permission, unknown_permission, "actions", index, uncertainties),
                "not_actions": _permission_strings(permission, unknown_permission, "not_actions", index, uncertainties),
                "data_actions": _permission_strings(
                    permission, unknown_permission, "data_actions", index, uncertainties
                ),
                "not_data_actions": _permission_strings(
                    permission,
                    unknown_permission,
                    "not_data_actions",
                    index,
                    uncertainties,
                ),
            }
        )
    return records


def _permission_strings(
    permission: Mapping[str, Any],
    unknown_permission: Any,
    key: str,
    index: int,
    uncertainties: list[str],
) -> list[str]:
    if _permission_field_unknown(unknown_permission, key):
        uncertainties.append(f"permissions[{index}].{key} is unknown after planning")
        return []
    return compact_strings(as_list(permission.get(key)))


def _permission_field_unknown(unknown_permission: Any, key: str) -> bool:
    if isinstance(unknown_permission, Mapping):
        return value_is_unknown(unknown_permission.get(key))
    return False


def _permission_values(permissions: list[dict[str, Any]], key: str) -> list[str]:
    return compact_strings(value for permission in permissions for value in permission.get(key, []))
