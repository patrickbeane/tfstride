from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.rbac_breadth import classify_role_definition_breadth
from tfstride.providers.azure.resource_utils import as_list, compact_strings, first_non_empty

AZURE_PROVIDER = "azure"
_USER_ASSIGNED_IDENTITY_TYPE = "UserAssigned"


def normalize_user_assigned_identity(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    principal_id = _known_string(resource, values, "principal_id", uncertainties)
    client_id = _known_string(resource, values, "client_id", uncertainties)
    tenant_id = _known_string(resource, values, "tenant_id", uncertainties)
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
    role_name = _known_string(resource, values, "name", uncertainties)
    scope = _known_string(resource, values, "scope", uncertainties)
    assignable_scopes = _known_string_list(resource, values, "assignable_scopes", uncertainties)
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
        identifier=first_non_empty(values.get("role_definition_id"), values.get("id"), role_name, resource.address),
        metadata=metadata,
    )


def managed_identity_metadata(resource: TerraformResource) -> dict[Any, Any]:
    identity = _first_mapping(resource.values.get("identity"))
    identity_unknown = resource.unknown_values.get("identity")
    if identity is None and identity_unknown is None:
        return {}

    uncertainties: list[str] = []
    if identity_unknown is True:
        return {AzureResourceMetadata.MANAGED_IDENTITY_UNCERTAINTIES: ["identity is unknown after planning"]}

    identity_type = _block_known_string(identity, identity_unknown, "type", uncertainties)
    principal_id = _block_known_string(identity, identity_unknown, "principal_id", uncertainties)
    client_id = _block_known_string(identity, identity_unknown, "client_id", uncertainties)
    tenant_id = _block_known_string(identity, identity_unknown, "tenant_id", uncertainties)
    attached_identity_references = _block_known_strings(
        identity,
        identity_unknown,
        "identity_ids",
        uncertainties,
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


def _known_string(
    resource: TerraformResource,
    values: Mapping[str, Any],
    key: str,
    uncertainties: list[str],
) -> str | None:
    if resource.unknown_values.get(key) is True:
        uncertainties.append(f"{key} is unknown after planning")
        return None
    return first_non_empty(values.get(key))


def _known_string_list(
    resource: TerraformResource,
    values: Mapping[str, Any],
    key: str,
    uncertainties: list[str],
) -> list[str]:
    if _value_is_unknown(resource.unknown_values.get(key)):
        uncertainties.append(f"{key} is unknown after planning")
        return []
    return compact_strings(as_list(values.get(key)))


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
        return _value_is_unknown(unknown_permission.get(key))
    return False


def _permission_values(permissions: list[dict[str, Any]], key: str) -> list[str]:
    return compact_strings(value for permission in permissions for value in permission.get(key, []))


def _block_known_string(
    values: Mapping[str, Any] | None,
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
) -> str | None:
    if _block_attribute_unknown(unknown_block, key):
        uncertainties.append(f"identity.{key} is unknown after planning")
        return None
    return first_non_empty(values.get(key)) if values is not None else None


def _block_known_strings(
    values: Mapping[str, Any] | None,
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
) -> list[str]:
    if _block_attribute_unknown(unknown_block, key):
        uncertainties.append(f"identity.{key} is unknown after planning")
        return []
    return compact_strings(as_list(values.get(key))) if values is not None else []


def _block_attribute_unknown(unknown_block: Any, key: str) -> bool:
    if unknown_block is True:
        return True
    if isinstance(unknown_block, Mapping):
        return _value_is_unknown(unknown_block.get(key))
    if isinstance(unknown_block, list) and unknown_block:
        first = unknown_block[0]
        return first is True or (isinstance(first, Mapping) and _value_is_unknown(first.get(key)))
    return False


def _value_is_unknown(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, Mapping):
        return any(_value_is_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(_value_is_unknown(item) for item in value)
    return False


def _first_mapping(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, list) and value and isinstance(value[0], Mapping):
        return value[0]
    return None
