from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.public_network import public_network_fallback_state
from tfstride.providers.azure.resource_utils import (
    attribute_unknown,
    first_block_attribute_unknown,
    first_mapping,
    first_non_empty,
    known_block_bool,
    known_block_int,
    known_bool,
    unknown_block_at,
)

AZURE_PROVIDER = "azure"


def normalize_storage_account(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    name = _optional_string(values.get("name")) or resource.name
    account_id = _optional_string(values.get("id"))
    uncertainties: list[str] = []
    inline_network_rules = first_mapping(values.get("network_rules"))
    network_rules_unknown = attribute_unknown(resource.unknown_values, "network_rules")
    default_action_unknown = network_rules_unknown or first_block_attribute_unknown(
        resource.unknown_values,
        "network_rules",
        "default_action",
    )
    if default_action_unknown:
        network_default_action = None
        uncertainties.append("network_rules.default_action is unknown after planning")
    elif inline_network_rules is not None:
        network_default_action = _optional_string(inline_network_rules.get("default_action")) or "Allow"
    else:
        network_default_action = "Allow"

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: name,
        AzureResourceMetadata.STORAGE_ACCOUNT_ID: account_id,
        AzureResourceMetadata.NETWORK_DEFAULT_ACTION: network_default_action,
        AzureResourceMetadata.NETWORK_RULE_SOURCE_ADDRESS: (
            resource.address if inline_network_rules is not None or network_rules_unknown else None
        ),
    }
    _set_bool_posture(
        metadata,
        resource,
        values,
        key="allow_nested_items_to_be_public",
        field=AzureResourceMetadata.ALLOW_NESTED_ITEMS_TO_BE_PUBLIC,
        default=True,
        uncertainties=uncertainties,
    )
    _set_bool_posture(
        metadata,
        resource,
        values,
        key="shared_access_key_enabled",
        field=AzureResourceMetadata.SHARED_ACCESS_KEY_ENABLED,
        default=True,
        uncertainties=uncertainties,
    )
    _set_storage_encryption_posture(metadata, resource, values, uncertainties)
    _set_storage_blob_recovery_posture(metadata, resource, values, uncertainties)
    public_network_access_enabled = known_bool(
        values, resource.unknown_values, "public_network_access_enabled", uncertainties
    )
    metadata[AzureResourceMetadata.PUBLIC_NETWORK_FALLBACK_STATE] = public_network_fallback_state(
        public_network_access_enabled
    )
    if public_network_access_enabled is not None:
        metadata[AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED] = public_network_access_enabled
    if attribute_unknown(resource.unknown_values, "min_tls_version"):
        uncertainties.append("min_tls_version is unknown after planning")
    else:
        metadata[AzureResourceMetadata.MIN_TLS_VERSION] = _optional_string(values.get("min_tls_version")) or "TLS1_2"
    if uncertainties:
        metadata[AzureResourceMetadata.STORAGE_POSTURE_UNCERTAINTIES] = uncertainties

    return _with_storage_encrypted(
        NormalizedResource(
            address=resource.address,
            provider=AZURE_PROVIDER,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=account_id or name or resource.address,
            data_sensitivity="sensitive",
            metadata=metadata,
        )
    )


def normalize_storage_container(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    name = _optional_string(values.get("name")) or resource.name
    uncertainties: list[str] = []
    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: name,
        AzureResourceMetadata.STORAGE_ACCOUNT_REFERENCE: first_non_empty(
            values.get("storage_account_id"),
            values.get("storage_account_name"),
        ),
    }
    if attribute_unknown(resource.unknown_values, "container_access_type"):
        uncertainties.append("container_access_type is unknown after planning")
    else:
        metadata[AzureResourceMetadata.CONTAINER_ACCESS_TYPE] = (
            _optional_string(values.get("container_access_type")) or "private"
        )
    if uncertainties:
        metadata[AzureResourceMetadata.STORAGE_POSTURE_UNCERTAINTIES] = uncertainties

    return _with_storage_encrypted(
        NormalizedResource(
            address=resource.address,
            provider=AZURE_PROVIDER,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=_optional_string(values.get("id")) or name or resource.address,
            data_sensitivity="sensitive",
            metadata=metadata,
        )
    )


def normalize_storage_account_network_rules(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    storage_account_reference = _optional_string(values.get("storage_account_id"))
    uncertainties: list[str] = []
    metadata: dict[Any, Any] = {
        AzureResourceMetadata.STORAGE_ACCOUNT_REFERENCE: storage_account_reference,
        AzureResourceMetadata.NETWORK_RULE_SOURCE_ADDRESS: resource.address,
    }
    if attribute_unknown(resource.unknown_values, "default_action"):
        uncertainties.append("default_action is unknown after planning")
    else:
        metadata[AzureResourceMetadata.NETWORK_DEFAULT_ACTION] = _optional_string(values.get("default_action"))
    if uncertainties:
        metadata[AzureResourceMetadata.STORAGE_POSTURE_UNCERTAINTIES] = uncertainties

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=_optional_string(values.get("id")) or storage_account_reference or resource.address,
        metadata=metadata,
    )


def _set_storage_encryption_posture(
    metadata: dict[Any, Any],
    resource: TerraformResource,
    values: Mapping[str, Any],
    uncertainties: list[str],
) -> None:
    infrastructure_encryption_enabled = known_bool(
        values,
        resource.unknown_values,
        "infrastructure_encryption_enabled",
        uncertainties,
    )
    if infrastructure_encryption_enabled is not None:
        metadata[AzureResourceMetadata.STORAGE_INFRASTRUCTURE_ENCRYPTION_ENABLED] = infrastructure_encryption_enabled

    customer_managed_key_unknown = attribute_unknown(resource.unknown_values, "customer_managed_key")
    if customer_managed_key_unknown:
        uncertainties.append("customer_managed_key is unknown after planning")
        return

    customer_managed_key = first_mapping(values.get("customer_managed_key"))
    if customer_managed_key is None:
        return

    key_id = first_non_empty(
        customer_managed_key.get("key_vault_key_id"),
        customer_managed_key.get("key_vault_key_uri"),
    )
    if key_id:
        metadata[AzureResourceMetadata.STORAGE_CUSTOMER_MANAGED_KEY_ID] = key_id

    identity_id = first_non_empty(
        customer_managed_key.get("user_assigned_identity_id"),
        customer_managed_key.get("user_assigned_identity_resource_id"),
    )
    if identity_id:
        metadata[AzureResourceMetadata.STORAGE_CUSTOMER_MANAGED_KEY_IDENTITY_ID] = identity_id


def _set_storage_blob_recovery_posture(
    metadata: dict[Any, Any],
    resource: TerraformResource,
    values: Mapping[str, Any],
    uncertainties: list[str],
) -> None:
    blob_properties = first_mapping(values.get("blob_properties"))
    blob_unknown_value = resource.unknown_values.get("blob_properties")
    blob_unknown = (
        blob_unknown_value
        if blob_unknown_value is True or isinstance(blob_unknown_value, Mapping)
        else unknown_block_at(blob_unknown_value, 0)
    )

    versioning_enabled = known_block_bool(
        blob_properties,
        blob_unknown,
        "versioning_enabled",
        uncertainties,
        path="blob_properties",
    )
    if versioning_enabled is not None:
        metadata[AzureResourceMetadata.STORAGE_BLOB_VERSIONING_ENABLED] = versioning_enabled

    _set_storage_blob_policy_days(
        metadata,
        blob_properties,
        blob_unknown,
        block_name="delete_retention_policy",
        field=AzureResourceMetadata.STORAGE_BLOB_DELETE_RETENTION_DAYS,
        uncertainties=uncertainties,
    )
    _set_storage_blob_policy_days(
        metadata,
        blob_properties,
        blob_unknown,
        block_name="container_delete_retention_policy",
        field=AzureResourceMetadata.STORAGE_CONTAINER_DELETE_RETENTION_DAYS,
        uncertainties=uncertainties,
    )
    _set_storage_blob_policy_days(
        metadata,
        blob_properties,
        blob_unknown,
        block_name="restore_policy",
        field=AzureResourceMetadata.STORAGE_BLOB_RESTORE_POLICY_DAYS,
        uncertainties=uncertainties,
    )


def _set_storage_blob_policy_days(
    metadata: dict[Any, Any],
    blob_properties: Mapping[str, Any] | None,
    blob_unknown: Any,
    *,
    block_name: str,
    field: Any,
    uncertainties: list[str],
) -> None:
    policy = first_mapping(blob_properties.get(block_name)) if blob_properties is not None else None
    policy_unknown = _unknown_child_block(blob_unknown, block_name)
    days = known_block_int(
        policy,
        policy_unknown,
        "days",
        uncertainties,
        path=f"blob_properties.{block_name}",
    )
    if days is not None:
        metadata[field] = days


def _unknown_child_block(unknown_block: Any, key: str) -> Any:
    if unknown_block is True:
        return True
    if isinstance(unknown_block, Mapping):
        return unknown_block.get(key)
    return None


def _set_bool_posture(
    metadata: dict[Any, Any],
    resource: TerraformResource,
    values: Mapping[str, Any],
    *,
    key: str,
    field: Any,
    default: bool,
    uncertainties: list[str],
) -> None:
    if attribute_unknown(resource.unknown_values, key):
        uncertainties.append(f"{key} is unknown after planning")
        return
    metadata[field] = _bool_with_default(values, key, default)


def _with_storage_encrypted(resource: NormalizedResource) -> NormalizedResource:
    resource.storage_encrypted = True
    return resource


def _bool_with_default(values: Mapping[str, Any], key: str, default: bool) -> bool:
    if key not in values or values[key] is None:
        return default
    value = values[key]
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "enabled", "yes", "on"}:
            return True
        if normalized in {"false", "disabled", "no", "off"}:
            return False
    return bool(value)


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
