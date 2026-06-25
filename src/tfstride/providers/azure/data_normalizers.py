from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata

AZURE_PROVIDER = "azure"


def normalize_storage_account(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    name = _optional_string(values.get("name")) or resource.name
    account_id = _optional_string(values.get("id"))
    inline_network_rules = _first_mapping(values.get("network_rules"))
    network_default_action = (
        _optional_string(inline_network_rules.get("default_action")) if inline_network_rules is not None else "Allow"
    )
    return _with_storage_encrypted(
        NormalizedResource(
            address=resource.address,
            provider=AZURE_PROVIDER,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=account_id or name or resource.address,
            data_sensitivity="sensitive",
            metadata={
                AzureResourceMetadata.NAME: name,
                AzureResourceMetadata.STORAGE_ACCOUNT_ID: account_id,
                AzureResourceMetadata.ALLOW_NESTED_ITEMS_TO_BE_PUBLIC: _bool_with_default(
                    values,
                    "allow_nested_items_to_be_public",
                    True,
                ),
                AzureResourceMetadata.SHARED_ACCESS_KEY_ENABLED: _bool_with_default(
                    values,
                    "shared_access_key_enabled",
                    True,
                ),
                AzureResourceMetadata.MIN_TLS_VERSION: _optional_string(values.get("min_tls_version")) or "TLS1_2",
                AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED: _bool_with_default(
                    values,
                    "public_network_access_enabled",
                    True,
                ),
                AzureResourceMetadata.NETWORK_DEFAULT_ACTION: network_default_action or "Allow",
                AzureResourceMetadata.NETWORK_RULE_SOURCE_ADDRESS: (
                    resource.address if inline_network_rules is not None else None
                ),
            },
        )
    )


def normalize_storage_container(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    name = _optional_string(values.get("name")) or resource.name
    return _with_storage_encrypted(
        NormalizedResource(
            address=resource.address,
            provider=AZURE_PROVIDER,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=_optional_string(values.get("id")) or name or resource.address,
            data_sensitivity="sensitive",
            metadata={
                AzureResourceMetadata.NAME: name,
                AzureResourceMetadata.STORAGE_ACCOUNT_REFERENCE: _first_non_empty(
                    values.get("storage_account_id"),
                    values.get("storage_account_name"),
                ),
                AzureResourceMetadata.CONTAINER_ACCESS_TYPE: _optional_string(values.get("container_access_type"))
                or "private",
            },
        )
    )


def normalize_storage_account_network_rules(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    storage_account_reference = _optional_string(values.get("storage_account_id"))
    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=_optional_string(values.get("id")) or storage_account_reference or resource.address,
        metadata={
            AzureResourceMetadata.STORAGE_ACCOUNT_REFERENCE: storage_account_reference,
            AzureResourceMetadata.NETWORK_DEFAULT_ACTION: _optional_string(values.get("default_action")),
            AzureResourceMetadata.NETWORK_RULE_SOURCE_ADDRESS: resource.address,
        },
    )


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


def _first_mapping(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, list) and value and isinstance(value[0], Mapping):
        return value[0]
    return None


def _first_non_empty(*values: Any) -> str | None:
    for value in values:
        normalized = _optional_string(value)
        if normalized is not None:
            return normalized
    return None


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
