from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.public_network import public_network_fallback_state
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_utils import (
    as_list,
    attribute_unknown,
    compact_strings,
    first_block_attribute_unknown,
    first_mapping,
    first_non_empty,
)
from tfstride.providers.azure.resource_utils import (
    known_bool as known_optional_bool,
)

AZURE_PROVIDER = "azure"
_PERMISSION_FIELDS = (
    "key_permissions",
    "secret_permissions",
    "certificate_permissions",
    "storage_permissions",
)


def normalize_key_vault(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    vault_id = first_non_empty(values.get("id"))
    name = first_non_empty(values.get("name"), resource.name)
    network_acls = first_mapping(values.get("network_acls"))
    network_uncertainties: list[str] = []
    authorization_uncertainties: list[str] = []
    recovery_uncertainties: list[str] = []

    public_network_access_enabled = known_optional_bool(
        values, resource.unknown_values, "public_network_access_enabled", network_uncertainties
    )
    network_default_action = _network_default_action(
        resource,
        network_acls,
        uncertainties=network_uncertainties,
    )
    purge_protection_enabled = _known_bool(
        resource,
        values,
        "purge_protection_enabled",
        default=False,
        uncertainties=recovery_uncertainties,
    )
    rbac_authorization_enabled = _known_bool(
        resource,
        values,
        "enable_rbac_authorization",
        default=False,
        uncertainties=authorization_uncertainties,
    )
    if resource.unknown_values.get("access_policy") is True:
        authorization_uncertainties.append("access_policy is unknown after planning")

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: name,
        AzureResourceMetadata.KEY_VAULT_ID: vault_id,
        AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
        AzureResourceMetadata.TENANT_ID: first_non_empty(values.get("tenant_id")),
        AzureResourceMetadata.NETWORK_DEFAULT_ACTION: network_default_action,
        AzureResourceMetadata.NETWORK_RULE_SOURCE_ADDRESS: resource.address if network_acls is not None else None,
        AzureResourceMetadata.PUBLIC_NETWORK_FALLBACK_STATE: public_network_fallback_state(
            public_network_access_enabled
        ),
        AzureResourceMetadata.KEY_VAULT_NETWORK_IP_RULES: compact_strings(
            as_list(network_acls.get("ip_rules")) if network_acls is not None else []
        ),
        AzureResourceMetadata.KEY_VAULT_NETWORK_SUBNET_IDS: compact_strings(
            as_list(network_acls.get("virtual_network_subnet_ids")) if network_acls is not None else []
        ),
        AzureResourceMetadata.KEY_VAULT_ACCESS_POLICIES: _inline_access_policies(resource, values),
    }
    if public_network_access_enabled is not None:
        metadata[AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED] = public_network_access_enabled
    if purge_protection_enabled is not None:
        metadata[AzureResourceMetadata.PURGE_PROTECTION_ENABLED] = purge_protection_enabled
    if rbac_authorization_enabled is not None:
        metadata[AzureResourceMetadata.RBAC_AUTHORIZATION_ENABLED] = rbac_authorization_enabled
    if network_uncertainties:
        metadata[AzureResourceMetadata.KEY_VAULT_NETWORK_UNCERTAINTIES] = network_uncertainties
    if authorization_uncertainties:
        metadata[AzureResourceMetadata.KEY_VAULT_AUTHORIZATION_UNCERTAINTIES] = authorization_uncertainties
    if recovery_uncertainties:
        metadata[AzureResourceMetadata.KEY_VAULT_RECOVERY_UNCERTAINTIES] = recovery_uncertainties

    return _with_storage_encrypted(
        NormalizedResource(
            address=resource.address,
            provider=AZURE_PROVIDER,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=vault_id or name or resource.address,
            data_sensitivity="sensitive",
            metadata=metadata,
        )
    )


def normalize_key_vault_access_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    vault_reference = first_non_empty(values.get("key_vault_id"))
    policy = _access_policy_record(values, source_address=resource.address)
    uncertainties = [
        f"{field} is unknown after planning"
        for field in _PERMISSION_FIELDS
        if resource.unknown_values.get(field) is True
    ]
    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=first_non_empty(values.get("id"), values.get("object_id"), resource.address),
        metadata={
            AzureResourceMetadata.KEY_VAULT_REFERENCE: vault_reference,
            AzureResourceMetadata.TENANT_ID: first_non_empty(values.get("tenant_id")),
            AzureResourceMetadata.OBJECT_ID: first_non_empty(values.get("object_id")),
            AzureResourceMetadata.APPLICATION_ID: first_non_empty(values.get("application_id")),
            AzureResourceMetadata.KEY_VAULT_ACCESS_POLICIES: [policy],
            AzureResourceMetadata.KEY_VAULT_AUTHORIZATION_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_key_vault_secret(resource: TerraformResource) -> NormalizedResource:
    return _normalize_key_vault_child(resource)


def normalize_key_vault_key(resource: TerraformResource) -> NormalizedResource:
    return _normalize_key_vault_child(resource)


def normalize_key_vault_certificate(resource: TerraformResource) -> NormalizedResource:
    return _normalize_key_vault_child(resource)


def _normalize_key_vault_child(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    name = first_non_empty(values.get("name"), resource.name)
    return _with_storage_encrypted(
        NormalizedResource(
            address=resource.address,
            provider=AZURE_PROVIDER,
            resource_type=resource.resource_type,
            name=resource.name,
            category=ResourceCategory.DATA,
            identifier=first_non_empty(values.get("id"), name, resource.address),
            data_sensitivity="sensitive",
            metadata={
                AzureResourceMetadata.NAME: name,
                AzureResourceMetadata.KEY_VAULT_REFERENCE: first_non_empty(values.get("key_vault_id")),
            },
        )
    )


def _inline_access_policies(resource: TerraformResource, values: Mapping[str, Any]) -> list[dict[str, Any]]:
    if resource.unknown_values.get("access_policy") is True:
        return []
    return [
        _access_policy_record(policy, source_address=resource.address)
        for policy in as_list(values.get("access_policy"))
        if isinstance(policy, Mapping)
    ]


def _access_policy_record(values: Mapping[str, Any], *, source_address: str) -> dict[str, Any]:
    record: dict[str, Any] = {
        "source": source_address,
        "tenant_id": first_non_empty(values.get("tenant_id")),
        "object_id": first_non_empty(values.get("object_id")),
        "application_id": first_non_empty(values.get("application_id")),
    }
    for field in _PERMISSION_FIELDS:
        record[field] = sorted(permission.lower() for permission in compact_strings(as_list(values.get(field))))
    return record


def _network_default_action(
    resource: TerraformResource,
    network_acls: Mapping[str, Any] | None,
    *,
    uncertainties: list[str],
) -> str | None:
    if attribute_unknown(resource.unknown_values, "network_acls") or first_block_attribute_unknown(
        resource.unknown_values,
        "network_acls",
        "default_action",
    ):
        uncertainties.append("network_acls.default_action is unknown after planning")
        return None
    if network_acls is None:
        return "Allow"
    default_action = first_non_empty(network_acls.get("default_action"))
    if default_action is None:
        uncertainties.append("network_acls.default_action is not represented in planned values")
    return default_action


def _known_bool(
    resource: TerraformResource,
    values: Mapping[str, Any],
    key: str,
    *,
    default: bool,
    uncertainties: list[str],
) -> bool | None:
    if attribute_unknown(resource.unknown_values, key):
        uncertainties.append(f"{key} is unknown after planning")
        return None
    return _bool_with_default(values, key, default)


def _bool_with_default(values: Mapping[str, Any], key: str, default: bool) -> bool:
    value = values.get(key)
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "enabled", "yes", "on"}:
            return True
        if normalized in {"false", "disabled", "no", "off"}:
            return False
    return bool(value)


def _with_storage_encrypted(resource: NormalizedResource) -> NormalizedResource:
    azure_facts(resource).set_storage_encrypted(True)
    return resource
