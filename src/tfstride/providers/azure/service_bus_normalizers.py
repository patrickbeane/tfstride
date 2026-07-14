from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.public_network import public_network_fallback_state
from tfstride.providers.azure.resource_utils import (
    first_block_attribute_unknown,
    first_mapping,
    first_non_empty,
    known_bool,
    known_string,
)
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
    bool_state,
)

AZURE_PROVIDER = "azure"


def normalize_servicebus_namespace(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    namespace_id = known_string(values, resource.unknown_values, "id", uncertainties, require_string=True)
    name = known_string(values, resource.unknown_values, "name", uncertainties, require_string=True) or resource.name
    sku = known_string(values, resource.unknown_values, "sku", uncertainties, require_string=True)
    tier = known_string(values, resource.unknown_values, "tier", uncertainties, require_string=True)
    public_network_access_enabled = known_bool(
        values,
        resource.unknown_values,
        "public_network_access_enabled",
        uncertainties,
        allow_string=False,
    )
    minimum_tls_version = known_string(
        values,
        resource.unknown_values,
        "minimum_tls_version",
        uncertainties,
        require_string=True,
    )
    local_auth_enabled = known_bool(
        values,
        resource.unknown_values,
        "local_auth_enabled",
        uncertainties,
        allow_string=False,
    )
    network_default_action, network_rule_source_address = _inline_network_rule_posture(
        resource,
        values,
        uncertainties,
    )
    cmk_state, key_vault_key_id, cmk_source_address = _inline_cmk_posture(resource, values, uncertainties)

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: name,
        AzureResourceMetadata.SERVICE_BUS_NAMESPACE_ID: namespace_id,
        AzureResourceMetadata.SERVICE_BUS_SKU: sku,
        AzureResourceMetadata.SERVICE_BUS_TIER: tier,
        AzureResourceMetadata.PUBLIC_NETWORK_FALLBACK_STATE: public_network_fallback_state(
            public_network_access_enabled
        ),
        AzureResourceMetadata.SERVICE_BUS_LOCAL_AUTH_STATE: bool_state(local_auth_enabled),
        AzureResourceMetadata.NETWORK_DEFAULT_ACTION: network_default_action,
        AzureResourceMetadata.SERVICE_BUS_NETWORK_RULE_SOURCE_ADDRESS: network_rule_source_address,
        AzureResourceMetadata.SERVICE_BUS_CUSTOMER_MANAGED_KEY_STATE: cmk_state,
        AzureResourceMetadata.SERVICE_BUS_KEY_VAULT_KEY_ID: key_vault_key_id,
        AzureResourceMetadata.SERVICE_BUS_CUSTOMER_MANAGED_KEY_SOURCE_ADDRESS: cmk_source_address,
    }
    if public_network_access_enabled is not None:
        metadata[AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED] = public_network_access_enabled
    if minimum_tls_version is not None:
        metadata[AzureResourceMetadata.MIN_TLS_VERSION] = minimum_tls_version
    if uncertainties:
        metadata[AzureResourceMetadata.SERVICE_BUS_POSTURE_UNCERTAINTIES] = uncertainties

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=namespace_id or name or resource.address,
        data_sensitivity="sensitive",
        metadata=metadata,
    )


def normalize_servicebus_namespace_network_rule_set(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    namespace_reference = known_string(
        values,
        resource.unknown_values,
        "namespace_id",
        uncertainties,
        require_string=True,
    )
    default_action = known_string(
        values,
        resource.unknown_values,
        "default_action",
        uncertainties,
        require_string=True,
    )
    public_network_access_enabled = known_bool(
        values,
        resource.unknown_values,
        "public_network_access_enabled",
        uncertainties,
        allow_string=False,
    )
    metadata: dict[Any, Any] = {
        AzureResourceMetadata.SERVICE_BUS_NAMESPACE_REFERENCE: namespace_reference,
        AzureResourceMetadata.NETWORK_DEFAULT_ACTION: default_action,
        AzureResourceMetadata.SERVICE_BUS_NETWORK_RULE_SOURCE_ADDRESS: resource.address,
        AzureResourceMetadata.PUBLIC_NETWORK_FALLBACK_STATE: public_network_fallback_state(
            public_network_access_enabled
        ),
    }
    if public_network_access_enabled is not None:
        metadata[AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED] = public_network_access_enabled
    if uncertainties:
        metadata[AzureResourceMetadata.SERVICE_BUS_POSTURE_UNCERTAINTIES] = uncertainties

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=first_non_empty(values.get("id"), namespace_reference, resource.address),
        metadata=metadata,
    )


def normalize_servicebus_namespace_customer_managed_key(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    namespace_reference = known_string(
        values,
        resource.unknown_values,
        "namespace_id",
        uncertainties,
        require_string=True,
    )
    key_vault_key_id = known_string(
        values,
        resource.unknown_values,
        "key_vault_key_id",
        uncertainties,
        require_string=True,
    )
    cmk_state = STATE_CONFIGURED if key_vault_key_id else STATE_UNKNOWN
    if key_vault_key_id is None and not uncertainties:
        uncertainties.append("key_vault_key_id is not represented in planned values")
    metadata: dict[Any, Any] = {
        AzureResourceMetadata.SERVICE_BUS_NAMESPACE_REFERENCE: namespace_reference,
        AzureResourceMetadata.SERVICE_BUS_CUSTOMER_MANAGED_KEY_STATE: cmk_state,
        AzureResourceMetadata.SERVICE_BUS_KEY_VAULT_KEY_ID: key_vault_key_id,
        AzureResourceMetadata.SERVICE_BUS_CUSTOMER_MANAGED_KEY_SOURCE_ADDRESS: resource.address,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.SERVICE_BUS_POSTURE_UNCERTAINTIES] = uncertainties

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=first_non_empty(values.get("id"), namespace_reference, resource.address),
        data_sensitivity="sensitive",
        metadata=metadata,
    )


def _inline_network_rule_posture(
    resource: TerraformResource,
    values: Mapping[str, Any],
    uncertainties: list[str],
) -> tuple[str | None, str | None]:
    network_rule_set = first_mapping(values.get("network_rule_set"))
    if network_rule_set is None:
        return None, None
    if first_block_attribute_unknown(resource.unknown_values, "network_rule_set", "default_action"):
        uncertainties.append("network_rule_set.default_action is unknown after planning")
        return None, resource.address

    default_action = first_non_empty(network_rule_set.get("default_action"))
    if default_action is None:
        uncertainties.append("network_rule_set.default_action is not represented in planned values")
    return default_action, resource.address


def _inline_cmk_posture(
    resource: TerraformResource,
    values: Mapping[str, Any],
    uncertainties: list[str],
) -> tuple[str, str | None, str | None]:
    customer_managed_key = first_mapping(values.get("customer_managed_key"))
    if customer_managed_key is None:
        return STATE_NOT_CONFIGURED, None, None
    if first_block_attribute_unknown(resource.unknown_values, "customer_managed_key", "key_vault_key_id"):
        uncertainties.append("customer_managed_key.key_vault_key_id is unknown after planning")
        return STATE_UNKNOWN, None, resource.address

    key_vault_key_id = first_non_empty(
        customer_managed_key.get("key_vault_key_id"),
        customer_managed_key.get("key_vault_key_uri"),
    )
    if key_vault_key_id is None:
        uncertainties.append("customer_managed_key.key_vault_key_id is not represented in planned values")
        return STATE_UNKNOWN, None, resource.address
    return STATE_CONFIGURED, key_vault_key_id, resource.address
