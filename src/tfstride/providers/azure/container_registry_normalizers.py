from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.container_registry_references import normalize_container_registry_login_server
from tfstride.providers.azure.identity_normalizers import managed_identity_metadata
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.public_network import public_network_fallback_state
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_utils import (
    as_list,
    as_optional_int,
    attribute_unknown,
    first_mapping,
    known_block_bool,
    known_block_int,
    known_block_string,
    known_bool,
    known_string,
    unknown_block_at,
)
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
    bool_state,
)

AZURE_PROVIDER = "azure"
_STATE_NOT_APPLICABLE = "not_applicable"


def normalize_container_registry(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    registry_id = known_string(values, resource.unknown_values, "id", uncertainties, require_string=True)
    name = known_string(values, resource.unknown_values, "name", uncertainties, require_string=True) or resource.name
    sku = known_string(values, resource.unknown_values, "sku", uncertainties, require_string=True)
    raw_login_server = known_string(
        values,
        resource.unknown_values,
        "login_server",
        uncertainties,
        require_string=True,
    )
    login_server = normalize_container_registry_login_server(raw_login_server)
    if raw_login_server and login_server is None:
        uncertainties.append("login_server is unresolved")
    public_network_access_enabled = known_bool(
        values,
        resource.unknown_values,
        "public_network_access_enabled",
        uncertainties,
        allow_string=False,
    )
    admin_enabled = known_bool(
        values,
        resource.unknown_values,
        "admin_enabled",
        uncertainties,
        allow_string=False,
    )
    anonymous_pull_enabled = known_bool(
        values,
        resource.unknown_values,
        "anonymous_pull_enabled",
        uncertainties,
        allow_string=False,
    )
    network_rule_set, network_default_action = _network_rule_posture(resource, uncertainties)
    cmk_state, key_vault_key_id, encryption_identity_client_id, encryption = _encryption_posture(
        resource,
        uncertainties,
    )
    retention_state, retention_days = _retention_posture(resource, sku, uncertainties)

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: name,
        AzureResourceMetadata.LOCATION: known_string(
            values,
            resource.unknown_values,
            "location",
            uncertainties,
            require_string=True,
        ),
        AzureResourceMetadata.CONTAINER_REGISTRY_ID: registry_id,
        AzureResourceMetadata.CONTAINER_REGISTRY_SKU: sku,
        AzureResourceMetadata.CONTAINER_REGISTRY_LOGIN_SERVER: login_server,
        AzureResourceMetadata.CONTAINER_REGISTRY_PREMIUM_TIER_STATE: _premium_tier_state(sku),
        AzureResourceMetadata.PUBLIC_NETWORK_FALLBACK_STATE: public_network_fallback_state(
            public_network_access_enabled
        ),
        AzureResourceMetadata.CONTAINER_REGISTRY_ADMIN_STATE: bool_state(admin_enabled),
        AzureResourceMetadata.CONTAINER_REGISTRY_ANONYMOUS_PULL_STATE: bool_state(anonymous_pull_enabled),
        AzureResourceMetadata.CONTAINER_REGISTRY_CUSTOMER_MANAGED_KEY_STATE: cmk_state,
        AzureResourceMetadata.CONTAINER_REGISTRY_KEY_VAULT_KEY_ID: key_vault_key_id,
        AzureResourceMetadata.CONTAINER_REGISTRY_ENCRYPTION_IDENTITY_CLIENT_ID: encryption_identity_client_id,
        AzureResourceMetadata.CONTAINER_REGISTRY_RETENTION_STATE: retention_state,
        AzureResourceMetadata.CONTAINER_REGISTRY_RETENTION_DAYS: retention_days,
        AzureResourceMetadata.CONTAINER_REGISTRY_EXPORT_POLICY_STATE: _premium_bool_state(
            resource,
            sku,
            "export_policy_enabled",
            uncertainties,
        ),
        AzureResourceMetadata.CONTAINER_REGISTRY_QUARANTINE_POLICY_STATE: _premium_bool_state(
            resource,
            sku,
            "quarantine_policy_enabled",
            uncertainties,
        ),
        AzureResourceMetadata.CONTAINER_REGISTRY_TRUST_POLICY_STATE: _premium_bool_state(
            resource,
            sku,
            "trust_policy_enabled",
            uncertainties,
            legacy_block="trust_policy",
        ),
        AzureResourceMetadata.CONTAINER_REGISTRY_ZONE_REDUNDANCY_STATE: _premium_bool_state(
            resource,
            sku,
            "zone_redundancy_enabled",
            uncertainties,
        ),
        AzureResourceMetadata.CONTAINER_REGISTRY_DATA_ENDPOINT_STATE: _premium_bool_state(
            resource,
            sku,
            "data_endpoint_enabled",
            uncertainties,
        ),
        AzureResourceMetadata.CONTAINER_REGISTRY_NETWORK_RULE_BYPASS_OPTION: known_string(
            values,
            resource.unknown_values,
            "network_rule_bypass_option",
            uncertainties,
            require_string=True,
        ),
        AzureResourceMetadata.CONTAINER_REGISTRY_NETWORK_RULE_SET: network_rule_set,
        AzureResourceMetadata.CONTAINER_REGISTRY_ENCRYPTION_CONFIGURATION: encryption,
    }
    if public_network_access_enabled is not None:
        metadata[AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED] = public_network_access_enabled
    if network_default_action is not None:
        metadata[AzureResourceMetadata.NETWORK_DEFAULT_ACTION] = network_default_action
        metadata[AzureResourceMetadata.NETWORK_RULE_SOURCE_ADDRESS] = resource.address
    metadata.update(managed_identity_metadata(resource))
    if uncertainties:
        metadata[AzureResourceMetadata.CONTAINER_REGISTRY_POSTURE_UNCERTAINTIES] = uncertainties

    normalized = NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=registry_id or name or resource.address,
        data_sensitivity="sensitive",
        metadata=metadata,
    )
    azure_facts(normalized).set_storage_encrypted(True)
    return normalized


def _network_rule_posture(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[dict[str, Any], str | None]:
    values = resource.values
    raw_unknown = resource.unknown_values.get("network_rule_set")
    network_rule_set = first_mapping(values.get("network_rule_set"))
    if network_rule_set is None:
        if raw_unknown is True:
            uncertainties.append("network_rule_set is unknown after planning")
        return {}, None

    unknown_block = True if raw_unknown is True else unknown_block_at(raw_unknown, 0)
    default_action = known_block_string(
        network_rule_set,
        unknown_block,
        "default_action",
        uncertainties,
        path="network_rule_set",
    )
    ip_rules = _network_ip_rules(
        network_rule_set.get("ip_rule"),
        unknown_block.get("ip_rule") if isinstance(unknown_block, Mapping) else None,
        uncertainties,
    )
    record: dict[str, Any] = {"ip_rules": ip_rules}
    if default_action:
        record["default_action"] = default_action
    return record, default_action


def _network_ip_rules(value: Any, unknown_value: Any, uncertainties: list[str]) -> list[dict[str, str]]:
    if unknown_value is True:
        uncertainties.append("network_rule_set.ip_rule is unknown after planning")
        return []

    records: list[dict[str, str]] = []
    for index, item in enumerate(as_list(value)):
        if not isinstance(item, Mapping):
            uncertainties.append(f"network_rule_set.ip_rule[{index}] has an unrecognized value shape")
            continue
        unknown_item = unknown_block_at(unknown_value, index)
        action = known_block_string(
            item,
            unknown_item,
            "action",
            uncertainties,
            path=f"network_rule_set.ip_rule[{index}]",
        )
        ip_range = known_block_string(
            item,
            unknown_item,
            "ip_range",
            uncertainties,
            path=f"network_rule_set.ip_rule[{index}]",
        )
        record = {key: item_value for key, item_value in (("action", action), ("ip_range", ip_range)) if item_value}
        if record:
            records.append(record)
    return records


def _encryption_posture(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[str, str | None, str | None, dict[str, str]]:
    raw_unknown = resource.unknown_values.get("encryption")
    encryption = first_mapping(resource.values.get("encryption"))
    if encryption is None:
        if raw_unknown is True:
            uncertainties.append("encryption is unknown after planning")
            return STATE_UNKNOWN, None, None, {}
        return STATE_NOT_CONFIGURED, None, None, {}

    unknown_block = True if raw_unknown is True else unknown_block_at(raw_unknown, 0)
    key_vault_key_id = known_block_string(
        encryption,
        unknown_block,
        "key_vault_key_id",
        uncertainties,
        path="encryption",
    )
    identity_client_id = known_block_string(
        encryption,
        unknown_block,
        "identity_client_id",
        uncertainties,
        path="encryption",
    )
    if key_vault_key_id is None and not any("encryption.key_vault_key_id" in item for item in uncertainties):
        uncertainties.append("encryption.key_vault_key_id is not represented in planned values")
    record = {
        key: value
        for key, value in (
            ("key_vault_key_id", key_vault_key_id),
            ("identity_client_id", identity_client_id),
        )
        if value
    }
    return (STATE_CONFIGURED if key_vault_key_id else STATE_UNKNOWN), key_vault_key_id, identity_client_id, record


def _retention_posture(
    resource: TerraformResource,
    sku: str | None,
    uncertainties: list[str],
) -> tuple[str, int | None]:
    values = resource.values
    if "retention_policy_in_days" in values or attribute_unknown(resource.unknown_values, "retention_policy_in_days"):
        days = _known_int(resource, "retention_policy_in_days", uncertainties)
        return (STATE_CONFIGURED if days is not None else STATE_UNKNOWN), days

    raw_unknown = resource.unknown_values.get("retention_policy")
    retention_policy = first_mapping(values.get("retention_policy"))
    if retention_policy is None:
        if raw_unknown is True:
            uncertainties.append("retention_policy is unknown after planning")
            return STATE_UNKNOWN, None
        return (_STATE_NOT_APPLICABLE if _known_non_premium(sku) else STATE_UNKNOWN), None

    unknown_block = True if raw_unknown is True else unknown_block_at(raw_unknown, 0)
    enabled = known_block_bool(
        retention_policy,
        unknown_block,
        "enabled",
        uncertainties,
        path="retention_policy",
    )
    days = known_block_int(
        retention_policy,
        unknown_block,
        "days",
        uncertainties,
        path="retention_policy",
    )
    if enabled is True:
        return STATE_ENABLED, days
    if enabled is False:
        return STATE_DISABLED, days
    return (STATE_CONFIGURED if days is not None else STATE_UNKNOWN), days


def _premium_bool_state(
    resource: TerraformResource,
    sku: str | None,
    key: str,
    uncertainties: list[str],
    *,
    legacy_block: str | None = None,
) -> str:
    if key in resource.values or attribute_unknown(resource.unknown_values, key):
        value = known_bool(
            resource.values,
            resource.unknown_values,
            key,
            uncertainties,
            allow_string=False,
        )
        return bool_state(value)

    if legacy_block is not None:
        raw_unknown = resource.unknown_values.get(legacy_block)
        block = first_mapping(resource.values.get(legacy_block))
        if block is not None:
            unknown_block = True if raw_unknown is True else unknown_block_at(raw_unknown, 0)
            return bool_state(
                known_block_bool(
                    block,
                    unknown_block,
                    "enabled",
                    uncertainties,
                    path=legacy_block,
                )
            )
        if raw_unknown is True:
            uncertainties.append(f"{legacy_block} is unknown after planning")
            return STATE_UNKNOWN

    return _STATE_NOT_APPLICABLE if _known_non_premium(sku) else STATE_UNKNOWN


def _premium_tier_state(sku: str | None) -> str:
    if sku is None:
        return STATE_UNKNOWN
    return STATE_ENABLED if sku.strip().lower() == "premium" else STATE_DISABLED


def _known_non_premium(sku: str | None) -> bool:
    return bool(sku and sku.strip().lower() != "premium")


def _known_int(resource: TerraformResource, key: str, uncertainties: list[str]) -> int | None:
    if attribute_unknown(resource.unknown_values, key):
        uncertainties.append(f"{key} is unknown after planning")
        return None
    raw_value = resource.values.get(key)
    if raw_value is None:
        return None
    if isinstance(raw_value, bool):
        uncertainties.append(f"{key} has an unrecognized value shape")
        return None
    parsed = as_optional_int(raw_value)
    if parsed is None:
        uncertainties.append(f"{key} has an unrecognized value shape")
    return parsed
