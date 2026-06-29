from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.identity_normalizers import managed_identity_metadata
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_utils import (
    as_list,
    first_mapping,
    first_non_empty,
    known_block_bool,
    known_block_string,
    known_block_strings,
    known_bool,
    known_string,
    value_is_unknown,
)

AZURE_PROVIDER = "azure"
_STATE_ENABLED = "enabled"
_STATE_DISABLED = "disabled"
_STATE_CONFIGURED = "configured"
_STATE_NOT_CONFIGURED = "not_configured"
_STATE_UNKNOWN = "unknown"


def normalize_kubernetes_cluster(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    cluster_id = known_string(values, resource.unknown_values, "id", uncertainties)
    api_server_profile = first_mapping(values.get("api_server_access_profile"))
    api_server_unknown = _first_unknown_block(resource.unknown_values.get("api_server_access_profile"))
    aad_profile = first_mapping(values.get("azure_active_directory_role_based_access_control"))
    aad_unknown = _first_unknown_block(resource.unknown_values.get("azure_active_directory_role_based_access_control"))
    network_profile = first_mapping(values.get("network_profile"))
    network_unknown = _first_unknown_block(resource.unknown_values.get("network_profile"))
    kubelet_uncertainties: list[str] = []
    kubelet_identity = _kubelet_identities(resource, kubelet_uncertainties)
    kms_profile = first_mapping(values.get("key_management_service"))
    kms_unknown = _first_unknown_block(resource.unknown_values.get("key_management_service"))
    oms_agent = first_mapping(values.get("oms_agent"))
    oms_unknown = _first_unknown_block(resource.unknown_values.get("oms_agent"))
    defender_profile = _defender_profile(resource)
    identity_metadata = managed_identity_metadata(resource)
    identity_ids = identity_metadata.get(AzureResourceMetadata.ATTACHED_IDENTITY_REFERENCES, [])

    private_cluster_state = _bool_state(
        values,
        resource.unknown_values,
        "private_cluster_enabled",
        uncertainties,
    )
    authorized_ip_ranges = _authorized_ip_ranges(api_server_profile, api_server_unknown, uncertainties)
    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
        AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
        AzureResourceMetadata.AKS_CLUSTER_ID: cluster_id,
        AzureResourceMetadata.AKS_PRIVATE_CLUSTER_STATE: private_cluster_state,
        AzureResourceMetadata.AKS_PRIVATE_DNS_ZONE_ID: known_string(
            values,
            resource.unknown_values,
            "private_dns_zone_id",
            uncertainties,
        ),
        AzureResourceMetadata.AKS_AUTHORIZED_IP_RANGES: authorized_ip_ranges,
        AzureResourceMetadata.AKS_AUTHORIZED_IP_RANGES_STATE: _configured_state(
            authorized_ip_ranges, api_server_unknown, "authorized_ip_ranges"
        ),
        AzureResourceMetadata.AKS_API_SERVER_VNET_INTEGRATION_STATE: _block_bool_state(
            api_server_profile,
            api_server_unknown,
            "vnet_integration_enabled",
            uncertainties,
            path="api_server_access_profile",
        ),
        AzureResourceMetadata.AKS_API_SERVER_SUBNET_ID: known_block_string(
            api_server_profile,
            api_server_unknown,
            "subnet_id",
            uncertainties,
            path="api_server_access_profile",
        ),
        AzureResourceMetadata.AKS_LOCAL_ACCOUNT_STATE: _disabled_state(
            values,
            resource.unknown_values,
            "local_account_disabled",
            uncertainties,
        ),
        AzureResourceMetadata.AKS_RBAC_STATE: _bool_state(
            values,
            resource.unknown_values,
            "role_based_access_control_enabled",
            uncertainties,
        ),
        AzureResourceMetadata.AKS_AAD_RBAC_STATE: _block_config_state(aad_profile, aad_unknown),
        AzureResourceMetadata.AKS_AAD_MANAGED_STATE: _block_bool_state(
            aad_profile,
            aad_unknown,
            "managed",
            uncertainties,
            path="azure_active_directory_role_based_access_control",
        ),
        AzureResourceMetadata.AKS_AAD_AZURE_RBAC_STATE: _block_bool_state(
            aad_profile,
            aad_unknown,
            "azure_rbac_enabled",
            uncertainties,
            path="azure_active_directory_role_based_access_control",
        ),
        AzureResourceMetadata.AKS_AAD_ADMIN_GROUP_OBJECT_IDS: known_block_strings(
            aad_profile,
            aad_unknown,
            "admin_group_object_ids",
            uncertainties,
            path="azure_active_directory_role_based_access_control",
        ),
        AzureResourceMetadata.AKS_AAD_TENANT_ID: known_block_string(
            aad_profile,
            aad_unknown,
            "tenant_id",
            uncertainties,
            path="azure_active_directory_role_based_access_control",
        ),
        AzureResourceMetadata.AKS_OIDC_ISSUER_STATE: _bool_state(
            values,
            resource.unknown_values,
            "oidc_issuer_enabled",
            uncertainties,
        ),
        AzureResourceMetadata.AKS_WORKLOAD_IDENTITY_STATE: _bool_state(
            values,
            resource.unknown_values,
            "workload_identity_enabled",
            uncertainties,
        ),
        AzureResourceMetadata.AKS_NETWORK_PLUGIN: known_block_string(
            network_profile,
            network_unknown,
            "network_plugin",
            uncertainties,
            path="network_profile",
        ),
        AzureResourceMetadata.AKS_NETWORK_POLICY: known_block_string(
            network_profile,
            network_unknown,
            "network_policy",
            uncertainties,
            path="network_profile",
        ),
        AzureResourceMetadata.AKS_NETWORK_POLICY_STATE: _string_config_state(
            network_profile,
            network_unknown,
            "network_policy",
        ),
        AzureResourceMetadata.AKS_NETWORK_MODE: known_block_string(
            network_profile,
            network_unknown,
            "network_mode",
            uncertainties,
            path="network_profile",
        ),
        AzureResourceMetadata.AKS_OUTBOUND_TYPE: known_block_string(
            network_profile,
            network_unknown,
            "outbound_type",
            uncertainties,
            path="network_profile",
        ),
        AzureResourceMetadata.AKS_LOAD_BALANCER_SKU: known_block_string(
            network_profile,
            network_unknown,
            "load_balancer_sku",
            uncertainties,
            path="network_profile",
        ),
        AzureResourceMetadata.AKS_USER_ASSIGNED_IDENTITY_IDS: identity_ids,
        AzureResourceMetadata.AKS_KUBELET_IDENTITY_STATE: _record_state(
            kubelet_identity,
            resource.unknown_values.get("kubelet_identity"),
        ),
        AzureResourceMetadata.AKS_KUBELET_IDENTITIES: kubelet_identity,
        AzureResourceMetadata.AKS_KMS_STATE: _block_config_state(kms_profile, kms_unknown),
        AzureResourceMetadata.AKS_KMS_KEY_VAULT_KEY_ID: known_block_string(
            kms_profile,
            kms_unknown,
            "key_vault_key_id",
            uncertainties,
            path="key_management_service",
        ),
        AzureResourceMetadata.AKS_OMS_AGENT_STATE: _block_presence_state(oms_agent, oms_unknown),
        AzureResourceMetadata.AKS_LOG_ANALYTICS_WORKSPACE_ID: known_block_string(
            oms_agent,
            oms_unknown,
            "log_analytics_workspace_id",
            uncertainties,
            path="oms_agent",
        ),
        AzureResourceMetadata.AKS_DEFENDER_STATE: _block_presence_state(
            defender_profile,
            _defender_unknown(resource),
        ),
        AzureResourceMetadata.AKS_AZURE_POLICY_STATE: _bool_state(
            values,
            resource.unknown_values,
            "azure_policy_enabled",
            uncertainties,
        ),
        AzureResourceMetadata.AKS_KUBERNETES_VERSION: known_string(
            values,
            resource.unknown_values,
            "kubernetes_version",
            uncertainties,
        ),
        AzureResourceMetadata.AKS_AUTOMATIC_CHANNEL_UPGRADE: known_string(
            values,
            resource.unknown_values,
            "automatic_channel_upgrade",
            uncertainties,
        ),
        AzureResourceMetadata.AKS_MAINTENANCE_WINDOWS: _maintenance_windows(resource, uncertainties),
    }
    metadata.update(identity_metadata)
    combined_uncertainties = _dedupe([*uncertainties, *kubelet_uncertainties])
    if combined_uncertainties:
        metadata[AzureResourceMetadata.AKS_POSTURE_UNCERTAINTIES] = combined_uncertainties

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=cluster_id or first_non_empty(values.get("name"), resource.name, resource.address),
        public_access_configured=private_cluster_state == _STATE_DISABLED,
        metadata=metadata,
    )


def _bool_state(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    key: str,
    uncertainties: list[str],
) -> str:
    value = known_bool(values, unknown_values, key, uncertainties, allow_string=False)
    if value is None:
        return _STATE_UNKNOWN
    return _STATE_ENABLED if value else _STATE_DISABLED


def _disabled_state(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    key: str,
    uncertainties: list[str],
) -> str:
    value = known_bool(values, unknown_values, key, uncertainties, allow_string=False)
    if value is None:
        return _STATE_UNKNOWN
    return _STATE_DISABLED if value else _STATE_ENABLED


def _block_bool_state(
    block: Mapping[str, Any] | None,
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
) -> str:
    value = known_block_bool(block, unknown_block, key, uncertainties, path=path)
    if value is None:
        return _STATE_UNKNOWN
    return _STATE_ENABLED if value else _STATE_DISABLED


def _block_config_state(block: Mapping[str, Any] | None, unknown_block: Any) -> str:
    if unknown_block is True and block is None:
        return _STATE_UNKNOWN
    return _STATE_CONFIGURED if block else _STATE_NOT_CONFIGURED


def _block_presence_state(block: Mapping[str, Any] | None, unknown_block: Any) -> str:
    if unknown_block is True and block is None:
        return _STATE_UNKNOWN
    return _STATE_ENABLED if block else _STATE_NOT_CONFIGURED


def _record_state(records: list[dict[str, Any]], unknown_block: Any) -> str:
    if unknown_block is True and not records:
        return _STATE_UNKNOWN
    return _STATE_CONFIGURED if records else _STATE_NOT_CONFIGURED


def _configured_state(values: list[str], unknown_block: Any, key: str) -> str:
    if _block_field_unknown(unknown_block, key):
        return _STATE_UNKNOWN
    return _STATE_CONFIGURED if values else _STATE_NOT_CONFIGURED


def _string_config_state(block: Mapping[str, Any] | None, unknown_block: Any, key: str) -> str:
    if _block_field_unknown(unknown_block, key):
        return _STATE_UNKNOWN
    if block is None:
        return _STATE_UNKNOWN
    return _STATE_CONFIGURED if first_non_empty(block.get(key)) else _STATE_NOT_CONFIGURED


def _authorized_ip_ranges(
    api_server_profile: Mapping[str, Any] | None,
    api_server_unknown: Any,
    uncertainties: list[str],
) -> list[str]:
    return known_block_strings(
        api_server_profile,
        api_server_unknown,
        "authorized_ip_ranges",
        uncertainties,
        path="api_server_access_profile",
    )


def _kubelet_identities(resource: TerraformResource, uncertainties: list[str]) -> list[dict[str, Any]]:
    raw_unknown = resource.unknown_values.get("kubelet_identity")
    if raw_unknown is True and not resource.values.get("kubelet_identity"):
        uncertainties.append("kubelet_identity is unknown after planning")
        return []

    records: list[dict[str, Any]] = []
    for index, item in enumerate(as_list(resource.values.get("kubelet_identity"))):
        if not isinstance(item, Mapping):
            if item is not None:
                uncertainties.append(f"kubelet_identity[{index}] has an unrecognized value shape")
            continue
        path = f"kubelet_identity[{index}]"
        unknown_item = _unknown_block_at(raw_unknown, index)
        record: dict[str, Any] = {}
        for key in ("client_id", "object_id", "user_assigned_identity_id"):
            value = known_block_string(item, unknown_item, key, uncertainties, path=path)
            if value:
                record[key] = value
        records.append(record)
    return records


def _maintenance_windows(resource: TerraformResource, uncertainties: list[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for key in ("maintenance_window", "maintenance_window_auto_upgrade", "maintenance_window_node_os"):
        raw_unknown = resource.unknown_values.get(key)
        if raw_unknown is True and not resource.values.get(key):
            uncertainties.append(f"{key} is unknown after planning")
            continue
        for index, item in enumerate(as_list(resource.values.get(key))):
            if isinstance(item, Mapping):
                record = {"type": key}
                record.update(dict(item))
                records.append(record)
            elif item is not None:
                uncertainties.append(f"{key}[{index}] has an unrecognized value shape")
    return records


def _defender_profile(resource: TerraformResource) -> Mapping[str, Any] | None:
    direct = first_mapping(resource.values.get("microsoft_defender"))
    if direct is not None:
        return direct
    security_profile = first_mapping(resource.values.get("security_profile"))
    if security_profile is None:
        return None
    defender = first_mapping(security_profile.get("defender"))
    return defender or security_profile


def _defender_unknown(resource: TerraformResource) -> Any:
    if resource.unknown_values.get("microsoft_defender") is True:
        return True
    security_unknown = _first_unknown_block(resource.unknown_values.get("security_profile"))
    if security_unknown is True:
        return True
    if isinstance(security_unknown, Mapping) and value_is_unknown(security_unknown.get("defender")):
        return True
    return None


def _first_unknown_block(value: Any) -> Any:
    if value is True:
        return True
    if isinstance(value, list) and value:
        return value[0]
    if isinstance(value, Mapping):
        return value
    return None


def _unknown_block_at(value: Any, index: int) -> Any:
    if value is True:
        return True
    if isinstance(value, list) and index < len(value):
        return value[index]
    if isinstance(value, Mapping) and index == 0:
        return value
    return None


def _block_field_unknown(unknown_block: Any, key: str) -> bool:
    if unknown_block is True:
        return True
    if isinstance(unknown_block, Mapping):
        return value_is_unknown(unknown_block.get(key))
    return False


def _dedupe(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        deduped.append(value)
        seen.add(value)
    return deduped
