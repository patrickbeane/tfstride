from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.network_normalizers.core import _known_int, _network_resource
from tfstride.providers.azure.resource_utils import (
    bool_state,
    first_mapping,
    first_non_empty,
    known_block_bool,
    known_block_int,
    known_block_string,
    known_bool,
    known_string,
    unknown_block_at,
)
from tfstride.providers.coercion import (
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
)


def normalize_network_watcher_flow_log(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    flow_log_id = known_string(values, unknown_values, "id", uncertainties, path="id")
    name = known_string(values, unknown_values, "name", uncertainties, path="name") or resource.name
    network_security_group_id = known_string(
        values,
        unknown_values,
        "network_security_group_id",
        uncertainties,
        path="network_security_group_id",
    )
    target_resource_id = known_string(
        values,
        unknown_values,
        "target_resource_id",
        uncertainties,
        path="target_resource_id",
    )
    target_id = first_non_empty(network_security_group_id, target_resource_id)
    location = known_string(values, unknown_values, "location", uncertainties)
    enabled = known_bool(values, unknown_values, "enabled", uncertainties, path="enabled")
    storage_account_id = known_string(
        values,
        unknown_values,
        "storage_account_id",
        uncertainties,
        path="storage_account_id",
    )
    network_watcher_name = known_string(
        values,
        unknown_values,
        "network_watcher_name",
        uncertainties,
        path="network_watcher_name",
    )
    resource_group_name = known_string(
        values,
        unknown_values,
        "resource_group_name",
        uncertainties,
        path="resource_group_name",
    )
    version = _known_int(values, unknown_values, "version", uncertainties)
    retention_policy, retention_state, retention_days = _flow_log_retention_policy(resource, uncertainties)
    traffic_analytics, traffic_analytics_state = _flow_log_traffic_analytics(resource, uncertainties)

    return _network_resource(
        resource,
        identifier=first_non_empty(flow_log_id, name, target_id, resource.address),
        security_group_ids=tuple([target_id] if target_id else []),
        metadata={
            AzureResourceMetadata.NAME: name,
            AzureResourceMetadata.LOCATION: location,
            AzureResourceMetadata.NETWORK_FLOW_LOG_ID: flow_log_id,
            AzureResourceMetadata.NETWORK_FLOW_LOG_NAME: name,
            AzureResourceMetadata.NETWORK_FLOW_LOG_STATE: bool_state(enabled),
            AzureResourceMetadata.NETWORK_FLOW_LOG_TARGET_RESOURCE_ID: target_id,
            AzureResourceMetadata.NETWORK_FLOW_LOG_NETWORK_SECURITY_GROUP_ID: network_security_group_id,
            AzureResourceMetadata.NETWORK_FLOW_LOG_STORAGE_ACCOUNT_ID: storage_account_id,
            AzureResourceMetadata.NETWORK_FLOW_LOG_NETWORK_WATCHER_NAME: network_watcher_name,
            AzureResourceMetadata.NETWORK_FLOW_LOG_RESOURCE_GROUP_NAME: resource_group_name,
            AzureResourceMetadata.NETWORK_FLOW_LOG_VERSION: version,
            AzureResourceMetadata.NETWORK_FLOW_LOG_RETENTION_STATE: retention_state,
            AzureResourceMetadata.NETWORK_FLOW_LOG_RETENTION_DAYS: retention_days,
            AzureResourceMetadata.NETWORK_FLOW_LOG_RETENTION_POLICY: retention_policy,
            AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS_STATE: traffic_analytics_state,
            AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS_WORKSPACE_ID: traffic_analytics.get(
                "workspace_id"
            ),
            AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS_WORKSPACE_REGION: traffic_analytics.get(
                "workspace_region"
            ),
            AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS_WORKSPACE_RESOURCE_ID: traffic_analytics.get(
                "workspace_resource_id"
            ),
            AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS_INTERVAL_MINUTES: traffic_analytics.get(
                "interval_in_minutes"
            ),
            AzureResourceMetadata.NETWORK_FLOW_LOG_TRAFFIC_ANALYTICS: traffic_analytics,
            AzureResourceMetadata.NETWORK_TELEMETRY_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def _flow_log_retention_policy(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[dict[str, Any], str, int | None]:
    values = resource.values
    raw_unknown = resource.unknown_values.get("retention_policy")
    if raw_unknown is True and not values.get("retention_policy"):
        uncertainties.append("retention_policy is unknown after planning")
        return {}, STATE_UNKNOWN, None
    retention_policy = first_mapping(values.get("retention_policy"), expand_tuples=True)
    if retention_policy is None:
        if raw_unknown:
            uncertainties.append("retention_policy is unknown after planning")
            return {}, STATE_UNKNOWN, None
        return {}, STATE_NOT_CONFIGURED, None
    unknown_block = unknown_block_at(raw_unknown, 0)
    unknown_fields: list[str] = []
    enabled = known_block_bool(
        retention_policy,
        unknown_block,
        "enabled",
        uncertainties,
        path="retention_policy",
        unknown_fields=unknown_fields,
    )
    days = known_block_int(
        retention_policy,
        unknown_block,
        "days",
        uncertainties,
        path="retention_policy",
        unknown_fields=unknown_fields,
    )
    record: dict[str, Any] = {}
    if enabled is not None:
        record["enabled"] = enabled
    if days is not None:
        record["days"] = days
    if unknown_fields:
        record["unknown_fields"] = unknown_fields
    return record, bool_state(enabled), days


def _flow_log_traffic_analytics(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[dict[str, Any], str]:
    values = resource.values
    raw_unknown = resource.unknown_values.get("traffic_analytics")
    if raw_unknown is True and not values.get("traffic_analytics"):
        uncertainties.append("traffic_analytics is unknown after planning")
        return {}, STATE_UNKNOWN
    traffic_analytics = first_mapping(values.get("traffic_analytics"), expand_tuples=True)
    if traffic_analytics is None:
        if raw_unknown:
            uncertainties.append("traffic_analytics is unknown after planning")
            return {}, STATE_UNKNOWN
        return {}, STATE_NOT_CONFIGURED
    unknown_block = unknown_block_at(raw_unknown, 0)
    unknown_fields: list[str] = []
    enabled = known_block_bool(
        traffic_analytics,
        unknown_block,
        "enabled",
        uncertainties,
        path="traffic_analytics",
        unknown_fields=unknown_fields,
    )
    record: dict[str, Any] = {}
    if enabled is not None:
        record["enabled"] = enabled
    for field in ("workspace_id", "workspace_region", "workspace_resource_id"):
        value = known_block_string(
            traffic_analytics,
            unknown_block,
            field,
            uncertainties,
            path="traffic_analytics",
            unknown_fields=unknown_fields,
        )
        if value:
            record[field] = value
    interval = known_block_int(
        traffic_analytics,
        unknown_block,
        "interval_in_minutes",
        uncertainties,
        path="traffic_analytics",
        unknown_fields=unknown_fields,
    )
    if interval is not None:
        record["interval_in_minutes"] = interval
    if unknown_fields:
        record["unknown_fields"] = unknown_fields
    return record, bool_state(enabled)
