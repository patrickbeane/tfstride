from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_utils import (
    as_list,
    block_attribute_unknown,
    first_non_empty,
    known_bool,
    known_string,
    value_is_unknown,
)

AZURE_PROVIDER = "azure"
_STATE_ENABLED = "enabled"
_STATE_DISABLED = "disabled"
_STATE_UNKNOWN = "unknown"


def normalize_monitor_diagnostic_setting(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    name = known_string(values, unknown_values, "name", uncertainties) or resource.name
    enabled_logs = _known_records(
        values,
        unknown_values,
        "enabled_log",
        uncertainties,
        tracked_fields=("category", "category_group"),
    )
    legacy_logs = _known_records(
        values,
        unknown_values,
        "log",
        uncertainties,
        tracked_fields=("category", "enabled"),
    )
    metrics = _known_records(
        values,
        unknown_values,
        "metric",
        uncertainties,
        tracked_fields=("category", "enabled"),
    )
    log_records = [*enabled_logs, *legacy_logs]

    return _audit_resource(
        resource,
        identifier=known_string(values, unknown_values, "id", uncertainties) or name,
        metadata={
            AzureResourceMetadata.NAME: name,
            AzureResourceMetadata.DIAGNOSTIC_SETTING_ID: known_string(values, unknown_values, "id", uncertainties),
            AzureResourceMetadata.DIAGNOSTIC_SETTING_NAME: name,
            AzureResourceMetadata.DIAGNOSTIC_TARGET_RESOURCE_ID: known_string(
                values,
                unknown_values,
                "target_resource_id",
                uncertainties,
            ),
            AzureResourceMetadata.DIAGNOSTIC_LOG_ANALYTICS_WORKSPACE_ID: known_string(
                values,
                unknown_values,
                "log_analytics_workspace_id",
                uncertainties,
            ),
            AzureResourceMetadata.DIAGNOSTIC_STORAGE_ACCOUNT_ID: known_string(
                values,
                unknown_values,
                "storage_account_id",
                uncertainties,
            ),
            AzureResourceMetadata.DIAGNOSTIC_EVENTHUB_AUTHORIZATION_RULE_ID: known_string(
                values,
                unknown_values,
                "eventhub_authorization_rule_id",
                uncertainties,
            ),
            AzureResourceMetadata.DIAGNOSTIC_EVENTHUB_NAME: known_string(
                values,
                unknown_values,
                "eventhub_name",
                uncertainties,
            ),
            AzureResourceMetadata.DIAGNOSTIC_MARKETPLACE_PARTNER_RESOURCE_ID: known_string(
                values,
                unknown_values,
                "marketplace_partner_resource_id",
                uncertainties,
            ),
            AzureResourceMetadata.DIAGNOSTIC_LOG_RECORDS: log_records,
            AzureResourceMetadata.DIAGNOSTIC_METRIC_RECORDS: metrics,
            AzureResourceMetadata.DIAGNOSTIC_ENABLED_LOG_CATEGORIES: _enabled_record_values(log_records, "category"),
            AzureResourceMetadata.DIAGNOSTIC_ENABLED_LOG_CATEGORY_GROUPS: _enabled_record_values(
                log_records,
                "category_group",
            ),
            AzureResourceMetadata.DIAGNOSTIC_METRIC_CATEGORIES: _enabled_record_values(metrics, "category"),
            AzureResourceMetadata.AZURE_SECURITY_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_security_center_subscription_pricing(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    resource_type = known_string(values, unknown_values, "resource_type", uncertainties)
    extensions = _known_records(
        values,
        unknown_values,
        "extension",
        uncertainties,
        tracked_fields=("name",),
    )

    return _audit_resource(
        resource,
        identifier=known_string(values, unknown_values, "id", uncertainties) or resource_type or resource.address,
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.DEFENDER_RESOURCE_TYPE: resource_type,
            AzureResourceMetadata.DEFENDER_PRICING_TIER: known_string(values, unknown_values, "tier", uncertainties),
            AzureResourceMetadata.DEFENDER_SUBPLAN: known_string(values, unknown_values, "subplan", uncertainties),
            AzureResourceMetadata.DEFENDER_EXTENSION_NAMES: _record_values(extensions, "name"),
            AzureResourceMetadata.DEFENDER_EXTENSIONS: extensions,
            AzureResourceMetadata.AZURE_SECURITY_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_security_center_auto_provisioning(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    return _audit_resource(
        resource,
        identifier=known_string(values, unknown_values, "id", uncertainties) or resource.address,
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.SECURITY_CENTER_AUTO_PROVISIONING_STATE: _known_on_off_state(
                values,
                unknown_values,
                "auto_provision",
                uncertainties,
            ),
            AzureResourceMetadata.AZURE_SECURITY_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_security_center_contact(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    email = known_string(values, unknown_values, "email", uncertainties)

    return _audit_resource(
        resource,
        identifier=known_string(values, unknown_values, "id", uncertainties) or email or resource.address,
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.SECURITY_CENTER_CONTACT_EMAIL: email,
            AzureResourceMetadata.SECURITY_CENTER_CONTACT_PHONE: known_string(
                values, unknown_values, "phone", uncertainties
            ),
            AzureResourceMetadata.SECURITY_CENTER_ALERT_NOTIFICATIONS_STATE: _known_on_off_state(
                values,
                unknown_values,
                "alert_notifications",
                uncertainties,
            ),
            AzureResourceMetadata.SECURITY_CENTER_ALERTS_TO_ADMINS_STATE: _known_on_off_state(
                values,
                unknown_values,
                "alerts_to_admins",
                uncertainties,
            ),
            AzureResourceMetadata.AZURE_SECURITY_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_security_center_workspace(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    scope = known_string(values, unknown_values, "scope", uncertainties)

    return _audit_resource(
        resource,
        identifier=known_string(values, unknown_values, "id", uncertainties) or scope or resource.address,
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.SECURITY_CENTER_WORKSPACE_SCOPE: scope,
            AzureResourceMetadata.SECURITY_CENTER_WORKSPACE_ID: known_string(
                values,
                unknown_values,
                "workspace_id",
                uncertainties,
            ),
            AzureResourceMetadata.AZURE_SECURITY_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_security_center_setting(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    setting_name = known_string(values, unknown_values, "setting_name", uncertainties) or first_non_empty(
        values.get("name"),
        resource.name,
    )

    return _audit_resource(
        resource,
        identifier=known_string(values, unknown_values, "id", uncertainties) or setting_name or resource.address,
        metadata={
            AzureResourceMetadata.NAME: setting_name,
            AzureResourceMetadata.SECURITY_CENTER_SETTING_NAME: setting_name,
            AzureResourceMetadata.SECURITY_CENTER_SETTING_STATE: _known_bool_state(
                values,
                unknown_values,
                "enabled",
                uncertainties,
            ),
            AzureResourceMetadata.AZURE_SECURITY_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_advanced_threat_protection(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    target_resource_id = known_string(values, unknown_values, "target_resource_id", uncertainties)

    return _audit_resource(
        resource,
        identifier=known_string(values, unknown_values, "id", uncertainties) or target_resource_id or resource.address,
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.ADVANCED_THREAT_PROTECTION_TARGET_RESOURCE_ID: target_resource_id,
            AzureResourceMetadata.ADVANCED_THREAT_PROTECTION_STATE: _known_bool_state(
                values,
                unknown_values,
                "enabled",
                uncertainties,
            ),
            AzureResourceMetadata.AZURE_SECURITY_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def _audit_resource(
    resource: TerraformResource,
    *,
    identifier: str | None,
    metadata: dict[Any, Any],
) -> NormalizedResource:
    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=identifier or resource.address,
        metadata=metadata,
    )


def _known_bool_state(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    key: str,
    uncertainties: list[str],
) -> str:
    value = known_bool(values, unknown_values, key, uncertainties, allow_string=False)
    if value is True:
        return _STATE_ENABLED
    if value is False:
        return _STATE_DISABLED
    return _STATE_UNKNOWN


def _known_on_off_state(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    key: str,
    uncertainties: list[str],
) -> str:
    if value_is_unknown(unknown_values.get(key)):
        uncertainties.append(f"{key} is unknown after planning")
        return _STATE_UNKNOWN
    raw = values.get(key)
    if raw is None:
        return _STATE_UNKNOWN
    normalized = str(raw).strip().lower()
    if normalized in {"on", "enabled", "true"}:
        return _STATE_ENABLED
    if normalized in {"off", "disabled", "false"}:
        return _STATE_DISABLED
    uncertainties.append(f"{key} has an unrecognized value shape")
    return _STATE_UNKNOWN


def _known_records(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    key: str,
    uncertainties: list[str],
    *,
    tracked_fields: tuple[str, ...],
) -> list[dict[str, Any]]:
    if unknown_values.get(key) is True:
        uncertainties.append(f"{key} is unknown after planning")
        return []
    records: list[dict[str, Any]] = []
    unknown_blocks = unknown_values.get(key)
    for index, item in enumerate(as_list(values.get(key))):
        if not isinstance(item, Mapping):
            if item not in (None, ""):
                uncertainties.append(f"{key}[{index}] has an unrecognized value shape")
            continue
        record = deepcopy(dict(item))
        unknown_block = _unknown_block_at(unknown_blocks, index)
        unknown_fields = [field for field in tracked_fields if block_attribute_unknown(unknown_block, field)]
        if unknown_fields:
            record["unknown_fields"] = unknown_fields
            for field in unknown_fields:
                uncertainties.append(f"{key}.{field} is unknown after planning")
        records.append(record)
    return records


def _unknown_block_at(value: Any, index: int) -> Any:
    if value is True:
        return True
    if isinstance(value, list) and index < len(value):
        return value[index]
    return None


def _record_values(records: list[dict[str, Any]], key: str) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for record in records:
        value = first_non_empty(record.get(key))
        if value is None or value in seen:
            continue
        values.append(value)
        seen.add(value)
    return values


def _enabled_record_values(records: list[dict[str, Any]], key: str) -> list[str]:
    enabled_records = [record for record in records if record.get("enabled") is not False]
    return _record_values(enabled_records, key)
