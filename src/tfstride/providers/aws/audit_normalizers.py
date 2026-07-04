from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.network_normalizers import AWS_PROVIDER
from tfstride.providers.coercion import (
    as_list,
    attribute_unknown,
    compact_strings,
    first_mapping,
    known_string,
)

_STATE_ENABLED = "enabled"
_STATE_DISABLED = "disabled"
_STATE_UNKNOWN = "unknown"


def normalize_cloudtrail(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    name = known_string(values, unknown_values, "name", uncertainties) or resource.name

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=known_string(values, unknown_values, "id", uncertainties) or name,
        arn=known_string(values, unknown_values, "arn", uncertainties),
        metadata={
            AwsResourceMetadata.NAME: name,
            AwsResourceMetadata.CLOUDTRAIL_S3_BUCKET_NAME: known_string(
                values,
                unknown_values,
                "s3_bucket_name",
                uncertainties,
            ),
            AwsResourceMetadata.CLOUDTRAIL_S3_KEY_PREFIX: known_string(
                values,
                unknown_values,
                "s3_key_prefix",
                uncertainties,
            ),
            AwsResourceMetadata.CLOUDTRAIL_KMS_KEY_ID: known_string(
                values, unknown_values, "kms_key_id", uncertainties
            ),
            AwsResourceMetadata.CLOUDTRAIL_CLOUDWATCH_LOGS_GROUP_ARN: known_string(
                values,
                unknown_values,
                "cloud_watch_logs_group_arn",
                uncertainties,
            ),
            AwsResourceMetadata.CLOUDTRAIL_CLOUDWATCH_LOGS_ROLE_ARN: known_string(
                values,
                unknown_values,
                "cloud_watch_logs_role_arn",
                uncertainties,
            ),
            AwsResourceMetadata.CLOUDTRAIL_ENABLE_LOGGING_STATE: _known_bool_state(
                values,
                unknown_values,
                "enable_logging",
                uncertainties,
            ),
            AwsResourceMetadata.CLOUDTRAIL_LOG_FILE_VALIDATION_STATE: _known_bool_state(
                values,
                unknown_values,
                "enable_log_file_validation",
                uncertainties,
            ),
            AwsResourceMetadata.CLOUDTRAIL_MULTI_REGION_STATE: _known_bool_state(
                values,
                unknown_values,
                "is_multi_region_trail",
                uncertainties,
            ),
            AwsResourceMetadata.CLOUDTRAIL_GLOBAL_SERVICE_EVENTS_STATE: _known_bool_state(
                values,
                unknown_values,
                "include_global_service_events",
                uncertainties,
            ),
            AwsResourceMetadata.CLOUDTRAIL_ORGANIZATION_TRAIL_STATE: _known_bool_state(
                values,
                unknown_values,
                "is_organization_trail",
                uncertainties,
            ),
            AwsResourceMetadata.CLOUDTRAIL_EVENT_SELECTORS: _known_dict_records(
                values,
                unknown_values,
                "event_selector",
                uncertainties,
            ),
            AwsResourceMetadata.CLOUDTRAIL_INSIGHT_SELECTORS: _insight_selector_types(
                values,
                unknown_values,
                uncertainties,
            ),
            AwsResourceMetadata.AUDIT_DETECTION_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_guardduty_detector(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=known_string(values, unknown_values, "id", uncertainties) or resource.address,
        metadata={
            AwsResourceMetadata.GUARDDUTY_ENABLE_STATE: _known_bool_state(
                values,
                unknown_values,
                "enable",
                uncertainties,
            ),
            AwsResourceMetadata.GUARDDUTY_FINDING_PUBLISHING_FREQUENCY: known_string(
                values,
                unknown_values,
                "finding_publishing_frequency",
                uncertainties,
            ),
            AwsResourceMetadata.GUARDDUTY_DATASOURCES: _known_first_record(
                values,
                unknown_values,
                "datasources",
                uncertainties,
            ),
            AwsResourceMetadata.GUARDDUTY_FEATURES: _known_dict_records(
                values,
                unknown_values,
                "features",
                uncertainties,
            ),
            AwsResourceMetadata.AUDIT_DETECTION_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_securityhub_account(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=known_string(values, unknown_values, "id", uncertainties) or resource.address,
        metadata={
            AwsResourceMetadata.SECURITYHUB_ENABLE_DEFAULT_STANDARDS_STATE: _known_bool_state(
                values,
                unknown_values,
                "enable_default_standards",
                uncertainties,
            ),
            AwsResourceMetadata.SECURITYHUB_AUTO_ENABLE_CONTROLS_STATE: _known_bool_state(
                values,
                unknown_values,
                "auto_enable_controls",
                uncertainties,
            ),
            AwsResourceMetadata.SECURITYHUB_CONTROL_FINDING_GENERATOR: known_string(
                values,
                unknown_values,
                "control_finding_generator",
                uncertainties,
            ),
            AwsResourceMetadata.AUDIT_DETECTION_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_config_configuration_recorder(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    recording_group = first_mapping(values.get("recording_group"), scan_all=True)
    unknown_recording_group = first_mapping(unknown_values.get("recording_group"), scan_all=True)
    recording_strategy = first_mapping(values.get("recording_strategy"), scan_all=True)
    unknown_recording_strategy = first_mapping(unknown_values.get("recording_strategy"), scan_all=True)
    name = known_string(values, unknown_values, "name", uncertainties) or resource.name

    if unknown_values.get("recording_group") is True:
        uncertainties.append("recording_group is unknown after planning")
    if unknown_values.get("recording_strategy") is True:
        uncertainties.append("recording_strategy is unknown after planning")

    return NormalizedResource(
        address=resource.address,
        provider=AWS_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=known_string(values, unknown_values, "id", uncertainties) or name,
        metadata={
            AwsResourceMetadata.CONFIG_RECORDER_NAME: name,
            AwsResourceMetadata.CONFIG_RECORDER_ROLE_ARN: known_string(
                values, unknown_values, "role_arn", uncertainties
            ),
            AwsResourceMetadata.CONFIG_RECORDER_ALL_SUPPORTED_STATE: _known_block_bool_state(
                recording_group,
                unknown_recording_group,
                "all_supported",
                uncertainties,
                path="recording_group",
            ),
            AwsResourceMetadata.CONFIG_RECORDER_INCLUDE_GLOBAL_RESOURCE_TYPES_STATE: _known_block_bool_state(
                recording_group,
                unknown_recording_group,
                "include_global_resource_types",
                uncertainties,
                path="recording_group",
            ),
            AwsResourceMetadata.CONFIG_RECORDER_RESOURCE_TYPES: _known_block_string_list(
                recording_group,
                unknown_recording_group,
                "resource_types",
                uncertainties,
                path="recording_group",
            ),
            AwsResourceMetadata.CONFIG_RECORDER_RECORDING_STRATEGY_USE_ONLY: _known_block_string(
                recording_strategy,
                unknown_recording_strategy,
                "use_only",
                uncertainties,
                path="recording_strategy",
            ),
            AwsResourceMetadata.CONFIG_RECORDER_RECORDING_GROUP: dict(recording_group) if recording_group else {},
            AwsResourceMetadata.CONFIG_RECORDER_RECORDING_STRATEGY: dict(recording_strategy)
            if recording_strategy
            else {},
            AwsResourceMetadata.AUDIT_DETECTION_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )


def _known_bool_state(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    key: str,
    uncertainties: list[str],
) -> str | None:
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{key} is unknown after planning")
        return _STATE_UNKNOWN
    value = values.get(key)
    if value is None:
        return None
    if isinstance(value, bool):
        return _STATE_ENABLED if value else _STATE_DISABLED
    uncertainties.append(f"{key} has an unrecognized value shape")
    return None


def _known_block_bool_state(
    values: Mapping[str, Any] | None,
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
) -> str | None:
    if attribute_unknown(unknown_values or {}, key):
        uncertainties.append(f"{path}.{key} is unknown after planning")
        return _STATE_UNKNOWN
    value = values.get(key) if values else None
    if value is None:
        return None
    if isinstance(value, bool):
        return _STATE_ENABLED if value else _STATE_DISABLED
    uncertainties.append(f"{path}.{key} has an unrecognized value shape")
    return None


def _known_block_string(
    values: Mapping[str, Any] | None,
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
) -> str | None:
    if attribute_unknown(unknown_values or {}, key):
        uncertainties.append(f"{path}.{key} is unknown after planning")
        return None
    raw = values.get(key) if values else None
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None


def _known_block_string_list(
    values: Mapping[str, Any] | None,
    unknown_values: Mapping[str, Any] | None,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
) -> list[str]:
    if attribute_unknown(unknown_values or {}, key):
        uncertainties.append(f"{path}.{key} is unknown after planning")
        return []
    return compact_strings(as_list(values.get(key) if values else []))


def _known_first_record(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    key: str,
    uncertainties: list[str],
) -> dict[str, Any]:
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{key} is unknown after planning")
        return {}
    record = first_mapping(values.get(key), scan_all=True)
    return deepcopy(dict(record)) if record else {}


def _known_dict_records(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    key: str,
    uncertainties: list[str],
) -> list[dict[str, Any]]:
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{key} is unknown after planning")
        return []
    records: list[dict[str, Any]] = []
    for item in as_list(values.get(key)):
        if isinstance(item, Mapping):
            records.append(deepcopy(dict(item)))
    return records


def _insight_selector_types(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    uncertainties: list[str],
) -> list[str]:
    records = _known_dict_records(values, unknown_values, "insight_selector", uncertainties)
    return compact_strings(record.get("insight_type") for record in records)
