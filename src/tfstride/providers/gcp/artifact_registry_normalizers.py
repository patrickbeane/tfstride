from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_DISABLED,
    STATE_ENABLED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
    known_block_bool,
    known_block_string,
    value_is_unknown,
)
from tfstride.providers.gcp.attributes import GcpAttr, GcpValues
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_identifier, resource_name
from tfstride.providers.kubernetes import first_unknown_block


def normalize_artifact_registry_repository(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    uncertainties: list[str] = []
    format_value = _known_string(values, resource.unknown_values, GcpAttr.FORMAT, uncertainties)
    repository_id = _known_string(values, resource.unknown_values, GcpAttr.REPOSITORY_ID, uncertainties)
    project = _known_string(values, resource.unknown_values, GcpAttr.PROJECT, uncertainties)
    location = _known_string(values, resource.unknown_values, GcpAttr.LOCATION, uncertainties)
    mode = _known_string(values, resource.unknown_values, GcpAttr.MODE, uncertainties)
    kms_key_name = _known_string(values, resource.unknown_values, GcpAttr.KMS_KEY_NAME, uncertainties)

    docker_config = _first_mapping(values.raw(GcpAttr.DOCKER_CONFIG))
    unknown_docker_config = first_unknown_block(resource.unknown_values.get(GcpAttr.DOCKER_CONFIG.key))
    docker_immutable_state = _docker_immutable_tags_state(
        format_value,
        docker_config,
        unknown_docker_config,
        uncertainties,
    )

    vulnerability_config = _first_mapping(values.raw(GcpAttr.VULNERABILITY_SCANNING_CONFIG))
    unknown_vulnerability_config = first_unknown_block(
        resource.unknown_values.get(GcpAttr.VULNERABILITY_SCANNING_CONFIG.key)
    )
    vulnerability_enablement_config, vulnerability_enablement_state, vulnerability_state = (
        _vulnerability_scanning_posture(
            vulnerability_config,
            unknown_vulnerability_config,
            uncertainties,
        )
    )

    cleanup_policies, cleanup_policy_state = _cleanup_policy_posture(
        values.raw(GcpAttr.CLEANUP_POLICIES),
        resource.unknown_values.get(GcpAttr.CLEANUP_POLICIES.key),
        uncertainties,
    )
    cleanup_dry_run_state = _top_level_bool_state(
        values,
        resource.unknown_values,
        GcpAttr.CLEANUP_POLICY_DRY_RUN,
        uncertainties,
    )
    deletion_policy = _known_string(values, resource.unknown_values, GcpAttr.DELETION_POLICY, uncertainties)
    deletion_policy_state = _known_configuration_state(
        values,
        resource.unknown_values,
        GcpAttr.DELETION_POLICY,
        deletion_policy,
        uncertainties,
    )

    normalized = NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=resource_identifier(resource),
        data_sensitivity="sensitive",
        metadata={
            GcpResourceMetadata.NAME: resource_name(resource),
            GcpResourceMetadata.PROJECT: project,
            GcpResourceMetadata.REGION: location,
            GcpResourceMetadata.LABELS: values.get(GcpAttr.LABELS),
            GcpResourceMetadata.ARTIFACT_REGISTRY_REPOSITORY_ID: repository_id,
            GcpResourceMetadata.ARTIFACT_REGISTRY_REPOSITORY_PATH: _artifact_registry_repository_path(
                project, location, repository_id
            ),
            GcpResourceMetadata.ARTIFACT_REGISTRY_FORMAT: format_value,
            GcpResourceMetadata.ARTIFACT_REGISTRY_MODE: mode,
            GcpResourceMetadata.ARTIFACT_REGISTRY_KMS_KEY_NAME: kms_key_name,
            GcpResourceMetadata.ARTIFACT_REGISTRY_ENCRYPTION_STATE: _encryption_state(
                kms_key_name,
                resource.unknown_values,
            ),
            GcpResourceMetadata.ARTIFACT_REGISTRY_DOCKER_IMMUTABLE_TAGS_STATE: docker_immutable_state,
            GcpResourceMetadata.ARTIFACT_REGISTRY_DOCKER_CONFIG: dict(docker_config) if docker_config else None,
            GcpResourceMetadata.ARTIFACT_REGISTRY_VULNERABILITY_SCANNING_ENABLEMENT_CONFIG: (
                vulnerability_enablement_config
            ),
            GcpResourceMetadata.ARTIFACT_REGISTRY_VULNERABILITY_SCANNING_ENABLEMENT_STATE: (
                vulnerability_enablement_state
            ),
            GcpResourceMetadata.ARTIFACT_REGISTRY_VULNERABILITY_SCANNING_STATE: vulnerability_state,
            GcpResourceMetadata.ARTIFACT_REGISTRY_VULNERABILITY_SCANNING_STATE_REASON: _known_block_string(
                vulnerability_config,
                unknown_vulnerability_config,
                GcpAttr.ENABLEMENT_STATE_REASON,
                uncertainties,
                "vulnerability_scanning_config",
            ),
            GcpResourceMetadata.ARTIFACT_REGISTRY_VULNERABILITY_SCANNING_CONFIG: (
                dict(vulnerability_config) if vulnerability_config else None
            ),
            GcpResourceMetadata.ARTIFACT_REGISTRY_CLEANUP_POLICIES: cleanup_policies,
            GcpResourceMetadata.ARTIFACT_REGISTRY_CLEANUP_POLICY_STATE: cleanup_policy_state,
            GcpResourceMetadata.ARTIFACT_REGISTRY_CLEANUP_POLICY_DRY_RUN_STATE: cleanup_dry_run_state,
            GcpResourceMetadata.ARTIFACT_REGISTRY_DELETION_POLICY: deletion_policy,
            GcpResourceMetadata.ARTIFACT_REGISTRY_DELETION_POLICY_STATE: deletion_policy_state,
            GcpResourceMetadata.ARTIFACT_REGISTRY_POSTURE_UNCERTAINTIES: uncertainties,
        },
    )
    gcp_mutations(normalized).set_storage_encrypted(True)
    return normalized


def _artifact_registry_repository_path(
    project: str | None,
    location: str | None,
    repository_id: str | None,
) -> str | None:
    if not project or not location or not repository_id:
        return None
    return f"projects/{project}/locations/{location}/repositories/{repository_id}"


def _known_string(
    values: GcpValues,
    unknown_values: Mapping[str, Any],
    attribute: Any,
    uncertainties: list[str],
) -> str | None:
    if value_is_unknown(unknown_values.get(attribute.key)):
        uncertainties.append(f"{attribute.key} is unknown after planning")
        return None
    raw_value = values.raw(attribute)
    if raw_value is None:
        return None
    if not isinstance(raw_value, str):
        uncertainties.append(f"{attribute.key} has an unrecognized value shape")
        return None
    return first_non_empty(raw_value)


def _known_block_string(
    values: Mapping[str, Any] | None,
    unknown_values: Any,
    attribute: Any,
    uncertainties: list[str],
    path: str,
) -> str | None:
    return known_block_string(
        values,
        unknown_values,
        attribute.key,
        uncertainties,
        path=path,
    )


def _known_bool(
    values: GcpValues,
    unknown_values: Mapping[str, Any],
    attribute: Any,
    uncertainties: list[str],
) -> bool | None:
    if value_is_unknown(unknown_values.get(attribute.key)):
        uncertainties.append(f"{attribute.key} is unknown after planning")
        return None
    if not values.has(attribute):
        return None
    raw_value = values.raw(attribute)
    if isinstance(raw_value, bool):
        return raw_value
    uncertainties.append(f"{attribute.key} has an unrecognized value shape")
    return None


def _top_level_bool_state(
    values: GcpValues,
    unknown_values: Mapping[str, Any],
    attribute: Any,
    uncertainties: list[str],
) -> str:
    if value_is_unknown(unknown_values.get(attribute.key)):
        uncertainties.append(f"{attribute.key} is unknown after planning")
        return STATE_UNKNOWN
    if not values.has(attribute):
        return STATE_NOT_CONFIGURED
    value = _known_bool(values, unknown_values, attribute, uncertainties)
    if value is True:
        return STATE_ENABLED
    if value is False:
        return STATE_DISABLED
    return STATE_UNKNOWN


def _known_configuration_state(
    values: GcpValues,
    unknown_values: Mapping[str, Any],
    attribute: Any,
    known_value: str | None,
    uncertainties: list[str],
) -> str:
    if value_is_unknown(unknown_values.get(attribute.key)):
        uncertainties.append(f"{attribute.key} is unknown after planning")
        return STATE_UNKNOWN
    if not values.has(attribute):
        return STATE_NOT_CONFIGURED
    return STATE_CONFIGURED if known_value else STATE_UNKNOWN


def _encryption_state(
    kms_key_name: str | None,
    unknown_values: Mapping[str, Any],
) -> str:
    if value_is_unknown(unknown_values.get(GcpAttr.KMS_KEY_NAME.key)):
        return STATE_UNKNOWN
    if kms_key_name:
        return STATE_CONFIGURED
    return STATE_NOT_CONFIGURED


def _docker_immutable_tags_state(
    format_value: str | None,
    docker_config: Mapping[str, Any] | None,
    unknown_docker_config: Any,
    uncertainties: list[str],
) -> str:
    normalized_format = format_value.strip().upper() if format_value else None
    if normalized_format is not None and normalized_format != "DOCKER":
        return "not_applicable"
    if unknown_docker_config is True and docker_config is None:
        uncertainties.append("docker_config is unknown after planning")
        return STATE_UNKNOWN
    if docker_config is None:
        return STATE_UNKNOWN if normalized_format is None else STATE_NOT_CONFIGURED
    value = known_block_bool(
        docker_config,
        unknown_docker_config,
        GcpAttr.IMMUTABLE_TAGS.key,
        uncertainties,
        path=GcpAttr.DOCKER_CONFIG.key,
    )
    if value is True:
        return STATE_ENABLED
    if value is False:
        return STATE_DISABLED
    return STATE_UNKNOWN


def _vulnerability_scanning_posture(
    config: Mapping[str, Any] | None,
    unknown_config: Any,
    uncertainties: list[str],
) -> tuple[str | None, str | None, str]:
    if unknown_config is True and config is None:
        uncertainties.append("vulnerability_scanning_config is unknown after planning")
        return None, None, STATE_UNKNOWN
    if config is None:
        return None, None, STATE_NOT_CONFIGURED

    enablement_config = _known_block_string(
        config,
        unknown_config,
        GcpAttr.ENABLEMENT_CONFIG,
        uncertainties,
        GcpAttr.VULNERABILITY_SCANNING_CONFIG.key,
    )
    enablement_state = _known_block_string(
        config,
        unknown_config,
        GcpAttr.ENABLEMENT_STATE,
        uncertainties,
        GcpAttr.VULNERABILITY_SCANNING_CONFIG.key,
    )
    normalized_config = enablement_config.strip().upper() if enablement_config else None
    normalized_state = enablement_state.strip().upper() if enablement_state else None
    if normalized_config == "DISABLED" or normalized_state in {"DISABLED", "SCANNING_DISABLED"}:
        state = STATE_DISABLED
    elif normalized_state in {"ENABLED", "SCANNING", "SCANNING_ENABLED", "ACTIVE"}:
        state = STATE_ENABLED
    else:
        state = STATE_UNKNOWN
    return enablement_config, enablement_state, state


def _cleanup_policy_posture(
    value: Any,
    unknown_value: Any,
    uncertainties: list[str],
) -> tuple[list[dict[str, Any]], str]:
    if value_is_unknown(unknown_value):
        uncertainties.append("cleanup_policies is unknown after planning")
        return [], STATE_UNKNOWN
    if value is None:
        return [], STATE_NOT_CONFIGURED
    if not isinstance(value, list):
        uncertainties.append("cleanup_policies has an unrecognized value shape")
        return [], STATE_UNKNOWN
    policies = [dict(item) for item in value if isinstance(item, Mapping)]
    if len(policies) != len(value):
        uncertainties.append("cleanup_policies has an unrecognized value shape")
    return policies, STATE_CONFIGURED if policies else STATE_NOT_CONFIGURED


def _first_mapping(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, list):
        for item in value:
            if isinstance(item, Mapping):
                return item
    return None
