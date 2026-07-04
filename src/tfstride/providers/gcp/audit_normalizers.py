from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.coercion import (
    first_mapping,
    known_block_string,
    known_block_strings,
    known_bool,
    known_string,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_identifier, resource_name


def normalize_logging_project_sink(resource: TerraformResource) -> NormalizedResource:
    return _normalize_logging_sink(
        resource,
        scope_type="project",
        scope=first_non_empty(resource.values.get("project")),
    )


def normalize_logging_organization_sink(resource: TerraformResource) -> NormalizedResource:
    return _normalize_logging_sink(
        resource,
        scope_type="organization",
        scope=first_non_empty(
            resource.values.get("org_id"),
            resource.values.get("organization_id"),
            resource.values.get("organization"),
        ),
    )


def normalize_logging_project_exclusion(resource: TerraformResource) -> NormalizedResource:
    return _normalize_logging_exclusion(
        resource,
        scope_type="project",
        scope=first_non_empty(resource.values.get("project")),
    )


def normalize_logging_organization_exclusion(resource: TerraformResource) -> NormalizedResource:
    return _normalize_logging_exclusion(
        resource,
        scope_type="organization",
        scope=first_non_empty(
            resource.values.get("org_id"),
            resource.values.get("organization_id"),
            resource.values.get("organization"),
        ),
    )


def normalize_scc_organization_settings(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    organization = known_string(values, unknown_values, "organization", uncertainties) or first_non_empty(
        values.get("organization_id"),
        values.get("org_id"),
    )
    asset_discovery_enabled = known_bool(values, unknown_values, "enable_asset_discovery", uncertainties)
    asset_discovery_config = first_mapping(values.get("asset_discovery_config"), scan_all=True)
    unknown_asset_discovery_config = first_mapping(unknown_values.get("asset_discovery_config"), scan_all=True)

    inclusion_mode = known_block_string(
        asset_discovery_config,
        unknown_asset_discovery_config,
        "inclusion_mode",
        uncertainties,
        path="asset_discovery_config",
    )
    project_ids = known_block_strings(
        asset_discovery_config,
        unknown_asset_discovery_config,
        "project_ids",
        uncertainties,
        path="asset_discovery_config",
    )
    folder_ids = known_block_strings(
        asset_discovery_config,
        unknown_asset_discovery_config,
        "folder_ids",
        uncertainties,
        path="asset_discovery_config",
    )

    metadata: dict[Any, Any] = {
        GcpResourceMetadata.NAME: resource_name(resource),
        GcpResourceMetadata.ORGANIZATION_ID: organization,
        GcpResourceMetadata.SCC_ORGANIZATION: organization,
        GcpResourceMetadata.SCC_ASSET_DISCOVERY_STATE: _enabled_state(asset_discovery_enabled),
        GcpResourceMetadata.SCC_ASSET_DISCOVERY_INCLUSION_MODE: inclusion_mode,
        GcpResourceMetadata.SCC_ASSET_DISCOVERY_PROJECT_IDS: project_ids,
        GcpResourceMetadata.SCC_ASSET_DISCOVERY_FOLDER_IDS: folder_ids,
        GcpResourceMetadata.SCC_ASSET_DISCOVERY_CONFIG: _snapshot(asset_discovery_config),
        GcpResourceMetadata.AUDIT_SECURITY_POSTURE_UNCERTAINTIES: uncertainties,
    }
    if asset_discovery_enabled is not None:
        metadata[GcpResourceMetadata.SCC_ENABLE_ASSET_DISCOVERY] = asset_discovery_enabled
    if values.get("labels"):
        metadata[GcpResourceMetadata.LABELS] = values.get("labels")

    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=resource_identifier(resource),
        metadata=metadata,
    )


def _normalize_logging_sink(
    resource: TerraformResource,
    *,
    scope_type: str,
    scope: str | None,
) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    name = known_string(values, unknown_values, "name", uncertainties) or resource_name(resource)
    destination = known_string(values, unknown_values, "destination", uncertainties)
    sink_filter = known_string(values, unknown_values, "filter", uncertainties)
    writer_identity = known_string(values, unknown_values, "writer_identity", uncertainties)
    include_children = known_bool(values, unknown_values, "include_children", uncertainties)
    unique_writer_identity = known_bool(values, unknown_values, "unique_writer_identity", uncertainties)

    metadata = _scope_metadata(scope_type, scope)
    metadata.update(
        {
            GcpResourceMetadata.NAME: name,
            GcpResourceMetadata.SELF_LINK: values.get("self_link"),
            GcpResourceMetadata.LOGGING_SINK_NAME: name,
            GcpResourceMetadata.LOGGING_SINK_DESTINATION: destination,
            GcpResourceMetadata.LOGGING_SINK_FILTER: sink_filter,
            GcpResourceMetadata.LOGGING_SINK_WRITER_IDENTITY: writer_identity,
            GcpResourceMetadata.LOGGING_SINK_SCOPE_TYPE: scope_type,
            GcpResourceMetadata.LOGGING_SINK_SCOPE: scope,
            GcpResourceMetadata.AUDIT_SECURITY_POSTURE_UNCERTAINTIES: uncertainties,
        }
    )
    if include_children is not None:
        metadata[GcpResourceMetadata.LOGGING_SINK_INCLUDE_CHILDREN] = include_children
    if unique_writer_identity is not None:
        metadata[GcpResourceMetadata.LOGGING_SINK_UNIQUE_WRITER_IDENTITY] = unique_writer_identity
    if values.get("labels"):
        metadata[GcpResourceMetadata.LABELS] = values.get("labels")

    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=resource_identifier(resource),
        metadata=metadata,
    )


def _normalize_logging_exclusion(
    resource: TerraformResource,
    *,
    scope_type: str,
    scope: str | None,
) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    name = known_string(values, unknown_values, "name", uncertainties) or resource_name(resource)
    description = known_string(values, unknown_values, "description", uncertainties)
    exclusion_filter = known_string(values, unknown_values, "filter", uncertainties)
    disabled = known_bool(values, unknown_values, "disabled", uncertainties)

    metadata = _scope_metadata(scope_type, scope)
    metadata.update(
        {
            GcpResourceMetadata.NAME: name,
            GcpResourceMetadata.SELF_LINK: values.get("self_link"),
            GcpResourceMetadata.LOGGING_EXCLUSION_NAME: name,
            GcpResourceMetadata.LOGGING_EXCLUSION_DESCRIPTION: description,
            GcpResourceMetadata.LOGGING_EXCLUSION_FILTER: exclusion_filter,
            GcpResourceMetadata.LOGGING_EXCLUSION_SCOPE_TYPE: scope_type,
            GcpResourceMetadata.LOGGING_EXCLUSION_SCOPE: scope,
            GcpResourceMetadata.AUDIT_SECURITY_POSTURE_UNCERTAINTIES: uncertainties,
        }
    )
    if disabled is not None:
        metadata[GcpResourceMetadata.LOGGING_EXCLUSION_DISABLED] = disabled
    if values.get("labels"):
        metadata[GcpResourceMetadata.LABELS] = values.get("labels")

    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.IAM,
        identifier=resource_identifier(resource),
        metadata=metadata,
    )


def _scope_metadata(scope_type: str, scope: str | None) -> dict[Any, Any]:
    metadata: dict[Any, Any] = {}
    if scope_type == "project":
        metadata[GcpResourceMetadata.PROJECT] = scope
    elif scope_type == "organization":
        metadata[GcpResourceMetadata.ORGANIZATION_ID] = scope
    return metadata


def _enabled_state(value: bool | None) -> str:
    if value is True:
        return "enabled"
    if value is False:
        return "disabled"
    return "unknown"


def _snapshot(value: Any) -> dict[str, Any]:
    return deepcopy(dict(value)) if isinstance(value, Mapping) else {}
