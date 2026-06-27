from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_utils import first_non_empty

AZURE_PROVIDER = "azure"


def normalize_postgresql_flexible_server(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    server_id = first_non_empty(values.get("id"))
    name = first_non_empty(values.get("name"), resource.name)
    uncertainties: list[str] = []

    public_network_access_enabled = _known_bool(
        resource,
        values,
        "public_network_access_enabled",
        uncertainties=uncertainties,
    )
    geo_redundant_backup_enabled = _known_bool(
        resource,
        values,
        "geo_redundant_backup_enabled",
        uncertainties=uncertainties,
    )
    delegated_subnet_id = _known_string(
        resource,
        values,
        "delegated_subnet_id",
        uncertainties=uncertainties,
    )

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: name,
        AzureResourceMetadata.POSTGRESQL_SERVER_ID: server_id,
        AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
    }
    if public_network_access_enabled is not None:
        metadata[AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED] = public_network_access_enabled
    if geo_redundant_backup_enabled is not None:
        metadata[AzureResourceMetadata.POSTGRESQL_GEO_REDUNDANT_BACKUP_ENABLED] = geo_redundant_backup_enabled
    if delegated_subnet_id is not None:
        metadata[AzureResourceMetadata.POSTGRESQL_DELEGATED_SUBNET_ID] = delegated_subnet_id
    if uncertainties:
        metadata[AzureResourceMetadata.POSTGRESQL_POSTURE_UNCERTAINTIES] = uncertainties

    normalized = NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=server_id or name or resource.address,
        data_sensitivity="sensitive",
        metadata=metadata,
    )
    return normalized


def normalize_postgresql_flexible_server_database(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    name = first_non_empty(values.get("name"), resource.name)
    server_id = first_non_empty(values.get("server_id"))

    if resource.unknown_values.get("server_id") is True:
        server_id = None

    normalized = NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=first_non_empty(values.get("id"), name, resource.address),
        data_sensitivity="sensitive",
        metadata={
            AzureResourceMetadata.NAME: name,
            AzureResourceMetadata.POSTGRESQL_SERVER_ID: server_id,
        },
    )
    return normalized


def normalize_postgresql_flexible_server_firewall_rule(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    server_id = first_non_empty(values.get("server_id"))
    start_ip = first_non_empty(values.get("start_ip_address"))
    end_ip = first_non_empty(values.get("end_ip_address"))
    uncertainties: list[str] = []

    if resource.unknown_values.get("server_id") is True:
        uncertainties.append("server_id is unknown after planning")
        server_id = None
    if resource.unknown_values.get("start_ip_address") is True:
        uncertainties.append("start_ip_address is unknown after planning")
        start_ip = None
    if resource.unknown_values.get("end_ip_address") is True:
        uncertainties.append("end_ip_address is unknown after planning")
        end_ip = None

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.POSTGRESQL_SERVER_ID: server_id,
        AzureResourceMetadata.POSTGRESQL_FIREWALL_START_IP: start_ip,
        AzureResourceMetadata.POSTGRESQL_FIREWALL_END_IP: end_ip,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.POSTGRESQL_POSTURE_UNCERTAINTIES] = uncertainties

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=first_non_empty(values.get("id"), resource.address),
        metadata=metadata,
    )


def normalize_postgresql_flexible_server_configuration(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    name = first_non_empty(values.get("name"))
    server_id = first_non_empty(values.get("server_id"))
    uncertainties: list[str] = []

    value = _known_string(
        resource,
        values,
        "value",
        uncertainties=uncertainties,
    )

    if resource.unknown_values.get("server_id") is True:
        uncertainties.append("server_id is unknown after planning")
        server_id = None

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.POSTGRESQL_CONFIG_NAME: name,
        AzureResourceMetadata.POSTGRESQL_CONFIG_VALUE: value,
        AzureResourceMetadata.POSTGRESQL_CONFIG_SERVER_ID: server_id,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.POSTGRESQL_POSTURE_UNCERTAINTIES] = uncertainties

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=first_non_empty(values.get("id"), resource.address),
        metadata=metadata,
    )


def _known_bool(
    resource: TerraformResource,
    values: Mapping[str, Any],
    key: str,
    *,
    uncertainties: list[str],
) -> bool | None:
    if resource.unknown_values.get(key) is True:
        uncertainties.append(f"{key} is unknown after planning")
        return None
    value = values.get(key)
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "enabled", "yes", "on"}:
            return True
        if normalized in {"false", "disabled", "no", "off"}:
            return False
    uncertainties.append(f"{key} has an unrecognized value shape")
    return None


def _known_string(
    resource: TerraformResource,
    values: Mapping[str, Any],
    key: str,
    *,
    uncertainties: list[str],
) -> str | None:
    if resource.unknown_values.get(key) is True:
        uncertainties.append(f"{key} is unknown after planning")
        return None
    raw = values.get(key)
    if raw is None:
        return None
    if isinstance(raw, str):
        stripped = raw.strip()
        return stripped or None
    uncertainties.append(f"{key} has an unrecognized value shape")
    return None
