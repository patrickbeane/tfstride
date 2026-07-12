from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.public_network import public_network_fallback_state
from tfstride.providers.azure.resource_utils import (
    block_attribute_unknown,
    first_mapping,
    first_non_empty,
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
)

AZURE_PROVIDER = "azure"


def normalize_mssql_server(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    server_id = first_non_empty(values.get("id"))
    name = first_non_empty(values.get("name"), resource.name)
    uncertainties: list[str] = []

    public_network_access_enabled = known_bool(
        values, resource.unknown_values, "public_network_access_enabled", uncertainties
    )
    min_tls_version = known_string(
        values, resource.unknown_values, "minimum_tls_version", uncertainties, require_string=True
    )

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: name,
        AzureResourceMetadata.MSSQL_SERVER_ID: server_id,
        AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
        AzureResourceMetadata.PUBLIC_NETWORK_FALLBACK_STATE: public_network_fallback_state(
            public_network_access_enabled
        ),
    }
    if public_network_access_enabled is not None:
        metadata[AzureResourceMetadata.PUBLIC_NETWORK_ACCESS_ENABLED] = public_network_access_enabled
    if min_tls_version is not None:
        metadata[AzureResourceMetadata.MIN_TLS_VERSION] = min_tls_version
    if uncertainties:
        metadata[AzureResourceMetadata.MSSQL_POSTURE_UNCERTAINTIES] = uncertainties

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


def normalize_mssql_database(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    database_id = first_non_empty(values.get("id"))
    name = first_non_empty(values.get("name"), resource.name)
    uncertainties: list[str] = []
    server_id = known_string(values, resource.unknown_values, "server_id", uncertainties, require_string=True)

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: name,
        AzureResourceMetadata.MSSQL_DATABASE_ID: database_id,
        AzureResourceMetadata.MSSQL_SERVER_ID: server_id,
    }
    _set_mssql_recovery_posture(metadata, resource, values, uncertainties)
    if uncertainties:
        metadata[AzureResourceMetadata.MSSQL_POSTURE_UNCERTAINTIES] = uncertainties

    normalized = NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=database_id or name or resource.address,
        data_sensitivity="sensitive",
        metadata=metadata,
    )
    return normalized


def normalize_mssql_firewall_rule(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    server_id = first_non_empty(values.get("server_id"))
    start_ip = first_non_empty(values.get("start_ip_address"))
    end_ip = first_non_empty(values.get("end_ip_address"))
    uncertainties: list[str] = []

    if resource.unknown_values.get("start_ip_address") is True:
        uncertainties.append("start_ip_address is unknown after planning")
        start_ip = None
    if resource.unknown_values.get("end_ip_address") is True:
        uncertainties.append("end_ip_address is unknown after planning")
        end_ip = None

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.MSSQL_SERVER_ID: server_id,
        AzureResourceMetadata.MSSQL_FIREWALL_START_IP: start_ip,
        AzureResourceMetadata.MSSQL_FIREWALL_END_IP: end_ip,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.MSSQL_POSTURE_UNCERTAINTIES] = uncertainties

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=first_non_empty(values.get("id"), resource.address),
        metadata=metadata,
    )


def normalize_mssql_virtual_network_rule(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    server_id = first_non_empty(values.get("server_id"))
    subnet_id = first_non_empty(values.get("subnet_id"))
    uncertainties: list[str] = []

    if resource.unknown_values.get("subnet_id") is True:
        uncertainties.append("subnet_id is unknown after planning")
        subnet_id = None

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.MSSQL_SERVER_ID: server_id,
        AzureResourceMetadata.MSSQL_VNET_SUBNET_ID: subnet_id,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.MSSQL_POSTURE_UNCERTAINTIES] = uncertainties

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=first_non_empty(values.get("id"), resource.address),
        metadata=metadata,
    )


def normalize_mssql_server_security_alert_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    server_id = first_non_empty(values.get("mssql_server_id"))
    state = first_non_empty(values.get("state"))
    uncertainties: list[str] = []

    if resource.unknown_values.get("state") is True:
        uncertainties.append("state is unknown after planning")
        state = None

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.MSSQL_SERVER_ID: server_id,
        AzureResourceMetadata.MSSQL_SECURITY_ALERT_STATE: state,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.MSSQL_POSTURE_UNCERTAINTIES] = uncertainties

    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.DATA,
        identifier=first_non_empty(values.get("id"), resource.address),
        metadata=metadata,
    )


def _set_mssql_recovery_posture(
    metadata: dict[Any, Any],
    resource: TerraformResource,
    values: Mapping[str, Any],
    uncertainties: list[str],
) -> None:
    short_term = first_mapping(values.get("short_term_retention_policy"))
    short_term_unknown = _first_unknown_block(resource.unknown_values.get("short_term_retention_policy"))
    short_term_days = known_block_int(
        short_term,
        short_term_unknown,
        "retention_days",
        uncertainties,
        path="short_term_retention_policy",
    )
    backup_interval_hours = known_block_int(
        short_term,
        short_term_unknown,
        "backup_interval_in_hours",
        uncertainties,
        path="short_term_retention_policy",
    )
    metadata[AzureResourceMetadata.MSSQL_SHORT_TERM_RETENTION_STATE] = _field_posture_state(
        short_term, short_term_unknown, "retention_days", short_term_days
    )
    if short_term_days is not None:
        metadata[AzureResourceMetadata.MSSQL_SHORT_TERM_RETENTION_DAYS] = short_term_days
    if backup_interval_hours is not None:
        metadata[AzureResourceMetadata.MSSQL_BACKUP_INTERVAL_HOURS] = backup_interval_hours

    long_term = first_mapping(values.get("long_term_retention_policy"))
    long_term_unknown = _first_unknown_block(resource.unknown_values.get("long_term_retention_policy"))
    long_term_unknown_fields: list[str] = []
    weekly_retention = known_block_string(
        long_term,
        long_term_unknown,
        "weekly_retention",
        uncertainties,
        path="long_term_retention_policy",
        unknown_fields=long_term_unknown_fields,
    )
    monthly_retention = known_block_string(
        long_term,
        long_term_unknown,
        "monthly_retention",
        uncertainties,
        path="long_term_retention_policy",
        unknown_fields=long_term_unknown_fields,
    )
    yearly_retention = known_block_string(
        long_term,
        long_term_unknown,
        "yearly_retention",
        uncertainties,
        path="long_term_retention_policy",
        unknown_fields=long_term_unknown_fields,
    )
    week_of_year = known_block_int(
        long_term,
        long_term_unknown,
        "week_of_year",
        uncertainties,
        path="long_term_retention_policy",
    )
    metadata[AzureResourceMetadata.MSSQL_LONG_TERM_RETENTION_STATE] = _long_term_retention_state(
        long_term, (weekly_retention, monthly_retention, yearly_retention), long_term_unknown_fields
    )
    if weekly_retention is not None:
        metadata[AzureResourceMetadata.MSSQL_LONG_TERM_WEEKLY_RETENTION] = weekly_retention
    if monthly_retention is not None:
        metadata[AzureResourceMetadata.MSSQL_LONG_TERM_MONTHLY_RETENTION] = monthly_retention
    if yearly_retention is not None:
        metadata[AzureResourceMetadata.MSSQL_LONG_TERM_YEARLY_RETENTION] = yearly_retention
    if week_of_year is not None:
        metadata[AzureResourceMetadata.MSSQL_LONG_TERM_WEEK_OF_YEAR] = week_of_year

    geo_backup_enabled = known_bool(values, resource.unknown_values, "geo_backup_enabled", uncertainties)
    metadata[AzureResourceMetadata.MSSQL_GEO_BACKUP_STATE] = _bool_posture_state(geo_backup_enabled)

    backup_storage_redundancy = known_string(
        values, resource.unknown_values, "storage_account_type", uncertainties, require_string=True
    )
    if backup_storage_redundancy is not None:
        metadata[AzureResourceMetadata.MSSQL_BACKUP_STORAGE_REDUNDANCY] = backup_storage_redundancy


def _first_unknown_block(value: Any) -> Any:
    if value is True or isinstance(value, Mapping):
        return value
    return unknown_block_at(value, 0)


def _field_posture_state(
    values: Mapping[str, Any] | None,
    unknown_block: Any,
    key: str,
    known_value: Any,
) -> str:
    if block_attribute_unknown(unknown_block, key):
        return STATE_UNKNOWN
    if values is None:
        return STATE_NOT_CONFIGURED
    if known_value is not None:
        return STATE_CONFIGURED
    if key in values:
        return STATE_UNKNOWN
    return STATE_NOT_CONFIGURED


def _long_term_retention_state(
    values: Mapping[str, Any] | None,
    retention_values: tuple[str | None, str | None, str | None],
    unknown_fields: list[str],
) -> str:
    if unknown_fields:
        return STATE_UNKNOWN
    if values is None:
        return STATE_NOT_CONFIGURED
    if any(retention_values):
        return STATE_CONFIGURED
    return STATE_NOT_CONFIGURED


def _bool_posture_state(value: bool | None) -> str:
    if value is True:
        return STATE_ENABLED
    if value is False:
        return STATE_DISABLED
    return STATE_UNKNOWN
