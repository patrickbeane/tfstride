from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.public_network import public_network_fallback_state
from tfstride.providers.azure.resource_utils import first_non_empty, known_bool, known_string

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
    name = first_non_empty(values.get("name"), resource.name)
    server_id = first_non_empty(values.get("server_id"))

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
            AzureResourceMetadata.MSSQL_SERVER_ID: server_id,
        },
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
