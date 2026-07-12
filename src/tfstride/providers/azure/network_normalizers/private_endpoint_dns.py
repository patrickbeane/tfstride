from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.network_normalizers.core import _network_resource
from tfstride.providers.azure.resource_utils import (
    as_list,
    bool_state,
    compact_strings,
    first_non_empty,
    known_block_bool,
    known_block_string,
    known_block_strings,
    known_bool,
    known_string,
    unknown_block_at,
)
from tfstride.providers.coercion import (
    STATE_CONFIGURED,
    STATE_NOT_CONFIGURED,
    STATE_UNKNOWN,
)


def normalize_private_endpoint(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    endpoint_id = known_string(values, resource.unknown_values, "id", uncertainties, path="id")
    subnet_reference = known_string(values, resource.unknown_values, "subnet_id", uncertainties, path="subnet_id")
    service_connections, connection_resource_ids, subresource_names = _private_service_connections(
        resource,
        uncertainties,
    )
    (
        private_dns_zone_groups,
        private_dns_zone_ids,
        private_dns_zone_group_names,
        private_dns_zone_group_state,
        private_dns_zone_ids_state,
    ) = _private_dns_zone_groups(resource, uncertainties)

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
        AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
        AzureResourceMetadata.PRIVATE_ENDPOINT_ID: endpoint_id,
        AzureResourceMetadata.SUBNET_REFERENCE: subnet_reference,
        AzureResourceMetadata.PRIVATE_SERVICE_CONNECTIONS: service_connections,
        AzureResourceMetadata.PRIVATE_CONNECTION_RESOURCE_IDS: connection_resource_ids,
        AzureResourceMetadata.PRIVATE_ENDPOINT_SUBRESOURCE_NAMES: subresource_names,
        AzureResourceMetadata.PRIVATE_DNS_ZONE_GROUP_NAMES: private_dns_zone_group_names,
        AzureResourceMetadata.PRIVATE_DNS_ZONE_IDS: private_dns_zone_ids,
        AzureResourceMetadata.PRIVATE_DNS_ZONE_GROUPS: private_dns_zone_groups,
        AzureResourceMetadata.PRIVATE_DNS_ZONE_GROUP_STATE: private_dns_zone_group_state,
        AzureResourceMetadata.PRIVATE_DNS_ZONE_IDS_STATE: private_dns_zone_ids_state,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.PRIVATE_ENDPOINT_UNCERTAINTIES] = uncertainties

    return _network_resource(
        resource,
        identifier=first_non_empty(endpoint_id, values.get("name"), resource.address),
        subnet_ids=tuple([subnet_reference] if subnet_reference else []),
        metadata=metadata,
    )


def normalize_private_dns_zone(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    zone_id = known_string(values, resource.unknown_values, "id", uncertainties, path="id")
    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
        AzureResourceMetadata.PRIVATE_DNS_ZONE_ID: zone_id,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.PRIVATE_DNS_ZONE_UNCERTAINTIES] = uncertainties
    return _network_resource(
        resource,
        identifier=first_non_empty(zone_id, values.get("name"), resource.address),
        metadata=metadata,
    )


def normalize_private_dns_zone_virtual_network_link(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    uncertainties: list[str] = []
    link_id = known_string(values, resource.unknown_values, "id", uncertainties, path="id")
    zone_reference = known_string(
        values,
        resource.unknown_values,
        "private_dns_zone_name",
        uncertainties,
        path="private_dns_zone_name",
    )
    virtual_network_reference = known_string(
        values,
        resource.unknown_values,
        "virtual_network_id",
        uncertainties,
        path="virtual_network_id",
    )
    registration_enabled = known_bool(
        values,
        resource.unknown_values,
        "registration_enabled",
        uncertainties,
        path="registration_enabled",
    )
    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
        AzureResourceMetadata.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_LINK_ID: link_id,
        AzureResourceMetadata.PRIVATE_DNS_ZONE_REFERENCE: zone_reference,
        AzureResourceMetadata.PRIVATE_DNS_ZONE_VIRTUAL_NETWORK_REFERENCE: virtual_network_reference,
        AzureResourceMetadata.PRIVATE_DNS_ZONE_REGISTRATION_STATE: bool_state(registration_enabled),
    }
    if uncertainties:
        metadata[AzureResourceMetadata.PRIVATE_DNS_ZONE_UNCERTAINTIES] = uncertainties
    return _network_resource(
        resource,
        identifier=first_non_empty(link_id, values.get("name"), resource.address),
        vpc_id=virtual_network_reference,
        metadata=metadata,
    )


def _private_service_connections(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    values = resource.values
    raw_unknown = resource.unknown_values.get("private_service_connection")
    if raw_unknown is True and not values.get("private_service_connection"):
        uncertainties.append("private_service_connection is unknown after planning")
        return [], [], []

    records: list[dict[str, Any]] = []
    connection_resource_ids: list[str] = []
    subresource_names: list[str] = []
    for index, item in enumerate(as_list(values.get("private_service_connection"))):
        path = f"private_service_connection[{index}]"
        if not isinstance(item, Mapping):
            uncertainties.append(f"{path} has an unrecognized value shape")
            continue
        unknown_item = unknown_block_at(raw_unknown, index)
        record: dict[str, Any] = {}
        unknown_fields: list[str] = []

        connection_name = known_block_string(item, unknown_item, "name", uncertainties, path=path)
        if connection_name:
            record["name"] = connection_name

        target_id = known_block_string(
            item,
            unknown_item,
            "private_connection_resource_id",
            uncertainties,
            path=path,
            unknown_fields=unknown_fields,
        )
        if target_id:
            record["private_connection_resource_id"] = target_id
            connection_resource_ids.append(target_id)

        names = known_block_strings(
            item,
            unknown_item,
            "subresource_names",
            uncertainties,
            path=path,
            unknown_fields=unknown_fields,
        )
        record["subresource_names"] = names
        subresource_names.extend(names)

        manual_connection = known_block_bool(
            item,
            unknown_item,
            "is_manual_connection",
            uncertainties,
            path=path,
            unknown_fields=unknown_fields,
        )
        if manual_connection is not None:
            record["is_manual_connection"] = manual_connection

        if unknown_fields:
            record["unknown_fields"] = unknown_fields
        records.append(record)

    return records, compact_strings(connection_resource_ids), compact_strings(subresource_names)


def _private_dns_zone_groups(
    resource: TerraformResource,
    uncertainties: list[str],
) -> tuple[list[dict[str, Any]], list[str], list[str], str, str]:
    values = resource.values
    raw_unknown = resource.unknown_values.get("private_dns_zone_group")
    if raw_unknown is True and not values.get("private_dns_zone_group"):
        uncertainties.append("private_dns_zone_group is unknown after planning")
        return [], [], [], STATE_UNKNOWN, STATE_UNKNOWN

    records: list[dict[str, Any]] = []
    all_zone_ids: list[str] = []
    group_names: list[str] = []
    group_state_unknown = raw_unknown is True
    for index, item in enumerate(as_list(values.get("private_dns_zone_group"))):
        path = f"private_dns_zone_group[{index}]"
        if not isinstance(item, Mapping):
            uncertainties.append(f"{path} has an unrecognized value shape")
            group_state_unknown = True
            continue
        unknown_item = unknown_block_at(raw_unknown, index)
        record: dict[str, Any] = {}
        unknown_fields: list[str] = []

        group_name = known_block_string(item, unknown_item, "name", uncertainties, path=path)
        if group_name:
            record["name"] = group_name
            group_names.append(group_name)
        record_zone_ids = known_block_strings(
            item,
            unknown_item,
            "private_dns_zone_ids",
            uncertainties,
            path=path,
            unknown_fields=unknown_fields,
        )
        record["private_dns_zone_ids"] = record_zone_ids
        all_zone_ids.extend(record_zone_ids)
        if unknown_fields:
            record["unknown_fields"] = unknown_fields
        records.append(record)

    compact_zone_ids = compact_strings(all_zone_ids)
    group_state = _private_dns_zone_group_state(records, group_state_unknown)
    zone_ids_state = _private_dns_zone_ids_state(records, compact_zone_ids, group_state_unknown)
    return records, compact_zone_ids, compact_strings(group_names), group_state, zone_ids_state


def _private_dns_zone_group_state(records: list[dict[str, Any]], unknown: bool) -> str:
    if unknown:
        return STATE_UNKNOWN
    if records:
        return STATE_CONFIGURED
    return STATE_NOT_CONFIGURED


def _private_dns_zone_ids_state(records: list[dict[str, Any]], zone_ids: list[str], unknown: bool) -> str:
    if unknown or any("private_dns_zone_ids" in record.get("unknown_fields", []) for record in records):
        return STATE_UNKNOWN
    if zone_ids:
        return STATE_CONFIGURED
    return STATE_NOT_CONFIGURED
