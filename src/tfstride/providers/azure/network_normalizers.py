from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_utils import (
    as_list,
    compact_strings,
    first_non_empty,
    known_block_bool,
    known_block_string,
    known_block_strings,
    known_string,
    parse_network_security_rules,
    unknown_block_at,
)

AZURE_PROVIDER = "azure"


def normalize_virtual_network(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return _network_resource(
        resource,
        identifier=first_non_empty(values.get("id"), values.get("name"), resource.address),
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
            AzureResourceMetadata.ADDRESS_SPACE: compact_strings(as_list(values.get("address_space"))),
        },
    )


def normalize_subnet(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    virtual_network_reference = first_non_empty(values.get("virtual_network_name"))
    return _network_resource(
        resource,
        identifier=first_non_empty(values.get("id"), values.get("name"), resource.address),
        vpc_id=virtual_network_reference,
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.VIRTUAL_NETWORK_REFERENCE: virtual_network_reference,
            AzureResourceMetadata.ADDRESS_PREFIXES: compact_strings(
                [values.get("address_prefix"), *as_list(values.get("address_prefixes"))]
            ),
            AzureResourceMetadata.DEFAULT_OUTBOUND_ACCESS_ENABLED: _bool_with_default(
                values.get("default_outbound_access_enabled"), True
            ),
        },
    )


def normalize_network_security_group(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    rules, records = parse_network_security_rules(values, resource.unknown_values)
    return _network_resource(
        resource,
        identifier=first_non_empty(values.get("id"), values.get("name"), resource.address),
        network_rules=rules,
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
            AzureResourceMetadata.NETWORK_SECURITY_RULES: records,
        },
    )


def normalize_network_security_rule(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    rules, records = parse_network_security_rules(values, resource.unknown_values)
    return _network_resource(
        resource,
        identifier=first_non_empty(values.get("id"), values.get("name"), resource.address),
        network_rules=rules,
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.NETWORK_SECURITY_GROUP_REFERENCE: first_non_empty(
                values.get("network_security_group_name")
            ),
            AzureResourceMetadata.NETWORK_SECURITY_RULES: records,
        },
    )


def normalize_subnet_network_security_group_association(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return _network_resource(
        resource,
        identifier=first_non_empty(values.get("id"), resource.address),
        metadata={
            AzureResourceMetadata.SUBNET_REFERENCE: first_non_empty(values.get("subnet_id")),
            AzureResourceMetadata.NETWORK_SECURITY_GROUP_REFERENCE: first_non_empty(
                values.get("network_security_group_id")
            ),
        },
    )


def normalize_network_interface(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    ip_configurations = [dict(item) for item in as_list(values.get("ip_configuration")) if isinstance(item, Mapping)]
    subnet_references = compact_strings(item.get("subnet_id") for item in ip_configurations)
    public_ip_references = compact_strings(item.get("public_ip_address_id") for item in ip_configurations)
    return _network_resource(
        resource,
        identifier=first_non_empty(values.get("id"), values.get("name"), resource.address),
        subnet_ids=tuple(subnet_references),
        public_access_configured=bool(public_ip_references),
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
            AzureResourceMetadata.IP_CONFIGURATIONS: ip_configurations,
            AzureResourceMetadata.PUBLIC_IP_REFERENCES: public_ip_references,
            AzureResourceMetadata.IP_FORWARDING_ENABLED: bool(values.get("ip_forwarding_enabled", False)),
        },
    )


def normalize_network_interface_security_group_association(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return _network_resource(
        resource,
        identifier=first_non_empty(values.get("id"), resource.address),
        metadata={
            AzureResourceMetadata.NETWORK_INTERFACE_REFERENCE: first_non_empty(values.get("network_interface_id")),
            AzureResourceMetadata.NETWORK_SECURITY_GROUP_REFERENCE: first_non_empty(
                values.get("network_security_group_id")
            ),
        },
    )


def normalize_public_ip(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=first_non_empty(values.get("id"), values.get("name"), resource.address),
        public_access_configured=True,
        metadata={
            AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
            AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
            AzureResourceMetadata.PUBLIC_IP_ADDRESS: first_non_empty(values.get("ip_address")),
        },
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
    private_dns_zone_groups = _private_dns_zone_groups(resource, uncertainties)

    metadata: dict[Any, Any] = {
        AzureResourceMetadata.NAME: first_non_empty(values.get("name"), resource.name),
        AzureResourceMetadata.LOCATION: first_non_empty(values.get("location")),
        AzureResourceMetadata.PRIVATE_ENDPOINT_ID: endpoint_id,
        AzureResourceMetadata.SUBNET_REFERENCE: subnet_reference,
        AzureResourceMetadata.PRIVATE_SERVICE_CONNECTIONS: service_connections,
        AzureResourceMetadata.PRIVATE_CONNECTION_RESOURCE_IDS: connection_resource_ids,
        AzureResourceMetadata.PRIVATE_ENDPOINT_SUBRESOURCE_NAMES: subresource_names,
        AzureResourceMetadata.PRIVATE_DNS_ZONE_GROUPS: private_dns_zone_groups,
    }
    if uncertainties:
        metadata[AzureResourceMetadata.PRIVATE_ENDPOINT_UNCERTAINTIES] = uncertainties

    return _network_resource(
        resource,
        identifier=first_non_empty(endpoint_id, values.get("name"), resource.address),
        subnet_ids=tuple([subnet_reference] if subnet_reference else []),
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


def _private_dns_zone_groups(resource: TerraformResource, uncertainties: list[str]) -> list[dict[str, Any]]:
    values = resource.values
    raw_unknown = resource.unknown_values.get("private_dns_zone_group")
    if raw_unknown is True and not values.get("private_dns_zone_group"):
        uncertainties.append("private_dns_zone_group is unknown after planning")
        return []

    records: list[dict[str, Any]] = []
    for index, item in enumerate(as_list(values.get("private_dns_zone_group"))):
        path = f"private_dns_zone_group[{index}]"
        if not isinstance(item, Mapping):
            uncertainties.append(f"{path} has an unrecognized value shape")
            continue
        unknown_item = unknown_block_at(raw_unknown, index)
        record: dict[str, Any] = {}
        unknown_fields: list[str] = []

        group_name = known_block_string(item, unknown_item, "name", uncertainties, path=path)
        if group_name:
            record["name"] = group_name
        zone_ids = known_block_strings(
            item,
            unknown_item,
            "private_dns_zone_ids",
            uncertainties,
            path=path,
            unknown_fields=unknown_fields,
        )
        record["private_dns_zone_ids"] = zone_ids
        if unknown_fields:
            record["unknown_fields"] = unknown_fields
        records.append(record)
    return records


def _network_resource(
    resource: TerraformResource,
    *,
    identifier: str | None,
    vpc_id: str | None = None,
    subnet_ids: tuple[str, ...] = (),
    network_rules=None,
    public_access_configured: bool = False,
    metadata=None,
) -> NormalizedResource:
    return NormalizedResource(
        address=resource.address,
        provider=AZURE_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=identifier,
        vpc_id=vpc_id,
        subnet_ids=subnet_ids,
        network_rules=network_rules or [],
        public_access_configured=public_access_configured,
        metadata=metadata,
    )


def _bool_with_default(value, default: bool) -> bool:
    return default if value is None else bool(value)
