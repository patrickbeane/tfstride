from __future__ import annotations

from collections.abc import Mapping

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_utils import (
    as_list,
    compact_strings,
    first_non_empty,
    parse_network_security_rules,
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
