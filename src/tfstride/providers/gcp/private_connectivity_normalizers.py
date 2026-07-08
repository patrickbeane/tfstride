from __future__ import annotations

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.coercion import known_string, known_string_list
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizer_utils import (
    _known_dict_list,
    _known_first_dict,
    _known_optional_int,
    _psc_config_subnetworks,
)
from tfstride.providers.gcp.normalizer_common import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_name


def normalize_compute_global_address(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    name = known_string(values, unknown_values, "name", uncertainties)
    self_link = known_string(values, unknown_values, "self_link", uncertainties)
    project = known_string(values, unknown_values, "project", uncertainties)
    network = known_string(values, unknown_values, "network", uncertainties)
    purpose = known_string(values, unknown_values, "purpose", uncertainties)
    address_type = known_string(values, unknown_values, "address_type", uncertainties)
    address = known_string(values, unknown_values, "address", uncertainties)
    prefix_length = _known_optional_int(values, unknown_values, "prefix_length", uncertainties)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=first_non_empty(self_link, address, name, resource.address),
        vpc_id=network,
        metadata={
            GcpResourceMetadata.NAME: name or resource.name,
            GcpResourceMetadata.SELF_LINK: self_link,
            GcpResourceMetadata.PROJECT: project,
            GcpResourceMetadata.NETWORK: network,
            GcpResourceMetadata.PRIVATE_CONNECTIVITY_PURPOSE: purpose,
            GcpResourceMetadata.PRIVATE_CONNECTIVITY_ADDRESS_TYPE: address_type,
            GcpResourceMetadata.PRIVATE_CONNECTIVITY_ADDRESS: address,
            GcpResourceMetadata.PRIVATE_CONNECTIVITY_PREFIX_LENGTH: prefix_length,
            GcpResourceMetadata.PRIVATE_CONNECTIVITY_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_compute_service_attachment(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    name = known_string(values, unknown_values, "name", uncertainties)
    self_link = known_string(values, unknown_values, "self_link", uncertainties)
    project = known_string(values, unknown_values, "project", uncertainties)
    region = known_string(values, unknown_values, "region", uncertainties)
    target_service = known_string(values, unknown_values, "target_service", uncertainties)
    connection_preference = known_string(values, unknown_values, "connection_preference", uncertainties)
    nat_subnets = known_string_list(values, unknown_values, "nat_subnets", uncertainties)
    domain_names = known_string_list(values, unknown_values, "domain_names", uncertainties)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=first_non_empty(self_link, name, resource.address),
        subnet_ids=tuple(nat_subnets),
        metadata={
            GcpResourceMetadata.NAME: name or resource.name,
            GcpResourceMetadata.SELF_LINK: self_link,
            GcpResourceMetadata.PROJECT: project,
            GcpResourceMetadata.REGION: region,
            GcpResourceMetadata.PRIVATE_CONNECTIVITY_TARGET_SERVICE: target_service,
            GcpResourceMetadata.PSC_CONNECTION_PREFERENCE: connection_preference,
            GcpResourceMetadata.PRIVATE_CONNECTIVITY_NAT_SUBNETS: nat_subnets,
            GcpResourceMetadata.PRIVATE_CONNECTIVITY_DOMAIN_NAMES: domain_names,
            GcpResourceMetadata.PSC_CONSUMER_ACCEPT_LIST: _known_dict_list(
                values, unknown_values, "consumer_accept_lists", uncertainties
            ),
            GcpResourceMetadata.PSC_CONSUMER_REJECT_LIST: _known_dict_list(
                values, unknown_values, "consumer_reject_lists", uncertainties
            ),
            GcpResourceMetadata.PRIVATE_CONNECTIVITY_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_service_networking_connection(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    network = known_string(values, unknown_values, "network", uncertainties)
    service = known_string(values, unknown_values, "service", uncertainties)
    reserved_ranges = known_string_list(values, unknown_values, "reserved_peering_ranges", uncertainties)
    peering = known_string(values, unknown_values, "peering", uncertainties)
    deletion_policy = known_string(values, unknown_values, "deletion_policy", uncertainties)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=first_non_empty(peering, service, resource.address),
        vpc_id=network,
        metadata={
            GcpResourceMetadata.NAME: resource_name(resource),
            GcpResourceMetadata.NETWORK: network,
            GcpResourceMetadata.PRIVATE_CONNECTIVITY_SERVICE: service,
            GcpResourceMetadata.PRIVATE_CONNECTIVITY_RESERVED_RANGES: reserved_ranges,
            GcpResourceMetadata.PRIVATE_CONNECTIVITY_PEERING: peering,
            "deletion_policy": deletion_policy,
            GcpResourceMetadata.PRIVATE_CONNECTIVITY_UNCERTAINTIES: uncertainties,
        },
    )


def normalize_network_connectivity_service_connection_policy(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    name = known_string(values, unknown_values, "name", uncertainties)
    network = known_string(values, unknown_values, "network", uncertainties)
    service_class = known_string(values, unknown_values, "service_class", uncertainties)
    region = known_string(values, unknown_values, "location", uncertainties, path="location")
    psc_config = _known_first_dict(values, unknown_values, "psc_config", uncertainties)
    psc_subnetworks = _psc_config_subnetworks(psc_config)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=first_non_empty(name, resource.address),
        vpc_id=network,
        subnet_ids=tuple(psc_subnetworks),
        metadata={
            GcpResourceMetadata.NAME: name or resource.name,
            GcpResourceMetadata.REGION: region,
            GcpResourceMetadata.NETWORK: network,
            GcpResourceMetadata.PSC_SERVICE_CLASS: service_class,
            GcpResourceMetadata.PSC_CONFIG: psc_config,
            GcpResourceMetadata.PRIVATE_CONNECTIVITY_SUBNETWORKS: psc_subnetworks,
            GcpResourceMetadata.PRIVATE_CONNECTIVITY_UNCERTAINTIES: uncertainties,
        },
    )
