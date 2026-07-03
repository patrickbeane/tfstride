from __future__ import annotations

from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, SecurityGroupRule, TerraformResource
from tfstride.providers.coercion import attribute_unknown, known_string, known_string_list
from tfstride.providers.gcp.attributes import GcpAttr, GcpValues
from tfstride.providers.gcp.coercion import as_list, as_optional_int, compact, first_item
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_identifier, resource_name

GCP_PROVIDER = "gcp"


def normalize_compute_network(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=resource_identifier(resource),
        metadata={
            GcpResourceMetadata.NAME: resource_name(resource),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.AUTO_CREATE_SUBNETWORKS: values.get(GcpAttr.AUTO_CREATE_SUBNETWORKS),
            "routing_mode": values.get(GcpAttr.ROUTING_MODE),
            "description": values.get(GcpAttr.DESCRIPTION),
        },
    )


def normalize_compute_subnetwork(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=resource_identifier(resource),
        vpc_id=values.get(GcpAttr.NETWORK),
        metadata={
            GcpResourceMetadata.NAME: resource_name(resource),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.REGION: values.get(GcpAttr.REGION),
            GcpResourceMetadata.NETWORK: values.get(GcpAttr.NETWORK),
            GcpResourceMetadata.CIDR_RANGE: values.get(GcpAttr.IP_CIDR_RANGE),
            GcpResourceMetadata.PRIVATE_IP_GOOGLE_ACCESS: (
                None
                if attribute_unknown(resource.unknown_values, GcpAttr.PRIVATE_IP_GOOGLE_ACCESS.key)
                else values.get(GcpAttr.PRIVATE_IP_GOOGLE_ACCESS)
            ),
            "purpose": values.get(GcpAttr.PURPOSE),
            "stack_type": values.get(GcpAttr.STACK_TYPE),
            "secondary_ip_ranges": values.get(GcpAttr.SECONDARY_IP_RANGE),
        },
    )


def normalize_compute_route(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=resource_identifier(resource),
        vpc_id=values.get(GcpAttr.NETWORK),
        metadata={
            GcpResourceMetadata.NAME: resource_name(resource),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.NETWORK: values.get(GcpAttr.NETWORK),
            GcpResourceMetadata.ROUTE_DEST_RANGE: values.get(GcpAttr.DEST_RANGE),
            GcpResourceMetadata.ROUTE_NEXT_HOP_GATEWAY: values.get(GcpAttr.NEXT_HOP_GATEWAY),
            GcpResourceMetadata.ROUTE_NEXT_HOP_INSTANCE: values.get(GcpAttr.NEXT_HOP_INSTANCE),
            GcpResourceMetadata.ROUTE_NEXT_HOP_IP: values.get(GcpAttr.NEXT_HOP_IP),
            GcpResourceMetadata.ROUTE_NEXT_HOP_ILB: values.get(GcpAttr.NEXT_HOP_ILB),
            GcpResourceMetadata.ROUTE_NEXT_HOP_VPN_TUNNEL: values.get(GcpAttr.NEXT_HOP_VPN_TUNNEL),
            GcpResourceMetadata.ROUTE_TAGS: values.get(GcpAttr.TAGS),
            GcpResourceMetadata.ROUTE_PRIORITY: values.get(GcpAttr.PRIORITY),
            "description": values.get(GcpAttr.DESCRIPTION),
        },
    )


def normalize_compute_router(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=resource_identifier(resource),
        vpc_id=values.get(GcpAttr.NETWORK),
        metadata={
            GcpResourceMetadata.NAME: resource_name(resource),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.REGION: values.get(GcpAttr.REGION),
            GcpResourceMetadata.NETWORK: values.get(GcpAttr.NETWORK),
            "bgp": first_item(values.get(GcpAttr.BGP)) or {},
            "description": values.get(GcpAttr.DESCRIPTION),
            "encrypted_interconnect_router": values.get(GcpAttr.ENCRYPTED_INTERCONNECT_ROUTER),
        },
    )


def normalize_compute_router_nat(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    router_reference = first_non_empty(values.get(GcpAttr.ROUTER))
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=resource_identifier(resource),
        metadata={
            GcpResourceMetadata.NAME: resource_name(resource),
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.REGION: values.get(GcpAttr.REGION),
            GcpResourceMetadata.ROUTER_REFERENCE: router_reference,
            GcpResourceMetadata.NAT_SUBNETWORKS: values.get(GcpAttr.SUBNETWORK_BLOCKS),
            "nat_ip_allocate_option": values.get(GcpAttr.NAT_IP_ALLOCATE_OPTION),
            "source_subnetwork_ip_ranges_to_nat": values.get(GcpAttr.SOURCE_SUBNETWORK_IP_RANGES_TO_NAT),
            "min_ports_per_vm": values.get(GcpAttr.MIN_PORTS_PER_VM),
            "enable_endpoint_independent_mapping": values.get(GcpAttr.ENABLE_ENDPOINT_INDEPENDENT_MAPPING),
            "log_config": first_item(values.get(GcpAttr.LOG_CONFIG)) or {},
        },
    )


def normalize_compute_forwarding_rule(resource: TerraformResource) -> NormalizedResource:
    return _normalize_forwarding_rule(resource)


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


def normalize_compute_global_forwarding_rule(resource: TerraformResource) -> NormalizedResource:
    return _normalize_forwarding_rule(resource)


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


def normalize_compute_url_map(resource: TerraformResource) -> NormalizedResource:
    return _normalize_url_map(resource)


def normalize_compute_region_url_map(resource: TerraformResource) -> NormalizedResource:
    return _normalize_url_map(resource)


def normalize_compute_target_http_proxy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_proxy(resource)


def normalize_compute_target_https_proxy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_proxy(resource)


def normalize_compute_ssl_policy(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.SSL_POLICY_NAME: first_non_empty(values.get(GcpAttr.NAME), resource.name),
                GcpResourceMetadata.SSL_POLICY_MIN_TLS_VERSION: values.get(GcpAttr.MIN_TLS_VERSION),
                GcpResourceMetadata.SSL_POLICY_PROFILE: values.get(GcpAttr.PROFILE),
                GcpResourceMetadata.SSL_POLICY_CUSTOM_FEATURES: values.get(GcpAttr.CUSTOM_FEATURES),
                GcpResourceMetadata.SSL_POLICY_ENABLED_FEATURES: values.get(GcpAttr.ENABLED_FEATURES),
            },
        ),
    )


def normalize_compute_managed_ssl_certificate(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    managed = first_item(values.get(GcpAttr.MANAGED)) or {}
    managed_values = GcpValues(managed)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.MANAGED_SSL_CERTIFICATE_NAME: first_non_empty(
                    values.get(GcpAttr.NAME), resource.name
                ),
                GcpResourceMetadata.MANAGED_SSL_CERTIFICATE_DOMAINS: managed_values.get(GcpAttr.DOMAINS),
                GcpResourceMetadata.MANAGED_SSL_CERTIFICATE_STATUS: managed_values.get(GcpAttr.STATUS_TEXT),
            },
        ),
    )


def normalize_compute_region_target_http_proxy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_proxy(resource)


def normalize_compute_region_target_https_proxy(resource: TerraformResource) -> NormalizedResource:
    return _normalize_target_proxy(resource)


def normalize_compute_backend_service(resource: TerraformResource) -> NormalizedResource:
    return _normalize_backend_service(resource)


def normalize_compute_region_backend_service(resource: TerraformResource) -> NormalizedResource:
    return _normalize_backend_service(resource)


def normalize_compute_backend_bucket(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.LOAD_BALANCER_BACKEND_BUCKET_NAME: values.get(GcpAttr.BUCKET_NAME),
            },
        ),
    )


def normalize_compute_network_endpoint_group(resource: TerraformResource) -> NormalizedResource:
    return _normalize_network_endpoint_group(resource)


def normalize_compute_region_network_endpoint_group(resource: TerraformResource) -> NormalizedResource:
    return _normalize_network_endpoint_group(resource)


def normalize_compute_firewall(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=resource_identifier(resource),
        vpc_id=values.get(GcpAttr.NETWORK),
        network_rules=parse_firewall_allow_rules(values),
        metadata={
            GcpResourceMetadata.NAME: resource_name(resource),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.NETWORK: values.get(GcpAttr.NETWORK),
            GcpResourceMetadata.FIREWALL_ALLOW: values.get(GcpAttr.ALLOW),
            GcpResourceMetadata.FIREWALL_DENY: values.get(GcpAttr.DENY),
            GcpResourceMetadata.FIREWALL_SOURCE_RANGES: values.get(GcpAttr.SOURCE_RANGES),
            GcpResourceMetadata.FIREWALL_DESTINATION_RANGES: values.get(GcpAttr.DESTINATION_RANGES),
            GcpResourceMetadata.FIREWALL_TARGET_TAGS: values.get(GcpAttr.TARGET_TAGS),
            GcpResourceMetadata.FIREWALL_SOURCE_TAGS: values.get(GcpAttr.SOURCE_TAGS),
            GcpResourceMetadata.FIREWALL_TARGET_SERVICE_ACCOUNTS: values.get(GcpAttr.TARGET_SERVICE_ACCOUNTS),
            GcpResourceMetadata.FIREWALL_SOURCE_SERVICE_ACCOUNTS: values.get(GcpAttr.SOURCE_SERVICE_ACCOUNTS),
            GcpResourceMetadata.FIREWALL_DIRECTION: str(values.get(GcpAttr.DIRECTION) or "INGRESS").lower(),
            GcpResourceMetadata.FIREWALL_PRIORITY: values.get(GcpAttr.PRIORITY),
            GcpResourceMetadata.FIREWALL_DISABLED: values.get(GcpAttr.DISABLED),
        },
    )


def normalize_compute_firewall_policy(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=first_non_empty(
            values.get(GcpAttr.SHORT_NAME), values.get(GcpAttr.NAME), resource_identifier(resource)
        ),
        metadata={
            GcpResourceMetadata.NAME: first_non_empty(values.get(GcpAttr.SHORT_NAME), values.get(GcpAttr.NAME)),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.FIREWALL_POLICY_REFERENCE: values.get(GcpAttr.NAME),
            GcpResourceMetadata.FIREWALL_POLICY_PARENT: values.get(GcpAttr.PARENT),
            "description": values.get(GcpAttr.DESCRIPTION),
            "display_name": values.get(GcpAttr.DISPLAY_NAME),
        },
    )


def normalize_compute_firewall_policy_rule(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    match = _firewall_policy_match(values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=_firewall_policy_rule_identifier(resource),
        network_rules=parse_firewall_policy_rules(values),
        metadata={
            GcpResourceMetadata.NAME: first_non_empty(values.get(GcpAttr.NAME)),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.FIREWALL_POLICY_REFERENCE: values.get(GcpAttr.FIREWALL_POLICY),
            GcpResourceMetadata.FIREWALL_POLICY_ACTION: values.get(GcpAttr.ACTION),
            GcpResourceMetadata.FIREWALL_POLICY_DIRECTION: _firewall_policy_direction(values),
            GcpResourceMetadata.FIREWALL_POLICY_PRIORITY: values.get(GcpAttr.PRIORITY),
            GcpResourceMetadata.FIREWALL_POLICY_MATCH: match,
            GcpResourceMetadata.FIREWALL_SOURCE_RANGES: _firewall_policy_source_ranges(match),
            GcpResourceMetadata.FIREWALL_DESTINATION_RANGES: _firewall_policy_destination_ranges(match),
            GcpResourceMetadata.FIREWALL_POLICY_TARGET_RESOURCES: values.get(GcpAttr.TARGET_RESOURCES),
            GcpResourceMetadata.FIREWALL_POLICY_TARGET_SERVICE_ACCOUNTS: values.get(GcpAttr.TARGET_SERVICE_ACCOUNTS),
            GcpResourceMetadata.FIREWALL_POLICY_DISABLED: values.get(GcpAttr.DISABLED),
            GcpResourceMetadata.FIREWALL_POLICY_ENABLE_LOGGING: values.get(GcpAttr.ENABLE_LOGGING),
            "description": values.get(GcpAttr.DESCRIPTION),
        },
    )


def normalize_compute_firewall_policy_association(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.NETWORK,
        identifier=first_non_empty(
            values.get(GcpAttr.ATTACHMENT_TARGET), values.get(GcpAttr.NAME), resource_identifier(resource)
        ),
        metadata={
            GcpResourceMetadata.NAME: first_non_empty(values.get(GcpAttr.NAME)),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.FIREWALL_POLICY_REFERENCE: values.get(GcpAttr.FIREWALL_POLICY),
            GcpResourceMetadata.FIREWALL_POLICY_ATTACHMENT_TARGET: values.get(GcpAttr.ATTACHMENT_TARGET),
            "display_name": values.get(GcpAttr.DISPLAY_NAME),
        },
    )


def _normalize_url_map(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.LOAD_BALANCER_DEFAULT_SERVICE: values.get(GcpAttr.DEFAULT_SERVICE),
                GcpResourceMetadata.LOAD_BALANCER_HOST_RULES: _dict_list(values.get(GcpAttr.HOST_RULE)),
                GcpResourceMetadata.LOAD_BALANCER_PATH_MATCHERS: _dict_list(values.get(GcpAttr.PATH_MATCHER)),
            },
        ),
    )


def _normalize_target_proxy(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.LOAD_BALANCER_URL_MAP: values.get(GcpAttr.URL_MAP),
                GcpResourceMetadata.LOAD_BALANCER_SSL_CERTIFICATES: values.get(GcpAttr.SSL_CERTIFICATES),
                GcpResourceMetadata.LOAD_BALANCER_SSL_POLICY: values.get(GcpAttr.SSL_POLICY),
                GcpResourceMetadata.LOAD_BALANCER_CERTIFICATE_MAP: values.get(GcpAttr.CERTIFICATE_MAP),
            },
        ),
    )


def _normalize_backend_service(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.LOAD_BALANCER_BACKEND_SERVICE_PROTOCOL: values.get(GcpAttr.PROTOCOL),
                GcpResourceMetadata.LOAD_BALANCER_BACKEND_SERVICE_LOAD_BALANCING_SCHEME: values.get(
                    GcpAttr.LOAD_BALANCING_SCHEME
                ),
                GcpResourceMetadata.LOAD_BALANCER_BACKENDS: _dict_list(values.get(GcpAttr.BACKEND)),
            },
        ),
    )


def _normalize_network_endpoint_group(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        vpc_id=values.get(GcpAttr.NETWORK),
        subnet_ids=tuple(compact([values.get(GcpAttr.SUBNETWORK)])),
        metadata=_load_balancer_metadata(
            values,
            {
                GcpResourceMetadata.NETWORK: values.get(GcpAttr.NETWORK),
                GcpResourceMetadata.SUBNETWORK: values.get(GcpAttr.SUBNETWORK),
                GcpResourceMetadata.LOAD_BALANCER_NETWORK_ENDPOINT_TYPE: values.get(GcpAttr.NETWORK_ENDPOINT_TYPE),
                GcpResourceMetadata.LOAD_BALANCER_SERVERLESS_ENDPOINTS: _serverless_neg_endpoints(values),
                GcpResourceMetadata.LOAD_BALANCER_NETWORK_ENDPOINTS: _dict_list(values.get(GcpAttr.NETWORK_ENDPOINT)),
            },
        ),
    )


def _load_balancer_metadata(values: GcpValues, metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        GcpResourceMetadata.NAME: first_non_empty(values.get(GcpAttr.NAME)),
        GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
        GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
        GcpResourceMetadata.REGION: values.get(GcpAttr.REGION),
        GcpResourceMetadata.ZONE: values.get(GcpAttr.ZONE),
        **metadata,
    }


def _known_optional_int(
    values: dict[str, Any],
    unknown_values: dict[str, Any] | None,
    key: str,
    uncertainties: list[str],
) -> int | None:
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{key} is unknown after planning")
        return None
    value = values.get(key)
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        uncertainties.append(f"{key} has an unrecognized value shape")
        return None


def _known_dict_list(
    values: dict[str, Any],
    unknown_values: dict[str, Any] | None,
    key: str,
    uncertainties: list[str],
) -> list[dict[str, Any]]:
    if attribute_unknown(unknown_values, key):
        uncertainties.append(f"{key} is unknown after planning")
        return []
    return [dict(item) for item in as_list(values.get(key)) if isinstance(item, dict)]


def _known_first_dict(
    values: dict[str, Any],
    unknown_values: dict[str, Any] | None,
    key: str,
    uncertainties: list[str],
) -> dict[str, Any]:
    records = _known_dict_list(values, unknown_values, key, uncertainties)
    return records[0] if records else {}


def _psc_config_subnetworks(psc_config: dict[str, Any]) -> list[str]:
    return compact(as_list(psc_config.get("subnetworks")))


def _string_from_raw(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text or None


def _dict_list(value: Any) -> list[dict[str, Any]]:
    return [item for item in as_list(value) if isinstance(item, dict)]


def _gcp_values(values: dict[str, Any] | GcpValues) -> GcpValues:
    if isinstance(values, GcpValues):
        return values
    return GcpValues(values)


def _serverless_neg_endpoints(values: GcpValues) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    endpoints.extend(_serverless_neg_endpoint("cloud_run", item) for item in _dict_list(values.get(GcpAttr.CLOUD_RUN)))
    endpoints.extend(
        _serverless_neg_endpoint("cloud_function", item)
        for item in _dict_list(values.get(GcpAttr.CLOUD_FUNCTION_BLOCKS))
    )
    endpoints.extend(
        _serverless_neg_endpoint("app_engine", item) for item in _dict_list(values.get(GcpAttr.APP_ENGINE))
    )
    return [endpoint for endpoint in endpoints if len(endpoint) > 1]


def _serverless_neg_endpoint(platform: str, values: dict[str, Any]) -> dict[str, Any]:
    endpoint_values = GcpValues(values)
    endpoint = {
        "platform": platform,
        "service": endpoint_values.get(GcpAttr.SERVICE),
        "function": endpoint_values.get(GcpAttr.FUNCTION),
        "version": endpoint_values.get(GcpAttr.VERSION),
        "tag": endpoint_values.get(GcpAttr.TAG),
        "url_mask": endpoint_values.get(GcpAttr.URL_MASK),
    }
    return {key: value for key, value in endpoint.items() if value not in (None, "", [], {})}


def _normalize_forwarding_rule(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    public_access_configured = _forwarding_rule_is_public(values)
    public_reasons = ["forwarding rule uses an external load balancing scheme"] if public_access_configured else []
    normalized = NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.EDGE,
        identifier=resource_identifier(resource),
        vpc_id=values.get(GcpAttr.NETWORK),
        subnet_ids=tuple(compact([values.get(GcpAttr.SUBNETWORK)])),
        public_access_configured=public_access_configured,
        public_exposure=public_access_configured,
        metadata={
            GcpResourceMetadata.NAME: resource_name(resource),
            GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
            GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
            GcpResourceMetadata.REGION: values.get(GcpAttr.REGION),
            GcpResourceMetadata.NETWORK: values.get(GcpAttr.NETWORK),
            GcpResourceMetadata.SUBNETWORK: values.get(GcpAttr.SUBNETWORK),
            GcpResourceMetadata.FORWARDING_RULE_IP_ADDRESS: values.get(GcpAttr.IP_ADDRESS),
            GcpResourceMetadata.FORWARDING_RULE_LOAD_BALANCING_SCHEME: values.get(GcpAttr.LOAD_BALANCING_SCHEME),
            GcpResourceMetadata.FORWARDING_RULE_TARGET: values.get(GcpAttr.TARGET),
            GcpResourceMetadata.FORWARDING_RULE_BACKEND_SERVICE: values.get(GcpAttr.BACKEND_SERVICE),
            GcpResourceMetadata.PSC_CONNECTION_ID: _string_from_raw(values.raw(GcpAttr.PSC_CONNECTION_ID)),
            GcpResourceMetadata.PSC_CONNECTION_STATUS: values.get(GcpAttr.PSC_CONNECTION_STATUS),
            GcpResourceMetadata.PSC_SERVICE_LABEL: values.get(GcpAttr.SERVICE_LABEL),
            GcpResourceMetadata.PSC_SERVICE_NAME: values.get(GcpAttr.SERVICE_NAME),
            GcpResourceMetadata.FORWARDING_RULE_PORTS: values.get(GcpAttr.PORTS),
            GcpResourceMetadata.FORWARDING_RULE_SOURCE_IP_RANGES: values.get(GcpAttr.SOURCE_IP_RANGES),
            "ip_protocol": values.get(GcpAttr.IP_PROTOCOL),
            "port_range": values.get(GcpAttr.PORT_RANGE),
            "all_ports": values.get(GcpAttr.ALL_PORTS),
            "allow_global_access": values.get(GcpAttr.ALLOW_GLOBAL_ACCESS),
        },
    )
    mutations = gcp_mutations(normalized)
    mutations.set_public_access(configured=public_access_configured, reasons=public_reasons)
    mutations.set_public_endpoint_posture(
        direct_internet_reachable=public_access_configured,
        internet_ingress_capable=public_access_configured,
        internet_ingress_reasons=public_reasons,
    )
    mutations.set_public_exposure(public_access_configured, reasons=public_reasons)
    return normalized


def parse_firewall_allow_rules(values: dict[str, Any] | GcpValues) -> list[SecurityGroupRule]:
    gcp_values = _gcp_values(values)
    direction = str(gcp_values.get(GcpAttr.DIRECTION) or "INGRESS").strip().lower()
    cidr_blocks = _firewall_cidr_blocks(gcp_values, direction)
    rules: list[SecurityGroupRule] = []
    for allow in gcp_values.get(GcpAttr.ALLOW):
        allow_values = GcpValues(allow)
        protocol = str(allow_values.get(GcpAttr.PROTOCOL) or "-1")
        ports = allow_values.get(GcpAttr.PORTS)
        if not ports:
            rules.append(_firewall_rule(direction, protocol, None, None, cidr_blocks))
            continue
        for port in ports:
            from_port, to_port = _parse_port_range(port)
            rules.append(_firewall_rule(direction, protocol, from_port, to_port, cidr_blocks))
    return rules


def parse_firewall_policy_allow_rules(values: dict[str, Any] | GcpValues) -> list[SecurityGroupRule]:
    gcp_values = _gcp_values(values)
    if str(gcp_values.get(GcpAttr.ACTION) or "").strip().lower() != "allow":
        return []
    return parse_firewall_policy_rules(gcp_values)


def parse_firewall_policy_rules(
    values: dict[str, Any] | GcpValues,
) -> list[SecurityGroupRule]:
    gcp_values = _gcp_values(values)
    match = _firewall_policy_match(gcp_values)
    direction = _firewall_policy_direction(gcp_values)
    cidr_blocks = _firewall_policy_cidr_blocks(match, direction)
    rules: list[SecurityGroupRule] = []
    for layer4_config in _firewall_policy_layer4_configs(match):
        layer4_values = GcpValues(layer4_config)
        protocol = str(layer4_values.get(GcpAttr.IP_PROTOCOL) or layer4_values.get(GcpAttr.PROTOCOL) or "-1")
        ports = layer4_values.get(GcpAttr.PORTS)
        if not ports:
            rules.append(_firewall_rule(direction, protocol, None, None, cidr_blocks))
            continue
        for port in ports:
            from_port, to_port = _parse_port_range(port)
            rules.append(_firewall_rule(direction, protocol, from_port, to_port, cidr_blocks))
    return rules


def _firewall_policy_rule_identifier(resource: TerraformResource) -> str | None:
    values = GcpValues(resource.values)
    firewall_policy = first_non_empty(values.get(GcpAttr.FIREWALL_POLICY))
    priority = first_non_empty(values.get(GcpAttr.PRIORITY))
    if firewall_policy and priority:
        return f"{firewall_policy}/rules/{priority}"
    return resource_identifier(resource)


def _firewall_policy_match(values: GcpValues) -> dict[str, Any]:
    return first_item(values.get(GcpAttr.MATCH)) or {}


def _firewall_policy_direction(values: GcpValues) -> str:
    return str(values.get(GcpAttr.DIRECTION) or "INGRESS").strip().lower()


def _firewall_policy_layer4_configs(match: dict[str, Any]) -> list[dict[str, Any]]:
    match_values = GcpValues(match)
    return match_values.get(GcpAttr.LAYER4_CONFIGS) or match_values.get(GcpAttr.LAYER4_CONFIG)


def _firewall_policy_source_ranges(match: dict[str, Any]) -> list[str]:
    match_values = GcpValues(match)
    return match_values.get(GcpAttr.SRC_IP_RANGES) or match_values.get(GcpAttr.SRC_IP_RANGE)


def _firewall_policy_destination_ranges(match: dict[str, Any]) -> list[str]:
    match_values = GcpValues(match)
    return match_values.get(GcpAttr.DEST_IP_RANGES) or match_values.get(GcpAttr.DEST_IP_RANGE)


def _firewall_policy_cidr_blocks(match: dict[str, Any], direction: str) -> list[str]:
    destination_ranges = _firewall_policy_destination_ranges(match)
    if direction == "egress" and destination_ranges:
        return destination_ranges
    source_ranges = _firewall_policy_source_ranges(match)
    if source_ranges:
        return source_ranges
    if direction == "ingress" and not _firewall_policy_has_non_cidr_source(match):
        return ["0.0.0.0/0"]
    return []


def _firewall_policy_has_non_cidr_source(match: dict[str, Any]) -> bool:
    match_values = GcpValues(match)
    source_scoped_fields = (
        GcpAttr.SRC_ADDRESS_GROUPS,
        GcpAttr.SRC_FQDNS,
        GcpAttr.SRC_REGION_CODES,
        GcpAttr.SRC_SECURE_TAGS,
        GcpAttr.SRC_THREAT_INTELLIGENCES,
    )
    return any(match_values.get(field) for field in source_scoped_fields)


def _firewall_rule(
    direction: str,
    protocol: str,
    from_port: int | None,
    to_port: int | None,
    cidr_blocks: list[str],
) -> SecurityGroupRule:
    return SecurityGroupRule(
        direction=direction,
        protocol="-1" if protocol.lower() in {"all", "-1"} else protocol,
        from_port=from_port,
        to_port=to_port,
        cidr_blocks=list(cidr_blocks),
    )


def _firewall_cidr_blocks(values: GcpValues, direction: str) -> list[str]:
    source_ranges = values.get(GcpAttr.SOURCE_RANGES)
    destination_ranges = values.get(GcpAttr.DESTINATION_RANGES)
    if direction == "egress" and destination_ranges:
        return destination_ranges
    if source_ranges:
        return source_ranges
    source_tags = values.get(GcpAttr.SOURCE_TAGS)
    source_service_accounts = values.get(GcpAttr.SOURCE_SERVICE_ACCOUNTS)
    if direction == "ingress" and not source_tags and not source_service_accounts:
        return ["0.0.0.0/0"]
    return []


def _forwarding_rule_is_public(values: GcpValues) -> bool:
    scheme = str(values.get(GcpAttr.LOAD_BALANCING_SCHEME) or "EXTERNAL").strip().upper()
    return scheme in {"EXTERNAL", "EXTERNAL_MANAGED"}


def _parse_port_range(value: Any) -> tuple[int | None, int | None]:
    text = str(value).strip()
    if not text:
        return (None, None)
    if "-" not in text:
        port = as_optional_int(text)
        return (port, port)
    start, end = text.split("-", 1)
    return (as_optional_int(start.strip()), as_optional_int(end.strip()))
