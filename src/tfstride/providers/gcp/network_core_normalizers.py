from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.coercion import (
    attribute_unknown,
    first_mapping,
    known_block_string,
    known_block_strings,
    unknown_block_at,
)
from tfstride.providers.gcp.attributes import GcpAttr, GcpValues
from tfstride.providers.gcp.coercion import first_item
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer_common import GCP_PROVIDER
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_identifier, resource_name


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
    flow_log_metadata = _subnetwork_flow_log_metadata(resource.values, resource.unknown_values)
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
            **flow_log_metadata,
        },
    )


def _subnetwork_flow_log_metadata(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any] | None,
) -> dict[Any, Any]:
    uncertainties: list[str] = []
    unknown_log_config = unknown_values.get(GcpAttr.LOG_CONFIG.key) if isinstance(unknown_values, Mapping) else None
    if unknown_log_config is True:
        uncertainties.append("log_config is unknown after planning")
        return _subnetwork_flow_log_metadata_fields(
            state="unknown",
            config={},
            uncertainties=uncertainties,
        )

    log_config = first_mapping(values.get(GcpAttr.LOG_CONFIG.key), expand_tuples=True)
    if log_config is None:
        if unknown_log_config:
            uncertainties.append("log_config is unknown after planning")
            state = "unknown"
        else:
            state = "not_configured"
        return _subnetwork_flow_log_metadata_fields(
            state=state,
            config={},
            uncertainties=uncertainties,
        )

    unknown_block = unknown_block_at(unknown_log_config, 0)
    return _subnetwork_flow_log_metadata_fields(
        state="enabled",
        config=dict(log_config),
        aggregation_interval=known_block_string(
            log_config,
            unknown_block,
            "aggregation_interval",
            uncertainties,
            path="log_config",
        ),
        sampling=known_block_string(
            log_config,
            unknown_block,
            "flow_sampling",
            uncertainties,
            path="log_config",
        ),
        metadata=known_block_string(
            log_config,
            unknown_block,
            "metadata",
            uncertainties,
            path="log_config",
        ),
        metadata_fields=known_block_strings(
            log_config,
            unknown_block,
            "metadata_fields",
            uncertainties,
            path="log_config",
        ),
        filter_expr=known_block_string(
            log_config,
            unknown_block,
            "filter_expr",
            uncertainties,
            path="log_config",
        ),
        uncertainties=uncertainties,
    )


def _subnetwork_flow_log_metadata_fields(
    *,
    state: str,
    config: dict[str, Any],
    uncertainties: list[str],
    aggregation_interval: str | None = None,
    sampling: str | None = None,
    metadata: str | None = None,
    metadata_fields: list[str] | None = None,
    filter_expr: str | None = None,
) -> dict[Any, Any]:
    return {
        GcpResourceMetadata.SUBNETWORK_FLOW_LOG_STATE: state,
        GcpResourceMetadata.SUBNETWORK_FLOW_LOG_CONFIG: config,
        GcpResourceMetadata.SUBNETWORK_FLOW_LOG_AGGREGATION_INTERVAL: aggregation_interval,
        GcpResourceMetadata.SUBNETWORK_FLOW_LOG_SAMPLING: sampling,
        GcpResourceMetadata.SUBNETWORK_FLOW_LOG_METADATA: metadata,
        GcpResourceMetadata.SUBNETWORK_FLOW_LOG_METADATA_FIELDS: metadata_fields or [],
        GcpResourceMetadata.SUBNETWORK_FLOW_LOG_FILTER_EXPR: filter_expr,
        GcpResourceMetadata.NETWORK_TELEMETRY_POSTURE_UNCERTAINTIES: uncertainties,
    }


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
            GcpResourceMetadata.NAT_SOURCE_SUBNETWORK_IP_RANGES_TO_NAT: values.get(
                GcpAttr.SOURCE_SUBNETWORK_IP_RANGES_TO_NAT
            ),
            "min_ports_per_vm": values.get(GcpAttr.MIN_PORTS_PER_VM),
            "enable_endpoint_independent_mapping": values.get(GcpAttr.ENABLE_ENDPOINT_INDEPENDENT_MAPPING),
            "log_config": first_item(values.get(GcpAttr.LOG_CONFIG)) or {},
        },
    )
