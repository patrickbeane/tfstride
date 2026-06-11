from __future__ import annotations

import ipaddress
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.attributes import GcpAttr, GcpAttribute, GcpValues
from tfstride.providers.gcp.coercion import as_bool, compact, first_item
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_identifier, resource_name


def normalize_container_cluster(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    private_cluster_config_values = _first_block(values, GcpAttr.PRIVATE_CLUSTER_CONFIG)
    private_cluster_config = GcpValues(private_cluster_config_values)
    authorized_networks_config = _optional_first_block(values, GcpAttr.MASTER_AUTHORIZED_NETWORKS_CONFIG)
    authorized_networks = _authorized_networks(authorized_networks_config)
    workload_identity_config_values = _first_block(values, GcpAttr.WORKLOAD_IDENTITY_CONFIG)
    workload_identity_config = GcpValues(workload_identity_config_values)
    node_config_value = _optional_first_block(values, GcpAttr.NODE_CONFIG)
    node_config_values = node_config_value or {}
    public_endpoint = _public_endpoint_enabled(values, private_cluster_config)
    broad_authorized_networks = _broad_authorized_networks(authorized_networks)
    public_exposure = public_endpoint and (
        authorized_networks_config is None or not authorized_networks or bool(broad_authorized_networks)
    )
    public_access_reasons = ["GKE control plane endpoint is public"] if public_endpoint else []
    public_exposure_reasons = _public_exposure_reasons(
        public_endpoint,
        authorized_networks_config,
        authorized_networks,
        broad_authorized_networks,
    )
    has_node_config = node_config_value is not None or not values.get(GcpAttr.REMOVE_DEFAULT_NODE_POOL)
    workload_pool = first_non_empty(workload_identity_config.get(GcpAttr.WORKLOAD_POOL))
    metadata = _container_metadata(
        resource,
        values,
        node_config_values,
        has_node_config,
        {
            GcpResourceMetadata.GKE_ENDPOINT: first_non_empty(values.get(GcpAttr.ENDPOINT)),
            GcpResourceMetadata.GKE_PRIVATE_ENDPOINT_ENABLED: private_cluster_config.get(
                GcpAttr.ENABLE_PRIVATE_ENDPOINT
            ),
            GcpResourceMetadata.GKE_PRIVATE_NODES_ENABLED: private_cluster_config.get(GcpAttr.ENABLE_PRIVATE_NODES),
            GcpResourceMetadata.GKE_MASTER_AUTHORIZED_NETWORKS: authorized_networks,
            GcpResourceMetadata.GKE_WORKLOAD_IDENTITY_POOL: workload_pool,
            GcpResourceMetadata.GKE_WORKLOAD_IDENTITY_ENABLED: bool(workload_pool),
            "private_cluster_config": private_cluster_config_values,
            "master_authorized_networks_config": authorized_networks_config or {},
            "workload_identity_config": workload_identity_config_values,
            "remove_default_node_pool": values.get(GcpAttr.REMOVE_DEFAULT_NODE_POOL),
        },
    )
    normalized = NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=resource_identifier(resource),
        vpc_id=first_non_empty(values.get(GcpAttr.NETWORK)),
        subnet_ids=tuple(compact([values.get(GcpAttr.SUBNETWORK)])),
        public_access_configured=public_endpoint,
        public_exposure=public_exposure,
        metadata=metadata,
    )
    mutations = gcp_mutations(normalized)
    mutations.set_public_access(configured=public_endpoint, reasons=public_access_reasons)
    mutations.set_public_endpoint_posture(
        direct_internet_reachable=public_exposure,
        internet_ingress_capable=public_endpoint,
        internet_ingress_reasons=public_exposure_reasons,
    )
    mutations.set_public_exposure(public_exposure, reasons=public_exposure_reasons)
    return normalized


def normalize_container_node_pool(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    node_config_value = _optional_first_block(values, GcpAttr.NODE_CONFIG)
    metadata = _container_metadata(
        resource,
        values,
        node_config_value or {},
        True,
        {
            "cluster": values.get(GcpAttr.CLUSTER),
            "node_locations": values.get(GcpAttr.NODE_LOCATIONS),
            "initial_node_count": values.raw(GcpAttr.INITIAL_NODE_COUNT),
        },
    )
    return NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=resource_identifier(resource),
        metadata=metadata,
    )


def _container_metadata(
    resource: TerraformResource,
    values: GcpValues,
    node_config_values: dict[str, Any],
    has_node_config: bool,
    extra: dict[str, Any],
) -> dict[str, Any]:
    node_config = GcpValues(node_config_values)
    node_metadata_values = node_config.get(GcpAttr.METADATA)
    metadata_mode = _node_metadata_mode(node_config)
    service_account = first_non_empty(node_config.get(GcpAttr.SERVICE_ACCOUNT))
    metadata = {
        GcpResourceMetadata.NAME: resource_name(resource),
        GcpResourceMetadata.SELF_LINK: values.get(GcpAttr.SELF_LINK),
        GcpResourceMetadata.PROJECT: values.get(GcpAttr.PROJECT),
        GcpResourceMetadata.REGION: values.get(GcpAttr.LOCATION),
        GcpResourceMetadata.NETWORK: values.get(GcpAttr.NETWORK),
        GcpResourceMetadata.SUBNETWORK: values.get(GcpAttr.SUBNETWORK),
        GcpResourceMetadata.LABELS: values.get(GcpAttr.RESOURCE_LABELS) or values.get(GcpAttr.LABELS),
        GcpResourceMetadata.GKE_NODE_SERVICE_ACCOUNT: service_account,
        GcpResourceMetadata.GKE_NODE_OAUTH_SCOPES: node_config.get(GcpAttr.OAUTH_SCOPES),
        GcpResourceMetadata.GKE_NODE_METADATA_MODE: metadata_mode,
        GcpResourceMetadata.GKE_LEGACY_METADATA_ENDPOINTS_ENABLED: (
            _legacy_metadata_enabled(node_metadata_values, metadata_mode) if has_node_config else None
        ),
        "node_config": node_config_values,
        "node_metadata": node_metadata_values,
    }
    metadata.update(extra)
    return metadata


def _first_block(values: GcpValues, attribute: GcpAttribute[Any]) -> dict[str, Any]:
    return first_item(values.get(attribute)) or {}


def _optional_first_block(values: GcpValues, attribute: GcpAttribute[Any]) -> dict[str, Any] | None:
    return first_item(values.get(attribute))


def _authorized_networks(config: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not config:
        return []
    return GcpValues(config).get(GcpAttr.CIDR_BLOCKS)


def _broad_authorized_networks(networks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [network for network in networks if _cidr_allows_internet(GcpValues(network).get(GcpAttr.CIDR_BLOCK))]


def _cidr_allows_internet(value: object) -> bool:
    if value in (None, ""):
        return False
    try:
        parsed = ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        return False
    return parsed.prefixlen == 0


def _public_endpoint_enabled(values: GcpValues, private_cluster_config: GcpValues) -> bool:
    if private_cluster_config.get(GcpAttr.ENABLE_PRIVATE_ENDPOINT):
        return False
    return bool(first_non_empty(values.get(GcpAttr.ENDPOINT))) or not private_cluster_config.values


def _public_exposure_reasons(
    public_endpoint: bool,
    authorized_networks_config: dict[str, Any] | None,
    authorized_networks: list[dict[str, Any]],
    broad_authorized_networks: list[dict[str, Any]],
) -> list[str]:
    if not public_endpoint:
        return []
    if authorized_networks_config is None:
        return ["GKE master authorized networks are not configured"]
    if not authorized_networks:
        return ["GKE master authorized networks do not define CIDR blocks"]
    return [
        f"authorized network `{_network_name(network)}` allows {GcpValues(network).get(GcpAttr.CIDR_BLOCK)}"
        for network in broad_authorized_networks
    ]


def _network_name(network: dict[str, Any]) -> str:
    values = GcpValues(network)
    return first_non_empty(values.get(GcpAttr.DISPLAY_NAME), values.get(GcpAttr.NAME), "unnamed") or "unnamed"


def _node_metadata_mode(node_config: GcpValues) -> str | None:
    workload_metadata_config = GcpValues(_first_block(node_config, GcpAttr.WORKLOAD_METADATA_CONFIG))
    return first_non_empty(
        workload_metadata_config.get(GcpAttr.MODE),
        workload_metadata_config.get(GcpAttr.NODE_METADATA),
    )


def _legacy_metadata_enabled(node_metadata_values: dict[str, Any], metadata_mode: str | None) -> bool:
    node_metadata = GcpValues(node_metadata_values)
    if node_metadata.has(GcpAttr.DISABLE_LEGACY_ENDPOINTS):
        return not as_bool(node_metadata.raw(GcpAttr.DISABLE_LEGACY_ENDPOINTS))
    if metadata_mode is None:
        return True
    return str(metadata_mode).strip().upper() in {"EXPOSE", "GCE_METADATA", "UNSPECIFIED"}