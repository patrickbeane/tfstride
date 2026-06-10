from __future__ import annotations

import ipaddress
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.coercion import as_bool, as_list, compact, first_item
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_identifier, resource_name


def normalize_container_cluster(resource: TerraformResource) -> NormalizedResource:
    values = resource.values
    private_cluster_config = first_item(values.get("private_cluster_config")) or {}
    authorized_networks_config = first_item(values.get("master_authorized_networks_config"))
    authorized_networks = _authorized_networks(authorized_networks_config)
    workload_identity_config = first_item(values.get("workload_identity_config")) or {}
    node_config_value = first_item(values.get("node_config"))
    node_config = node_config_value or {}
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
    has_node_config = node_config_value is not None or not as_bool(values.get("remove_default_node_pool", False))
    metadata = _container_metadata(
        resource,
        values,
        node_config,
        has_node_config,
        {
            GcpResourceMetadata.GKE_ENDPOINT.key: first_non_empty(values.get("endpoint")),
            GcpResourceMetadata.GKE_PRIVATE_ENDPOINT_ENABLED.key: as_bool(
                private_cluster_config.get("enable_private_endpoint", False)
            ),
            GcpResourceMetadata.GKE_PRIVATE_NODES_ENABLED.key: as_bool(
                private_cluster_config.get("enable_private_nodes", False)
            ),
            GcpResourceMetadata.GKE_MASTER_AUTHORIZED_NETWORKS.key: authorized_networks,
            GcpResourceMetadata.GKE_WORKLOAD_IDENTITY_POOL.key: first_non_empty(
                workload_identity_config.get("workload_pool")
            ),
            GcpResourceMetadata.GKE_WORKLOAD_IDENTITY_ENABLED.key: bool(
                first_non_empty(workload_identity_config.get("workload_pool"))
            ),
            "private_cluster_config": private_cluster_config,
            "master_authorized_networks_config": authorized_networks_config or {},
            "workload_identity_config": workload_identity_config,
            "remove_default_node_pool": as_bool(values.get("remove_default_node_pool", False)),
        },
    )
    normalized = NormalizedResource(
        address=resource.address,
        provider=GCP_PROVIDER,
        resource_type=resource.resource_type,
        name=resource.name,
        category=ResourceCategory.COMPUTE,
        identifier=resource_identifier(resource),
        vpc_id=first_non_empty(values.get("network")),
        subnet_ids=tuple(compact(as_list(values.get("subnetwork")))),
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
    values = resource.values
    node_config_value = first_item(values.get("node_config"))
    node_config = node_config_value or {}
    metadata = _container_metadata(
        resource,
        values,
        node_config,
        True,
        {
            "cluster": values.get("cluster"),
            "node_locations": compact(as_list(values.get("node_locations"))),
            "initial_node_count": values.get("initial_node_count"),
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
    values: dict[str, Any],
    node_config: dict[str, Any],
    has_node_config: bool,
    extra: dict[str, Any],
) -> dict[str, Any]:
    node_metadata = node_config.get("metadata") if isinstance(node_config.get("metadata"), dict) else {}
    metadata_mode = _node_metadata_mode(node_config)
    service_account = first_non_empty(node_config.get("service_account"))
    metadata = {
        GcpResourceMetadata.NAME.key: resource_name(resource),
        GcpResourceMetadata.SELF_LINK.key: values.get("self_link"),
        GcpResourceMetadata.PROJECT.key: values.get("project"),
        GcpResourceMetadata.REGION.key: values.get("location"),
        GcpResourceMetadata.NETWORK.key: values.get("network"),
        GcpResourceMetadata.SUBNETWORK.key: values.get("subnetwork"),
        GcpResourceMetadata.LABELS.key: values.get("resource_labels") or values.get("labels") or {},
        GcpResourceMetadata.GKE_NODE_SERVICE_ACCOUNT.key: service_account,
        GcpResourceMetadata.GKE_NODE_OAUTH_SCOPES.key: compact(as_list(node_config.get("oauth_scopes"))),
        GcpResourceMetadata.GKE_NODE_METADATA_MODE.key: metadata_mode,
        GcpResourceMetadata.GKE_LEGACY_METADATA_ENDPOINTS_ENABLED.key: (
            _legacy_metadata_enabled(node_metadata, metadata_mode) if has_node_config else None
        ),
        "node_config": node_config,
        "node_metadata": node_metadata,
    }
    metadata.update(extra)
    return metadata


def _authorized_networks(config: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not config:
        return []
    return [
        network
        for network in as_list(config.get("cidr_blocks"))
        if isinstance(network, dict)
    ]


def _broad_authorized_networks(networks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [network for network in networks if _cidr_allows_internet(network.get("cidr_block"))]


def _cidr_allows_internet(value: object) -> bool:
    if value in (None, ""):
        return False
    try:
        parsed = ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        return False
    return parsed.prefixlen == 0


def _public_endpoint_enabled(values: dict[str, Any], private_cluster_config: dict[str, Any]) -> bool:
    if as_bool(private_cluster_config.get("enable_private_endpoint", False)):
        return False
    return bool(first_non_empty(values.get("endpoint"))) or not private_cluster_config


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
        f"authorized network `{_network_name(network)}` allows {network.get('cidr_block')}"
        for network in broad_authorized_networks
    ]


def _network_name(network: dict[str, Any]) -> str:
    return first_non_empty(network.get("display_name"), network.get("name"), "unnamed") or "unnamed"


def _node_metadata_mode(node_config: dict[str, Any]) -> str | None:
    workload_metadata_config = first_item(node_config.get("workload_metadata_config")) or {}
    return first_non_empty(
        workload_metadata_config.get("mode"),
        workload_metadata_config.get("node_metadata"),
    )


def _legacy_metadata_enabled(node_metadata: dict[str, Any], metadata_mode: str | None) -> bool:
    disabled = node_metadata.get("disable-legacy-endpoints")
    if disabled is not None:
        return not as_bool(disabled)
    if metadata_mode is None:
        return True
    return str(metadata_mode).strip().upper() in {"EXPOSE", "GCE_METADATA", "UNSPECIFIED"}