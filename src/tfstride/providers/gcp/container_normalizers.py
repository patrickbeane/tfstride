from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.coercion import (
    block_attribute_unknown,
    known_block_bool,
    known_block_string,
    known_block_strings,
    known_string,
    unknown_block_at,
)
from tfstride.providers.gcp.attributes import GcpAttr, GcpAttribute, GcpValues
from tfstride.providers.gcp.coercion import as_bool, compact, first_item
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_identifier, resource_name

_STATE_CONFIGURED = "configured"
_STATE_DISABLED = "disabled"
_STATE_ENABLED = "enabled"
_STATE_NOT_CONFIGURED = "not_configured"
_STATE_UNKNOWN = "unknown"


def normalize_container_cluster(resource: TerraformResource) -> NormalizedResource:
    values = GcpValues(resource.values)
    unknown_values = resource.unknown_values
    uncertainties: list[str] = []
    private_cluster_config_values = _first_block(values, GcpAttr.PRIVATE_CLUSTER_CONFIG)
    private_cluster_config = GcpValues(private_cluster_config_values)
    authorized_networks_config = _optional_first_block(values, GcpAttr.MASTER_AUTHORIZED_NETWORKS_CONFIG)
    authorized_networks = _authorized_networks(authorized_networks_config)
    workload_identity_config_values = _first_block(values, GcpAttr.WORKLOAD_IDENTITY_CONFIG)
    workload_identity_config = GcpValues(workload_identity_config_values)
    node_config_value = _optional_first_block(values, GcpAttr.NODE_CONFIG)
    node_config_values = node_config_value or {}
    logging_config = _optional_first_block(values, GcpAttr.LOGGING_CONFIG)
    logging_unknown = _first_unknown_block(unknown_values.get(GcpAttr.LOGGING_CONFIG.key))
    logging_components = known_block_strings(
        logging_config,
        logging_unknown,
        GcpAttr.ENABLE_COMPONENTS.key,
        uncertainties,
        path=GcpAttr.LOGGING_CONFIG.key,
    )
    logging_service = known_string(
        resource.values,
        unknown_values,
        GcpAttr.LOGGING_SERVICE.key,
        uncertainties,
    )
    network_policy = _optional_first_block(values, GcpAttr.NETWORK_POLICY)
    network_policy_unknown = _first_unknown_block(unknown_values.get(GcpAttr.NETWORK_POLICY.key))
    network_policy_enabled = known_block_bool(
        network_policy,
        network_policy_unknown,
        GcpAttr.ENABLED.key,
        uncertainties,
        path=GcpAttr.NETWORK_POLICY.key,
    )
    database_encryption = _optional_first_block(values, GcpAttr.DATABASE_ENCRYPTION)
    database_encryption_unknown = _first_unknown_block(unknown_values.get(GcpAttr.DATABASE_ENCRYPTION.key))
    database_encryption_state = known_block_string(
        database_encryption,
        database_encryption_unknown,
        GcpAttr.STATE.key,
        uncertainties,
        path=GcpAttr.DATABASE_ENCRYPTION.key,
    )
    database_encryption_key_name = known_block_string(
        database_encryption,
        database_encryption_unknown,
        GcpAttr.KEY_NAME.key,
        uncertainties,
        path=GcpAttr.DATABASE_ENCRYPTION.key,
    )
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
            GcpResourceMetadata.GKE_LOGGING_SERVICE: logging_service,
            GcpResourceMetadata.GKE_LOGGING_COMPONENTS: logging_components,
            GcpResourceMetadata.GKE_CONTROL_PLANE_LOGGING_STATE: _control_plane_logging_state(
                logging_service,
                logging_components,
                unknown_values,
                logging_unknown,
            ),
            GcpResourceMetadata.GKE_LOGGING_CONFIG: dict(logging_config) if logging_config is not None else None,
            GcpResourceMetadata.GKE_NETWORK_POLICY_STATE: _network_policy_state(
                network_policy,
                network_policy_unknown,
                network_policy_enabled,
            ),
            GcpResourceMetadata.GKE_NETWORK_POLICY_PROVIDER: known_block_string(
                network_policy,
                network_policy_unknown,
                GcpAttr.PROVIDER.key,
                uncertainties,
                path=GcpAttr.NETWORK_POLICY.key,
            ),
            GcpResourceMetadata.GKE_NETWORK_POLICY: dict(network_policy) if network_policy is not None else None,
            GcpResourceMetadata.GKE_DATABASE_ENCRYPTION_STATE: database_encryption_state,
            GcpResourceMetadata.GKE_DATABASE_ENCRYPTION_KEY_NAME: database_encryption_key_name,
            GcpResourceMetadata.GKE_SECRETS_ENCRYPTION_STATE: _secrets_encryption_state(
                database_encryption,
                database_encryption_unknown,
                database_encryption_state,
                database_encryption_key_name,
            ),
            GcpResourceMetadata.GKE_DATABASE_ENCRYPTION: (
                dict(database_encryption) if database_encryption is not None else None
            ),
            "private_cluster_config": private_cluster_config_values,
            "master_authorized_networks_config": authorized_networks_config or {},
            "workload_identity_config": workload_identity_config_values,
            "remove_default_node_pool": values.get(GcpAttr.REMOVE_DEFAULT_NODE_POOL),
        },
    )
    if uncertainties:
        metadata[GcpResourceMetadata.GKE_POSTURE_UNCERTAINTIES] = _dedupe(uncertainties)

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


def _control_plane_logging_state(
    logging_service: str | None,
    logging_components: list[str],
    unknown_values: Mapping[str, Any],
    logging_unknown: Any,
) -> str:
    if block_attribute_unknown(unknown_values, GcpAttr.LOGGING_SERVICE.key) or block_attribute_unknown(
        logging_unknown,
        GcpAttr.ENABLE_COMPONENTS.key,
    ):
        return _STATE_UNKNOWN
    if logging_components:
        return _STATE_CONFIGURED
    if logging_service is None:
        return _STATE_NOT_CONFIGURED
    normalized = logging_service.strip().lower()
    if normalized in {"none", "logging.googleapis.com/none"}:
        return _STATE_DISABLED
    return _STATE_CONFIGURED


def _network_policy_state(
    network_policy: Mapping[str, Any] | None,
    network_policy_unknown: Any,
    enabled: bool | None,
) -> str:
    if block_attribute_unknown(network_policy_unknown, GcpAttr.ENABLED.key):
        return _STATE_UNKNOWN
    if network_policy is None:
        return _STATE_NOT_CONFIGURED
    if enabled is None:
        return _STATE_UNKNOWN
    return _STATE_ENABLED if enabled else _STATE_DISABLED


def _secrets_encryption_state(
    database_encryption: Mapping[str, Any] | None,
    database_encryption_unknown: Any,
    encryption_state: str | None,
    key_name: str | None,
) -> str:
    if database_encryption is None:
        return _STATE_UNKNOWN if database_encryption_unknown is True else _STATE_DISABLED
    if block_attribute_unknown(database_encryption_unknown, GcpAttr.STATE.key) or block_attribute_unknown(
        database_encryption_unknown,
        GcpAttr.KEY_NAME.key,
    ):
        return _STATE_UNKNOWN
    normalized = (encryption_state or "").strip().upper()
    if normalized == "ENCRYPTED" and key_name:
        return _STATE_ENABLED
    if normalized in {"ENCRYPTED", "DECRYPTED"}:
        return _STATE_DISABLED
    return _STATE_UNKNOWN


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


def _first_unknown_block(value: Any) -> Any:
    if value is True or isinstance(value, Mapping):
        return value
    return unknown_block_at(value, 0)


def _dedupe(values: Any) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text or text in seen:
            continue
        deduped.append(text)
        seen.add(text)
    return deduped


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
