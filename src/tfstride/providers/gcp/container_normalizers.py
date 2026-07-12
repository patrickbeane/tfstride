from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.coercion import (
    block_attribute_unknown,
    known_block_bool,
    known_block_string,
    known_block_strings,
    known_bool,
    known_string,
)
from tfstride.providers.gcp.attributes import GcpAttr, GcpAttribute, GcpValues
from tfstride.providers.gcp.coercion import as_bool, bool_state, compact, first_item
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import GCP_PROVIDER
from tfstride.providers.gcp.resource_mutations import gcp_mutations
from tfstride.providers.gcp.resource_utils import first_non_empty, resource_identifier, resource_name
from tfstride.providers.kubernetes import block_value, dedupe, first_unknown_block, is_broad_public_range

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
    logging_unknown = first_unknown_block(unknown_values.get(GcpAttr.LOGGING_CONFIG.key))
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
    network_policy_unknown = first_unknown_block(unknown_values.get(GcpAttr.NETWORK_POLICY.key))
    network_policy_enabled = known_block_bool(
        network_policy,
        network_policy_unknown,
        GcpAttr.ENABLED.key,
        uncertainties,
        path=GcpAttr.NETWORK_POLICY.key,
    )
    database_encryption = _optional_first_block(values, GcpAttr.DATABASE_ENCRYPTION)
    database_encryption_unknown = first_unknown_block(unknown_values.get(GcpAttr.DATABASE_ENCRYPTION.key))
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
    legacy_abac_enabled = known_bool(
        resource.values,
        unknown_values,
        GcpAttr.ENABLE_LEGACY_ABAC.key,
        uncertainties,
        allow_string=False,
    )
    master_auth = _optional_first_block(values, GcpAttr.MASTER_AUTH)
    master_auth_unknown = first_unknown_block(unknown_values.get(GcpAttr.MASTER_AUTH.key))
    client_certificate_config = _optional_nested_first_block(master_auth, GcpAttr.CLIENT_CERTIFICATE_CONFIG)
    client_certificate_config_unknown = first_unknown_block(
        block_value(master_auth_unknown, GcpAttr.CLIENT_CERTIFICATE_CONFIG.key)
    )
    client_certificate_auth_enabled = known_block_bool(
        client_certificate_config,
        client_certificate_config_unknown,
        GcpAttr.ISSUE_CLIENT_CERTIFICATE.key,
        uncertainties,
        path=f"{GcpAttr.MASTER_AUTH.key}.{GcpAttr.CLIENT_CERTIFICATE_CONFIG.key}",
    )
    basic_auth_username = known_block_string(
        master_auth,
        master_auth_unknown,
        GcpAttr.USERNAME.key,
        uncertainties,
        path=GcpAttr.MASTER_AUTH.key,
    )
    basic_auth_password_configured = _known_block_secret_configured(
        master_auth,
        master_auth_unknown,
        GcpAttr.PASSWORD.key,
        uncertainties,
        path=GcpAttr.MASTER_AUTH.key,
    )
    release_channel_config = _optional_first_block(values, GcpAttr.RELEASE_CHANNEL)
    release_channel_unknown = first_unknown_block(unknown_values.get(GcpAttr.RELEASE_CHANNEL.key))
    release_channel = known_block_string(
        release_channel_config,
        release_channel_unknown,
        GcpAttr.CHANNEL.key,
        uncertainties,
        path=GcpAttr.RELEASE_CHANNEL.key,
    )
    shielded_nodes = _optional_first_block(values, GcpAttr.SHIELDED_NODES)
    shielded_nodes_unknown = first_unknown_block(unknown_values.get(GcpAttr.SHIELDED_NODES.key))
    shielded_nodes_enabled = _shielded_nodes_enabled(
        resource.values,
        unknown_values,
        shielded_nodes,
        shielded_nodes_unknown,
        uncertainties,
    )
    binary_authorization = _optional_first_block(values, GcpAttr.BINARY_AUTHORIZATION)
    binary_authorization_unknown = first_unknown_block(unknown_values.get(GcpAttr.BINARY_AUTHORIZATION.key))
    binary_authorization_evaluation_mode = known_block_string(
        binary_authorization,
        binary_authorization_unknown,
        GcpAttr.EVALUATION_MODE.key,
        uncertainties,
        path=GcpAttr.BINARY_AUTHORIZATION.key,
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
            GcpResourceMetadata.GKE_LEGACY_ABAC_ENABLED: legacy_abac_enabled,
            GcpResourceMetadata.GKE_LEGACY_ABAC_STATE: bool_state(legacy_abac_enabled),
            GcpResourceMetadata.GKE_CLIENT_CERTIFICATE_AUTH_ENABLED: client_certificate_auth_enabled,
            GcpResourceMetadata.GKE_CLIENT_CERTIFICATE_AUTH_STATE: bool_state(client_certificate_auth_enabled),
            GcpResourceMetadata.GKE_BASIC_AUTH_USERNAME: basic_auth_username,
            GcpResourceMetadata.GKE_BASIC_AUTH_PASSWORD_CONFIGURED: basic_auth_password_configured,
            GcpResourceMetadata.GKE_BASIC_AUTH_STATE: _basic_auth_state(
                master_auth,
                master_auth_unknown,
                basic_auth_username,
                basic_auth_password_configured,
            ),
            GcpResourceMetadata.GKE_MASTER_AUTH: _sanitized_master_auth(
                basic_auth_username,
                basic_auth_password_configured,
                client_certificate_config,
            ),
            GcpResourceMetadata.GKE_CLIENT_CERTIFICATE_CONFIG: (
                dict(client_certificate_config) if client_certificate_config is not None else None
            ),
            GcpResourceMetadata.GKE_RELEASE_CHANNEL: release_channel,
            GcpResourceMetadata.GKE_RELEASE_CHANNEL_CONFIG: (
                dict(release_channel_config) if release_channel_config is not None else None
            ),
            GcpResourceMetadata.GKE_SHIELDED_NODES_ENABLED: shielded_nodes_enabled,
            GcpResourceMetadata.GKE_SHIELDED_NODES_STATE: bool_state(shielded_nodes_enabled),
            GcpResourceMetadata.GKE_SHIELDED_NODES_CONFIG: dict(shielded_nodes) if shielded_nodes is not None else None,
            GcpResourceMetadata.GKE_BINARY_AUTHORIZATION_EVALUATION_MODE: binary_authorization_evaluation_mode,
            GcpResourceMetadata.GKE_BINARY_AUTHORIZATION_STATE: _binary_authorization_state(
                binary_authorization,
                binary_authorization_unknown,
                binary_authorization_evaluation_mode,
            ),
            GcpResourceMetadata.GKE_BINARY_AUTHORIZATION: (
                dict(binary_authorization) if binary_authorization is not None else None
            ),
            "private_cluster_config": private_cluster_config_values,
            "master_authorized_networks_config": authorized_networks_config or {},
            "workload_identity_config": workload_identity_config_values,
            "remove_default_node_pool": values.get(GcpAttr.REMOVE_DEFAULT_NODE_POOL),
        },
    )
    if uncertainties:
        metadata[GcpResourceMetadata.GKE_POSTURE_UNCERTAINTIES] = dedupe(uncertainties)

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


def _basic_auth_state(
    master_auth: Mapping[str, Any] | None,
    master_auth_unknown: Any,
    username: str | None,
    password_configured: bool | None,
) -> str:
    if master_auth is None:
        return _STATE_UNKNOWN
    if block_attribute_unknown(master_auth_unknown, GcpAttr.USERNAME.key) or block_attribute_unknown(
        master_auth_unknown,
        GcpAttr.PASSWORD.key,
    ):
        return _STATE_UNKNOWN
    if username or password_configured:
        return _STATE_ENABLED
    if GcpAttr.USERNAME.key in master_auth or GcpAttr.PASSWORD.key in master_auth:
        return _STATE_DISABLED
    return _STATE_UNKNOWN


def _binary_authorization_state(
    binary_authorization: Mapping[str, Any] | None,
    binary_authorization_unknown: Any,
    evaluation_mode: str | None,
) -> str:
    if binary_authorization is None:
        return _STATE_UNKNOWN
    if block_attribute_unknown(binary_authorization_unknown, GcpAttr.EVALUATION_MODE.key):
        return _STATE_UNKNOWN
    if evaluation_mode is None:
        return _STATE_UNKNOWN
    return _STATE_DISABLED if evaluation_mode.strip().upper() == "DISABLED" else _STATE_ENABLED


def _known_block_secret_configured(
    values: Mapping[str, Any] | None,
    unknown_block: Any,
    key: str,
    uncertainties: list[str],
    *,
    path: str,
) -> bool | None:
    if block_attribute_unknown(unknown_block, key):
        uncertainties.append(f"{path}.{key} is unknown after planning")
        return None
    if values is None or key not in values or values.get(key) is None:
        return None
    value = values.get(key)
    if isinstance(value, str):
        return bool(value.strip())
    uncertainties.append(f"{path}.{key} has an unrecognized value shape")
    return None


def _shielded_nodes_enabled(
    values: Mapping[str, Any],
    unknown_values: Mapping[str, Any],
    shielded_nodes: Mapping[str, Any] | None,
    shielded_nodes_unknown: Any,
    uncertainties: list[str],
) -> bool | None:
    if GcpAttr.ENABLE_SHIELDED_NODES.key in values or block_attribute_unknown(
        unknown_values,
        GcpAttr.ENABLE_SHIELDED_NODES.key,
    ):
        return known_bool(
            values,
            unknown_values,
            GcpAttr.ENABLE_SHIELDED_NODES.key,
            uncertainties,
            allow_string=False,
        )
    return known_block_bool(
        shielded_nodes,
        shielded_nodes_unknown,
        GcpAttr.ENABLED.key,
        uncertainties,
        path=GcpAttr.SHIELDED_NODES.key,
    )


def _sanitized_master_auth(
    username: str | None,
    password_configured: bool | None,
    client_certificate_config: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    record: dict[str, Any] = {}
    if username is not None:
        record["username"] = username
    if password_configured is not None:
        record["password_configured"] = password_configured
    if client_certificate_config is not None:
        record["client_certificate_config"] = dict(client_certificate_config)
    return record or None


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


def _optional_nested_first_block(
    values: Mapping[str, Any] | None, attribute: GcpAttribute[Any]
) -> dict[str, Any] | None:
    if values is None:
        return None
    return first_item(values.get(attribute.key))


def _authorized_networks(config: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not config:
        return []
    return GcpValues(config).get(GcpAttr.CIDR_BLOCKS)


def _broad_authorized_networks(networks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [network for network in networks if is_broad_public_range(GcpValues(network).get(GcpAttr.CIDR_BLOCK))]


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
