from __future__ import annotations

from typing import Any

from tfstride.providers.gcp.metadata import GcpResourceMetadata


class GcpGkeFacts:
    __slots__ = ()

    @property
    def gke_endpoint(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_ENDPOINT)

    @property
    def gke_private_endpoint_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GKE_PRIVATE_ENDPOINT_ENABLED)

    @property
    def gke_private_nodes_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GKE_PRIVATE_NODES_ENABLED)

    @property
    def gke_master_authorized_networks(self) -> list[dict[str, Any]]:
        return self.get(GcpResourceMetadata.GKE_MASTER_AUTHORIZED_NETWORKS)

    @property
    def gke_workload_identity_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GKE_WORKLOAD_IDENTITY_ENABLED)

    @property
    def gke_workload_identity_pool(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_WORKLOAD_IDENTITY_POOL)

    @property
    def gke_node_service_account(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_NODE_SERVICE_ACCOUNT)

    @property
    def gke_node_oauth_scopes(self) -> list[str]:
        return self.get(GcpResourceMetadata.GKE_NODE_OAUTH_SCOPES)

    @property
    def gke_node_metadata_mode(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_NODE_METADATA_MODE)

    @property
    def gke_legacy_metadata_endpoints_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GKE_LEGACY_METADATA_ENDPOINTS_ENABLED)

    @property
    def gke_logging_service(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_LOGGING_SERVICE)

    @property
    def gke_logging_components(self) -> list[str]:
        return self.get(GcpResourceMetadata.GKE_LOGGING_COMPONENTS)

    @property
    def gke_control_plane_logging_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_CONTROL_PLANE_LOGGING_STATE)

    @property
    def gke_logging_config(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GKE_LOGGING_CONFIG)

    @property
    def gke_network_policy_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_NETWORK_POLICY_STATE)

    @property
    def gke_network_policy_provider(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_NETWORK_POLICY_PROVIDER)

    @property
    def gke_network_policy(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GKE_NETWORK_POLICY)

    @property
    def gke_database_encryption_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_DATABASE_ENCRYPTION_STATE)

    @property
    def gke_database_encryption_key_name(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_DATABASE_ENCRYPTION_KEY_NAME)

    @property
    def gke_secrets_encryption_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_SECRETS_ENCRYPTION_STATE)

    @property
    def gke_database_encryption(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GKE_DATABASE_ENCRYPTION)

    @property
    def gke_legacy_abac_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GKE_LEGACY_ABAC_ENABLED)

    @property
    def gke_legacy_abac_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_LEGACY_ABAC_STATE)

    @property
    def gke_client_certificate_auth_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GKE_CLIENT_CERTIFICATE_AUTH_ENABLED)

    @property
    def gke_client_certificate_auth_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_CLIENT_CERTIFICATE_AUTH_STATE)

    @property
    def gke_basic_auth_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_BASIC_AUTH_STATE)

    @property
    def gke_basic_auth_username(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_BASIC_AUTH_USERNAME)

    @property
    def gke_basic_auth_password_configured(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GKE_BASIC_AUTH_PASSWORD_CONFIGURED)

    @property
    def gke_master_auth(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GKE_MASTER_AUTH)

    @property
    def gke_client_certificate_config(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GKE_CLIENT_CERTIFICATE_CONFIG)

    @property
    def gke_release_channel(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_RELEASE_CHANNEL)

    @property
    def gke_release_channel_config(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GKE_RELEASE_CHANNEL_CONFIG)

    @property
    def gke_shielded_nodes_enabled(self) -> bool | None:
        return self.optional_bool(GcpResourceMetadata.GKE_SHIELDED_NODES_ENABLED)

    @property
    def gke_shielded_nodes_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_SHIELDED_NODES_STATE)

    @property
    def gke_shielded_nodes_config(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GKE_SHIELDED_NODES_CONFIG)

    @property
    def gke_binary_authorization_evaluation_mode(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_BINARY_AUTHORIZATION_EVALUATION_MODE)

    @property
    def gke_binary_authorization_state(self) -> str | None:
        return self.get(GcpResourceMetadata.GKE_BINARY_AUTHORIZATION_STATE)

    @property
    def gke_binary_authorization(self) -> dict[str, Any]:
        return self.get(GcpResourceMetadata.GKE_BINARY_AUTHORIZATION)

    @property
    def gke_posture_uncertainties(self) -> list[str]:
        return self.get(GcpResourceMetadata.GKE_POSTURE_UNCERTAINTIES)
