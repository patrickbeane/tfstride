from __future__ import annotations

from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_facts.base import AzureBaseFacts


class AzureAksFacts(AzureBaseFacts):
    __slots__ = ()

    @property
    def aks_cluster_id(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_CLUSTER_ID)

    @property
    def aks_private_cluster_state(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_PRIVATE_CLUSTER_STATE)

    @property
    def aks_private_dns_zone_id(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_PRIVATE_DNS_ZONE_ID)

    @property
    def aks_authorized_ip_ranges(self) -> list[str]:
        return self.get(AzureResourceMetadata.AKS_AUTHORIZED_IP_RANGES)

    @property
    def aks_authorized_ip_ranges_state(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_AUTHORIZED_IP_RANGES_STATE)

    @property
    def aks_api_server_vnet_integration_state(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_API_SERVER_VNET_INTEGRATION_STATE)

    @property
    def aks_api_server_subnet_id(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_API_SERVER_SUBNET_ID)

    @property
    def aks_local_account_state(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_LOCAL_ACCOUNT_STATE)

    @property
    def aks_rbac_state(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_RBAC_STATE)

    @property
    def aks_aad_rbac_state(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_AAD_RBAC_STATE)

    @property
    def aks_aad_managed_state(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_AAD_MANAGED_STATE)

    @property
    def aks_aad_azure_rbac_state(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_AAD_AZURE_RBAC_STATE)

    @property
    def aks_aad_admin_group_object_ids(self) -> list[str]:
        return self.get(AzureResourceMetadata.AKS_AAD_ADMIN_GROUP_OBJECT_IDS)

    @property
    def aks_aad_tenant_id(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_AAD_TENANT_ID)

    @property
    def aks_oidc_issuer_state(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_OIDC_ISSUER_STATE)

    @property
    def aks_workload_identity_state(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_WORKLOAD_IDENTITY_STATE)

    @property
    def aks_network_plugin(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_NETWORK_PLUGIN)

    @property
    def aks_network_policy(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_NETWORK_POLICY)

    @property
    def aks_network_policy_state(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_NETWORK_POLICY_STATE)

    @property
    def aks_network_mode(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_NETWORK_MODE)

    @property
    def aks_outbound_type(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_OUTBOUND_TYPE)

    @property
    def aks_load_balancer_sku(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_LOAD_BALANCER_SKU)

    @property
    def aks_user_assigned_identity_ids(self) -> list[str]:
        return self.get(AzureResourceMetadata.AKS_USER_ASSIGNED_IDENTITY_IDS)

    @property
    def aks_kubelet_identity_state(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_KUBELET_IDENTITY_STATE)

    @property
    def aks_kubelet_identities(self) -> list[dict]:
        return self.get(AzureResourceMetadata.AKS_KUBELET_IDENTITIES)

    @property
    def aks_kms_state(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_KMS_STATE)

    @property
    def aks_kms_key_vault_key_id(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_KMS_KEY_VAULT_KEY_ID)

    @property
    def aks_oms_agent_state(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_OMS_AGENT_STATE)

    @property
    def aks_log_analytics_workspace_id(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_LOG_ANALYTICS_WORKSPACE_ID)

    @property
    def aks_defender_state(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_DEFENDER_STATE)

    @property
    def aks_azure_policy_state(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_AZURE_POLICY_STATE)

    @property
    def aks_kubernetes_version(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_KUBERNETES_VERSION)

    @property
    def aks_automatic_channel_upgrade(self) -> str | None:
        return self.get(AzureResourceMetadata.AKS_AUTOMATIC_CHANNEL_UPGRADE)

    @property
    def aks_maintenance_windows(self) -> list[dict]:
        return self.get(AzureResourceMetadata.AKS_MAINTENANCE_WINDOWS)

    @property
    def aks_posture_uncertainties(self) -> list[str]:
        return self.get(AzureResourceMetadata.AKS_POSTURE_UNCERTAINTIES)
