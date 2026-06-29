from __future__ import annotations

import unittest

from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.azure.aks_normalizers import normalize_kubernetes_cluster
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType


def _cluster(
    values: dict[str, object],
    *,
    name: str = "cluster",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"azurerm_kubernetes_cluster.{name}",
        mode="managed",
        resource_type=AzureResourceType.KUBERNETES_CLUSTER,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values=unknown_values or {},
    )


def _azure_findings(resources: list[TerraformResource]) -> list[object]:
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(inventory, [])


class AzureAksNormalizerTests(unittest.TestCase):
    def test_publicish_cluster_normalizes_control_plane_auth_network_and_addon_posture(self) -> None:
        normalized = normalize_kubernetes_cluster(
            _cluster(
                {
                    "id": "/subscriptions/example/resourceGroups/app/providers/Microsoft.ContainerService/managedClusters/public",
                    "name": "public",
                    "location": "eastus",
                    "private_cluster_enabled": False,
                    "local_account_disabled": False,
                    "network_profile": [{"network_plugin": "azure", "outbound_type": "loadBalancer"}],
                    "azure_policy_enabled": False,
                    "kubernetes_version": "1.29.4",
                },
                name="public",
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.COMPUTE)
        self.assertTrue(normalized.public_access_configured)
        self.assertFalse(normalized.public_exposure)
        self.assertEqual(facts.aks_cluster_id, normalized.identifier)
        self.assertEqual(facts.aks_private_cluster_state, "disabled")
        self.assertEqual(facts.aks_authorized_ip_ranges, [])
        self.assertEqual(facts.aks_authorized_ip_ranges_state, "not_configured")
        self.assertEqual(facts.aks_local_account_state, "enabled")
        self.assertEqual(facts.aks_rbac_state, "unknown")
        self.assertEqual(facts.aks_aad_rbac_state, "not_configured")
        self.assertEqual(facts.aks_network_plugin, "azure")
        self.assertIsNone(facts.aks_network_policy)
        self.assertEqual(facts.aks_network_policy_state, "not_configured")
        self.assertEqual(facts.aks_outbound_type, "loadBalancer")
        self.assertEqual(facts.aks_oms_agent_state, "not_configured")
        self.assertEqual(facts.aks_defender_state, "not_configured")
        self.assertEqual(facts.aks_azure_policy_state, "disabled")
        self.assertEqual(facts.aks_kubernetes_version, "1.29.4")
        self.assertEqual(facts.aks_posture_uncertainties, [])

    def test_restricted_cluster_normalizes_safe_posture_values(self) -> None:
        normalized = normalize_kubernetes_cluster(
            _cluster(
                {
                    "id": "/subscriptions/example/resourceGroups/app/providers/Microsoft.ContainerService/managedClusters/restricted",
                    "name": "restricted",
                    "location": "eastus",
                    "private_cluster_enabled": True,
                    "private_dns_zone_id": "azurerm_private_dns_zone.aks.id",
                    "api_server_access_profile": [
                        {
                            "authorized_ip_ranges": ["198.51.100.10/32"],
                            "vnet_integration_enabled": True,
                            "subnet_id": "azurerm_subnet.aks_api.id",
                        }
                    ],
                    "local_account_disabled": True,
                    "role_based_access_control_enabled": True,
                    "azure_active_directory_role_based_access_control": [
                        {
                            "managed": True,
                            "azure_rbac_enabled": True,
                            "admin_group_object_ids": ["group-a", "group-b"],
                            "tenant_id": "tenant-id",
                        }
                    ],
                    "oidc_issuer_enabled": True,
                    "workload_identity_enabled": True,
                    "network_profile": [
                        {
                            "network_plugin": "azure",
                            "network_policy": "azure",
                            "network_mode": "transparent",
                            "outbound_type": "userDefinedRouting",
                            "load_balancer_sku": "standard",
                        }
                    ],
                    "key_management_service": [{"key_vault_key_id": "azurerm_key_vault_key.aks.id"}],
                    "oms_agent": [{"log_analytics_workspace_id": "azurerm_log_analytics_workspace.aks.id"}],
                    "microsoft_defender": [{"log_analytics_workspace_id": "azurerm_log_analytics_workspace.aks.id"}],
                    "azure_policy_enabled": True,
                    "automatic_channel_upgrade": "stable",
                    "maintenance_window_auto_upgrade": [{"frequency": "Weekly", "day_of_week": "Sunday"}],
                },
                name="restricted",
            )
        )
        facts = azure_facts(normalized)

        self.assertFalse(normalized.public_access_configured)
        self.assertEqual(facts.aks_private_cluster_state, "enabled")
        self.assertEqual(facts.aks_private_dns_zone_id, "azurerm_private_dns_zone.aks.id")
        self.assertEqual(facts.aks_authorized_ip_ranges, ["198.51.100.10/32"])
        self.assertEqual(facts.aks_authorized_ip_ranges_state, "configured")
        self.assertEqual(facts.aks_api_server_vnet_integration_state, "enabled")
        self.assertEqual(facts.aks_api_server_subnet_id, "azurerm_subnet.aks_api.id")
        self.assertEqual(facts.aks_local_account_state, "disabled")
        self.assertEqual(facts.aks_rbac_state, "enabled")
        self.assertEqual(facts.aks_aad_rbac_state, "configured")
        self.assertEqual(facts.aks_aad_managed_state, "enabled")
        self.assertEqual(facts.aks_aad_azure_rbac_state, "enabled")
        self.assertEqual(facts.aks_aad_admin_group_object_ids, ["group-a", "group-b"])
        self.assertEqual(facts.aks_aad_tenant_id, "tenant-id")
        self.assertEqual(facts.aks_oidc_issuer_state, "enabled")
        self.assertEqual(facts.aks_workload_identity_state, "enabled")
        self.assertEqual(facts.aks_network_policy, "azure")
        self.assertEqual(facts.aks_network_policy_state, "configured")
        self.assertEqual(facts.aks_network_mode, "transparent")
        self.assertEqual(facts.aks_outbound_type, "userDefinedRouting")
        self.assertEqual(facts.aks_load_balancer_sku, "standard")
        self.assertEqual(facts.aks_kms_state, "configured")
        self.assertEqual(facts.aks_kms_key_vault_key_id, "azurerm_key_vault_key.aks.id")
        self.assertEqual(facts.aks_oms_agent_state, "enabled")
        self.assertEqual(facts.aks_log_analytics_workspace_id, "azurerm_log_analytics_workspace.aks.id")
        self.assertEqual(facts.aks_defender_state, "enabled")
        self.assertEqual(facts.aks_azure_policy_state, "enabled")
        self.assertEqual(facts.aks_automatic_channel_upgrade, "stable")
        self.assertEqual(
            facts.aks_maintenance_windows,
            [{"type": "maintenance_window_auto_upgrade", "frequency": "Weekly", "day_of_week": "Sunday"}],
        )
        self.assertEqual(
            _azure_findings(
                [
                    _cluster(
                        {
                            "name": "restricted",
                            "private_cluster_enabled": True,
                            "local_account_disabled": True,
                            "role_based_access_control_enabled": True,
                            "azure_active_directory_role_based_access_control": [
                                {"managed": True, "azure_rbac_enabled": True}
                            ],
                            "network_profile": [{"network_plugin": "azure", "network_policy": "azure"}],
                        }
                    )
                ]
            ),
            [],
        )

    def test_minimal_cluster_uses_explicit_unknown_and_not_configured_states(self) -> None:
        normalized = normalize_kubernetes_cluster(_cluster({"name": "minimal"}, name="minimal"))
        facts = azure_facts(normalized)

        self.assertEqual(normalized.identifier, "minimal")
        self.assertFalse(normalized.public_access_configured)
        self.assertEqual(facts.aks_private_cluster_state, "unknown")
        self.assertEqual(facts.aks_authorized_ip_ranges_state, "not_configured")
        self.assertEqual(facts.aks_api_server_vnet_integration_state, "unknown")
        self.assertEqual(facts.aks_local_account_state, "unknown")
        self.assertEqual(facts.aks_rbac_state, "unknown")
        self.assertEqual(facts.aks_aad_rbac_state, "not_configured")
        self.assertEqual(facts.aks_oidc_issuer_state, "unknown")
        self.assertEqual(facts.aks_workload_identity_state, "unknown")
        self.assertEqual(facts.aks_network_policy_state, "unknown")
        self.assertEqual(facts.aks_kubelet_identity_state, "not_configured")
        self.assertEqual(facts.aks_kms_state, "not_configured")
        self.assertEqual(facts.aks_oms_agent_state, "not_configured")
        self.assertEqual(facts.aks_defender_state, "not_configured")
        self.assertEqual(facts.aks_azure_policy_state, "unknown")
        self.assertEqual(facts.aks_posture_uncertainties, [])

    def test_identity_enabled_cluster_captures_cluster_and_kubelet_identity(self) -> None:
        normalized = normalize_kubernetes_cluster(
            _cluster(
                {
                    "name": "identity",
                    "identity": [
                        {
                            "type": "SystemAssigned, UserAssigned",
                            "principal_id": "cluster-principal",
                            "client_id": "cluster-client",
                            "tenant_id": "tenant-id",
                            "identity_ids": ["azurerm_user_assigned_identity.aks.id"],
                        }
                    ],
                    "kubelet_identity": [
                        {
                            "client_id": "kubelet-client",
                            "object_id": "kubelet-object",
                            "user_assigned_identity_id": "azurerm_user_assigned_identity.kubelet.id",
                        }
                    ],
                },
                name="identity",
            )
        )
        facts = azure_facts(normalized)

        self.assertTrue(facts.has_system_assigned_identity)
        self.assertTrue(facts.has_user_assigned_identity)
        self.assertEqual(facts.principal_id, "cluster-principal")
        self.assertEqual(facts.client_id, "cluster-client")
        self.assertEqual(facts.tenant_id, "tenant-id")
        self.assertEqual(facts.attached_identity_references, ["azurerm_user_assigned_identity.aks.id"])
        self.assertEqual(facts.aks_user_assigned_identity_ids, ["azurerm_user_assigned_identity.aks.id"])
        self.assertEqual(facts.aks_kubelet_identity_state, "configured")
        self.assertEqual(
            facts.aks_kubelet_identities,
            [
                {
                    "client_id": "kubelet-client",
                    "object_id": "kubelet-object",
                    "user_assigned_identity_id": "azurerm_user_assigned_identity.kubelet.id",
                }
            ],
        )

    def test_unknown_cluster_values_are_preserved_as_uncertainties(self) -> None:
        normalized = normalize_kubernetes_cluster(
            _cluster(
                {
                    "name": "pending",
                    "private_cluster_enabled": None,
                    "api_server_access_profile": [
                        {
                            "authorized_ip_ranges": [],
                            "vnet_integration_enabled": None,
                            "subnet_id": None,
                        }
                    ],
                    "network_profile": [{"network_policy": None}],
                    "identity": None,
                    "kubelet_identity": [
                        {
                            "client_id": None,
                            "object_id": None,
                            "user_assigned_identity_id": None,
                        }
                    ],
                },
                name="pending",
                unknown_values={
                    "private_cluster_enabled": True,
                    "api_server_access_profile": [
                        {
                            "authorized_ip_ranges": True,
                            "vnet_integration_enabled": True,
                            "subnet_id": True,
                        }
                    ],
                    "network_profile": [{"network_policy": True}],
                    "identity": True,
                    "kubelet_identity": [
                        {
                            "client_id": True,
                            "object_id": True,
                            "user_assigned_identity_id": True,
                        }
                    ],
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(facts.aks_private_cluster_state, "unknown")
        self.assertEqual(facts.aks_authorized_ip_ranges_state, "unknown")
        self.assertEqual(facts.aks_api_server_vnet_integration_state, "unknown")
        self.assertEqual(facts.aks_api_server_subnet_id, None)
        self.assertEqual(facts.aks_network_policy_state, "unknown")
        self.assertEqual(facts.managed_identity_uncertainties, ["identity is unknown after planning"])
        self.assertEqual(
            facts.aks_posture_uncertainties,
            [
                "private_cluster_enabled is unknown after planning",
                "api_server_access_profile.authorized_ip_ranges is unknown after planning",
                "api_server_access_profile.vnet_integration_enabled is unknown after planning",
                "api_server_access_profile.subnet_id is unknown after planning",
                "network_profile.network_policy is unknown after planning",
                "kubelet_identity[0].client_id is unknown after planning",
                "kubelet_identity[0].object_id is unknown after planning",
                "kubelet_identity[0].user_assigned_identity_id is unknown after planning",
            ],
        )

    def test_azure_normalizer_supports_kubernetes_cluster_resource_type(self) -> None:
        inventory = AzureNormalizer().normalize(
            [
                _cluster(
                    {
                        "name": "cluster",
                        "private_cluster_enabled": True,
                        "local_account_disabled": True,
                        "role_based_access_control_enabled": True,
                        "azure_active_directory_role_based_access_control": [
                            {"managed": True, "azure_rbac_enabled": True}
                        ],
                        "network_profile": [{"network_plugin": "azure", "network_policy": "azure"}],
                    }
                )
            ]
        )

        self.assertEqual([resource.address for resource in inventory.resources], ["azurerm_kubernetes_cluster.cluster"])
        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual(StrideRuleEngine().evaluate(inventory, []), [])


if __name__ == "__main__":
    unittest.main()
