from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_types import AzureResourceType
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS

_AKS_CONTROL_PLANE_RULE_IDS = (
    "azure-aks-api-server-public-unrestricted",
    "azure-aks-private-cluster-not-enabled",
    "azure-aks-local-accounts-not-disabled",
    "azure-aks-rbac-posture-weak",
    "azure-aks-network-policy-missing",
)
_AKS_SECURITY_ADDON_RULE_IDS = (
    "azure-aks-workload-identity-not-enabled",
    "azure-aks-key-management-service-not-configured",
    "azure-aks-monitoring-agent-not-enabled",
    "azure-aks-defender-not-enabled",
    "azure-aks-azure-policy-not-enabled",
)
_AKS_RULE_IDS = _AKS_CONTROL_PLANE_RULE_IDS + _AKS_SECURITY_ADDON_RULE_IDS
_MISSING = object()


def _cluster(
    *,
    name: str = "cluster",
    private_cluster: object = _MISSING,
    authorized_ip_ranges: object = _MISSING,
    local_account_disabled: object = _MISSING,
    kubernetes_rbac: object = _MISSING,
    aad_rbac: object = _MISSING,
    azure_rbac_enabled: object = _MISSING,
    network_policy: object = _MISSING,
    oidc_issuer: object = _MISSING,
    workload_identity: object = _MISSING,
    kms_key_vault_key_id: object = _MISSING,
    oms_workspace_id: object = _MISSING,
    defender: object = _MISSING,
    azure_policy: object = _MISSING,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": f"/subscriptions/example/resourceGroups/app/providers/Microsoft.ContainerService/managedClusters/{name}",
        "name": name,
        "location": "eastus",
    }
    if private_cluster is not _MISSING:
        values["private_cluster_enabled"] = private_cluster
    if authorized_ip_ranges is not _MISSING:
        values["api_server_access_profile"] = [{"authorized_ip_ranges": authorized_ip_ranges}]
    if local_account_disabled is not _MISSING:
        values["local_account_disabled"] = local_account_disabled
    if kubernetes_rbac is not _MISSING:
        values["role_based_access_control_enabled"] = kubernetes_rbac
    if aad_rbac is not _MISSING:
        aad_block: dict[str, object] = {"managed": True}
        if azure_rbac_enabled is not _MISSING:
            aad_block["azure_rbac_enabled"] = azure_rbac_enabled
        values["azure_active_directory_role_based_access_control"] = [aad_block]
    if network_policy is not _MISSING:
        values["network_profile"] = [{"network_plugin": "azure", "network_policy": network_policy}]
    if oidc_issuer is not _MISSING:
        values["oidc_issuer_enabled"] = oidc_issuer
    if workload_identity is not _MISSING:
        values["workload_identity_enabled"] = workload_identity
    if kms_key_vault_key_id is not _MISSING:
        values["key_management_service"] = [
            {} if kms_key_vault_key_id is None else {"key_vault_key_id": kms_key_vault_key_id}
        ]
    if oms_workspace_id is not _MISSING:
        values["oms_agent"] = [{} if oms_workspace_id is None else {"log_analytics_workspace_id": oms_workspace_id}]
    if defender is not _MISSING:
        values["microsoft_defender"] = [{"enabled": True}] if defender else []
    if azure_policy is not _MISSING:
        values["azure_policy_enabled"] = azure_policy
    return TerraformResource(
        address=f"azurerm_kubernetes_cluster.{name}",
        mode="managed",
        resource_type=AzureResourceType.KUBERNETES_CLUSTER,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values=unknown_values or {},
    )


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evidence_by_key(finding):
    return {item.key: item.values for item in finding.evidence}


class AzureAksControlPlaneRuleTests(unittest.TestCase):
    def test_public_unrestricted_cluster_emits_control_plane_local_rbac_and_network_policy_findings(self) -> None:
        findings = _evaluate(
            [
                _cluster(
                    private_cluster=False,
                    authorized_ip_ranges=[],
                    local_account_disabled=False,
                    kubernetes_rbac=False,
                    network_policy=_MISSING,
                )
            ],
            *_AKS_CONTROL_PLANE_RULE_IDS,
        )

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "azure-aks-api-server-public-unrestricted",
                "azure-aks-local-accounts-not-disabled",
                "azure-aks-rbac-posture-weak",
                "azure-aks-network-policy-missing",
            ],
        )
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual(findings_by_rule["azure-aks-api-server-public-unrestricted"].severity.value, "high")
        self.assertEqual(findings_by_rule["azure-aks-local-accounts-not-disabled"].severity.value, "medium")
        self.assertEqual(findings_by_rule["azure-aks-rbac-posture-weak"].severity.value, "medium")
        self.assertEqual(findings_by_rule["azure-aks-network-policy-missing"].severity.value, "low")
        evidence = _evidence_by_key(findings_by_rule["azure-aks-api-server-public-unrestricted"])
        self.assertEqual(
            evidence["control_plane_posture"],
            [
                "private_cluster_state=disabled",
                "authorized_ip_ranges_state=not_configured",
                "api_server_vnet_integration_state=unknown",
            ],
        )

    def test_restricted_private_cluster_has_no_aks_control_plane_posture_findings(self) -> None:
        findings = _evaluate(
            [
                _cluster(
                    private_cluster=True,
                    authorized_ip_ranges=["198.51.100.10/32"],
                    local_account_disabled=True,
                    kubernetes_rbac=True,
                    aad_rbac=True,
                    azure_rbac_enabled=True,
                    network_policy="azure",
                )
            ],
            *_AKS_CONTROL_PLANE_RULE_IDS,
        )

        self.assertEqual(findings, [])

    def test_public_cluster_with_narrow_authorized_ranges_emits_private_cluster_only(self) -> None:
        findings = _evaluate(
            [
                _cluster(
                    private_cluster=False,
                    authorized_ip_ranges=["198.51.100.10/32"],
                    local_account_disabled=True,
                    kubernetes_rbac=True,
                    network_policy="calico",
                )
            ],
            *_AKS_CONTROL_PLANE_RULE_IDS,
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-aks-private-cluster-not-enabled"])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertIn(
            "authorized_ip_ranges=[198.51.100.10/32]",
            _evidence_by_key(finding)["control_plane_posture"],
        )

    def test_broad_authorized_range_counts_as_unrestricted_public_api_server(self) -> None:
        findings = _evaluate(
            [
                _cluster(
                    private_cluster=False,
                    authorized_ip_ranges=["0.0.0.0/0"],
                    local_account_disabled=True,
                    kubernetes_rbac=True,
                    network_policy="azure",
                )
            ],
            "azure-aks-api-server-public-unrestricted",
            "azure-aks-private-cluster-not-enabled",
        )

        self.assertEqual([finding.rule_id for finding in findings], ["azure-aks-api-server-public-unrestricted"])
        evidence = _evidence_by_key(findings[0])
        self.assertIn("broad_authorized_ip_ranges=[0.0.0.0/0]", evidence["control_plane_posture"])

    def test_unknown_minimal_cluster_emits_uncertain_findings_without_disabled_claims(self) -> None:
        findings = _evaluate([_cluster()], *_AKS_CONTROL_PLANE_RULE_IDS)

        self.assertEqual(
            [finding.rule_id for finding in findings],
            [
                "azure-aks-api-server-public-unrestricted",
                "azure-aks-local-accounts-not-disabled",
                "azure-aks-rbac-posture-weak",
                "azure-aks-network-policy-missing",
            ],
        )
        self.assertEqual([finding.severity.value for finding in findings], ["medium", "low", "low", "low"])
        public_evidence = _evidence_by_key(findings[0])
        self.assertEqual(
            public_evidence["control_plane_posture"],
            [
                "private_cluster_state=unknown",
                "authorized_ip_ranges_state=not_configured",
                "api_server_vnet_integration_state=unknown",
            ],
        )
        local_evidence = _evidence_by_key(findings[1])
        self.assertEqual(local_evidence["authentication_posture"], ["local_account_state=unknown"])

    def test_unknown_planned_values_are_included_as_uncertainty_evidence(self) -> None:
        findings = _evaluate(
            [
                _cluster(
                    private_cluster=None,
                    authorized_ip_ranges=[],
                    local_account_disabled=None,
                    kubernetes_rbac=None,
                    network_policy=None,
                    unknown_values={
                        "private_cluster_enabled": True,
                        "api_server_access_profile": [{"authorized_ip_ranges": True}],
                        "local_account_disabled": True,
                        "role_based_access_control_enabled": True,
                        "network_profile": [{"network_policy": True}],
                    },
                )
            ],
            *_AKS_CONTROL_PLANE_RULE_IDS,
        )

        findings_by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual(
            _evidence_by_key(findings_by_rule["azure-aks-api-server-public-unrestricted"])["posture_uncertainty"],
            [
                "private_cluster_enabled is unknown after planning",
                "api_server_access_profile.authorized_ip_ranges is unknown after planning",
            ],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule["azure-aks-network-policy-missing"])["posture_uncertainty"],
            ["network_profile.network_policy is unknown after planning"],
        )

    def test_missing_security_addons_emit_focused_findings(self) -> None:
        findings = _evaluate(
            [
                _cluster(
                    oidc_issuer=False,
                    workload_identity=False,
                    kms_key_vault_key_id=_MISSING,
                    oms_workspace_id=_MISSING,
                    defender=False,
                    azure_policy=False,
                )
            ],
            *_AKS_SECURITY_ADDON_RULE_IDS,
        )

        self.assertEqual([finding.rule_id for finding in findings], list(_AKS_SECURITY_ADDON_RULE_IDS))
        self.assertEqual(
            [finding.severity.value for finding in findings], ["medium", "medium", "medium", "medium", "medium"]
        )
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual(
            _evidence_by_key(findings_by_rule["azure-aks-workload-identity-not-enabled"])["workload_identity_posture"],
            ["oidc_issuer_state=disabled", "workload_identity_state=disabled"],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule["azure-aks-key-management-service-not-configured"])[
                "secret_encryption_posture"
            ],
            ["key_management_service_state=not_configured", "key_vault_key_id is not represented in planned values"],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule["azure-aks-monitoring-agent-not-enabled"])["monitoring_posture"],
            ["oms_agent_state=not_configured", "log_analytics_workspace_id is not represented in planned values"],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule["azure-aks-defender-not-enabled"])["defender_posture"],
            ["defender_state=not_configured"],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule["azure-aks-azure-policy-not-enabled"])["azure_policy_posture"],
            ["azure_policy_state=disabled"],
        )

    def test_configured_security_addons_are_quiet(self) -> None:
        findings = _evaluate(
            [
                _cluster(
                    oidc_issuer=True,
                    workload_identity=True,
                    kms_key_vault_key_id="azurerm_key_vault_key.aks.id",
                    oms_workspace_id="azurerm_log_analytics_workspace.aks.id",
                    defender=True,
                    azure_policy=True,
                )
            ],
            *_AKS_SECURITY_ADDON_RULE_IDS,
        )

        self.assertEqual(findings, [])

    def test_unknown_security_addon_values_emit_uncertain_low_severity_findings(self) -> None:
        findings = _evaluate(
            [
                _cluster(
                    oidc_issuer=None,
                    workload_identity=None,
                    kms_key_vault_key_id=_MISSING,
                    oms_workspace_id=_MISSING,
                    defender=_MISSING,
                    azure_policy=None,
                    unknown_values={
                        "oidc_issuer_enabled": True,
                        "workload_identity_enabled": True,
                        "key_management_service": True,
                        "oms_agent": True,
                        "microsoft_defender": True,
                        "azure_policy_enabled": True,
                    },
                )
            ],
            *_AKS_SECURITY_ADDON_RULE_IDS,
        )

        self.assertEqual([finding.rule_id for finding in findings], list(_AKS_SECURITY_ADDON_RULE_IDS))
        self.assertEqual([finding.severity.value for finding in findings], ["low", "low", "low", "low", "low"])
        findings_by_rule = {finding.rule_id: finding for finding in findings}
        self.assertEqual(
            _evidence_by_key(findings_by_rule["azure-aks-workload-identity-not-enabled"])["posture_uncertainty"],
            ["oidc_issuer_enabled is unknown after planning", "workload_identity_enabled is unknown after planning"],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule["azure-aks-key-management-service-not-configured"])[
                "posture_uncertainty"
            ],
            ["key_management_service.key_vault_key_id is unknown after planning"],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule["azure-aks-monitoring-agent-not-enabled"])["posture_uncertainty"],
            ["oms_agent.log_analytics_workspace_id is unknown after planning"],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule["azure-aks-defender-not-enabled"])["defender_posture"],
            ["defender_state=unknown"],
        )
        self.assertEqual(
            _evidence_by_key(findings_by_rule["azure-aks-azure-policy-not-enabled"])["posture_uncertainty"],
            ["azure_policy_enabled is unknown after planning"],
        )

    def test_aks_rule_ids_are_registered_with_azure_rule_group(self) -> None:
        registered = tuple(rule_id for group in AZURE_RULE_GROUP_IDS for rule_id in group)

        for rule_id in _AKS_RULE_IDS:
            with self.subTest(rule_id=rule_id):
                self.assertIn(rule_id, registered)


if __name__ == "__main__":
    unittest.main()
