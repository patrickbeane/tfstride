from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_eks_rules import (
    _EKS_RULE_IDS as AWS_EKS_RULE_IDS,
)
from tests.providers.aws.test_aws_eks_rules import (
    _cluster as _aws_eks_cluster,
)
from tests.providers.aws.test_aws_eks_rules import (
    _safe_cluster as _aws_safe_eks_cluster,
)
from tests.providers.azure.test_azure_aks_rules import (
    _AKS_RULE_IDS as AZURE_AKS_RULE_IDS,
)
from tests.providers.azure.test_azure_aks_rules import (
    _MISSING as AZURE_MISSING,
)
from tests.providers.azure.test_azure_aks_rules import (
    _cluster as _azure_aks_cluster,
)
from tests.providers.gcp.rule_support.compute import (
    _gke_cluster,
    _gke_node_pool,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.gcp.normalizer import GcpNormalizer

GCP_GKE_RULE_IDS = (
    "gcp-gke-public-control-plane",
    "gcp-gke-broad-authorized-networks",
    "gcp-gke-workload-identity-disabled",
    "gcp-gke-legacy-metadata-endpoints-enabled",
    "gcp-gke-broad-node-service-account",
)
ALL_MANAGED_KUBERNETES_RULE_IDS = frozenset(AWS_EKS_RULE_IDS + GCP_GKE_RULE_IDS + AZURE_AKS_RULE_IDS)


def _evaluate_aws(resources: list[TerraformResource], rule_ids=ALL_MANAGED_KUBERNETES_RULE_IDS):
    inventory = AwsNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evaluate_gcp(resources: list[TerraformResource], rule_ids=ALL_MANAGED_KUBERNETES_RULE_IDS):
    inventory = GcpNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _evaluate_azure(resources: list[TerraformResource], rule_ids=ALL_MANAGED_KUBERNETES_RULE_IDS):
    inventory = AzureNormalizer().normalize(resources)
    return StrideRuleEngine().evaluate(
        inventory,
        detect_trust_boundaries(inventory),
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )


def _finding_ids(findings) -> frozenset[str]:
    return frozenset(finding.rule_id for finding in findings)


class ManagedKubernetesPostureParityTests(unittest.TestCase):
    def test_managed_kubernetes_public_control_plane_findings_are_pinned(self) -> None:
        aws_findings = _evaluate_aws(
            [
                _aws_eks_cluster(
                    name="public",
                    endpoint_public_access=True,
                    endpoint_private_access=False,
                    public_access_cidrs=["0.0.0.0/0"],
                    enabled_cluster_log_types=[],
                    authentication_mode="API_AND_CONFIG_MAP",
                )
            ]
        )
        gcp_findings = _evaluate_gcp(
            [
                _gke_cluster(
                    authorized_networks=[{"display_name": "anywhere", "cidr_block": "0.0.0.0/0"}],
                ),
                _gke_node_pool(),
            ]
        )
        azure_findings = _evaluate_azure(
            [
                _azure_aks_cluster(
                    private_cluster=False,
                    authorized_ip_ranges=[],
                    local_account_disabled=False,
                    kubernetes_rbac=False,
                    network_policy=AZURE_MISSING,
                    oidc_issuer=True,
                    workload_identity=True,
                    kms_key_vault_key_id="azurerm_key_vault_key.aks.id",
                    oms_workspace_id="azurerm_log_analytics_workspace.aks.id",
                    defender=True,
                    azure_policy=True,
                )
            ]
        )

        self.assertEqual(
            _finding_ids(aws_findings),
            frozenset(
                {
                    "aws-eks-api-endpoint-public-unrestricted",
                    "aws-eks-secrets-encryption-not-configured",
                    "aws-eks-control-plane-logging-incomplete",
                }
            ),
        )
        self.assertEqual(
            _finding_ids(gcp_findings),
            frozenset(GCP_GKE_RULE_IDS),
        )
        self.assertEqual(
            _finding_ids(azure_findings),
            frozenset(
                {
                    "azure-aks-api-server-public-unrestricted",
                    "azure-aks-local-accounts-not-disabled",
                    "azure-aks-rbac-posture-weak",
                    "azure-aks-network-policy-missing",
                }
            ),
        )

    def test_managed_kubernetes_safe_cluster_posture_is_quiet(self) -> None:
        aws_findings = _evaluate_aws([_aws_safe_eks_cluster()])
        gcp_findings = _evaluate_gcp(
            [
                _gke_cluster(
                    endpoint=None,
                    private_endpoint=True,
                    authorized_networks=[{"display_name": "admin", "cidr_block": "198.51.100.10/32"}],
                    workload_identity_pool="tfstride-demo.svc.id.goog",
                    node_service_account="gke-nodes@tfstride-demo.iam.gserviceaccount.com",
                    oauth_scopes=["https://www.googleapis.com/auth/logging.write"],
                    disable_legacy_endpoints="true",
                    metadata_mode="GKE_METADATA",
                ),
                _gke_node_pool(
                    node_service_account="gke-nodes@tfstride-demo.iam.gserviceaccount.com",
                    oauth_scopes=["https://www.googleapis.com/auth/logging.write"],
                    disable_legacy_endpoints="true",
                    metadata_mode="GKE_METADATA",
                ),
            ]
        )
        azure_findings = _evaluate_azure(
            [
                _azure_aks_cluster(
                    private_cluster=True,
                    authorized_ip_ranges=["198.51.100.10/32"],
                    local_account_disabled=True,
                    kubernetes_rbac=True,
                    aad_rbac=True,
                    azure_rbac_enabled=True,
                    network_policy="azure",
                    oidc_issuer=True,
                    workload_identity=True,
                    kms_key_vault_key_id="azurerm_key_vault_key.aks.id",
                    oms_workspace_id="azurerm_log_analytics_workspace.aks.id",
                    defender=True,
                    azure_policy=True,
                )
            ]
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_managed_kubernetes_provider_specific_controls_are_preserved(self) -> None:
        aws_private_endpoint_findings = _evaluate_aws(
            [
                _aws_safe_eks_cluster(
                    endpoint_public_access=True,
                    endpoint_private_access=False,
                    public_access_cidrs=["198.51.100.10/32"],
                )
            ]
        )
        azure_private_cluster_findings = _evaluate_azure(
            [
                _azure_aks_cluster(
                    private_cluster=False,
                    authorized_ip_ranges=["198.51.100.10/32"],
                    local_account_disabled=True,
                    kubernetes_rbac=True,
                    network_policy="calico",
                    oidc_issuer=True,
                    workload_identity=True,
                    kms_key_vault_key_id="azurerm_key_vault_key.aks.id",
                    oms_workspace_id="azurerm_log_analytics_workspace.aks.id",
                    defender=True,
                    azure_policy=True,
                )
            ]
        )
        gcp_private_cluster_findings = _evaluate_gcp(
            [_gke_cluster(endpoint=None, private_endpoint=True)],
            ("gcp-gke-broad-authorized-networks",),
        )

        self.assertEqual(
            _finding_ids(aws_private_endpoint_findings), frozenset({"aws-eks-private-endpoint-not-enabled"})
        )
        self.assertEqual(
            _finding_ids(azure_private_cluster_findings),
            frozenset({"azure-aks-private-cluster-not-enabled"}),
        )
        self.assertEqual(gcp_private_cluster_findings, [])

        for prefix, findings in (
            ("aws-", aws_private_endpoint_findings),
            ("azure-", azure_private_cluster_findings),
        ):
            with self.subTest(provider_prefix=prefix):
                self.assertTrue(all(finding.rule_id.startswith(prefix) for finding in findings))


if __name__ == "__main__":
    unittest.main()
