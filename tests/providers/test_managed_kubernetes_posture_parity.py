from __future__ import annotations

import unittest

from tests.providers.aws.test_aws_eks_rules import (
    _EKS_RULE_IDS as AWS_EKS_RULE_IDS,
)
from tests.providers.aws.test_aws_eks_rules import (
    _addon as _aws_eks_addon,
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
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS

GCP_GKE_RULE_IDS = (
    "gcp-gke-public-control-plane",
    "gcp-gke-broad-authorized-networks",
    "gcp-gke-workload-identity-disabled",
    "gcp-gke-legacy-metadata-endpoints-enabled",
    "gcp-gke-broad-node-service-account",
    "gcp-gke-control-plane-logging-incomplete",
    "gcp-gke-network-policy-disabled",
    "gcp-gke-secrets-encryption-not-configured",
    "gcp-gke-legacy-abac-enabled-or-unknown",
    "gcp-gke-client-certificate-auth-enabled-or-unknown",
    "gcp-gke-shielded-nodes-disabled-or-unknown",
    "gcp-gke-binary-authorization-not-enabled",
)
ALL_MANAGED_KUBERNETES_RULE_IDS = frozenset(AWS_EKS_RULE_IDS + GCP_GKE_RULE_IDS + AZURE_AKS_RULE_IDS)

SECOND_TIER_MANAGED_KUBERNETES_CONCEPT_RULE_IDS = {
    "identity_and_auth_hardening": {
        "aws": frozenset({"aws-eks-authentication-mode-weak-or-unknown"}),
        "gcp": frozenset(
            {
                "gcp-gke-workload-identity-disabled",
                "gcp-gke-legacy-abac-enabled-or-unknown",
                "gcp-gke-client-certificate-auth-enabled-or-unknown",
                "gcp-gke-shielded-nodes-disabled-or-unknown",
                "gcp-gke-binary-authorization-not-enabled",
            }
        ),
        "azure": frozenset(
            {
                "azure-aks-local-accounts-not-disabled",
                "azure-aks-rbac-posture-weak",
                "azure-aks-workload-identity-not-enabled",
            }
        ),
    },
    "secrets_encryption": {
        "aws": frozenset({"aws-eks-secrets-encryption-not-configured"}),
        "gcp": frozenset({"gcp-gke-secrets-encryption-not-configured"}),
        "azure": frozenset({"azure-aks-key-management-service-not-configured"}),
    },
    "logging_and_monitoring": {
        "aws": frozenset({"aws-eks-control-plane-logging-incomplete"}),
        "gcp": frozenset({"gcp-gke-control-plane-logging-incomplete"}),
        "azure": frozenset(
            {
                "azure-aks-monitoring-agent-not-enabled",
                "azure-aks-defender-not-enabled",
                "azure-aks-azure-policy-not-enabled",
            }
        ),
    },
    "network_policy_and_addons": {
        "aws": frozenset({"aws-eks-vpc-cni-network-policy-not-enabled"}),
        "gcp": frozenset({"gcp-gke-network-policy-disabled"}),
        "azure": frozenset({"azure-aks-network-policy-missing"}),
    },
}
SECOND_TIER_MANAGED_KUBERNETES_RULE_IDS_BY_PROVIDER = {
    provider: frozenset(
        rule_id
        for provider_expectations in SECOND_TIER_MANAGED_KUBERNETES_CONCEPT_RULE_IDS.values()
        for rule_id in provider_expectations[provider]
    )
    for provider in ("aws", "gcp", "azure")
}
SECOND_TIER_MANAGED_KUBERNETES_RULE_IDS = frozenset(
    rule_id for rule_ids in SECOND_TIER_MANAGED_KUBERNETES_RULE_IDS_BY_PROVIDER.values() for rule_id in rule_ids
)


def _flatten(rule_groups: tuple[tuple[str, ...], ...]) -> frozenset[str]:
    return frozenset(rule_id for rule_group in rule_groups for rule_id in rule_group)


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
                    legacy_abac_enabled=True,
                    client_certificate_enabled=True,
                    shielded_nodes_enabled=False,
                    binary_authorization_evaluation_mode="DISABLED",
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
                    logging_service="logging.googleapis.com/kubernetes",
                    logging_components=["SYSTEM_COMPONENTS", "APISERVER", "SCHEDULER", "CONTROLLER_MANAGER"],
                    network_policy_enabled=True,
                    network_policy_provider="CALICO",
                    database_encryption_state="ENCRYPTED",
                    database_encryption_key_name=(
                        "projects/tfstride-demo/locations/global/keyRings/gke/cryptoKeys/secrets"
                    ),
                    legacy_abac_enabled=False,
                    client_certificate_enabled=False,
                    shielded_nodes_enabled=True,
                    binary_authorization_evaluation_mode="PROJECT_SINGLETON_POLICY_ENFORCE",
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

    def test_managed_kubernetes_second_tier_rule_families_are_registered(self) -> None:
        self.assertLessEqual(SECOND_TIER_MANAGED_KUBERNETES_RULE_IDS, ALL_MANAGED_KUBERNETES_RULE_IDS)
        self.assertLessEqual(SECOND_TIER_MANAGED_KUBERNETES_RULE_IDS_BY_PROVIDER["aws"], _flatten(AWS_RULE_GROUP_IDS))
        self.assertLessEqual(SECOND_TIER_MANAGED_KUBERNETES_RULE_IDS_BY_PROVIDER["gcp"], _flatten(GCP_RULE_GROUP_IDS))
        self.assertLessEqual(
            SECOND_TIER_MANAGED_KUBERNETES_RULE_IDS_BY_PROVIDER["azure"],
            _flatten(AZURE_RULE_GROUP_IDS),
        )

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

    def test_managed_kubernetes_second_tier_posture_findings_are_pinned_by_concept(self) -> None:
        aws_findings = _evaluate_aws(
            [
                _aws_safe_eks_cluster(
                    enabled_cluster_log_types=[],
                    encryption_resources=[],
                    authentication_mode="CONFIG_MAP",
                ),
                _aws_eks_addon(configuration_values='{ "env": { "ENABLE_NETWORK_POLICY": "false" } }'),
            ],
            SECOND_TIER_MANAGED_KUBERNETES_RULE_IDS,
        )
        gcp_findings = _evaluate_gcp(
            [
                _gke_cluster(
                    logging_service="logging.googleapis.com/none",
                    logging_components=[],
                    network_policy_enabled=False,
                    network_policy_provider="PROVIDER_UNSPECIFIED",
                    database_encryption_state="DECRYPTED",
                    legacy_abac_enabled=True,
                    client_certificate_enabled=True,
                    shielded_nodes_enabled=False,
                    binary_authorization_evaluation_mode="DISABLED",
                )
            ],
            SECOND_TIER_MANAGED_KUBERNETES_RULE_IDS,
        )
        azure_findings = _evaluate_azure(
            [
                _azure_aks_cluster(
                    private_cluster=True,
                    authorized_ip_ranges=["198.51.100.10/32"],
                    local_account_disabled=False,
                    kubernetes_rbac=False,
                    network_policy=AZURE_MISSING,
                    oidc_issuer=False,
                    workload_identity=False,
                    kms_key_vault_key_id=AZURE_MISSING,
                    oms_workspace_id=AZURE_MISSING,
                    defender=False,
                    azure_policy=False,
                )
            ],
            SECOND_TIER_MANAGED_KUBERNETES_RULE_IDS,
        )

        findings_by_provider = {
            "aws": _finding_ids(aws_findings),
            "gcp": _finding_ids(gcp_findings),
            "azure": _finding_ids(azure_findings),
        }
        self.assertEqual(findings_by_provider, SECOND_TIER_MANAGED_KUBERNETES_RULE_IDS_BY_PROVIDER)
        for concept, provider_expectations in SECOND_TIER_MANAGED_KUBERNETES_CONCEPT_RULE_IDS.items():
            for provider, expected_rule_ids in provider_expectations.items():
                with self.subTest(concept=concept, provider=provider):
                    self.assertLessEqual(expected_rule_ids, findings_by_provider[provider])

    def test_managed_kubernetes_second_tier_safe_posture_is_quiet(self) -> None:
        aws_findings = _evaluate_aws(
            [
                _aws_safe_eks_cluster(),
                _aws_eks_addon(configuration_values='{ "env": { "ENABLE_NETWORK_POLICY": "true" } }'),
            ],
            SECOND_TIER_MANAGED_KUBERNETES_RULE_IDS,
        )
        gcp_findings = _evaluate_gcp(
            [
                _gke_cluster(
                    workload_identity_pool="tfstride-demo.svc.id.goog",
                    logging_service="logging.googleapis.com/kubernetes",
                    logging_components=["SYSTEM_COMPONENTS", "APISERVER", "SCHEDULER", "CONTROLLER_MANAGER"],
                    network_policy_enabled=True,
                    network_policy_provider="CALICO",
                    database_encryption_state="ENCRYPTED",
                    database_encryption_key_name=(
                        "projects/tfstride-demo/locations/global/keyRings/gke/cryptoKeys/secrets"
                    ),
                    legacy_abac_enabled=False,
                    client_certificate_enabled=False,
                    shielded_nodes_enabled=True,
                    binary_authorization_evaluation_mode="PROJECT_SINGLETON_POLICY_ENFORCE",
                )
            ],
            SECOND_TIER_MANAGED_KUBERNETES_RULE_IDS,
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
            ],
            SECOND_TIER_MANAGED_KUBERNETES_RULE_IDS,
        )

        self.assertEqual(aws_findings, [])
        self.assertEqual(gcp_findings, [])
        self.assertEqual(azure_findings, [])

    def test_managed_kubernetes_second_tier_rules_remain_provider_local(self) -> None:
        findings_by_provider = {
            "aws": _evaluate_aws(
                [
                    _aws_safe_eks_cluster(
                        enabled_cluster_log_types=[],
                        encryption_resources=[],
                        authentication_mode="CONFIG_MAP",
                    ),
                    _aws_eks_addon(configuration_values='{ "env": { "ENABLE_NETWORK_POLICY": "false" } }'),
                ],
                SECOND_TIER_MANAGED_KUBERNETES_RULE_IDS,
            ),
            "gcp": _evaluate_gcp(
                [
                    _gke_cluster(
                        logging_service="logging.googleapis.com/none",
                        logging_components=[],
                        network_policy_enabled=False,
                        network_policy_provider="PROVIDER_UNSPECIFIED",
                        database_encryption_state="DECRYPTED",
                        legacy_abac_enabled=True,
                        client_certificate_enabled=True,
                        shielded_nodes_enabled=False,
                        binary_authorization_evaluation_mode="DISABLED",
                    )
                ],
                SECOND_TIER_MANAGED_KUBERNETES_RULE_IDS,
            ),
            "azure": _evaluate_azure(
                [
                    _azure_aks_cluster(
                        private_cluster=True,
                        authorized_ip_ranges=["198.51.100.10/32"],
                        local_account_disabled=False,
                        kubernetes_rbac=False,
                        network_policy=AZURE_MISSING,
                        oidc_issuer=False,
                        workload_identity=False,
                        kms_key_vault_key_id=AZURE_MISSING,
                        oms_workspace_id=AZURE_MISSING,
                        defender=False,
                        azure_policy=False,
                    )
                ],
                SECOND_TIER_MANAGED_KUBERNETES_RULE_IDS,
            ),
        }

        for provider, findings in findings_by_provider.items():
            with self.subTest(provider=provider):
                self.assertTrue(findings)
                self.assertTrue(all(finding.rule_id.startswith(f"{provider}-") for finding in findings))


if __name__ == "__main__":
    unittest.main()
