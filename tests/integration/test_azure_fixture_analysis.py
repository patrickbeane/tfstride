from __future__ import annotations

import unittest
from collections import Counter

from tests.integration.analysis_support import AZURE_FIXTURE_PATH
from tfstride.app import TfStride
from tfstride.models import BoundaryType
from tfstride.reporting.markdown import render_markdown


class AzureFixtureAnalysisIntegrationTests(unittest.TestCase):
    def test_mixed_fixture_combines_existing_storage_and_compute_findings(self) -> None:
        result = TfStride().analyze_plan(AZURE_FIXTURE_PATH)

        self.assertEqual(
            [finding.rule_id for finding in result.findings],
            [
                "azure-aks-api-server-public-unrestricted",
                "azure-storage-account-shared-key-enabled",
                "azure-storage-account-nested-public-access-enabled",
                "azure-aks-defender-not-enabled",
                "azure-aks-key-management-service-not-configured",
                "azure-aks-monitoring-agent-not-enabled",
                "azure-key-vault-public-network-access",
                "azure-key-vault-missing-private-endpoint",
                "azure-key-vault-purge-protection-disabled",
                "azure-storage-account-minimum-tls-below-1-2",
                "azure-storage-account-public-network-unrestricted",
                "azure-storage-account-missing-private-endpoint",
                "azure-storage-container-public-access",
                "azure-diagnostic-settings-missing",
                "azure-diagnostic-settings-missing",
                "azure-diagnostic-settings-missing",
                "azure-public-compute-broad-ingress",
                "azure-aks-azure-policy-not-enabled",
                "azure-aks-rbac-posture-weak",
                "azure-aks-local-accounts-not-disabled",
                "azure-aks-network-policy-missing",
                "azure-aks-workload-identity-not-enabled",
            ],
        )
        self.assertEqual(
            Counter(finding.severity.value for finding in result.findings),
            Counter({"medium": 14, "high": 3, "low": 5}),
        )
        self.assertEqual(
            [boundary.identifier for boundary in result.trust_boundaries],
            [
                "internet-to-service:internet->azurerm_storage_account.assets",
                "internet-to-service:internet->azurerm_linux_virtual_machine.web",
                "internet-to-service:internet->azurerm_key_vault.application",
            ],
        )
        self.assertTrue(
            all(boundary.boundary_type is BoundaryType.INTERNET_TO_SERVICE for boundary in result.trust_boundaries)
        )

    def test_mixed_fixture_auto_detection_and_explicit_provider_match(self) -> None:
        automatic = TfStride().analyze_plan(AZURE_FIXTURE_PATH)
        explicit = TfStride(provider="azure").analyze_plan(AZURE_FIXTURE_PATH)

        self.assertEqual(automatic.inventory.provider, "azure")
        self.assertEqual(
            [resource.address for resource in automatic.inventory.resources],
            [resource.address for resource in explicit.inventory.resources],
        )
        self.assertEqual(
            [boundary.identifier for boundary in automatic.trust_boundaries],
            [boundary.identifier for boundary in explicit.trust_boundaries],
        )
        self.assertEqual(
            [finding.rule_id for finding in automatic.findings],
            [finding.rule_id for finding in explicit.findings],
        )

    def test_mixed_fixture_report_is_deterministic(self) -> None:
        engine = TfStride()

        first = render_markdown(engine.analyze_plan(AZURE_FIXTURE_PATH))
        second = render_markdown(engine.analyze_plan(AZURE_FIXTURE_PATH))

        self.assertEqual(first, second)
        self.assertIn("azurerm_key_vault", first)
        self.assertIn("Unsupported resources: `0`", first)
        self.assertIn("Internet-exposed Azure virtual machine permits broad ingress", first)
        self.assertIn("Azure Storage container is publicly accessible", first)
        self.assertIn("Azure Key Vault allows unrestricted public network access", first)
        self.assertIn("AKS control plane is public without narrow authorized IP ranges", first)
        self.assertIn("AKS workload identity is not fully enabled", first)


if __name__ == "__main__":
    unittest.main()
