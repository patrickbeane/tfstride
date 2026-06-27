from __future__ import annotations

import unittest
from collections import Counter

from tests.integration.analysis_support import AZURE_NIGHTMARE_FIXTURE_PATH
from tfstride.app import TfStride
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.reporting.markdown import render_markdown


class AzureNightmareAnalysisIntegrationTests(unittest.TestCase):
    def test_nightmare_fixture_stacks_existing_storage_and_compute_findings(self) -> None:
        result = TfStride().analyze_plan(AZURE_NIGHTMARE_FIXTURE_PATH)

        self.assertEqual(result.inventory.provider, "azure")
        self.assertEqual(len(result.inventory.resources), 26)
        self.assertEqual(len(result.findings), 20)
        self.assertEqual(
            Counter(finding.rule_id for finding in result.findings),
            Counter(
                {
                    "azure-storage-container-public-access": 3,
                    "azure-storage-account-shared-key-enabled": 2,
                    "azure-storage-account-nested-public-access-enabled": 2,
                    "azure-storage-account-minimum-tls-below-1-2": 2,
                    "azure-storage-account-public-network-unrestricted": 2,
                    "azure-storage-account-missing-private-endpoint": 2,
                    "azure-public-compute-broad-ingress": 2,
                    "azure-managed-identity-broad-rbac": 1,
                    "azure-public-workload-sensitive-resource-access": 1,
                    "azure-key-vault-public-network-access": 1,
                    "azure-key-vault-missing-private-endpoint": 1,
                    "azure-key-vault-purge-protection-disabled": 1,
                }
            ),
        )
        self.assertEqual(
            Counter(finding.severity.value for finding in result.findings),
            Counter({"medium": 14, "high": 6}),
        )

    def test_nightmare_fixture_stresses_distinct_ssh_and_rdp_nsg_paths(self) -> None:
        result = TfStride().analyze_plan(AZURE_NIGHTMARE_FIXTURE_PATH)
        linux_vm = result.inventory.get_by_address("azurerm_linux_virtual_machine.web")
        windows_vm = result.inventory.get_by_address("azurerm_windows_virtual_machine.admin")
        assert linux_vm is not None
        assert windows_vm is not None

        linux_paths = azure_facts(linux_vm).public_compute_exposure_paths
        windows_paths = azure_facts(windows_vm).public_compute_exposure_paths

        self.assertEqual([(path["from_port"], path["to_port"]) for path in linux_paths], [(22, 22)])
        self.assertEqual([(path["from_port"], path["to_port"]) for path in windows_paths], [(3389, 3389)])
        self.assertTrue(any("allow-ssh priority 200" in rule for rule in linux_paths[0]["network_security_rules"]))
        self.assertTrue(any("allow-rdp priority 200" in rule for rule in windows_paths[0]["network_security_rules"]))
        self.assertEqual(
            [boundary.target for boundary in result.trust_boundaries],
            [
                "azurerm_storage_account.assets",
                "azurerm_linux_virtual_machine.web",
                "azurerm_storage_account.logs",
                "azurerm_windows_virtual_machine.admin",
                "azurerm_key_vault.application",
            ],
        )

    def test_nightmare_fixture_includes_managed_identity_sensitive_resource_path(self) -> None:
        result = TfStride().analyze_plan(AZURE_NIGHTMARE_FIXTURE_PATH)
        identity = result.inventory.get_by_address("azurerm_user_assigned_identity.deploy")
        assert identity is not None

        identity_assignments = azure_facts(identity).managed_identity_role_assignments
        self.assertEqual(len(identity_assignments), 1)
        self.assertEqual(identity_assignments[0]["target_resource_address"], "azurerm_storage_account.logs")
        findings = {finding.rule_id: finding for finding in result.findings}
        self.assertEqual(
            findings["azure-public-workload-sensitive-resource-access"].trust_boundary_id,
            "internet-to-service:internet->azurerm_linux_virtual_machine.web",
        )
        self.assertEqual(
            findings["azure-managed-identity-broad-rbac"].affected_resources,
            [
                "azurerm_user_assigned_identity.deploy",
                "azurerm_role_assignment.storage_owner",
                "azurerm_storage_account.logs",
            ],
        )

    def test_nightmare_fixture_keeps_unsupported_resources_as_coverage_only(self) -> None:
        result = TfStride().analyze_plan(AZURE_NIGHTMARE_FIXTURE_PATH)
        coverage = result.analysis_coverage.resources

        self.assertEqual(coverage.total_resources, 27)
        self.assertEqual(coverage.provider_resources, 27)
        self.assertEqual(coverage.normalized_resources, 26)
        self.assertEqual(coverage.unsupported_resources, 1)
        self.assertEqual(
            coverage.unsupported_resource_types,
            {"azurerm_kubernetes_cluster": 1},
        )
        self.assertEqual(
            result.inventory.unsupported_resources,
            ["azurerm_kubernetes_cluster.platform"],
        )

    def test_nightmare_report_is_deterministic(self) -> None:
        engine = TfStride()

        first = render_markdown(engine.analyze_plan(AZURE_NIGHTMARE_FIXTURE_PATH))
        second = render_markdown(engine.analyze_plan(AZURE_NIGHTMARE_FIXTURE_PATH))

        self.assertEqual(first, second)
        self.assertIn("azurerm_windows_virtual_machine.admin", first)
        self.assertIn("allow-rdp priority 200", first)
        self.assertIn("azurerm_storage_container.public_backups", first)
        self.assertIn("Internet-exposed Azure workload can access sensitive resources", first)


if __name__ == "__main__":
    unittest.main()
