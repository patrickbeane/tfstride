from __future__ import annotations

import unittest
from collections import Counter

from tests.integration.analysis_support import AZURE_IDENTITY_FIXTURE_PATH
from tfstride.app import TfStride
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.reporting.markdown import render_markdown


class AzureIdentityAnalysisIntegrationTests(unittest.TestCase):
    def test_identity_fixture_emits_managed_identity_and_sensitive_path_findings(self) -> None:
        result = TfStride().analyze_plan(AZURE_IDENTITY_FIXTURE_PATH)

        self.assertEqual(result.inventory.provider, "azure")
        self.assertEqual(len(result.inventory.resources), 13)
        self.assertEqual(result.inventory.unsupported_resources, [])
        self.assertEqual(
            [finding.rule_id for finding in result.findings],
            [
                "azure-managed-identity-broad-rbac",
                "azure-public-workload-sensitive-resource-access",
                "azure-public-compute-broad-ingress",
            ],
        )
        self.assertEqual(
            Counter(finding.severity.value for finding in result.findings),
            Counter({"high": 2, "medium": 1}),
        )

    def test_identity_fixture_keeps_private_storage_quiet_while_modeling_sensitive_scope(self) -> None:
        result = TfStride().analyze_plan(AZURE_IDENTITY_FIXTURE_PATH)
        storage = result.inventory.get_by_address("azurerm_storage_account.logs")
        identity = result.inventory.get_by_address("azurerm_user_assigned_identity.deploy")
        assert storage is not None
        assert identity is not None

        self.assertFalse(storage.public_exposure)
        self.assertNotIn(
            "azure-storage-account-public-network-unrestricted",
            [finding.rule_id for finding in result.findings],
        )
        self.assertEqual(
            [
                assignment["target_resource_address"]
                for assignment in azure_facts(identity).managed_identity_role_assignments
            ],
            [None, "azurerm_storage_account.logs"],
        )

    def test_identity_fixture_findings_include_deterministic_role_evidence(self) -> None:
        result = TfStride().analyze_plan(AZURE_IDENTITY_FIXTURE_PATH)
        findings = {finding.rule_id: finding for finding in result.findings}
        broad_rbac = findings["azure-managed-identity-broad-rbac"]
        sensitive_path = findings["azure-public-workload-sensitive-resource-access"]
        broad_evidence = {item.key: item.values for item in broad_rbac.evidence}
        path_evidence = {item.key: item.values for item in sensitive_path.evidence}

        self.assertEqual(
            broad_rbac.affected_resources,
            [
                "azurerm_user_assigned_identity.deploy",
                "azurerm_role_assignment.subscription_owner",
                "azurerm_role_assignment.storage_owner",
                "azurerm_storage_account.logs",
            ],
        )
        self.assertEqual(
            broad_evidence["breadth_signals"],
            ["subscription_scope", "broad_builtin_role", "sensitive_resource_scope"],
        )
        self.assertIn("role=Owner", broad_evidence["role_assignments"][0])
        self.assertEqual(
            sensitive_path.trust_boundary_id,
            "internet-to-service:internet->azurerm_linux_virtual_machine.web",
        )
        self.assertIn("target=azurerm_storage_account.logs", path_evidence["sensitive_resource_assignments"][0])

    def test_identity_fixture_report_is_deterministic(self) -> None:
        engine = TfStride()

        first = render_markdown(engine.analyze_plan(AZURE_IDENTITY_FIXTURE_PATH))
        second = render_markdown(engine.analyze_plan(AZURE_IDENTITY_FIXTURE_PATH))

        self.assertEqual(first, second)
        self.assertIn("Azure managed identity has broad RBAC authority", first)
        self.assertIn("Internet-exposed Azure workload can access sensitive resources", first)


if __name__ == "__main__":
    unittest.main()
