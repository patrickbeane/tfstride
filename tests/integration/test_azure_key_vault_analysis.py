from __future__ import annotations

import unittest

from tests.integration.analysis_support import AZURE_KEY_VAULT_FIXTURE_PATH
from tfstride.app import TfStride
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.reporting.markdown import render_markdown


class AzureKeyVaultAnalysisIntegrationTests(unittest.TestCase):
    def test_key_vault_fixture_models_network_identity_and_child_resources(self) -> None:
        result = TfStride().analyze_plan(AZURE_KEY_VAULT_FIXTURE_PATH)

        self.assertEqual(result.inventory.provider, "azure")
        self.assertEqual(len(result.inventory.resources), 8)
        self.assertEqual(result.inventory.unsupported_resources, [])
        public_vault = result.inventory.get_by_address("azurerm_key_vault.public")
        secret = result.inventory.get_by_address("azurerm_key_vault_secret.api_key")
        assert public_vault is not None
        assert secret is not None
        self.assertTrue(public_vault.direct_internet_reachable)
        self.assertEqual(
            azure_facts(public_vault).key_vault_related_resource_addresses,
            [
                "azurerm_key_vault_secret.api_key",
                "azurerm_key_vault_key.signing",
                "azurerm_key_vault_certificate.tls",
                "azurerm_key_vault_access_policy.operators",
                "azurerm_role_assignment.key_vault_admin",
            ],
        )
        self.assertEqual(
            azure_facts(secret).resolved_key_vault_address,
            "azurerm_key_vault.public",
        )

    def test_key_vault_fixture_emits_distinct_network_identity_and_recovery_findings(self) -> None:
        result = TfStride().analyze_plan(AZURE_KEY_VAULT_FIXTURE_PATH)

        self.assertEqual(
            [finding.rule_id for finding in result.findings],
            [
                "azure-key-vault-privileged-access",
                "azure-key-vault-public-network-access",
                "azure-key-vault-purge-protection-disabled",
            ],
        )
        self.assertEqual(
            [boundary.identifier for boundary in result.trust_boundaries],
            ["internet-to-service:internet->azurerm_key_vault.public"],
        )
        findings = {finding.rule_id: finding for finding in result.findings}
        self.assertIsNone(findings["azure-key-vault-privileged-access"].trust_boundary_id)
        self.assertEqual(
            findings["azure-key-vault-public-network-access"].trust_boundary_id,
            "internet-to-service:internet->azurerm_key_vault.public",
        )

    def test_key_vault_fixture_observes_private_network_and_authorization_posture(self) -> None:
        result = TfStride().analyze_plan(AZURE_KEY_VAULT_FIXTURE_PATH)
        observation_ids = [observation.observation_id for observation in result.observations]

        self.assertEqual(observation_ids.count("azure-key-vault-network-restricted"), 2)
        self.assertEqual(observation_ids.count("azure-key-vault-authorization-model-observed"), 2)
        private_observations = [
            observation
            for observation in result.observations
            if "azurerm_key_vault.private" in observation.affected_resources
        ]
        self.assertEqual(len(private_observations), 2)

    def test_key_vault_report_is_deterministic(self) -> None:
        engine = TfStride()

        first = render_markdown(engine.analyze_plan(AZURE_KEY_VAULT_FIXTURE_PATH))
        second = render_markdown(engine.analyze_plan(AZURE_KEY_VAULT_FIXTURE_PATH))

        self.assertEqual(first, second)
        self.assertIn("Azure Key Vault grants privileged identity access", first)
        self.assertIn("Azure Key Vault network access is restricted", first)


if __name__ == "__main__":
    unittest.main()
