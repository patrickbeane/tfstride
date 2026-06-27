from __future__ import annotations

import unittest

from tests.integration.analysis_support import (
    AZURE_COMPUTE_FIXTURE_PATH,
    AZURE_NSG_PRECEDENCE_FIXTURE_PATH,
)
from tfstride.app import TfStride
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.reporting.markdown import render_markdown


class AzureNsgPrecedenceAnalysisIntegrationTests(unittest.TestCase):
    def test_deny_before_allow_fixture_blocks_public_compute_exposure(self) -> None:
        result = TfStride().analyze_plan(AZURE_NSG_PRECEDENCE_FIXTURE_PATH)
        virtual_machine = result.inventory.get_by_address("azurerm_linux_virtual_machine.web")
        network_security_group = result.inventory.get_by_address("azurerm_network_security_group.web_nic")
        assert virtual_machine is not None
        assert network_security_group is not None

        self.assertEqual(result.inventory.provider, "azure")
        self.assertEqual(result.findings, [])
        self.assertEqual(result.trust_boundaries, [])
        self.assertFalse(virtual_machine.public_exposure)
        self.assertEqual(azure_facts(virtual_machine).public_compute_exposure_paths, [])
        self.assertEqual(
            [rule["name"] for rule in azure_facts(network_security_group).network_security_rules],
            ["allow-ssh", "deny-ssh"],
        )

    def test_deny_before_allow_changes_outcome_from_compute_fixture(self) -> None:
        exposed = TfStride().analyze_plan(AZURE_COMPUTE_FIXTURE_PATH)
        denied = TfStride().analyze_plan(AZURE_NSG_PRECEDENCE_FIXTURE_PATH)

        self.assertIn("azure-public-compute-broad-ingress", [finding.rule_id for finding in exposed.findings])
        self.assertNotIn("azure-public-compute-broad-ingress", [finding.rule_id for finding in denied.findings])
        self.assertEqual(
            [boundary.identifier for boundary in exposed.trust_boundaries],
            ["internet-to-service:internet->azurerm_linux_virtual_machine.web"],
        )
        self.assertEqual(denied.trust_boundaries, [])

    def test_nsg_precedence_report_is_deterministic(self) -> None:
        engine = TfStride()

        first = render_markdown(engine.analyze_plan(AZURE_NSG_PRECEDENCE_FIXTURE_PATH))
        second = render_markdown(engine.analyze_plan(AZURE_NSG_PRECEDENCE_FIXTURE_PATH))

        self.assertEqual(first, second)
        self.assertIn("This run identified **0 trust boundaries** and **0 findings**", first)
        self.assertIn("No trust boundaries were discovered.", first)


if __name__ == "__main__":
    unittest.main()
