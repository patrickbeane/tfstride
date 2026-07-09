from __future__ import annotations

import unittest

from tests.helpers.paths import FIXTURES_DIR
from tfstride.app import TfStride
from tfstride.models import Severity

FIXTURE_PATH = FIXTURES_DIR / "azure" / "sample_azure_compute_plan.json"


class AzureComputeRuleTests(unittest.TestCase):
    def test_public_compute_finding_contains_readable_relationship_evidence(self) -> None:
        result = TfStride().analyze_plan(FIXTURE_PATH)

        compute_findings = [
            finding for finding in result.findings if finding.rule_id == "azure-public-compute-broad-ingress"
        ]
        self.assertEqual(len(compute_findings), 1)
        finding = compute_findings[0]
        evidence = {item.key: item.values for item in finding.evidence}

        self.assertEqual(finding.rule_id, "azure-public-compute-broad-ingress")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(
            finding.affected_resources,
            [
                "azurerm_linux_virtual_machine.web",
                "azurerm_network_interface.web",
                "azurerm_public_ip.web",
                "azurerm_network_security_group.web_nic",
                "azurerm_network_security_group.web_subnet",
            ],
        )
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->azurerm_linux_virtual_machine.web",
        )
        self.assertEqual(
            evidence["public_ip_path"],
            [
                "azurerm_linux_virtual_machine.web -> azurerm_network_interface.web -> "
                "azurerm_public_ip.web (203.0.113.10)"
            ],
        )
        self.assertEqual(
            evidence["network_security_path"],
            [
                "azurerm_linux_virtual_machine.web -> azurerm_network_interface.web -> "
                "azurerm_network_security_group.web_nic",
                "azurerm_linux_virtual_machine.web -> azurerm_network_interface.web -> "
                "azurerm_network_security_group.web_subnet",
            ],
        )
        self.assertTrue(any("allow-ssh priority 200" in value for value in evidence["network_security_rules"]))
        self.assertTrue(any("allow-internet-tcp priority 300" in value for value in evidence["network_security_rules"]))


if __name__ == "__main__":
    unittest.main()
