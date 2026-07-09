from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from tests.helpers.paths import FIXTURES_DIR
from tfstride.app import TfStride
from tfstride.providers.azure.resource_decoration.public_exposure import is_risky_public_compute_path
from tfstride.providers.azure.resource_facts import azure_facts

FIXTURE_PATH = FIXTURES_DIR / "azure" / "sample_azure_compute_plan.json"


class AzureComputeExposureNormalizationTests(unittest.TestCase):
    def test_fixture_intersects_subnet_and_nic_nsg_decisions(self) -> None:
        result = TfStride().analyze_plan(FIXTURE_PATH)
        virtual_machine = result.inventory.get_by_address("azurerm_linux_virtual_machine.web")
        assert virtual_machine is not None

        paths = azure_facts(virtual_machine).public_compute_exposure_paths

        self.assertTrue(virtual_machine.public_access_configured)
        self.assertTrue(virtual_machine.public_exposure)
        self.assertTrue(virtual_machine.direct_internet_reachable)
        self.assertEqual(len(paths), 1)
        self.assertEqual(
            (paths[0]["protocol"], paths[0]["from_port"], paths[0]["to_port"]),
            ("tcp", 22, 22),
        )
        self.assertEqual(
            paths[0]["network_security_groups"],
            [
                "azurerm_network_security_group.web_nic",
                "azurerm_network_security_group.web_subnet",
            ],
        )
        self.assertTrue(is_risky_public_compute_path(paths[0]))
        self.assertTrue(any("allow-ssh priority 200" in rule for rule in paths[0]["network_security_rules"]))
        self.assertTrue(any("allow-internet-tcp priority 300" in rule for rule in paths[0]["network_security_rules"]))
        self.assertFalse(any("deny-rdp" in rule for rule in paths[0]["network_security_rules"]))

    def test_public_https_path_is_exposed_but_not_broad_ingress(self) -> None:
        payload = self._fixture_payload()
        ssh_rule = next(
            resource
            for resource in payload["planned_values"]["root_module"]["resources"]
            if resource["address"] == "azurerm_network_security_rule.allow_ssh"
        )
        ssh_rule["values"]["name"] = "allow-https"
        ssh_rule["values"]["destination_port_range"] = "443"

        result = self._analyze_payload(payload)
        virtual_machine = result.inventory.get_by_address("azurerm_linux_virtual_machine.web")
        assert virtual_machine is not None
        paths = azure_facts(virtual_machine).public_compute_exposure_paths

        self.assertTrue(virtual_machine.public_exposure)
        self.assertEqual([(path["from_port"], path["to_port"]) for path in paths], [(443, 443)])
        self.assertFalse(any(is_risky_public_compute_path(path) for path in paths))
        self.assertNotIn(
            "azure-public-compute-broad-ingress",
            {finding.rule_id for finding in result.findings},
        )

    def test_higher_priority_nic_deny_all_blocks_subnet_allow(self) -> None:
        payload = self._fixture_payload()
        nic_nsg = next(
            resource
            for resource in payload["planned_values"]["root_module"]["resources"]
            if resource["address"] == "azurerm_network_security_group.web_nic"
        )
        deny_rule = nic_nsg["values"]["security_rule"][0]
        deny_rule["name"] = "deny-internet"
        deny_rule["destination_port_range"] = "*"

        result = self._analyze_payload(payload)
        virtual_machine = result.inventory.get_by_address("azurerm_linux_virtual_machine.web")
        assert virtual_machine is not None

        self.assertTrue(virtual_machine.public_access_configured)
        self.assertFalse(virtual_machine.public_exposure)
        self.assertFalse(virtual_machine.direct_internet_reachable)
        self.assertEqual(azure_facts(virtual_machine).public_compute_exposure_paths, [])
        self.assertNotIn(
            "azure-public-compute-broad-ingress",
            {finding.rule_id for finding in result.findings},
        )

    def _fixture_payload(self) -> dict:
        return copy.deepcopy(json.loads(FIXTURE_PATH.read_text(encoding="utf-8")))

    def _analyze_payload(self, payload: dict):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "plan.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return TfStride().analyze_plan(path)


if __name__ == "__main__":
    unittest.main()
