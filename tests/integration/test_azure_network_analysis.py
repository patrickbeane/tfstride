from __future__ import annotations

import unittest

from tests.integration.analysis_support import AZURE_COMPUTE_FIXTURE_PATH
from tfstride.app import TfStride
from tfstride.providers.azure.resource_facts import azure_facts


class AzureNetworkAnalysisIntegrationTests(unittest.TestCase):
    def test_compute_fixture_resolves_public_ip_nic_subnet_and_nsg_graph(self) -> None:
        result = TfStride().analyze_plan(AZURE_COMPUTE_FIXTURE_PATH)
        inventory = result.inventory
        virtual_machine = inventory.get_by_address("azurerm_linux_virtual_machine.web")
        network_interface = inventory.get_by_address("azurerm_network_interface.web")
        subnet = inventory.get_by_address("azurerm_subnet.web")
        assert virtual_machine is not None
        assert network_interface is not None
        assert subnet is not None

        self.assertEqual(inventory.provider, "azure")
        self.assertEqual(len(inventory.resources), 10)
        self.assertEqual(inventory.unsupported_resources, [])
        self.assertEqual(virtual_machine.vpc_id, "azurerm_virtual_network.main")
        self.assertEqual(virtual_machine.subnet_ids, ("azurerm_subnet.web",))
        self.assertEqual(
            virtual_machine.security_group_ids,
            (
                "azurerm_network_security_group.web_nic",
                "azurerm_network_security_group.web_subnet",
            ),
        )
        self.assertEqual(
            azure_facts(virtual_machine).resolved_network_interface_addresses,
            ["azurerm_network_interface.web"],
        )
        self.assertEqual(
            azure_facts(virtual_machine).resolved_public_ip_addresses,
            ["azurerm_public_ip.web"],
        )
        self.assertEqual(subnet.security_group_ids, ("azurerm_network_security_group.web_subnet",))
        self.assertEqual(
            network_interface.security_group_ids,
            (
                "azurerm_network_security_group.web_nic",
                "azurerm_network_security_group.web_subnet",
            ),
        )


if __name__ == "__main__":
    unittest.main()
