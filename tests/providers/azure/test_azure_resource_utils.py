from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_utils import (
    azure_reference_key,
    azure_resource_references,
    parse_network_security_rules,
)


class AzureResourceUtilsTests(unittest.TestCase):
    def test_reference_keys_normalize_terraform_expressions_and_suffixes(self) -> None:
        self.assertEqual(azure_reference_key("${azurerm_subnet.app.id}"), "azurerm_subnet.app")
        self.assertEqual(azure_reference_key("azurerm_virtual_network.main.name"), "azurerm_virtual_network.main")
        self.assertEqual(
            azure_reference_key(
                "/subscriptions/EXAMPLE/resourceGroups/App/providers/Microsoft.Network/virtualNetworks/Main"
            ),
            "/subscriptions/example/resourcegroups/app/providers/microsoft.network/virtualnetworks/main",
        )

    def test_resource_references_include_address_identifier_and_name(self) -> None:
        resource = NormalizedResource(
            address="azurerm_virtual_network.main",
            provider="azure",
            resource_type="azurerm_virtual_network",
            name="main",
            category=ResourceCategory.NETWORK,
            identifier="/subscriptions/example/virtualNetworks/main",
            metadata={AzureResourceMetadata.NAME: "tfstride-main"},
        )

        references = azure_resource_references(resource)

        self.assertIn("azurerm_virtual_network.main", references)
        self.assertIn("/subscriptions/example/virtualnetworks/main", references)
        self.assertIn("tfstride-main", references)

    def test_network_security_rule_parser_preserves_decision_data_and_allow_rules(self) -> None:
        allow_rules, records = parse_network_security_rules(
            {
                "security_rule": [
                    {
                        "name": "allow-web",
                        "priority": 200,
                        "direction": "Inbound",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "source_address_prefix": "Internet",
                        "destination_port_ranges": ["80", "443"],
                    },
                    {
                        "name": "deny-admin",
                        "priority": 100,
                        "direction": "Inbound",
                        "access": "Deny",
                        "protocol": "*",
                        "source_address_prefix": "*",
                        "destination_port_range": "22",
                    },
                ]
            }
        )

        self.assertEqual(len(allow_rules), 2)
        self.assertTrue(all(rule.allows_internet() for rule in allow_rules))
        self.assertEqual([(rule.from_port, rule.to_port) for rule in allow_rules], [(80, 80), (443, 443)])
        self.assertEqual([record["access"] for record in records], ["allow", "deny"])
        self.assertEqual([record["rule_priority"] for record in records], [200, 100])
        self.assertEqual(records[1]["protocol"], "-1")


if __name__ == "__main__":
    unittest.main()
