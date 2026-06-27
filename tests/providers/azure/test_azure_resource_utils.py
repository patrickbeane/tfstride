from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.resource_utils import (
    azure_reference_key,
    azure_resource_references,
    first_mapping,
    known_block_string,
    known_bool,
    known_string,
    known_string_list,
    parse_network_security_rules,
    tls_version_below_1_2,
    value_is_unknown,
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

    def test_managed_identity_references_include_client_and_principal_ids(self) -> None:
        identity = NormalizedResource(
            address="azurerm_user_assigned_identity.deploy",
            provider="azure",
            resource_type="azurerm_user_assigned_identity",
            name="deploy",
            category=ResourceCategory.IAM,
            identifier="/subscriptions/example/userAssignedIdentities/deploy",
            metadata={
                AzureResourceMetadata.NAME: "deploy",
                AzureResourceMetadata.CLIENT_ID: "client-id",
                AzureResourceMetadata.PRINCIPAL_ID: "principal-id",
            },
        )

        references = azure_resource_references(identity)

        self.assertIn("azurerm_user_assigned_identity.deploy", references)
        self.assertIn("/subscriptions/example/userassignedidentities/deploy", references)
        self.assertIn("client-id", references)
        self.assertIn("principal-id", references)

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

    def test_unknown_value_helpers_handle_nested_plan_shapes(self) -> None:
        self.assertTrue(value_is_unknown({"site_config": [{"minimum_tls_version": True}]}))
        self.assertFalse(value_is_unknown({"site_config": [{"minimum_tls_version": False}]}))
        self.assertEqual(first_mapping([{"default_action": "Deny"}]), {"default_action": "Deny"})
        self.assertIsNone(first_mapping(["not-a-block"]))

    def test_known_string_and_bool_helpers_record_uncertainty(self) -> None:
        uncertainties: list[str] = []

        self.assertIsNone(known_string({"name": "app"}, {"name": True}, "name", uncertainties))
        self.assertEqual(uncertainties, ["name is unknown after planning"])

        uncertainties.clear()
        self.assertIsNone(
            known_string(
                {"minimum_tls_version": 12},
                {},
                "minimum_tls_version",
                uncertainties,
                require_string=True,
            )
        )
        self.assertEqual(uncertainties, ["minimum_tls_version has an unrecognized value shape"])

        uncertainties.clear()
        self.assertEqual(
            known_string_list({"identity_ids": ["a", "a", " b "]}, {}, "identity_ids", uncertainties), ["a", "b"]
        )
        self.assertTrue(
            known_bool({"public_network_access_enabled": "enabled"}, {}, "public_network_access_enabled", uncertainties)
        )
        self.assertFalse(
            known_bool({"public_network_access_enabled": "off"}, {}, "public_network_access_enabled", uncertainties)
        )

    def test_known_block_string_records_field_uncertainty(self) -> None:
        uncertainties: list[str] = []
        unknown_fields: list[str] = []

        self.assertIsNone(
            known_block_string(
                {"private_connection_resource_id": "/subscriptions/example/storage"},
                {"private_connection_resource_id": True},
                "private_connection_resource_id",
                uncertainties,
                path="private_service_connection[0]",
                unknown_fields=unknown_fields,
            )
        )

        self.assertEqual(
            uncertainties,
            ["private_service_connection[0].private_connection_resource_id is unknown after planning"],
        )
        self.assertEqual(unknown_fields, ["private_connection_resource_id"])

    def test_tls_version_below_1_2_accepts_provider_spellings(self) -> None:
        for weak_version in ("TLS1_0", "TLS1.1", "TLSv1", "TLSv1_1", "1.0", "1_1"):
            with self.subTest(weak_version=weak_version):
                self.assertTrue(tls_version_below_1_2(weak_version))

        for strong_version in (None, "TLS1_2", "TLSv1.2", "1.2", "TLS1_3"):
            with self.subTest(strong_version=strong_version):
                self.assertFalse(tls_version_below_1_2(strong_version))


if __name__ == "__main__":
    unittest.main()
