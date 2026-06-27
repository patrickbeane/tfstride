from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.mssql_normalizers import (
    normalize_mssql_database,
    normalize_mssql_firewall_rule,
    normalize_mssql_server,
    normalize_mssql_server_security_alert_policy,
    normalize_mssql_virtual_network_rule,
)
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType


def _resource(
    resource_type: str,
    values: dict[str, object],
    *,
    name: str = "example",
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.{name}",
        mode="managed",
        resource_type=resource_type,
        name=name,
        provider_name="registry.terraform.io/hashicorp/azurerm",
        values=values,
        unknown_values=unknown_values or {},
    )


class AzureMssqlServerNormalizerTests(unittest.TestCase):
    def test_mssql_server_normalizes_public_network_and_tls(self) -> None:
        normalized = normalize_mssql_server(
            _resource(
                AzureResourceType.MSSQL_SERVER,
                {
                    "id": "/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver",
                    "name": "sqlserver",
                    "location": "eastus",
                    "public_network_access_enabled": True,
                    "minimum_tls_version": "1.0",
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertTrue(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "enabled")
        self.assertEqual(facts.min_tls_version, "1.0")
        self.assertEqual(facts.mssql_server_id, normalized.identifier)
        self.assertFalse(normalized.storage_encrypted)
        self.assertEqual(normalized.data_sensitivity, "sensitive")

    def test_mssql_server_normalizes_restricted_public_access(self) -> None:
        normalized = normalize_mssql_server(
            _resource(
                AzureResourceType.MSSQL_SERVER,
                {
                    "id": "/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver",
                    "name": "sqlserver",
                    "location": "eastus",
                    "public_network_access_enabled": False,
                    "minimum_tls_version": "1.2",
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertFalse(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "disabled")
        self.assertEqual(facts.min_tls_version, "1.2")

    def test_mssql_server_preserves_computed_values_as_unknown(self) -> None:
        normalized = normalize_mssql_server(
            _resource(
                AzureResourceType.MSSQL_SERVER,
                {
                    "name": "pending",
                    "public_network_access_enabled": None,
                    "minimum_tls_version": None,
                },
                unknown_values={
                    "public_network_access_enabled": True,
                    "minimum_tls_version": True,
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertIsNone(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "unknown")
        self.assertIsNone(facts.min_tls_version)
        self.assertEqual(
            facts.mssql_posture_uncertainties,
            [
                "public_network_access_enabled is unknown after planning",
                "minimum_tls_version is unknown after planning",
            ],
        )


class AzureMssqlDatabaseNormalizerTests(unittest.TestCase):
    def test_mssql_database_normalizes_server_reference(self) -> None:
        normalized = normalize_mssql_database(
            _resource(
                AzureResourceType.MSSQL_DATABASE,
                {
                    "id": "/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver/databases/mydb",
                    "name": "mydb",
                    "server_id": "azurerm_mssql_server.sqlserver.id",
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(facts.mssql_server_id, "azurerm_mssql_server.sqlserver.id")
        self.assertFalse(normalized.storage_encrypted)
        self.assertEqual(normalized.data_sensitivity, "sensitive")


class AzureMssqlFirewallRuleNormalizerTests(unittest.TestCase):
    def test_mssql_firewall_rule_normalizes_ip_range(self) -> None:
        normalized = normalize_mssql_firewall_rule(
            _resource(
                AzureResourceType.MSSQL_FIREWALL_RULE,
                {
                    "id": "/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver/firewallRules/wide",
                    "name": "wide",
                    "server_id": "azurerm_mssql_server.sqlserver.id",
                    "start_ip_address": "0.0.0.0",
                    "end_ip_address": "255.255.255.255",
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(facts.mssql_server_id, "azurerm_mssql_server.sqlserver.id")
        self.assertEqual(facts.mssql_firewall_start_ip, "0.0.0.0")
        self.assertEqual(facts.mssql_firewall_end_ip, "255.255.255.255")

    def test_mssql_firewall_rule_preserves_computed_values_as_unknown(self) -> None:
        normalized = normalize_mssql_firewall_rule(
            _resource(
                AzureResourceType.MSSQL_FIREWALL_RULE,
                {
                    "name": "pending",
                    "server_id": "azurerm_mssql_server.sqlserver.id",
                    "start_ip_address": None,
                    "end_ip_address": None,
                },
                unknown_values={
                    "start_ip_address": True,
                    "end_ip_address": True,
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertIsNone(facts.mssql_firewall_start_ip)
        self.assertIsNone(facts.mssql_firewall_end_ip)
        self.assertEqual(
            facts.mssql_posture_uncertainties,
            [
                "start_ip_address is unknown after planning",
                "end_ip_address is unknown after planning",
            ],
        )


class AzureMssqlVnetRuleNormalizerTests(unittest.TestCase):
    def test_mssql_vnet_rule_normalizes_subnet(self) -> None:
        normalized = normalize_mssql_virtual_network_rule(
            _resource(
                AzureResourceType.MSSQL_VIRTUAL_NETWORK_RULE,
                {
                    "id": "/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver/virtualNetworkRules/vnet",
                    "name": "vnet",
                    "server_id": "azurerm_mssql_server.sqlserver.id",
                    "subnet_id": "azurerm_subnet.app.id",
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(facts.mssql_server_id, "azurerm_mssql_server.sqlserver.id")
        self.assertEqual(facts.mssql_vnet_subnet_id, "azurerm_subnet.app.id")


class AzureMssqlSecurityAlertPolicyNormalizerTests(unittest.TestCase):
    def test_security_alert_policy_enabled(self) -> None:
        normalized = normalize_mssql_server_security_alert_policy(
            _resource(
                AzureResourceType.MSSQL_SERVER_SECURITY_ALERT_POLICY,
                {
                    "id": "/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver/securityAlertPolicies/Default",
                    "name": "Default",
                    "mssql_server_id": "azurerm_mssql_server.sqlserver.id",
                    "state": "Enabled",
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(facts.mssql_server_id, "azurerm_mssql_server.sqlserver.id")
        self.assertEqual(facts.mssql_security_alert_state, "Enabled")

    def test_security_alert_policy_disabled(self) -> None:
        normalized = normalize_mssql_server_security_alert_policy(
            _resource(
                AzureResourceType.MSSQL_SERVER_SECURITY_ALERT_POLICY,
                {
                    "id": "/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver/securityAlertPolicies/Default",
                    "name": "Default",
                    "mssql_server_id": "azurerm_mssql_server.sqlserver.id",
                    "state": "Disabled",
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(facts.mssql_security_alert_state, "Disabled")

    def test_security_alert_policy_unknown_state_clears_value(self) -> None:
        normalized = normalize_mssql_server_security_alert_policy(
            _resource(
                AzureResourceType.MSSQL_SERVER_SECURITY_ALERT_POLICY,
                {
                    "id": "/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver/securityAlertPolicies/Default",
                    "name": "Default",
                    "mssql_server_id": "azurerm_mssql_server.sqlserver.id",
                    "state": "Enabled",
                },
                unknown_values={"state": True},
            )
        )
        facts = azure_facts(normalized)

        self.assertIsNone(facts.mssql_security_alert_state)
        self.assertEqual(
            facts.mssql_posture_uncertainties,
            ["state is unknown after planning"],
        )

    def test_mssql_server_unknown_bool_value_records_uncertainty(self) -> None:
        normalized = normalize_mssql_server(
            _resource(
                AzureResourceType.MSSQL_SERVER,
                {
                    "name": "sqlserver",
                    "public_network_access_enabled": 42,
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertIsNone(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "unknown")
        self.assertIn(
            "public_network_access_enabled has an unrecognized value shape",
            facts.mssql_posture_uncertainties,
        )

    def test_mssql_server_missing_bool_field_stays_none(self) -> None:
        normalized = normalize_mssql_server(
            _resource(
                AzureResourceType.MSSQL_SERVER,
                {
                    "name": "sqlserver",
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertIsNone(facts.public_network_access_enabled)
        self.assertEqual(facts.public_network_fallback_state, "unknown")
        self.assertIsNone(facts.min_tls_version)
        self.assertEqual(facts.mssql_posture_uncertainties, [])

    def test_mssql_server_non_string_tls_records_uncertainty(self) -> None:
        normalized = normalize_mssql_server(
            _resource(
                AzureResourceType.MSSQL_SERVER,
                {
                    "name": "sqlserver",
                    "minimum_tls_version": 42,
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertIsNone(facts.min_tls_version)
        self.assertIn(
            "minimum_tls_version has an unrecognized value shape",
            facts.mssql_posture_uncertainties,
        )


if __name__ == "__main__":
    unittest.main()
