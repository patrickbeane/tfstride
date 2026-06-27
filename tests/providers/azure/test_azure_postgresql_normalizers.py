from __future__ import annotations

import unittest

from tfstride.models import TerraformResource
from tfstride.providers.azure.postgresql_normalizers import (
    normalize_postgresql_flexible_server,
    normalize_postgresql_flexible_server_configuration,
    normalize_postgresql_flexible_server_database,
    normalize_postgresql_flexible_server_firewall_rule,
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


class AzurePostgresqlFlexibleServerNormalizerTests(unittest.TestCase):
    def test_server_normalizes_public_network_and_geo_backup(self) -> None:
        normalized = normalize_postgresql_flexible_server(
            _resource(
                AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
                {
                    "id": "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver",
                    "name": "pgserver",
                    "location": "eastus",
                    "public_network_access_enabled": True,
                    "geo_redundant_backup_enabled": False,
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertTrue(facts.public_network_access_enabled)
        self.assertFalse(facts.postgresql_geo_redundant_backup_enabled)
        self.assertEqual(facts.postgresql_server_id, normalized.identifier)
        self.assertFalse(normalized.storage_encrypted)
        self.assertEqual(normalized.data_sensitivity, "sensitive")

    def test_server_normalizes_restricted_public_access(self) -> None:
        normalized = normalize_postgresql_flexible_server(
            _resource(
                AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
                {
                    "id": "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver",
                    "name": "pgserver",
                    "location": "eastus",
                    "public_network_access_enabled": False,
                    "geo_redundant_backup_enabled": True,
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertFalse(facts.public_network_access_enabled)
        self.assertTrue(facts.postgresql_geo_redundant_backup_enabled)

    def test_server_normalizes_delegated_subnet(self) -> None:
        normalized = normalize_postgresql_flexible_server(
            _resource(
                AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
                {
                    "id": "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver",
                    "name": "pgserver",
                    "location": "eastus",
                    "delegated_subnet_id": "azurerm_subnet.pg.id",
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(facts.postgresql_delegated_subnet_id, "azurerm_subnet.pg.id")

    def test_server_preserves_computed_values_as_unknown(self) -> None:
        normalized = normalize_postgresql_flexible_server(
            _resource(
                AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
                {
                    "name": "pending",
                    "public_network_access_enabled": None,
                    "geo_redundant_backup_enabled": None,
                },
                unknown_values={
                    "public_network_access_enabled": True,
                    "geo_redundant_backup_enabled": True,
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertIsNone(facts.public_network_access_enabled)
        self.assertIsNone(facts.postgresql_geo_redundant_backup_enabled)
        self.assertEqual(
            facts.postgresql_posture_uncertainties,
            [
                "public_network_access_enabled is unknown after planning",
                "geo_redundant_backup_enabled is unknown after planning",
            ],
        )

    def test_server_unknown_bool_value_records_uncertainty(self) -> None:
        normalized = normalize_postgresql_flexible_server(
            _resource(
                AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
                {
                    "name": "pgserver",
                    "public_network_access_enabled": 42,
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertIsNone(facts.public_network_access_enabled)
        self.assertIn(
            "public_network_access_enabled has an unrecognized value shape",
            facts.postgresql_posture_uncertainties,
        )

    def test_server_missing_bool_field_stays_none(self) -> None:
        normalized = normalize_postgresql_flexible_server(
            _resource(
                AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
                {
                    "name": "pgserver",
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertIsNone(facts.public_network_access_enabled)
        self.assertIsNone(facts.postgresql_geo_redundant_backup_enabled)
        self.assertEqual(facts.postgresql_posture_uncertainties, [])

    def test_server_non_string_delegated_subnet_records_uncertainty(self) -> None:
        normalized = normalize_postgresql_flexible_server(
            _resource(
                AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
                {
                    "name": "pgserver",
                    "delegated_subnet_id": 42,
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertIsNone(facts.postgresql_delegated_subnet_id)
        self.assertIn(
            "delegated_subnet_id has an unrecognized value shape",
            facts.postgresql_posture_uncertainties,
        )


class AzurePostgresqlDatabaseNormalizerTests(unittest.TestCase):
    def test_database_normalizes_server_reference(self) -> None:
        normalized = normalize_postgresql_flexible_server_database(
            _resource(
                AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_DATABASE,
                {
                    "id": "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver/databases/mydb",
                    "name": "mydb",
                    "server_id": "azurerm_postgresql_flexible_server.pgserver.id",
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(facts.postgresql_server_id, "azurerm_postgresql_flexible_server.pgserver.id")
        self.assertFalse(normalized.storage_encrypted)
        self.assertEqual(normalized.data_sensitivity, "sensitive")

    def test_database_unknown_server_id_clears_value(self) -> None:
        normalized = normalize_postgresql_flexible_server_database(
            _resource(
                AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_DATABASE,
                {
                    "name": "mydb",
                    "server_id": "azurerm_postgresql_flexible_server.pgserver.id",
                },
                unknown_values={"server_id": True},
            )
        )
        facts = azure_facts(normalized)

        self.assertIsNone(facts.postgresql_server_id)


class AzurePostgresqlFirewallRuleNormalizerTests(unittest.TestCase):
    def test_firewall_rule_normalizes_ip_range(self) -> None:
        normalized = normalize_postgresql_flexible_server_firewall_rule(
            _resource(
                AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_FIREWALL_RULE,
                {
                    "id": "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver/firewallRules/wide",
                    "name": "wide",
                    "server_id": "azurerm_postgresql_flexible_server.pgserver.id",
                    "start_ip_address": "0.0.0.0",
                    "end_ip_address": "255.255.255.255",
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(facts.postgresql_server_id, "azurerm_postgresql_flexible_server.pgserver.id")
        self.assertEqual(facts.postgresql_firewall_start_ip, "0.0.0.0")
        self.assertEqual(facts.postgresql_firewall_end_ip, "255.255.255.255")

    def test_firewall_rule_preserves_computed_values_as_unknown(self) -> None:
        normalized = normalize_postgresql_flexible_server_firewall_rule(
            _resource(
                AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_FIREWALL_RULE,
                {
                    "name": "pending",
                    "server_id": "azurerm_postgresql_flexible_server.pgserver.id",
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

        self.assertIsNone(facts.postgresql_firewall_start_ip)
        self.assertIsNone(facts.postgresql_firewall_end_ip)
        self.assertEqual(
            facts.postgresql_posture_uncertainties,
            [
                "start_ip_address is unknown after planning",
                "end_ip_address is unknown after planning",
            ],
        )

    def test_firewall_rule_unknown_server_id_clears_value(self) -> None:
        normalized = normalize_postgresql_flexible_server_firewall_rule(
            _resource(
                AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_FIREWALL_RULE,
                {
                    "name": "pending",
                    "server_id": "azurerm_postgresql_flexible_server.pgserver.id",
                    "start_ip_address": "0.0.0.0",
                    "end_ip_address": "255.255.255.255",
                },
                unknown_values={"server_id": True},
            )
        )
        facts = azure_facts(normalized)

        self.assertIsNone(facts.postgresql_server_id)
        self.assertIn(
            "server_id is unknown after planning",
            facts.postgresql_posture_uncertainties,
        )


class AzurePostgresqlConfigurationNormalizerTests(unittest.TestCase):
    def test_configuration_normalizes_name_and_value(self) -> None:
        normalized = normalize_postgresql_flexible_server_configuration(
            _resource(
                AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_CONFIGURATION,
                {
                    "id": "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver/configurations/ssl_min_protocol_version",
                    "name": "ssl_min_protocol_version",
                    "server_id": "azurerm_postgresql_flexible_server.pgserver.id",
                    "value": "TLSv1.2",
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertEqual(facts.postgresql_config_name, "ssl_min_protocol_version")
        self.assertEqual(facts.postgresql_config_value, "TLSv1.2")
        self.assertEqual(facts.postgresql_config_server_id, "azurerm_postgresql_flexible_server.pgserver.id")

    def test_configuration_unknown_value_stays_none(self) -> None:
        normalized = normalize_postgresql_flexible_server_configuration(
            _resource(
                AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_CONFIGURATION,
                {
                    "name": "ssl_min_protocol_version",
                    "server_id": "azurerm_postgresql_flexible_server.pgserver.id",
                    "value": None,
                },
                unknown_values={"value": True},
            )
        )
        facts = azure_facts(normalized)

        self.assertIsNone(facts.postgresql_config_value)
        self.assertEqual(
            facts.postgresql_posture_uncertainties,
            ["value is unknown after planning"],
        )

    def test_configuration_unknown_server_id_clears_value(self) -> None:
        normalized = normalize_postgresql_flexible_server_configuration(
            _resource(
                AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_CONFIGURATION,
                {
                    "name": "ssl_min_protocol_version",
                    "server_id": "azurerm_postgresql_flexible_server.pgserver.id",
                    "value": "TLSv1.2",
                },
                unknown_values={"server_id": True},
            )
        )
        facts = azure_facts(normalized)

        self.assertIsNone(facts.postgresql_config_server_id)
        self.assertEqual(
            facts.postgresql_posture_uncertainties,
            ["server_id is unknown after planning"],
        )

    def test_configuration_blank_value_becomes_none(self) -> None:
        normalized = normalize_postgresql_flexible_server_configuration(
            _resource(
                AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_CONFIGURATION,
                {
                    "name": "require_secure_transport",
                    "server_id": "azurerm_postgresql_flexible_server.pgserver.id",
                    "value": "  ",
                },
            )
        )
        facts = azure_facts(normalized)

        self.assertIsNone(facts.postgresql_config_value)


if __name__ == "__main__":
    unittest.main()
