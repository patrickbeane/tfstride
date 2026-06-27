from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_PG_SERVER_ID = "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver"


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, object],
    *,
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


def _server(
    *,
    name: str = "pgserver",
    public_network: bool = True,
    geo_backup: bool | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": f"/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/{name}",
        "name": name,
        "location": "eastus",
        "public_network_access_enabled": public_network,
    }
    if geo_backup is not None:
        values["geo_redundant_backup_enabled"] = geo_backup
    return _resource(AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER, name, values)


def _firewall_rule(
    *,
    name: str = "wide",
    server_id: str = _PG_SERVER_ID,
    start_ip: str = "0.0.0.0",
    end_ip: str = "255.255.255.255",
) -> TerraformResource:
    return _resource(
        AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_FIREWALL_RULE,
        name,
        {
            "id": f"/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver/firewallRules/{name}",
            "name": name,
            "server_id": server_id,
            "start_ip_address": start_ip,
            "end_ip_address": end_ip,
        },
    )


def _configuration(
    *,
    name: str,
    server_id: str = _PG_SERVER_ID,
    value: str = "",
) -> TerraformResource:
    return _resource(
        AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_CONFIGURATION,
        name,
        {
            "id": f"/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver/configurations/{name}",
            "name": name,
            "server_id": server_id,
            "value": value,
        },
    )


def _evaluate(resources: list[TerraformResource], *rule_ids: str):
    inventory = AzureNormalizer().normalize(resources)
    findings = StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset(rule_ids)),
    )
    return findings


class AzurePostgresqlPublicNetworkAccessTests(unittest.TestCase):
    def test_public_network_access_emits_finding(self) -> None:
        findings = _evaluate(
            [_server(public_network=True)],
            "azure-postgresql-public-network-access-enabled",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "azure-postgresql-public-network-access-enabled")
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertIn("azurerm_postgresql_flexible_server.pgserver", findings[0].affected_resources)

    def test_restricted_public_network_access_stays_quiet(self) -> None:
        findings = _evaluate(
            [_server(public_network=False)],
            "azure-postgresql-public-network-access-enabled",
        )

        self.assertEqual(findings, [])

    def test_missing_public_network_access_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _resource(
                    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
                    "pgserver",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver",
                        "name": "pgserver",
                        "public_network_access_enabled": None,
                    },
                )
            ],
            "azure-postgresql-public-network-access-enabled",
        )

        self.assertEqual(findings, [])

    def test_unknown_public_network_access_via_unknown_values_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _resource(
                    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
                    "pgserver",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver",
                        "name": "pgserver",
                        "public_network_access_enabled": True,
                    },
                    unknown_values={"public_network_access_enabled": True},
                ),
            ],
            "azure-postgresql-public-network-access-enabled",
        )

        self.assertEqual(findings, [])


class AzurePostgresqlFirewallRuleTests(unittest.TestCase):
    def test_broad_firewall_rule_emits_finding(self) -> None:
        findings = _evaluate(
            [_server(), _firewall_rule()],
            "azure-postgresql-firewall-broad-public-access",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "azure-postgresql-firewall-broad-public-access")
        self.assertIn("azurerm_postgresql_flexible_server.pgserver", findings[0].affected_resources)
        self.assertIn("azurerm_postgresql_flexible_server_firewall_rule.wide", findings[0].affected_resources)

    def test_narrow_firewall_rule_stays_quiet(self) -> None:
        findings = _evaluate(
            [_server(), _firewall_rule(start_ip="198.51.100.0", end_ip="198.51.100.255")],
            "azure-postgresql-firewall-broad-public-access",
        )

        self.assertEqual(findings, [])

    def test_missing_ip_range_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _server(),
                _resource(
                    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_FIREWALL_RULE,
                    "pending",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver/firewallRules/pending",
                        "name": "pending",
                        "server_id": _PG_SERVER_ID,
                        "start_ip_address": None,
                        "end_ip_address": None,
                    },
                ),
            ],
            "azure-postgresql-firewall-broad-public-access",
        )

        self.assertEqual(findings, [])

    def test_unknown_firewall_ip_values_via_unknown_values_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _server(),
                _resource(
                    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_FIREWALL_RULE,
                    "pending",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver/firewallRules/pending",
                        "name": "pending",
                        "server_id": _PG_SERVER_ID,
                        "start_ip_address": "0.0.0.0",
                        "end_ip_address": "255.255.255.255",
                    },
                    unknown_values={"start_ip_address": True, "end_ip_address": True},
                ),
            ],
            "azure-postgresql-firewall-broad-public-access",
        )

        self.assertEqual(findings, [])

    def test_unknown_server_id_clears_association(self) -> None:
        findings = _evaluate(
            [
                _server(),
                _resource(
                    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_FIREWALL_RULE,
                    "pending",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver/firewallRules/pending",
                        "name": "pending",
                        "server_id": _PG_SERVER_ID,
                        "start_ip_address": "0.0.0.0",
                        "end_ip_address": "255.255.255.255",
                    },
                    unknown_values={"server_id": True},
                ),
            ],
            "azure-postgresql-firewall-broad-public-access",
        )

        self.assertEqual(len(findings), 1)
        self.assertNotIn("azurerm_postgresql_flexible_server.pgserver", findings[0].affected_resources)
        self.assertIn("azurerm_postgresql_flexible_server_firewall_rule.pending", findings[0].affected_resources)

    def test_broad_firewall_with_unmatched_server_reports_only_rule(self) -> None:
        findings = _evaluate(
            [
                _resource(
                    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_FIREWALL_RULE,
                    "orphan",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver/firewallRules/orphan",
                        "name": "orphan",
                        "server_id": "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/unknown",
                        "start_ip_address": "0.0.0.0",
                        "end_ip_address": "255.255.255.255",
                    },
                ),
            ],
            "azure-postgresql-firewall-broad-public-access",
        )

        self.assertEqual(len(findings), 1)
        self.assertNotIn("azurerm_postgresql_flexible_server.pgserver", findings[0].affected_resources)
        self.assertIn("azurerm_postgresql_flexible_server_firewall_rule.orphan", findings[0].affected_resources)


class AzurePostgresqlWeakTlsTests(unittest.TestCase):
    def test_missing_tls_posture_stays_quiet(self) -> None:
        findings = _evaluate(
            [_server()],
            "azure-postgresql-weak-tls-or-ssl",
        )

        self.assertEqual(findings, [])

    def test_ssl_min_protocol_version_tls1_0_emits_finding(self) -> None:
        findings = _evaluate(
            [
                _server(),
                _configuration(name="ssl_min_protocol_version", value="TLSv1.0"),
            ],
            "azure-postgresql-weak-tls-or-ssl",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "azure-postgresql-weak-tls-or-ssl")
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertTrue(any("ssl_min_protocol_version" in v for v in evidence.get("transport_posture", [])))

    def test_ssl_min_protocol_version_tls1_1_emits_finding(self) -> None:
        findings = _evaluate(
            [
                _server(),
                _configuration(name="ssl_min_protocol_version", value="TLSv1.1"),
            ],
            "azure-postgresql-weak-tls-or-ssl",
        )

        self.assertEqual(len(findings), 1)

    def test_strong_tls_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _server(),
                _configuration(name="ssl_min_protocol_version", value="TLSv1.2"),
            ],
            "azure-postgresql-weak-tls-or-ssl",
        )

        self.assertEqual(findings, [])

    def test_unknown_ssl_version_via_unknown_values_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _server(),
                _resource(
                    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_CONFIGURATION,
                    "ssl_min_protocol_version",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver/configurations/ssl_min_protocol_version",
                        "name": "ssl_min_protocol_version",
                        "server_id": _PG_SERVER_ID,
                        "value": "TLSv1.0",
                    },
                    unknown_values={"value": True},
                ),
            ],
            "azure-postgresql-weak-tls-or-ssl",
        )

        self.assertEqual(findings, [])

    def test_require_secure_transport_disabled_emits_finding(self) -> None:
        findings = _evaluate(
            [
                _server(),
                _configuration(name="require_secure_transport", value="0"),
            ],
            "azure-postgresql-weak-tls-or-ssl",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "azure-postgresql-weak-tls-or-ssl")
        evidence = {item.key: item.values for item in findings[0].evidence}
        self.assertTrue(any("require_secure_transport" in v for v in evidence.get("transport_posture", [])))

    def test_require_secure_transport_off_emits_finding(self) -> None:
        findings = _evaluate(
            [
                _server(),
                _configuration(name="require_secure_transport", value="OFF"),
            ],
            "azure-postgresql-weak-tls-or-ssl",
        )

        self.assertEqual(len(findings), 1)

    def test_require_secure_transport_enabled_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _server(),
                _configuration(name="require_secure_transport", value="1"),
            ],
            "azure-postgresql-weak-tls-or-ssl",
        )

        self.assertEqual(findings, [])

    def test_missing_require_secure_transport_stays_quiet(self) -> None:
        findings = _evaluate(
            [_server()],
            "azure-postgresql-weak-tls-or-ssl",
        )

        self.assertEqual(findings, [])


class AzurePostgresqlGeoBackupTests(unittest.TestCase):
    def test_geo_backup_disabled_emits_finding(self) -> None:
        findings = _evaluate(
            [_server(geo_backup=False)],
            "azure-postgresql-geo-backup-disabled",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "azure-postgresql-geo-backup-disabled")
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertIn("azurerm_postgresql_flexible_server.pgserver", findings[0].affected_resources)

    def test_geo_backup_enabled_stays_quiet(self) -> None:
        findings = _evaluate(
            [_server(geo_backup=True)],
            "azure-postgresql-geo-backup-disabled",
        )

        self.assertEqual(findings, [])

    def test_missing_geo_backup_stays_quiet(self) -> None:
        findings = _evaluate(
            [_server()],
            "azure-postgresql-geo-backup-disabled",
        )

        self.assertEqual(findings, [])

    def test_unknown_geo_backup_via_unknown_values_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _resource(
                    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
                    "pgserver",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver",
                        "name": "pgserver",
                        "public_network_access_enabled": False,
                        "geo_redundant_backup_enabled": False,
                    },
                    unknown_values={"geo_redundant_backup_enabled": True},
                ),
            ],
            "azure-postgresql-geo-backup-disabled",
        )

        self.assertEqual(findings, [])


class AzurePostgresqlNormalizationIntegrationTests(unittest.TestCase):
    def test_server_normalizes_with_facts(self) -> None:
        inventory = AzureNormalizer().normalize([_server(public_network=True)])
        server = inventory.resources[0]
        facts = azure_facts(server)

        self.assertTrue(facts.public_network_access_enabled)
        self.assertEqual(server.resource_type, AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER)

    def test_firewall_rule_normalizes_with_facts(self) -> None:
        inventory = AzureNormalizer().normalize([_server(), _firewall_rule()])
        firewall_rules = [
            r
            for r in inventory.resources
            if r.resource_type == AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER_FIREWALL_RULE
        ]
        self.assertEqual(len(firewall_rules), 1)
        facts = azure_facts(firewall_rules[0])
        self.assertEqual(facts.postgresql_firewall_start_ip, "0.0.0.0")
        self.assertEqual(facts.postgresql_firewall_end_ip, "255.255.255.255")


class AzurePostgresqlUncertaintyObservationTests(unittest.TestCase):
    def test_unknown_posture_produces_observation(self) -> None:
        from tfstride.providers.azure.observations import observe_azure_posture

        inventory = AzureNormalizer().normalize(
            [
                _resource(
                    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
                    "pgserver",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver",
                        "name": "pgserver",
                        "public_network_access_enabled": None,
                        "geo_redundant_backup_enabled": None,
                    },
                    unknown_values={
                        "public_network_access_enabled": True,
                        "geo_redundant_backup_enabled": True,
                    },
                )
            ]
        )
        observations = observe_azure_posture(inventory)
        observation_ids = [obs.observation_id for obs in observations]
        self.assertIn("azure-postgresql-posture-unknown", observation_ids)


class AzurePostgresqlDelegatedSubnetObservationTests(unittest.TestCase):
    def test_delegated_subnet_produces_observation(self) -> None:
        from tfstride.providers.azure.observations import observe_azure_posture

        inventory = AzureNormalizer().normalize(
            [
                _resource(
                    AzureResourceType.POSTGRESQL_FLEXIBLE_SERVER,
                    "pgserver",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.DBforPostgreSQL/flexibleServers/pgserver",
                        "name": "pgserver",
                        "public_network_access_enabled": False,
                        "delegated_subnet_id": "azurerm_subnet.pg.id",
                    },
                )
            ]
        )
        observations = observe_azure_posture(inventory)
        observation_ids = [obs.observation_id for obs in observations]
        self.assertIn("azure-postgresql-delegated-subnet-observed", observation_ids)


if __name__ == "__main__":
    unittest.main()
