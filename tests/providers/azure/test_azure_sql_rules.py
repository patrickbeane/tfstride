from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.azure.normalizer import AzureNormalizer
from tfstride.providers.azure.resource_facts import azure_facts
from tfstride.providers.azure.resource_types import AzureResourceType

_SERVER_ID = "/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver"


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
    name: str = "sqlserver",
    public_network: bool = True,
    tls_version: str | None = None,
) -> TerraformResource:
    values: dict[str, object] = {
        "id": f"/subscriptions/example/providers/Microsoft.Sql/servers/{name}",
        "name": name,
        "location": "eastus",
        "public_network_access_enabled": public_network,
    }
    if tls_version is not None:
        values["minimum_tls_version"] = tls_version
    return _resource(AzureResourceType.MSSQL_SERVER, name, values)


def _firewall_rule(
    *,
    name: str = "wide",
    server_id: str = _SERVER_ID,
    start_ip: str = "0.0.0.0",
    end_ip: str = "255.255.255.255",
) -> TerraformResource:
    return _resource(
        AzureResourceType.MSSQL_FIREWALL_RULE,
        name,
        {
            "id": f"/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver/firewallRules/{name}",
            "name": name,
            "server_id": server_id,
            "start_ip_address": start_ip,
            "end_ip_address": end_ip,
        },
    )


def _security_alert_policy(
    *,
    name: str = "Default",
    server_id: str = _SERVER_ID,
    state: str = "Enabled",
) -> TerraformResource:
    return _resource(
        AzureResourceType.MSSQL_SERVER_SECURITY_ALERT_POLICY,
        name,
        {
            "id": f"/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver/securityAlertPolicies/{name}",
            "name": name,
            "mssql_server_id": server_id,
            "state": state,
        },
    )


def _vnet_rule(
    *,
    name: str = "vnet",
    server_id: str = _SERVER_ID,
    subnet_id: str = "azurerm_subnet.app.id",
) -> TerraformResource:
    return _resource(
        AzureResourceType.MSSQL_VIRTUAL_NETWORK_RULE,
        name,
        {
            "id": f"/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver/virtualNetworkRules/{name}",
            "name": name,
            "server_id": server_id,
            "subnet_id": subnet_id,
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


class AzureSqlPublicNetworkAccessTests(unittest.TestCase):
    def test_public_network_access_emits_finding(self) -> None:
        findings = _evaluate(
            [_server(public_network=True)],
            "azure-sql-public-network-access-enabled",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "azure-sql-public-network-access-enabled")
        self.assertEqual(findings[0].severity.value, "medium")
        self.assertIn("azurerm_mssql_server.sqlserver", findings[0].affected_resources)

    def test_restricted_public_network_access_stays_quiet(self) -> None:
        findings = _evaluate(
            [_server(public_network=False)],
            "azure-sql-public-network-access-enabled",
        )

        self.assertEqual(findings, [])

    def test_unknown_public_network_access_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _resource(
                    AzureResourceType.MSSQL_SERVER,
                    "sqlserver",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver",
                        "name": "sqlserver",
                        "public_network_access_enabled": None,
                    },
                )
            ],
            "azure-sql-public-network-access-enabled",
        )

        self.assertEqual(findings, [])


class AzureSqlFirewallRuleTests(unittest.TestCase):
    def test_broad_firewall_rule_emits_finding(self) -> None:
        findings = _evaluate(
            [_server(), _firewall_rule()],
            "azure-sql-firewall-broad-public-access",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "azure-sql-firewall-broad-public-access")
        self.assertIn("azurerm_mssql_server.sqlserver", findings[0].affected_resources)
        self.assertIn("azurerm_mssql_firewall_rule.wide", findings[0].affected_resources)

    def test_narrow_firewall_rule_stays_quiet(self) -> None:
        findings = _evaluate(
            [_server(), _firewall_rule(start_ip="198.51.100.0", end_ip="198.51.100.255")],
            "azure-sql-firewall-broad-public-access",
        )

        self.assertEqual(findings, [])

    def test_unknown_ip_range_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _server(),
                _resource(
                    AzureResourceType.MSSQL_FIREWALL_RULE,
                    "pending",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver/firewallRules/pending",
                        "name": "pending",
                        "server_id": _SERVER_ID,
                        "start_ip_address": None,
                        "end_ip_address": None,
                    },
                ),
            ],
            "azure-sql-firewall-broad-public-access",
        )

        self.assertEqual(findings, [])

    def test_broad_firewall_with_unmatched_server_reports_only_rule(self) -> None:
        findings = _evaluate(
            [
                _resource(
                    AzureResourceType.MSSQL_FIREWALL_RULE,
                    "orphan",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver/firewallRules/orphan",
                        "name": "orphan",
                        "server_id": "/subscriptions/example/providers/Microsoft.Sql/servers/unknown",
                        "start_ip_address": "0.0.0.0",
                        "end_ip_address": "255.255.255.255",
                    },
                ),
            ],
            "azure-sql-firewall-broad-public-access",
        )

        self.assertEqual(len(findings), 1)
        self.assertNotIn("azurerm_mssql_server.sqlserver", findings[0].affected_resources)
        self.assertIn("azurerm_mssql_firewall_rule.orphan", findings[0].affected_resources)


class AzureSqlMinimumTlsTests(unittest.TestCase):
    def test_tls_below_1_2_emits_finding(self) -> None:
        findings = _evaluate(
            [_server(tls_version="1.0")],
            "azure-sql-minimum-tls-below-1-2",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "azure-sql-minimum-tls-below-1-2")
        self.assertIn("1.0", findings[0].rationale)

    def test_tls_1_2_stays_quiet(self) -> None:
        findings = _evaluate(
            [_server(tls_version="1.2")],
            "azure-sql-minimum-tls-below-1-2",
        )

        self.assertEqual(findings, [])

    def test_unknown_tls_stays_quiet(self) -> None:
        findings = _evaluate(
            [_server()],
            "azure-sql-minimum-tls-below-1-2",
        )

        self.assertEqual(findings, [])


class AzureSqlSecurityAlertPolicyTests(unittest.TestCase):
    def test_disabled_alert_policy_emits_finding(self) -> None:
        findings = _evaluate(
            [_server(), _security_alert_policy(state="Disabled")],
            "azure-sql-security-alert-policy-disabled",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "azure-sql-security-alert-policy-disabled")
        self.assertIn("azurerm_mssql_server.sqlserver", findings[0].affected_resources)
        self.assertIn("azurerm_mssql_server_security_alert_policy.Default", findings[0].affected_resources)

    def test_enabled_alert_policy_stays_quiet(self) -> None:
        findings = _evaluate(
            [_server(), _security_alert_policy(state="Enabled")],
            "azure-sql-security-alert-policy-disabled",
        )

        self.assertEqual(findings, [])

    def test_unknown_alert_policy_state_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _server(),
                _resource(
                    AzureResourceType.MSSQL_SERVER_SECURITY_ALERT_POLICY,
                    "Default",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver/securityAlertPolicies/Default",
                        "name": "Default",
                        "mssql_server_id": _SERVER_ID,
                        "state": "Enabled",
                    },
                    unknown_values={"state": True},
                ),
            ],
            "azure-sql-security-alert-policy-disabled",
        )

        self.assertEqual(findings, [])

    def test_unknown_public_network_access_via_unknown_values_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _resource(
                    AzureResourceType.MSSQL_SERVER,
                    "sqlserver",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver",
                        "name": "sqlserver",
                        "public_network_access_enabled": True,
                    },
                    unknown_values={"public_network_access_enabled": True},
                ),
            ],
            "azure-sql-public-network-access-enabled",
        )

        self.assertEqual(findings, [])

    def test_unknown_tls_version_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _resource(
                    AzureResourceType.MSSQL_SERVER,
                    "sqlserver",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver",
                        "name": "sqlserver",
                        "public_network_access_enabled": False,
                        "minimum_tls_version": "1.0",
                    },
                    unknown_values={"minimum_tls_version": True},
                ),
            ],
            "azure-sql-minimum-tls-below-1-2",
        )

        self.assertEqual(findings, [])

    def test_unknown_firewall_ip_values_stays_quiet(self) -> None:
        findings = _evaluate(
            [
                _server(),
                _resource(
                    AzureResourceType.MSSQL_FIREWALL_RULE,
                    "pending",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver/firewallRules/pending",
                        "name": "pending",
                        "server_id": _SERVER_ID,
                        "start_ip_address": "0.0.0.0",
                        "end_ip_address": "255.255.255.255",
                    },
                    unknown_values={"start_ip_address": True, "end_ip_address": True},
                ),
            ],
            "azure-sql-firewall-broad-public-access",
        )

        self.assertEqual(findings, [])


class AzureSqlNormalizationIntegrationTests(unittest.TestCase):
    def test_mssql_server_normalizes_with_facts(self) -> None:
        inventory = AzureNormalizer().normalize([_server(public_network=True, tls_version="1.0")])
        server = inventory.resources[0]
        facts = azure_facts(server)

        self.assertTrue(facts.public_network_access_enabled)
        self.assertEqual(facts.min_tls_version, "1.0")
        self.assertEqual(server.resource_type, AzureResourceType.MSSQL_SERVER)

    def test_mssql_firewall_rule_normalizes_with_facts(self) -> None:
        inventory = AzureNormalizer().normalize([_server(), _firewall_rule()])
        firewall_rules = [r for r in inventory.resources if r.resource_type == AzureResourceType.MSSQL_FIREWALL_RULE]
        self.assertEqual(len(firewall_rules), 1)
        facts = azure_facts(firewall_rules[0])
        self.assertEqual(facts.mssql_firewall_start_ip, "0.0.0.0")
        self.assertEqual(facts.mssql_firewall_end_ip, "255.255.255.255")


class AzureSqlVnetObservationTests(unittest.TestCase):
    def test_vnet_rule_produces_observation(self) -> None:
        from tfstride.providers.azure.observations import observe_azure_posture

        inventory = AzureNormalizer().normalize([_server(), _vnet_rule()])
        observations = observe_azure_posture(inventory)
        observation_ids = [obs.observation_id for obs in observations]
        self.assertIn("azure-sql-vnet-restricted", observation_ids)


class AzureSqlUnknownPostureObservationTests(unittest.TestCase):
    def test_unknown_posture_produces_observation(self) -> None:
        from tfstride.providers.azure.observations import observe_azure_posture

        inventory = AzureNormalizer().normalize(
            [
                _resource(
                    AzureResourceType.MSSQL_SERVER,
                    "sqlserver",
                    {
                        "id": "/subscriptions/example/providers/Microsoft.Sql/servers/sqlserver",
                        "name": "sqlserver",
                        "public_network_access_enabled": None,
                        "minimum_tls_version": None,
                    },
                    unknown_values={
                        "public_network_access_enabled": True,
                        "minimum_tls_version": True,
                    },
                )
            ]
        )
        observations = observe_azure_posture(inventory)
        observation_ids = [obs.observation_id for obs in observations]
        self.assertIn("azure-sql-posture-unknown", observation_ids)


if __name__ == "__main__":
    unittest.main()
