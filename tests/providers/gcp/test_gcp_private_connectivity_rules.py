from __future__ import annotations

import unittest

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer

_RULE_ID = "gcp-cloud-sql-private-connectivity-not-modeled"


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
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
        unknown_values=unknown_values or {},
    )


def _network(name: str = "main") -> TerraformResource:
    return _resource(
        "google_compute_network",
        name,
        {
            "name": name,
            "self_link": f"projects/demo/global/networks/{name}",
        },
    )


def _cloud_sql(
    *,
    private_network: str | None = "projects/demo/global/networks/main",
    ipv4_enabled: bool = True,
) -> TerraformResource:
    ip_configuration: dict[str, object] = {
        "ipv4_enabled": ipv4_enabled,
        "require_ssl": True,
        "authorized_networks": [],
    }
    if private_network is not None:
        ip_configuration["private_network"] = private_network
    return _resource(
        "google_sql_database_instance",
        "app",
        {
            "name": "tfstride-app-db",
            "database_version": "POSTGRES_15",
            "settings": [
                {
                    "backup_configuration": [
                        {
                            "enabled": True,
                            "point_in_time_recovery_enabled": True,
                        }
                    ],
                    "ip_configuration": [ip_configuration],
                }
            ],
            "deletion_protection": True,
        },
    )


def _service_networking_connection(
    *,
    network: str = "projects/demo/global/networks/main",
    unknown_network: bool = False,
) -> TerraformResource:
    values: dict[str, object] = {
        "service": "servicenetworking.googleapis.com",
        "reserved_peering_ranges": ["private-services-range"],
        "peering": "servicenetworking-googleapis-com",
    }
    unknown_values = None
    if unknown_network:
        unknown_values = {"network": True}
    else:
        values["network"] = network
    return _resource(
        "google_service_networking_connection",
        "private_services",
        values,
        unknown_values=unknown_values,
    )


def _cloud_sql_psc_policy(
    *,
    network: str = "projects/demo/global/networks/main",
) -> TerraformResource:
    return _resource(
        "google_network_connectivity_service_connection_policy",
        "sql",
        {
            "name": "sql-policy",
            "location": "us-central1",
            "network": network,
            "service_class": "gcp-cloud-sql",
            "psc_config": [{"subnetworks": ["google_compute_subnetwork.psc.id"], "limit": 8}],
        },
    )


def _evaluate(*resources: TerraformResource) -> list:
    inventory = GcpNormalizer().normalize(list(resources))
    return StrideRuleEngine().evaluate(
        inventory,
        [],
        rule_policy=RulePolicy(enabled_rule_ids=frozenset({_RULE_ID})),
    )


class GcpPrivateConnectivityRuleTests(unittest.TestCase):
    def test_cloud_sql_private_network_without_modeled_private_connectivity_is_detected(self) -> None:
        findings = _evaluate(_network(), _cloud_sql())

        self.assertEqual([finding.rule_id for finding in findings], [_RULE_ID])
        finding = findings[0]
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_sql_database_instance.app"])
        self.assertIn("does not model a Private Service Access connection", finding.rationale)
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["cloud_sql_network_posture"],
            ["private_network=projects/demo/global/networks/main", "ipv4_enabled=true"],
        )
        self.assertEqual(
            evidence["private_connectivity_coverage"],
            ["private_service_access_connections=0", "cloud_sql_psc_service_connection_policies=0"],
        )

    def test_private_service_access_connection_suppresses_finding(self) -> None:
        findings = _evaluate(_network(), _service_networking_connection(), _cloud_sql())

        self.assertEqual(findings, [])

    def test_cloud_sql_psc_policy_suppresses_finding(self) -> None:
        findings = _evaluate(_network(), _cloud_sql_psc_policy(), _cloud_sql())

        self.assertEqual(findings, [])

    def test_cloud_sql_without_private_network_is_left_to_public_ip_rule(self) -> None:
        findings = _evaluate(_network(), _cloud_sql(private_network=None))

        self.assertEqual(findings, [])

    def test_unresolved_private_service_access_connection_suppresses_overclaim(self) -> None:
        findings = _evaluate(_network(), _service_networking_connection(unknown_network=True), _cloud_sql())

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
