from __future__ import annotations

import unittest

from tests.providers.gcp.rule_support.data import _cloud_sql_instance
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.analysis.stride_rules import StrideRuleEngine
from tfstride.analysis.trust_boundaries import detect_trust_boundaries
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer


def _service_networking_connection() -> TerraformResource:
    return TerraformResource(
        address="google_service_networking_connection.private_services",
        mode="managed",
        resource_type="google_service_networking_connection",
        name="private_services",
        provider_name="registry.terraform.io/hashicorp/google",
        values={
            "network": "google_compute_network.main.id",
            "service": "servicenetworking.googleapis.com",
            "reserved_peering_ranges": ["private-services-range"],
            "peering": "servicenetworking-googleapis-com",
        },
    )


class GcpCloudSqlRuleTests(unittest.TestCase):
    def test_cloud_sql_public_authorized_network_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    authorized_networks=[{"name": "anywhere", "value": "0.0.0.0/0"}],
                )
            ]
        )
        boundaries = detect_trust_boundaries(inventory)

        findings = StrideRuleEngine().evaluate(
            inventory,
            boundaries,
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-sql-public-authorized-network"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-public-authorized-network")
        self.assertEqual(finding.severity.value, "high")
        self.assertEqual(finding.affected_resources, ["google_sql_database_instance.app"])
        self.assertEqual(
            finding.trust_boundary_id,
            "internet-to-service:internet->google_sql_database_instance.app",
        )
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["authorized_networks"], ["anywhere (0.0.0.0/0)"])
        self.assertEqual(
            evidence["public_exposure_reasons"],
            ["authorized network `anywhere` allows 0.0.0.0/0"],
        )

    def test_cloud_sql_backup_disabled_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    backup_enabled=False,
                    pitr_enabled=False,
                    private_network="google_compute_network.main.id",
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-sql-backup-disabled"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-backup-disabled")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_sql_database_instance.app"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["backup_posture"],
            [
                "backup_configuration.enabled is false",
                "point_in_time_recovery_enabled is false",
                "engine is POSTGRES_15",
            ],
        )

    def test_private_backed_up_cloud_sql_instance_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _service_networking_connection(),
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    backup_enabled=True,
                    pitr_enabled=True,
                    private_network="google_compute_network.main.id",
                ),
            ]
        )

        findings = StrideRuleEngine().evaluate(inventory, [])

        self.assertEqual(findings, [])

    def test_cloud_sql_public_ip_without_private_network_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_cloud_sql_instance(ipv4_enabled=True, private_network=None)])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-sql-public-ip-without-private-network"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-public-ip-without-private-network")
        self.assertEqual(finding.severity.value, "medium")
        self.assertEqual(finding.affected_resources, ["google_sql_database_instance.app"])
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["network_posture"],
            [
                "ipv4_enabled is true",
                "private_network is unset",
                "authorized_networks configured: 0",
            ],
        )
        self.assertEqual(
            evidence["public_access_reasons"],
            ["Cloud SQL public IPv4 access is enabled"],
        )

    def test_cloud_sql_private_network_suppresses_public_ip_without_private_network(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    ipv4_enabled=True,
                    private_network="google_compute_network.main.id",
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-sql-public-ip-without-private-network"})),
        )

        self.assertEqual(findings, [])

    def test_cloud_sql_ssl_not_required_is_detected_for_public_ipv4(self) -> None:
        inventory = GcpNormalizer().normalize([_cloud_sql_instance(require_ssl=False)])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-sql-ssl-not-required"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-ssl-not-required")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["ssl_posture"],
            ["require_ssl is false", "ssl_mode is unset", "ipv4_enabled is true"],
        )

    def test_cloud_sql_enforcing_ssl_mode_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize([_cloud_sql_instance(require_ssl=False, ssl_mode="ENCRYPTED_ONLY")])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-sql-ssl-not-required"})),
        )

        self.assertEqual(findings, [])

    def test_cloud_sql_point_in_time_recovery_disabled_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    backup_enabled=True,
                    pitr_enabled=False,
                    private_network="google_compute_network.main.id",
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-sql-point-in-time-recovery-disabled"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-point-in-time-recovery-disabled")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["backup_posture"],
            [
                "backup_configuration.enabled is true",
                "point_in_time_recovery_enabled is false",
                "engine is POSTGRES_15",
            ],
        )

    def test_cloud_sql_zonal_availability_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_cloud_sql_instance(ipv4_enabled=False, availability_type="ZONAL")])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-sql-zonal-availability"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-zonal-availability")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["availability_posture"], ["availability_type=ZONAL", "engine=POSTGRES_15"])

    def test_cloud_sql_regional_availability_is_not_flagged(self) -> None:
        inventory = GcpNormalizer().normalize([_cloud_sql_instance(ipv4_enabled=False, availability_type="REGIONAL")])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-sql-zonal-availability"})),
        )

        self.assertEqual(findings, [])

    def test_cloud_sql_query_insights_disabled_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize([_cloud_sql_instance(ipv4_enabled=False, query_insights_enabled=False)])

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-sql-query-insights-disabled"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-query-insights-disabled")
        self.assertEqual(finding.severity.value, "low")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["query_insights_posture"],
            ["query_insights_enabled=false", "query_insights_state=disabled"],
        )

    def test_cloud_sql_enabled_or_unknown_query_insights_are_not_flagged(self) -> None:
        resources = (
            _cloud_sql_instance(ipv4_enabled=False, query_insights_enabled=True),
            _cloud_sql_instance(
                ipv4_enabled=False,
                unknown_settings={"insights_config": [{"query_insights_enabled": True}]},
            ),
        )

        for resource in resources:
            with self.subTest(resource=resource.unknown_values):
                inventory = GcpNormalizer().normalize([resource])
                findings = StrideRuleEngine().evaluate(
                    inventory,
                    [],
                    rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-sql-query-insights-disabled"})),
                )

                self.assertEqual(findings, [])

    def test_cloud_sql_connector_enforcement_not_required_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    private_network="google_compute_network.main.id",
                    connector_enforcement="NOT_REQUIRED",
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-sql-connector-enforcement-not-required"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-connector-enforcement-not-required")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(
            evidence["connector_enforcement_posture"],
            [
                "connector_enforcement=NOT_REQUIRED",
                "ipv4_enabled=false",
                "private_network=google_compute_network.main.id",
            ],
        )

    def test_cloud_sql_required_or_unknown_connector_enforcement_is_not_flagged(self) -> None:
        resources = (
            _cloud_sql_instance(ipv4_enabled=False, connector_enforcement="REQUIRED"),
            _cloud_sql_instance(
                ipv4_enabled=False,
                unknown_settings={"connector_enforcement": True},
            ),
        )

        for resource in resources:
            with self.subTest(resource=resource.unknown_values):
                inventory = GcpNormalizer().normalize([resource])
                findings = StrideRuleEngine().evaluate(
                    inventory,
                    [],
                    rule_policy=RulePolicy(
                        enabled_rule_ids=frozenset({"gcp-cloud-sql-connector-enforcement-not-required"})
                    ),
                )

                self.assertEqual(findings, [])

    def test_cloud_sql_deletion_protection_disabled_is_detected(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _cloud_sql_instance(
                    ipv4_enabled=False,
                    private_network="google_compute_network.main.id",
                    deletion_protection=False,
                )
            ]
        )

        findings = StrideRuleEngine().evaluate(
            inventory,
            [],
            rule_policy=RulePolicy(enabled_rule_ids=frozenset({"gcp-cloud-sql-deletion-protection-disabled"})),
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "gcp-cloud-sql-deletion-protection-disabled")
        self.assertEqual(finding.severity.value, "medium")
        evidence = {item.key: item.values for item in finding.evidence}
        self.assertEqual(evidence["lifecycle_posture"], ["deletion_protection is false"])


if __name__ == "__main__":
    unittest.main()
