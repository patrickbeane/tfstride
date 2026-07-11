from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.models import ResourceInventory, TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.private_connectivity_index import build_gcp_private_connectivity_index


def _resource(
    resource_type: str,
    name: str,
    values: dict[str, object],
    *,
    unknown_values: dict[str, object] | None = None,
) -> TerraformResource:
    return _terraform_resource(
        f"{resource_type}.{name}",
        resource_type,
        values,
        unknown_values=unknown_values,
    )


def _network(name: str, *, self_link: str | None = None) -> TerraformResource:
    values: dict[str, object] = {"name": name}
    if self_link:
        values["self_link"] = self_link
    return _resource("google_compute_network", name, values)


def _cloud_sql(name: str, private_network: str | None) -> TerraformResource:
    ip_configuration: dict[str, object] = {"ipv4_enabled": False}
    if private_network is not None:
        ip_configuration["private_network"] = private_network
    return _resource(
        "google_sql_database_instance",
        name,
        {
            "name": name,
            "settings": [
                {
                    "ip_configuration": [ip_configuration],
                    "backup_configuration": [
                        {
                            "enabled": True,
                            "point_in_time_recovery_enabled": True,
                        }
                    ],
                }
            ],
        },
    )


def _inventory(*resources: TerraformResource) -> ResourceInventory:
    return GcpNormalizer().normalize(list(resources))


class GcpPrivateConnectivityIndexTests(unittest.TestCase):
    def test_cloud_sql_private_network_matches_private_service_access(self) -> None:
        inventory = _inventory(
            _network("main", self_link="projects/demo/global/networks/main"),
            _resource(
                "google_compute_global_address",
                "private_services",
                {
                    "name": "private-services-range",
                    "purpose": "VPC_PEERING",
                    "address_type": "INTERNAL",
                    "address": "10.30.0.0",
                    "prefix_length": 16,
                    "network": "google_compute_network.main.id",
                },
            ),
            _resource(
                "google_service_networking_connection",
                "private_services",
                {
                    "network": "projects/demo/global/networks/main",
                    "service": "servicenetworking.googleapis.com",
                    "reserved_peering_ranges": ["private-services-range"],
                    "peering": "servicenetworking-googleapis-com",
                },
            ),
            _cloud_sql("db", "projects/demo/global/networks/main"),
        )
        sql = inventory.get_by_address("google_sql_database_instance.db")
        self.assertIsNotNone(sql)

        index = build_gcp_private_connectivity_index(inventory)
        coverage = index.coverage_for_cloud_sql(sql)

        self.assertTrue(coverage.has_private_service_access)
        self.assertTrue(coverage.has_cloud_sql_private_service_access)
        self.assertTrue(coverage.has_cloud_sql_private_connectivity)
        self.assertTrue(index.coverage_for_network("projects/demo/global/networks/main").has_private_service_access)
        self.assertEqual(
            coverage.private_service_access_connection_addresses,
            ("google_service_networking_connection.private_services",),
        )
        self.assertEqual(coverage.reserved_range_addresses, ("google_compute_global_address.private_services",))
        self.assertEqual(coverage.reserved_range_names, ("private-services-range",))
        self.assertEqual(coverage.uncertainties, ())

    def test_unresolved_private_service_access_connection_is_retained(self) -> None:
        inventory = _inventory(
            _resource(
                "google_service_networking_connection",
                "private_services",
                {
                    "service": "servicenetworking.googleapis.com",
                    "reserved_peering_ranges": ["private-services-range"],
                },
                unknown_values={"network": True},
            )
        )

        index = build_gcp_private_connectivity_index(inventory)

        self.assertEqual(len(index.unresolved_private_service_access_connections), 1)
        unresolved = index.unresolved_private_service_access_connections[0]
        self.assertEqual(unresolved.address, "google_service_networking_connection.private_services")
        self.assertIsNone(unresolved.network)
        self.assertIn("network is unknown after planning", unresolved.uncertainties)
        self.assertFalse(index.coverage_for_network("google_compute_network.main.id").has_private_service_access)

    def test_non_vpc_peering_global_address_is_ignored(self) -> None:
        inventory = _inventory(
            _network("main"),
            _resource(
                "google_compute_global_address",
                "psc_address",
                {
                    "name": "psc-address",
                    "purpose": "PRIVATE_SERVICE_CONNECT",
                    "address_type": "INTERNAL",
                    "address": "10.40.0.10",
                    "network": "google_compute_network.main.id",
                },
            ),
        )

        index = build_gcp_private_connectivity_index(inventory)
        coverage = index.coverage_for_network("google_compute_network.main.id")

        self.assertEqual(coverage.reserved_range_addresses, ())
        self.assertEqual(index.unresolved_private_service_access_reserved_ranges, ())

    def test_cloud_sql_psc_service_connection_policy_matches_network(self) -> None:
        inventory = _inventory(
            _network("main", self_link="projects/demo/global/networks/main"),
            _resource(
                "google_network_connectivity_service_connection_policy",
                "sql",
                {
                    "name": "sql-policy",
                    "location": "us-central1",
                    "network": "projects/demo/global/networks/main",
                    "service_class": "gcp-cloud-sql",
                    "psc_config": [
                        {
                            "subnetworks": ["google_compute_subnetwork.psc.id"],
                            "limit": 8,
                        }
                    ],
                },
            ),
            _cloud_sql("db", "google_compute_network.main.id"),
        )
        sql = inventory.get_by_address("google_sql_database_instance.db")
        self.assertIsNotNone(sql)

        coverage = build_gcp_private_connectivity_index(inventory).coverage_for_cloud_sql(sql)

        self.assertTrue(coverage.has_cloud_sql_psc_policy)
        self.assertTrue(coverage.has_cloud_sql_private_connectivity)
        self.assertEqual(
            coverage.psc_service_connection_policy_addresses,
            ("google_network_connectivity_service_connection_policy.sql",),
        )
        policy = coverage.psc_service_connection_policies[0]
        self.assertEqual(policy.service_class, "gcp-cloud-sql")
        self.assertEqual(policy.subnetworks, ("google_compute_subnetwork.psc.id",))
        self.assertEqual(policy.psc_config["limit"], 8)

    def test_psc_endpoint_and_service_attachment_evidence_is_preserved(self) -> None:
        inventory = _inventory(
            _network("main"),
            _resource(
                "google_compute_forwarding_rule",
                "sql_psc",
                {
                    "name": "sql-psc",
                    "load_balancing_scheme": "INTERNAL",
                    "network": "google_compute_network.main.id",
                    "subnetwork": "google_compute_subnetwork.private.id",
                    "target": "projects/prod/regions/us-central1/serviceAttachments/sql",
                    "psc_connection_id": 12345,
                    "psc_connection_status": "ACCEPTED",
                    "service_label": "sql",
                    "service_name": "projects/prod/regions/us-central1/serviceAttachments/sql",
                },
            ),
            _resource(
                "google_compute_service_attachment",
                "sql",
                {
                    "name": "sql-attachment",
                    "target_service": "google_compute_forwarding_rule.sql_ilb.id",
                    "connection_preference": "ACCEPT_AUTOMATIC",
                    "nat_subnets": ["google_compute_subnetwork.psc_nat.id"],
                    "domain_names": ["sql.internal.example.com"],
                    "consumer_accept_lists": [{"project_id_or_num": "consumer", "connection_limit": 10}],
                    "consumer_reject_lists": [{"project_id_or_num": "blocked"}],
                },
            ),
        )

        index = build_gcp_private_connectivity_index(inventory)
        coverage = index.coverage_for_network("google_compute_network.main.id")

        self.assertEqual(coverage.psc_forwarding_rule_addresses, ("google_compute_forwarding_rule.sql_psc",))
        endpoint = coverage.psc_forwarding_rule_endpoints[0]
        self.assertEqual(endpoint.connection_id, "12345")
        self.assertEqual(endpoint.connection_status, "ACCEPTED")
        self.assertEqual(endpoint.subnetwork, "google_compute_subnetwork.private.id")
        self.assertEqual(len(index.psc_service_attachments), 1)
        attachment = index.psc_service_attachments[0]
        self.assertEqual(attachment.target_service, "google_compute_forwarding_rule.sql_ilb.id")
        self.assertEqual(attachment.nat_subnets, ("google_compute_subnetwork.psc_nat.id",))
        self.assertEqual(attachment.domain_names, ("sql.internal.example.com",))
        self.assertEqual(attachment.consumer_accept_list[0]["project_id_or_num"], "consumer")

    def test_similarly_named_networks_do_not_match_without_reference_alias(self) -> None:
        inventory = _inventory(
            _network("main", self_link="projects/demo/global/networks/main"),
            _network("other", self_link="projects/demo/global/networks/other"),
            _resource(
                "google_service_networking_connection",
                "private_services",
                {
                    "network": "google_compute_network.other.id",
                    "service": "servicenetworking.googleapis.com",
                    "reserved_peering_ranges": ["private-services-range"],
                    "peering": "servicenetworking-googleapis-com",
                },
            ),
            _cloud_sql("db", "projects/demo/global/networks/main"),
        )
        sql = inventory.get_by_address("google_sql_database_instance.db")
        self.assertIsNotNone(sql)

        coverage = build_gcp_private_connectivity_index(inventory).coverage_for_cloud_sql(sql)

        self.assertFalse(coverage.has_private_service_access)
        self.assertFalse(coverage.has_cloud_sql_private_connectivity)
        self.assertEqual(coverage.private_service_access_connection_addresses, ())


if __name__ == "__main__":
    unittest.main()
