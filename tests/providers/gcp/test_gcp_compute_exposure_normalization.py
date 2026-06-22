from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import (
    GcpNormalizerTestCase,
    _terraform_resource,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer


class GcpComputeExposureNormalizationTests(GcpNormalizerTestCase):
    def test_normalizer_derives_public_compute_exposure_from_matching_firewall(self) -> None:
        inventory = GcpNormalizer().normalize(list(self.resources.values()))
        instance = inventory.get_by_address("google_compute_instance.web")

        self.assertIsNotNone(instance)
        assert instance is not None
        self.assertEqual(instance.vpc_id, "google_compute_network.main.id")
        self.assertTrue(instance.internet_ingress_capable)
        self.assertEqual(
            instance.internet_ingress_reasons,
            [
                "google_compute_firewall.public_ssh ingress tcp 22 from 0.0.0.0/0",
                "google_compute_firewall.public_app ingress tcp 8080 from 0.0.0.0/0",
            ],
        )
        self.assertEqual(
            instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS),
            ["google_compute_firewall.public_ssh", "google_compute_firewall.public_app"],
        )
        self.assertTrue(instance.public_exposure)
        self.assertTrue(instance.direct_internet_reachable)
        self.assertEqual(
            instance.public_exposure_reasons,
            ["compute instance has an external access config and matching firewall rules allow internet ingress"],
        )

    def test_normalizer_derives_public_compute_exposure_from_direct_network_firewall(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_compute_network.main",
                    "google_compute_network",
                    {"name": "tfstride-main"},
                ),
                _terraform_resource(
                    "google_compute_firewall.public_ssh",
                    "google_compute_firewall",
                    {
                        "network": "google_compute_network.main.name",
                        "source_ranges": ["0.0.0.0/0"],
                        "target_tags": ["web"],
                        "allow": [{"protocol": "tcp", "ports": ["22"]}],
                    },
                ),
                _terraform_resource(
                    "google_compute_instance.web",
                    "google_compute_instance",
                    {
                        "name": "tfstride-web",
                        "tags": ["web"],
                        "network_interface": [
                            {
                                "network": "google_compute_network.main.id",
                                "access_config": [{}],
                            }
                        ],
                    },
                ),
            ]
        )
        instance = inventory.get_by_address("google_compute_instance.web")

        self.assertIsNotNone(instance)
        assert instance is not None
        self.assertEqual(instance.vpc_id, "google_compute_network.main.id")
        self.assertTrue(instance.internet_ingress_capable)
        self.assertEqual(
            instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS),
            ["google_compute_firewall.public_ssh"],
        )
        self.assertTrue(instance.public_exposure)
        self.assertTrue(instance.direct_internet_reachable)

    def test_normalizer_derives_public_compute_exposure_from_project_firewall_policy(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_compute_network.main",
                    "google_compute_network",
                    {"name": "tfstride-main"},
                ),
                _terraform_resource(
                    "google_compute_subnetwork.app",
                    "google_compute_subnetwork",
                    {
                        "name": "tfstride-app",
                        "network": "google_compute_network.main.id",
                        "ip_cidr_range": "10.10.1.0/24",
                    },
                ),
                _terraform_resource(
                    "google_compute_firewall_policy.org",
                    "google_compute_firewall_policy",
                    {
                        "short_name": "tfstride-org-policy",
                        "name": "1234567890",
                        "parent": "organizations/1234567890",
                    },
                ),
                _terraform_resource(
                    "google_compute_firewall_policy_association.project",
                    "google_compute_firewall_policy_association",
                    {
                        "name": "tfstride-project-policy",
                        "firewall_policy": "google_compute_firewall_policy.org.name",
                        "attachment_target": "projects/tfstride-demo",
                    },
                ),
                _terraform_resource(
                    "google_compute_firewall_policy_rule.public_admin",
                    "google_compute_firewall_policy_rule",
                    {
                        "firewall_policy": "1234567890",
                        "priority": 1000,
                        "action": "ALLOW",
                        "direction": "INGRESS",
                        "match": [
                            {
                                "src_ip_ranges": ["0.0.0.0/0"],
                                "layer4_configs": [{"ip_protocol": "tcp", "ports": ["22"]}],
                            }
                        ],
                    },
                ),
                _terraform_resource(
                    "google_compute_instance.web",
                    "google_compute_instance",
                    {
                        "name": "tfstride-web",
                        "project": "tfstride-demo",
                        "network_interface": [
                            {
                                "subnetwork": "google_compute_subnetwork.app.id",
                                "access_config": [{}],
                            }
                        ],
                    },
                ),
            ]
        )
        instance = inventory.get_by_address("google_compute_instance.web")

        self.assertIsNotNone(instance)
        assert instance is not None
        self.assertTrue(instance.internet_ingress_capable)
        self.assertEqual(
            instance.internet_ingress_reasons,
            ["google_compute_firewall_policy_rule.public_admin ingress tcp 22 from 0.0.0.0/0"],
        )
        self.assertEqual(
            instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS),
            ["google_compute_firewall_policy_rule.public_admin"],
        )
        self.assertTrue(instance.public_exposure)
        self.assertTrue(instance.direct_internet_reachable)

    def test_firewall_policy_target_resources_can_apply_without_association(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_compute_network.main",
                    "google_compute_network",
                    {"name": "tfstride-main"},
                ),
                _terraform_resource(
                    "google_compute_firewall_policy_rule.public_admin",
                    "google_compute_firewall_policy_rule",
                    {
                        "firewall_policy": "google_compute_firewall_policy.org.name",
                        "priority": 1000,
                        "action": "allow",
                        "direction": "INGRESS",
                        "target_resources": ["google_compute_network.main.id"],
                        "match": [
                            {
                                "src_ip_ranges": ["0.0.0.0/0"],
                                "layer4_configs": [{"ip_protocol": "tcp", "ports": ["3389"]}],
                            }
                        ],
                    },
                ),
                _terraform_resource(
                    "google_compute_instance.web",
                    "google_compute_instance",
                    {
                        "name": "tfstride-web",
                        "network_interface": [
                            {
                                "network": "google_compute_network.main.id",
                                "access_config": [{}],
                            }
                        ],
                    },
                ),
            ]
        )
        instance = inventory.get_by_address("google_compute_instance.web")

        self.assertIsNotNone(instance)
        assert instance is not None
        self.assertTrue(instance.internet_ingress_capable)
        self.assertEqual(
            instance.internet_ingress_reasons,
            ["google_compute_firewall_policy_rule.public_admin ingress tcp 3389 from 0.0.0.0/0"],
        )

    def test_firewall_policy_target_service_accounts_limit_compute_matches(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_compute_network.main",
                    "google_compute_network",
                    {"name": "tfstride-main"},
                ),
                _terraform_resource(
                    "google_compute_firewall_policy_association.project",
                    "google_compute_firewall_policy_association",
                    {
                        "name": "tfstride-project-policy",
                        "firewall_policy": "google_compute_firewall_policy.org.name",
                        "attachment_target": "projects/tfstride-demo",
                    },
                ),
                _terraform_resource(
                    "google_compute_firewall_policy_rule.public_admin",
                    "google_compute_firewall_policy_rule",
                    {
                        "firewall_policy": "google_compute_firewall_policy.org.name",
                        "priority": 1000,
                        "action": "allow",
                        "direction": "INGRESS",
                        "target_service_accounts": ["other@tfstride-demo.iam.gserviceaccount.com"],
                        "match": [
                            {
                                "src_ip_ranges": ["0.0.0.0/0"],
                                "layer4_configs": [{"ip_protocol": "tcp", "ports": ["22"]}],
                            }
                        ],
                    },
                ),
                _terraform_resource(
                    "google_compute_instance.web",
                    "google_compute_instance",
                    {
                        "name": "tfstride-web",
                        "project": "tfstride-demo",
                        "network_interface": [
                            {
                                "network": "google_compute_network.main.id",
                                "access_config": [{}],
                            }
                        ],
                        "service_account": [
                            {
                                "email": "tfstride-web@tfstride-demo.iam.gserviceaccount.com",
                                "scopes": ["cloud-platform"],
                            }
                        ],
                    },
                ),
            ]
        )
        instance = inventory.get_by_address("google_compute_instance.web")

        self.assertIsNotNone(instance)
        assert instance is not None
        self.assertFalse(instance.internet_ingress_capable)
        self.assertEqual(instance.internet_ingress_reasons, [])
        self.assertFalse(instance.public_exposure)

    def test_normalizer_ignores_disabled_egress_and_non_public_firewall_policy_rules(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_compute_network.main",
                    "google_compute_network",
                    {"name": "tfstride-main"},
                ),
                _terraform_resource(
                    "google_compute_firewall_policy_association.project",
                    "google_compute_firewall_policy_association",
                    {
                        "name": "tfstride-project-policy",
                        "firewall_policy": "google_compute_firewall_policy.org.name",
                        "attachment_target": "projects/tfstride-demo",
                    },
                ),
                _terraform_resource(
                    "google_compute_firewall_policy_rule.disabled_admin",
                    "google_compute_firewall_policy_rule",
                    {
                        "firewall_policy": "google_compute_firewall_policy.org.name",
                        "priority": 1000,
                        "action": "allow",
                        "direction": "INGRESS",
                        "disabled": True,
                        "match": [
                            {
                                "src_ip_ranges": ["0.0.0.0/0"],
                                "layer4_configs": [{"ip_protocol": "tcp", "ports": ["22"]}],
                            }
                        ],
                    },
                ),
                _terraform_resource(
                    "google_compute_firewall_policy_rule.egress_admin",
                    "google_compute_firewall_policy_rule",
                    {
                        "firewall_policy": "google_compute_firewall_policy.org.name",
                        "priority": 1001,
                        "action": "allow",
                        "direction": "EGRESS",
                        "match": [
                            {
                                "dest_ip_ranges": ["0.0.0.0/0"],
                                "layer4_configs": [{"ip_protocol": "tcp", "ports": ["3389"]}],
                            }
                        ],
                    },
                ),
                _terraform_resource(
                    "google_compute_firewall_policy_rule.internal_admin",
                    "google_compute_firewall_policy_rule",
                    {
                        "firewall_policy": "google_compute_firewall_policy.org.name",
                        "priority": 1002,
                        "action": "allow",
                        "direction": "INGRESS",
                        "match": [
                            {
                                "src_ip_ranges": ["10.10.0.0/16"],
                                "layer4_configs": [{"ip_protocol": "tcp", "ports": ["22"]}],
                            }
                        ],
                    },
                ),
                _terraform_resource(
                    "google_compute_instance.web",
                    "google_compute_instance",
                    {
                        "name": "tfstride-web",
                        "project": "tfstride-demo",
                        "network_interface": [
                            {
                                "network": "google_compute_network.main.id",
                                "access_config": [{}],
                            }
                        ],
                    },
                ),
            ]
        )
        instance = inventory.get_by_address("google_compute_instance.web")

        self.assertIsNotNone(instance)
        assert instance is not None
        self.assertFalse(instance.internet_ingress_capable)
        self.assertEqual(instance.internet_ingress_reasons, [])
        self.assertEqual(instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS), [])
        self.assertFalse(instance.public_exposure)

    def test_normalizer_matches_firewall_on_later_instance_network_interface(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_compute_network.primary",
                    "google_compute_network",
                    {"name": "tfstride-primary"},
                ),
                _terraform_resource(
                    "google_compute_network.edge",
                    "google_compute_network",
                    {"name": "tfstride-edge"},
                ),
                _terraform_resource(
                    "google_compute_firewall.public_ssh",
                    "google_compute_firewall",
                    {
                        "network": "google_compute_network.edge.name",
                        "source_ranges": ["0.0.0.0/0"],
                        "target_tags": ["web"],
                        "allow": [{"protocol": "tcp", "ports": ["22"]}],
                    },
                ),
                _terraform_resource(
                    "google_compute_instance.web",
                    "google_compute_instance",
                    {
                        "name": "tfstride-web",
                        "tags": ["web"],
                        "network_interface": [
                            {"network": "google_compute_network.primary.id"},
                            {
                                "network": "google_compute_network.edge.id",
                                "access_config": [{}],
                            },
                        ],
                    },
                ),
            ]
        )
        instance = inventory.get_by_address("google_compute_instance.web")

        self.assertIsNotNone(instance)
        assert instance is not None
        self.assertIsNone(instance.vpc_id)
        self.assertTrue(instance.internet_ingress_capable)
        self.assertEqual(
            instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS),
            ["google_compute_firewall.public_ssh"],
        )
        self.assertTrue(instance.public_exposure)

    def test_normalizer_ignores_malformed_instance_network_reference(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_compute_instance.web",
                    "google_compute_instance",
                    {
                        "name": "tfstride-web",
                        "network_interface": [
                            {"network": {"self_link": "projects/demo/global/networks/tfstride-main"}}
                        ],
                    },
                ),
            ]
        )
        instance = inventory.get_by_address("google_compute_instance.web")

        self.assertIsNotNone(instance)
        assert instance is not None
        self.assertIsNone(instance.vpc_id)

    def test_normalizer_derives_subnet_public_route_and_nat_egress_posture(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_compute_network.main",
                    "google_compute_network",
                    {"name": "tfstride-main"},
                ),
                _terraform_resource(
                    "google_compute_subnetwork.app",
                    "google_compute_subnetwork",
                    {
                        "name": "tfstride-app",
                        "network": "google_compute_network.main.id",
                        "ip_cidr_range": "10.10.1.0/24",
                    },
                ),
                _terraform_resource(
                    "google_compute_route.default_internet",
                    "google_compute_route",
                    {
                        "name": "default-internet",
                        "network": "google_compute_network.main.id",
                        "dest_range": "0.0.0.0/0",
                        "next_hop_gateway": "default-internet-gateway",
                    },
                ),
                _terraform_resource(
                    "google_compute_router.main",
                    "google_compute_router",
                    {
                        "name": "tfstride-router",
                        "network": "google_compute_network.main.id",
                        "region": "us-central1",
                    },
                ),
                _terraform_resource(
                    "google_compute_router_nat.main",
                    "google_compute_router_nat",
                    {
                        "name": "tfstride-nat",
                        "router": "google_compute_router.main.name",
                        "source_subnetwork_ip_ranges_to_nat": "ALL_SUBNETWORKS_ALL_IP_RANGES",
                    },
                ),
                _terraform_resource(
                    "google_compute_instance.web",
                    "google_compute_instance",
                    {
                        "name": "tfstride-web",
                        "network_interface": [{"subnetwork": "google_compute_subnetwork.app.id"}],
                    },
                ),
            ]
        )
        subnet = inventory.get_by_address("google_compute_subnetwork.app")
        instance = inventory.get_by_address("google_compute_instance.web")

        self.assertIsNotNone(subnet)
        self.assertIsNotNone(instance)
        assert subnet is not None
        assert instance is not None
        self.assertTrue(subnet.has_public_route)
        self.assertTrue(subnet.is_public_subnet)
        self.assertTrue(subnet.has_nat_gateway_egress)
        self.assertTrue(instance.in_public_subnet)
        self.assertTrue(instance.has_nat_gateway_egress)

    def test_source_scoped_firewall_does_not_create_public_compute_exposure(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_compute_network.main",
                    "google_compute_network",
                    {"name": "tfstride-main"},
                ),
                _terraform_resource(
                    "google_compute_subnetwork.app",
                    "google_compute_subnetwork",
                    {
                        "name": "tfstride-app",
                        "network": "google_compute_network.main.id",
                        "ip_cidr_range": "10.10.1.0/24",
                    },
                ),
                _terraform_resource(
                    "google_compute_firewall.from_app",
                    "google_compute_firewall",
                    {
                        "network": "google_compute_network.main.id",
                        "source_tags": ["app"],
                        "target_tags": ["web"],
                        "allow": [{"protocol": "tcp", "ports": ["443"]}],
                    },
                ),
                _terraform_resource(
                    "google_compute_instance.web",
                    "google_compute_instance",
                    {
                        "name": "tfstride-web",
                        "tags": ["web"],
                        "network_interface": [
                            {
                                "subnetwork": "google_compute_subnetwork.app.id",
                                "access_config": [{}],
                            }
                        ],
                    },
                ),
            ]
        )
        instance = inventory.get_by_address("google_compute_instance.web")

        self.assertIsNotNone(instance)
        assert instance is not None
        self.assertFalse(instance.internet_ingress_capable)
        self.assertFalse(instance.public_exposure)
        self.assertEqual(instance.internet_ingress_reasons, [])

    def test_target_service_account_firewall_matches_compute_identity(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_compute_network.main",
                    "google_compute_network",
                    {"name": "tfstride-main"},
                ),
                _terraform_resource(
                    "google_compute_subnetwork.app",
                    "google_compute_subnetwork",
                    {
                        "name": "tfstride-app",
                        "network": "google_compute_network.main.id",
                        "ip_cidr_range": "10.10.1.0/24",
                    },
                ),
                _terraform_resource(
                    "google_compute_firewall.public_https",
                    "google_compute_firewall",
                    {
                        "network": "google_compute_network.main.id",
                        "source_ranges": ["0.0.0.0/0"],
                        "target_service_accounts": ["tfstride-web@tfstride-demo.iam.gserviceaccount.com"],
                        "allow": [{"protocol": "tcp", "ports": ["443"]}],
                    },
                ),
                _terraform_resource(
                    "google_compute_instance.web",
                    "google_compute_instance",
                    {
                        "name": "tfstride-web",
                        "network_interface": [
                            {
                                "subnetwork": "google_compute_subnetwork.app.id",
                                "access_config": [{}],
                            }
                        ],
                        "service_account": [
                            {
                                "email": "tfstride-web@tfstride-demo.iam.gserviceaccount.com",
                                "scopes": ["cloud-platform"],
                            }
                        ],
                    },
                ),
            ]
        )
        instance = inventory.get_by_address("google_compute_instance.web")

        self.assertIsNotNone(instance)
        assert instance is not None
        self.assertTrue(instance.public_exposure)
        self.assertEqual(
            instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS),
            ["google_compute_firewall.public_https"],
        )


if __name__ == "__main__":
    unittest.main()
