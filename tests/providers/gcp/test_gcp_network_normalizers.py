from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import (
    GcpNormalizerTestCase,
    _terraform_resource,
)
from tfstride.models import ResourceCategory
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.network_normalizers import (
    normalize_compute_backend_bucket,
    normalize_compute_backend_service,
    normalize_compute_firewall,
    normalize_compute_firewall_policy,
    normalize_compute_firewall_policy_association,
    normalize_compute_firewall_policy_rule,
    normalize_compute_forwarding_rule,
    normalize_compute_global_address,
    normalize_compute_global_forwarding_rule,
    normalize_compute_managed_ssl_certificate,
    normalize_compute_network,
    normalize_compute_network_endpoint_group,
    normalize_compute_region_network_endpoint_group,
    normalize_compute_route,
    normalize_compute_router,
    normalize_compute_router_nat,
    normalize_compute_service_attachment,
    normalize_compute_ssl_policy,
    normalize_compute_subnetwork,
    normalize_compute_target_https_proxy,
    normalize_compute_url_map,
    normalize_network_connectivity_service_connection_policy,
    normalize_service_networking_connection,
    parse_firewall_allow_rules,
    parse_firewall_policy_allow_rules,
    parse_firewall_policy_rules,
)
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts


class GcpNetworkNormalizerTests(GcpNormalizerTestCase):
    def test_compute_network_normalizer_preserves_network_metadata(self) -> None:
        normalized = normalize_compute_network(self.resources["google_compute_network.main"])

        self.assertEqual(normalized.provider, "gcp")
        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.identifier, "tfstride-main")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.NAME), "tfstride-main")
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.AUTO_CREATE_SUBNETWORKS))
        self.assertEqual(normalized.metadata_snapshot()["routing_mode"], "REGIONAL")

    def test_compute_subnetwork_normalizer_preserves_region_and_network(self) -> None:
        normalized = normalize_compute_subnetwork(self.resources["google_compute_subnetwork.app"])
        facts = gcp_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.vpc_id, "google_compute_network.main.id")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.REGION), "us-central1")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.CIDR_RANGE), "10.10.1.0/24")
        self.assertEqual(facts.subnetwork_flow_log_state, "not_configured")
        self.assertEqual(facts.subnetwork_flow_log_config, {})
        self.assertEqual(facts.network_telemetry_posture_uncertainties, [])

    def test_compute_subnetwork_normalizes_flow_log_posture(self) -> None:
        normalized = normalize_compute_subnetwork(
            _terraform_resource(
                "google_compute_subnetwork.app",
                "google_compute_subnetwork",
                {
                    "name": "app",
                    "network": "google_compute_network.main.id",
                    "region": "us-central1",
                    "ip_cidr_range": "10.10.1.0/24",
                    "log_config": [
                        {
                            "aggregation_interval": "INTERVAL_5_SEC",
                            "flow_sampling": 0.7,
                            "metadata": "INCLUDE_ALL_METADATA",
                            "metadata_fields": ["src_instance", "dest_instance"],
                            "filter_expr": "true",
                        }
                    ],
                },
            )
        )
        facts = gcp_facts(normalized)

        self.assertEqual(facts.subnetwork_flow_log_state, "enabled")
        self.assertEqual(
            facts.subnetwork_flow_log_config,
            {
                "aggregation_interval": "INTERVAL_5_SEC",
                "flow_sampling": 0.7,
                "metadata": "INCLUDE_ALL_METADATA",
                "metadata_fields": ["src_instance", "dest_instance"],
                "filter_expr": "true",
            },
        )
        self.assertEqual(facts.subnetwork_flow_log_aggregation_interval, "INTERVAL_5_SEC")
        self.assertEqual(facts.subnetwork_flow_log_sampling, "0.7")
        self.assertEqual(facts.subnetwork_flow_log_metadata, "INCLUDE_ALL_METADATA")
        self.assertEqual(facts.subnetwork_flow_log_metadata_fields, ["src_instance", "dest_instance"])
        self.assertEqual(facts.subnetwork_flow_log_filter_expr, "true")
        self.assertEqual(facts.network_telemetry_posture_uncertainties, [])

    def test_compute_subnetwork_preserves_unknown_flow_log_block(self) -> None:
        normalized = normalize_compute_subnetwork(
            _terraform_resource(
                "google_compute_subnetwork.app",
                "google_compute_subnetwork",
                {
                    "name": "app",
                    "network": "google_compute_network.main.id",
                    "region": "us-central1",
                    "ip_cidr_range": "10.10.1.0/24",
                },
                unknown_values={"log_config": True},
            )
        )
        facts = gcp_facts(normalized)

        self.assertEqual(facts.subnetwork_flow_log_state, "unknown")
        self.assertEqual(facts.subnetwork_flow_log_config, {})
        self.assertEqual(
            facts.network_telemetry_posture_uncertainties,
            ["log_config is unknown after planning"],
        )

    def test_compute_subnetwork_preserves_unknown_flow_log_fields(self) -> None:
        normalized = normalize_compute_subnetwork(
            _terraform_resource(
                "google_compute_subnetwork.app",
                "google_compute_subnetwork",
                {
                    "name": "app",
                    "network": "google_compute_network.main.id",
                    "region": "us-central1",
                    "ip_cidr_range": "10.10.1.0/24",
                    "log_config": [{"aggregation_interval": "INTERVAL_30_SEC"}],
                },
                unknown_values={"log_config": [{"flow_sampling": True, "metadata_fields": True}]},
            )
        )
        facts = gcp_facts(normalized)

        self.assertEqual(facts.subnetwork_flow_log_state, "enabled")
        self.assertEqual(facts.subnetwork_flow_log_aggregation_interval, "INTERVAL_30_SEC")
        self.assertIsNone(facts.subnetwork_flow_log_sampling)
        self.assertEqual(facts.subnetwork_flow_log_metadata_fields, [])
        self.assertEqual(
            facts.network_telemetry_posture_uncertainties,
            [
                "log_config.flow_sampling is unknown after planning",
                "log_config.metadata_fields is unknown after planning",
            ],
        )

    def test_compute_route_normalizer_preserves_default_route_context(self) -> None:
        normalized = normalize_compute_route(
            _terraform_resource(
                "google_compute_route.default_internet",
                "google_compute_route",
                {
                    "name": "default-internet",
                    "network": "google_compute_network.main.id",
                    "dest_range": "0.0.0.0/0",
                    "next_hop_gateway": "default-internet-gateway",
                    "priority": 1000,
                    "tags": ["web"],
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.vpc_id, "google_compute_network.main.id")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.ROUTE_DEST_RANGE), "0.0.0.0/0")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.ROUTE_NEXT_HOP_GATEWAY),
            "default-internet-gateway",
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.ROUTE_TAGS), ["web"])
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.ROUTE_PRIORITY), 1000)

    def test_compute_router_and_nat_normalizers_preserve_egress_context(self) -> None:
        router = normalize_compute_router(
            _terraform_resource(
                "google_compute_router.main",
                "google_compute_router",
                {
                    "name": "tfstride-router",
                    "network": "google_compute_network.main.id",
                    "region": "us-central1",
                    "bgp": [{"asn": 64514}],
                },
            )
        )
        router_nat = normalize_compute_router_nat(
            _terraform_resource(
                "google_compute_router_nat.main",
                "google_compute_router_nat",
                {
                    "name": "tfstride-nat",
                    "router": "google_compute_router.main.name",
                    "region": "us-central1",
                    "source_subnetwork_ip_ranges_to_nat": "LIST_OF_SUBNETWORKS",
                    "subnetwork": [
                        {
                            "name": "google_compute_subnetwork.app.id",
                            "source_ip_ranges_to_nat": ["ALL_IP_RANGES"],
                        }
                    ],
                },
            )
        )

        self.assertEqual(router.vpc_id, "google_compute_network.main.id")
        self.assertEqual(router.metadata_snapshot()["bgp"], {"asn": 64514})
        self.assertEqual(
            router_nat.get_metadata_field(GcpResourceMetadata.ROUTER_REFERENCE),
            "google_compute_router.main.name",
        )
        self.assertEqual(
            router_nat.get_metadata_field(GcpResourceMetadata.NAT_SUBNETWORKS),
            [{"name": "google_compute_subnetwork.app.id", "source_ip_ranges_to_nat": ["ALL_IP_RANGES"]}],
        )

    def test_private_service_access_address_normalizer_preserves_reserved_range_context(self) -> None:
        normalized = normalize_compute_global_address(
            _terraform_resource(
                "google_compute_global_address.private_services",
                "google_compute_global_address",
                {
                    "name": "private-services-range",
                    "project": "demo",
                    "self_link": "projects/demo/global/addresses/private-services-range",
                    "purpose": "VPC_PEERING",
                    "address_type": "INTERNAL",
                    "address": "10.30.0.0",
                    "prefix_length": 16,
                    "network": "google_compute_network.main.id",
                },
            )
        )
        facts = gcp_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.vpc_id, "google_compute_network.main.id")
        self.assertEqual(facts.private_connectivity_purpose, "VPC_PEERING")
        self.assertEqual(facts.private_connectivity_address_type, "INTERNAL")
        self.assertEqual(facts.private_connectivity_address, "10.30.0.0")
        self.assertEqual(facts.private_connectivity_prefix_length, 16)
        self.assertEqual(facts.private_connectivity_uncertainties, [])

    def test_service_networking_connection_normalizer_preserves_psa_connection_context(self) -> None:
        normalized = normalize_service_networking_connection(
            _terraform_resource(
                "google_service_networking_connection.private_services",
                "google_service_networking_connection",
                {
                    "network": "google_compute_network.main.id",
                    "service": "servicenetworking.googleapis.com",
                    "reserved_peering_ranges": ["private-services-range"],
                    "peering": "servicenetworking-googleapis-com",
                    "deletion_policy": "ABANDON",
                },
            )
        )
        facts = gcp_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.vpc_id, "google_compute_network.main.id")
        self.assertEqual(facts.private_connectivity_service, "servicenetworking.googleapis.com")
        self.assertEqual(facts.private_connectivity_reserved_ranges, ["private-services-range"])
        self.assertEqual(facts.private_connectivity_peering, "servicenetworking-googleapis-com")
        self.assertEqual(normalized.metadata_snapshot()["deletion_policy"], "ABANDON")
        self.assertEqual(facts.private_connectivity_uncertainties, [])

    def test_service_networking_connection_preserves_unknown_values_as_uncertainty(self) -> None:
        normalized = normalize_service_networking_connection(
            _terraform_resource(
                "google_service_networking_connection.private_services",
                "google_service_networking_connection",
                {},
                unknown_values={"network": True, "service": True, "reserved_peering_ranges": True},
            )
        )
        facts = gcp_facts(normalized)

        self.assertIsNone(normalized.vpc_id)
        self.assertIsNone(facts.private_connectivity_service)
        self.assertEqual(facts.private_connectivity_reserved_ranges, [])
        self.assertEqual(
            facts.private_connectivity_uncertainties,
            [
                "network is unknown after planning",
                "service is unknown after planning",
                "reserved_peering_ranges is unknown after planning",
            ],
        )

    def test_psc_forwarding_rule_evidence_is_preserved_without_changing_public_posture(self) -> None:
        normalized = normalize_compute_forwarding_rule(
            _terraform_resource(
                "google_compute_forwarding_rule.sql_psc",
                "google_compute_forwarding_rule",
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
            )
        )
        facts = gcp_facts(normalized)

        self.assertFalse(normalized.public_access_configured)
        self.assertFalse(normalized.direct_internet_reachable)
        self.assertEqual(normalized.vpc_id, "google_compute_network.main.id")
        self.assertEqual(normalized.subnet_ids, ("google_compute_subnetwork.private.id",))
        self.assertEqual(facts.forwarding_rule_target, "projects/prod/regions/us-central1/serviceAttachments/sql")
        self.assertEqual(facts.psc_connection_id, "12345")
        self.assertEqual(facts.psc_connection_status, "ACCEPTED")
        self.assertEqual(facts.psc_service_label, "sql")
        self.assertEqual(facts.psc_service_name, "projects/prod/regions/us-central1/serviceAttachments/sql")

    def test_psc_service_attachment_normalizer_preserves_producer_context(self) -> None:
        normalized = normalize_compute_service_attachment(
            _terraform_resource(
                "google_compute_service_attachment.sql",
                "google_compute_service_attachment",
                {
                    "name": "sql-attachment",
                    "self_link": "projects/prod/regions/us-central1/serviceAttachments/sql",
                    "project": "prod",
                    "region": "us-central1",
                    "target_service": "google_compute_forwarding_rule.sql_ilb.id",
                    "connection_preference": "ACCEPT_AUTOMATIC",
                    "nat_subnets": ["google_compute_subnetwork.psc_nat.id"],
                    "domain_names": ["sql.internal.example.com"],
                    "consumer_accept_lists": [{"project_id_or_num": "consumer", "connection_limit": 10}],
                    "consumer_reject_lists": [{"project_id_or_num": "blocked"}],
                },
            )
        )
        facts = gcp_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.subnet_ids, ("google_compute_subnetwork.psc_nat.id",))
        self.assertEqual(facts.private_connectivity_target_service, "google_compute_forwarding_rule.sql_ilb.id")
        self.assertEqual(facts.psc_connection_preference, "ACCEPT_AUTOMATIC")
        self.assertEqual(facts.private_connectivity_nat_subnets, ["google_compute_subnetwork.psc_nat.id"])
        self.assertEqual(facts.private_connectivity_domain_names, ["sql.internal.example.com"])
        self.assertEqual(facts.psc_consumer_accept_list, [{"project_id_or_num": "consumer", "connection_limit": 10}])
        self.assertEqual(facts.psc_consumer_reject_list, [{"project_id_or_num": "blocked"}])

    def test_service_connection_policy_normalizer_preserves_psc_config(self) -> None:
        normalized = normalize_network_connectivity_service_connection_policy(
            _terraform_resource(
                "google_network_connectivity_service_connection_policy.sql",
                "google_network_connectivity_service_connection_policy",
                {
                    "name": "sql-policy",
                    "location": "us-central1",
                    "network": "google_compute_network.main.id",
                    "service_class": "gcp-cloud-sql",
                    "psc_config": [
                        {
                            "subnetworks": ["google_compute_subnetwork.psc.id"],
                            "limit": 8,
                        }
                    ],
                },
            )
        )
        facts = gcp_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.vpc_id, "google_compute_network.main.id")
        self.assertEqual(normalized.subnet_ids, ("google_compute_subnetwork.psc.id",))
        self.assertEqual(facts.psc_service_class, "gcp-cloud-sql")
        self.assertEqual(facts.psc_config, {"subnetworks": ["google_compute_subnetwork.psc.id"], "limit": 8})
        self.assertEqual(facts.private_connectivity_subnetworks, ["google_compute_subnetwork.psc.id"])

    def test_forwarding_rule_normalizers_classify_public_edges(self) -> None:
        regional = normalize_compute_forwarding_rule(
            _terraform_resource(
                "google_compute_forwarding_rule.web",
                "google_compute_forwarding_rule",
                {
                    "name": "web-forwarding",
                    "load_balancing_scheme": "EXTERNAL",
                    "ip_address": "35.1.2.3",
                    "target": "google_compute_target_pool.web.id",
                    "ports": ["443"],
                },
            )
        )
        global_rule = normalize_compute_global_forwarding_rule(
            _terraform_resource(
                "google_compute_global_forwarding_rule.web",
                "google_compute_global_forwarding_rule",
                {
                    "name": "web-global",
                    "load_balancing_scheme": "INTERNAL_MANAGED",
                    "target": "google_compute_target_http_proxy.web.id",
                },
            )
        )

        self.assertEqual(regional.category, ResourceCategory.EDGE)
        self.assertTrue(regional.public_access_configured)
        self.assertTrue(regional.public_exposure)
        self.assertTrue(regional.direct_internet_reachable)
        self.assertEqual(
            regional.get_metadata_field(GcpResourceMetadata.FORWARDING_RULE_IP_ADDRESS),
            "35.1.2.3",
        )
        self.assertFalse(global_rule.public_access_configured)
        self.assertFalse(global_rule.direct_internet_reachable)

    def test_load_balancer_routing_normalizers_preserve_graph_references(self) -> None:
        url_map = normalize_compute_url_map(
            _terraform_resource(
                "google_compute_url_map.web",
                "google_compute_url_map",
                {
                    "name": "web-map",
                    "default_service": "google_compute_backend_service.web.id",
                    "host_rule": [{"hosts": ["app.example.com"], "path_matcher": "app"}],
                    "path_matcher": [
                        {
                            "name": "app",
                            "default_service": "google_compute_backend_service.web.id",
                            "path_rule": [
                                {"paths": ["/static/*"], "service": "google_compute_backend_bucket.assets.id"}
                            ],
                        }
                    ],
                },
            )
        )
        target_proxy = normalize_compute_target_https_proxy(
            _terraform_resource(
                "google_compute_target_https_proxy.web",
                "google_compute_target_https_proxy",
                {
                    "name": "web-proxy",
                    "url_map": "google_compute_url_map.web.id",
                    "ssl_certificates": ["google_compute_managed_ssl_certificate.web.id"],
                    "ssl_policy": "google_compute_ssl_policy.modern.id",
                    "certificate_map": "//certificatemanager.googleapis.com/projects/demo/locations/global/certificateMaps/web",
                },
            )
        )
        backend_service = normalize_compute_backend_service(
            _terraform_resource(
                "google_compute_backend_service.web",
                "google_compute_backend_service",
                {
                    "name": "web-backend",
                    "protocol": "HTTP",
                    "load_balancing_scheme": "EXTERNAL_MANAGED",
                    "backend": [{"group": "google_compute_region_network_endpoint_group.run.id"}],
                    "health_checks": ["google_compute_health_check.web.id"],
                },
            )
        )
        backend_bucket = normalize_compute_backend_bucket(
            _terraform_resource(
                "google_compute_backend_bucket.assets",
                "google_compute_backend_bucket",
                {"name": "assets", "bucket_name": "tfstride-assets", "enable_cdn": True},
            )
        )
        neg = normalize_compute_region_network_endpoint_group(
            _terraform_resource(
                "google_compute_region_network_endpoint_group.run",
                "google_compute_region_network_endpoint_group",
                {
                    "name": "run-neg",
                    "region": "us-central1",
                    "network_endpoint_type": "SERVERLESS",
                    "cloud_run": [{"service": "google_cloud_run_v2_service.app.name", "tag": "stable"}],
                },
            )
        )
        compute_neg = normalize_compute_network_endpoint_group(
            _terraform_resource(
                "google_compute_network_endpoint_group.web",
                "google_compute_network_endpoint_group",
                {
                    "name": "web-neg",
                    "zone": "us-central1-a",
                    "network_endpoint_type": "GCE_VM_IP_PORT",
                    "network_endpoint": [{"instance": "google_compute_instance.web.id", "port": 8080}],
                },
            )
        )

        self.assertEqual(url_map.category, ResourceCategory.EDGE)
        self.assertEqual(
            url_map.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_DEFAULT_SERVICE),
            "google_compute_backend_service.web.id",
        )
        self.assertEqual(
            url_map.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_HOST_RULES),
            [{"hosts": ["app.example.com"], "path_matcher": "app"}],
        )
        self.assertEqual(
            url_map.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_PATH_MATCHERS)[0]["path_rule"],
            [{"paths": ["/static/*"], "service": "google_compute_backend_bucket.assets.id"}],
        )
        self.assertEqual(
            target_proxy.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_URL_MAP),
            "google_compute_url_map.web.id",
        )
        self.assertEqual(
            target_proxy.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_SSL_CERTIFICATES),
            ["google_compute_managed_ssl_certificate.web.id"],
        )
        self.assertEqual(
            target_proxy.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_SSL_POLICY),
            "google_compute_ssl_policy.modern.id",
        )
        self.assertEqual(
            target_proxy.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_CERTIFICATE_MAP),
            "//certificatemanager.googleapis.com/projects/demo/locations/global/certificateMaps/web",
        )
        target_proxy_facts = gcp_facts(target_proxy)
        self.assertEqual(target_proxy_facts.load_balancer_ssl_policy, "google_compute_ssl_policy.modern.id")
        self.assertEqual(
            target_proxy_facts.load_balancer_certificate_map,
            "//certificatemanager.googleapis.com/projects/demo/locations/global/certificateMaps/web",
        )
        self.assertEqual(
            backend_service.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_BACKEND_SERVICE_PROTOCOL),
            "HTTP",
        )
        self.assertEqual(
            backend_service.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_BACKEND_SERVICE_LOAD_BALANCING_SCHEME),
            "EXTERNAL_MANAGED",
        )
        self.assertEqual(
            backend_service.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_BACKENDS),
            [{"group": "google_compute_region_network_endpoint_group.run.id"}],
        )
        self.assertEqual(
            backend_bucket.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_BACKEND_BUCKET_NAME),
            "tfstride-assets",
        )
        self.assertEqual(
            neg.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_NETWORK_ENDPOINT_TYPE),
            "SERVERLESS",
        )
        self.assertEqual(
            neg.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_SERVERLESS_ENDPOINTS),
            [{"platform": "cloud_run", "service": "google_cloud_run_v2_service.app.name", "tag": "stable"}],
        )
        self.assertEqual(
            compute_neg.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_NETWORK_ENDPOINT_TYPE),
            "GCE_VM_IP_PORT",
        )
        self.assertEqual(
            compute_neg.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_NETWORK_ENDPOINTS),
            [{"instance": "google_compute_instance.web.id", "port": 8080}],
        )

    def test_load_balancer_tls_posture_normalizers_preserve_policy_and_certificate_facts(self) -> None:
        ssl_policy = normalize_compute_ssl_policy(
            _terraform_resource(
                "google_compute_ssl_policy.modern",
                "google_compute_ssl_policy",
                {
                    "name": "modern-tls",
                    "min_tls_version": "TLS_1_2",
                    "profile": "MODERN",
                    "custom_features": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
                    "enabled_features": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
                },
            )
        )
        managed_certificate = normalize_compute_managed_ssl_certificate(
            _terraform_resource(
                "google_compute_managed_ssl_certificate.web",
                "google_compute_managed_ssl_certificate",
                {
                    "name": "web-cert",
                    "managed": [
                        {
                            "domains": ["app.example.com", "api.example.com"],
                            "status": "ACTIVE",
                        }
                    ],
                },
            )
        )

        self.assertEqual(ssl_policy.category, ResourceCategory.EDGE)
        self.assertEqual(
            ssl_policy.get_metadata_field(GcpResourceMetadata.SSL_POLICY_NAME),
            "modern-tls",
        )
        self.assertEqual(
            ssl_policy.get_metadata_field(GcpResourceMetadata.SSL_POLICY_MIN_TLS_VERSION),
            "TLS_1_2",
        )
        self.assertEqual(ssl_policy.get_metadata_field(GcpResourceMetadata.SSL_POLICY_PROFILE), "MODERN")
        self.assertEqual(
            ssl_policy.get_metadata_field(GcpResourceMetadata.SSL_POLICY_CUSTOM_FEATURES),
            ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
        )
        self.assertEqual(gcp_facts(ssl_policy).ssl_policy_min_tls_version, "TLS_1_2")
        self.assertEqual(gcp_facts(ssl_policy).ssl_policy_profile, "MODERN")

        self.assertEqual(managed_certificate.category, ResourceCategory.EDGE)
        self.assertEqual(
            managed_certificate.get_metadata_field(GcpResourceMetadata.MANAGED_SSL_CERTIFICATE_NAME),
            "web-cert",
        )
        self.assertEqual(
            managed_certificate.get_metadata_field(GcpResourceMetadata.MANAGED_SSL_CERTIFICATE_DOMAINS),
            ["app.example.com", "api.example.com"],
        )
        self.assertEqual(
            managed_certificate.get_metadata_field(GcpResourceMetadata.MANAGED_SSL_CERTIFICATE_STATUS),
            "ACTIVE",
        )
        self.assertEqual(
            gcp_facts(managed_certificate).managed_ssl_certificate_domains,
            ["app.example.com", "api.example.com"],
        )

    def test_gcp_normalizer_supports_tls_posture_resource_types(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_compute_ssl_policy.modern",
                    "google_compute_ssl_policy",
                    {"name": "modern-tls", "min_tls_version": "TLS_1_2"},
                ),
                _terraform_resource(
                    "google_compute_managed_ssl_certificate.web",
                    "google_compute_managed_ssl_certificate",
                    {"name": "web-cert", "managed": [{"domains": ["app.example.com"]}]},
                ),
            ]
        )

        resources_by_address = {resource.address: resource for resource in inventory.resources}
        self.assertEqual(inventory.unsupported_resources, [])
        self.assertIn("google_compute_ssl_policy.modern", resources_by_address)
        self.assertIn("google_compute_managed_ssl_certificate.web", resources_by_address)

    def test_compute_firewall_normalizer_builds_allow_rules(self) -> None:
        normalized = normalize_compute_firewall(self.resources["google_compute_firewall.public_ssh"])

        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.vpc_id, "google_compute_network.main.name")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_TARGET_TAGS), ["web"])
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_DIRECTION), "ingress")
        self.assertIsNone(normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_PRIORITY))
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_DISABLED))
        self.assertEqual(len(normalized.network_rules), 1)
        rule = normalized.network_rules[0]
        self.assertEqual(rule.direction, "ingress")
        self.assertEqual(rule.protocol, "tcp")
        self.assertEqual(rule.from_port, 22)
        self.assertEqual(rule.to_port, 22)
        self.assertEqual(rule.cidr_blocks, ["0.0.0.0/0"])

    def test_firewall_rule_parser_handles_port_ranges_and_all_protocols(self) -> None:
        rules = parse_firewall_allow_rules(
            {
                "direction": "EGRESS",
                "destination_ranges": ["10.0.0.0/8"],
                "allow": [
                    {"protocol": "tcp", "ports": ["443", "8000-8080"]},
                    {"protocol": "all"},
                ],
            }
        )

        self.assertEqual(
            [(rule.protocol, rule.from_port, rule.to_port) for rule in rules],
            [
                ("tcp", 443, 443),
                ("tcp", 8000, 8080),
                ("-1", None, None),
            ],
        )
        self.assertEqual(rules[0].direction, "egress")
        self.assertEqual(rules[0].cidr_blocks, ["10.0.0.0/8"])

    def test_firewall_rule_parser_does_not_default_source_scoped_rules_to_internet(self) -> None:
        rules = parse_firewall_allow_rules(
            {
                "direction": "INGRESS",
                "source_tags": ["app"],
                "allow": [{"protocol": "tcp", "ports": ["443"]}],
            }
        )

        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].cidr_blocks, [])

    def test_compute_firewall_policy_normalizer_preserves_policy_scope(self) -> None:
        normalized = normalize_compute_firewall_policy(
            _terraform_resource(
                "google_compute_firewall_policy.org",
                "google_compute_firewall_policy",
                {
                    "short_name": "tfstride-org-policy",
                    "name": "1234567890",
                    "parent": "organizations/1234567890",
                    "description": "organization ingress policy",
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.identifier, "tfstride-org-policy")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.NAME), "tfstride-org-policy")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_REFERENCE),
            "1234567890",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_PARENT),
            "organizations/1234567890",
        )

    def test_compute_firewall_policy_rule_normalizer_builds_allow_rules(self) -> None:
        normalized = normalize_compute_firewall_policy_rule(
            _terraform_resource(
                "google_compute_firewall_policy_rule.public_admin",
                "google_compute_firewall_policy_rule",
                {
                    "firewall_policy": "google_compute_firewall_policy.org.name",
                    "priority": 1000,
                    "action": "allow",
                    "direction": "INGRESS",
                    "target_service_accounts": ["app@tfstride.iam.gserviceaccount.com"],
                    "match": [
                        {
                            "src_ip_ranges": ["0.0.0.0/0"],
                            "layer4_configs": [
                                {"ip_protocol": "tcp", "ports": ["22", "3389"]},
                                {"ip_protocol": "icmp"},
                            ],
                        }
                    ],
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.identifier, "google_compute_firewall_policy.org.name/rules/1000")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_REFERENCE),
            "google_compute_firewall_policy.org.name",
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_ACTION), "allow")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_DIRECTION), "ingress")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_PRIORITY), 1000)
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_DISABLED))
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_ENABLE_LOGGING))
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_TARGET_SERVICE_ACCOUNTS),
            ["app@tfstride.iam.gserviceaccount.com"],
        )
        self.assertEqual(
            [(rule.protocol, rule.from_port, rule.to_port, rule.cidr_blocks) for rule in normalized.network_rules],
            [
                ("tcp", 22, 22, ["0.0.0.0/0"]),
                ("tcp", 3389, 3389, ["0.0.0.0/0"]),
                ("icmp", None, None, ["0.0.0.0/0"]),
            ],
        )

    def test_compute_firewall_policy_rule_normalizer_builds_deny_match_rules(self) -> None:
        normalized = normalize_compute_firewall_policy_rule(
            _terraform_resource(
                "google_compute_firewall_policy_rule.deny_admin",
                "google_compute_firewall_policy_rule",
                {
                    "firewall_policy": "google_compute_firewall_policy.org.name",
                    "priority": 900,
                    "action": "deny",
                    "direction": "INGRESS",
                    "match": [
                        {
                            "src_ip_ranges": ["0.0.0.0/0"],
                            "layer4_configs": [{"ip_protocol": "tcp", "ports": ["22"]}],
                        }
                    ],
                },
            )
        )

        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_ACTION),
            "deny",
        )
        self.assertEqual(
            [(rule.protocol, rule.from_port, rule.to_port, rule.cidr_blocks) for rule in normalized.network_rules],
            [("tcp", 22, 22, ["0.0.0.0/0"])],
        )

    def test_compute_firewall_policy_association_normalizer_preserves_attachment_target(self) -> None:
        normalized = normalize_compute_firewall_policy_association(
            _terraform_resource(
                "google_compute_firewall_policy_association.org",
                "google_compute_firewall_policy_association",
                {
                    "name": "tfstride-org-policy-association",
                    "firewall_policy": "google_compute_firewall_policy.org.name",
                    "attachment_target": "organizations/1234567890",
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.identifier, "organizations/1234567890")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_REFERENCE),
            "google_compute_firewall_policy.org.name",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.FIREWALL_POLICY_ATTACHMENT_TARGET),
            "organizations/1234567890",
        )

    def test_firewall_policy_rule_parser_handles_egress_and_non_allow_actions(self) -> None:
        allow_rules = parse_firewall_policy_allow_rules(
            {
                "action": "allow",
                "direction": "EGRESS",
                "match": [
                    {
                        "dest_ip_ranges": ["10.0.0.0/8"],
                        "layer4_configs": [{"ip_protocol": "tcp", "ports": ["443"]}],
                    }
                ],
            }
        )
        deny_values = {
            "action": "deny",
            "direction": "INGRESS",
            "match": [
                {
                    "src_ip_ranges": ["0.0.0.0/0"],
                    "layer4_configs": [{"ip_protocol": "tcp", "ports": ["22"]}],
                }
            ],
        }
        legacy_allow_parser_deny_rules = parse_firewall_policy_allow_rules(deny_values)
        policy_deny_rules = parse_firewall_policy_rules(deny_values)

        self.assertEqual(len(allow_rules), 1)
        self.assertEqual(allow_rules[0].direction, "egress")
        self.assertEqual(allow_rules[0].cidr_blocks, ["10.0.0.0/8"])
        self.assertEqual(legacy_allow_parser_deny_rules, [])
        self.assertEqual(len(policy_deny_rules), 1)
        self.assertEqual(policy_deny_rules[0].direction, "ingress")
        self.assertEqual(policy_deny_rules[0].cidr_blocks, ["0.0.0.0/0"])

    def test_firewall_policy_rule_parser_does_not_default_source_scoped_rules_to_internet(self) -> None:
        rules = parse_firewall_policy_allow_rules(
            {
                "action": "allow",
                "direction": "INGRESS",
                "match": [
                    {
                        "src_secure_tags": [{"name": "tagValues/123"}],
                        "layer4_configs": [{"ip_protocol": "tcp", "ports": ["443"]}],
                    }
                ],
            }
        )

        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].cidr_blocks, [])


if __name__ == "__main__":
    unittest.main()
