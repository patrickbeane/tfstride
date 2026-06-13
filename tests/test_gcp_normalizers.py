from __future__ import annotations

import json
import unittest
from pathlib import Path

from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import ResourceCategory, TerraformResource
from tfstride.providers.gcp.coercion import as_bool, as_list, as_optional_int, compact, first_item
from tfstride.providers.gcp.compute_normalizers import normalize_compute_instance
from tfstride.providers.gcp.container_normalizers import normalize_container_cluster, normalize_container_node_pool
from tfstride.providers.gcp.data_normalizers import (
    normalize_bigquery_dataset,
    normalize_bigquery_table,
    normalize_kms_crypto_key,
    normalize_pubsub_subscription,
    normalize_pubsub_topic,
    normalize_secret_manager_secret,
    normalize_sql_database_instance,
    normalize_storage_bucket,
)
from tfstride.providers.gcp.iam_normalizers import (
    normalize_bigquery_dataset_iam_member,
    normalize_bigquery_table_iam_binding,
    normalize_kms_crypto_key_iam_member,
    normalize_kms_key_ring_iam_binding,
    normalize_kms_key_ring_iam_member,
    normalize_kms_key_ring_iam_policy,
    normalize_folder_iam_binding,
    normalize_folder_iam_member,
    normalize_folder_iam_policy,
    normalize_organization_iam_binding,
    normalize_organization_iam_custom_role,
    normalize_organization_iam_member,
    normalize_organization_iam_policy,
    normalize_project_iam_binding,
    normalize_project_iam_custom_role,
    normalize_project_iam_member,
    normalize_project_iam_policy,
    normalize_pubsub_subscription_iam_binding,
    normalize_pubsub_topic_iam_member,
    normalize_secret_manager_secret_iam_member,
    normalize_service_account,
    normalize_service_account_iam_binding,
    normalize_service_account_iam_member,
    normalize_service_account_iam_policy,
    normalize_service_account_key,
    normalize_storage_bucket_iam_binding,
    normalize_storage_bucket_iam_member,
    normalize_storage_bucket_iam_policy,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.serverless_normalizers import (
    normalize_cloud_run_service_iam_member,
    normalize_cloud_run_v2_service,
    normalize_cloudfunctions_function,
    normalize_cloudfunctions_function_iam_member,
)
from tfstride.providers.gcp.org_policy_normalizers import (
    normalize_folder_organization_policy,
    normalize_org_policy_policy,
    normalize_organization_policy,
    normalize_project_organization_policy,
)
from tfstride.providers.gcp.network_normalizers import (
    normalize_compute_backend_bucket,
    normalize_compute_backend_service,
    normalize_compute_firewall,
    normalize_compute_firewall_policy,
    normalize_compute_firewall_policy_association,
    normalize_compute_firewall_policy_rule,
    normalize_compute_forwarding_rule,
    normalize_compute_global_forwarding_rule,
    normalize_compute_network,
    normalize_compute_network_endpoint_group,
    normalize_compute_region_network_endpoint_group,
    normalize_compute_route,
    normalize_compute_router,
    normalize_compute_router_nat,
    normalize_compute_subnetwork,
    normalize_compute_target_https_proxy,
    normalize_compute_url_map,
    parse_firewall_allow_rules,
    parse_firewall_policy_allow_rules,
    parse_firewall_policy_rules,
)
from tfstride.providers.gcp.resource_utils import last_path_segment


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "gcp" / "sample_gcp_plan.json"


def _fixture_resources_by_address():
    return {resource.address: resource for resource in load_terraform_plan(FIXTURE_PATH).resources}


def _terraform_resource(
    address: str,
    resource_type: str,
    values: dict[str, object],
) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name="registry.terraform.io/hashicorp/google",
        values=values,
    )


class GcpCoercionTests(unittest.TestCase):
    def test_coercion_helpers_normalize_terraform_shapes(self) -> None:
        self.assertEqual(as_list(None), [])
        self.assertEqual(as_list("value"), ["value"])
        self.assertEqual(as_list(("a", "b")), ["a", "b"])
        self.assertEqual(compact(["a", None, "", [], 1]), ["a", "1"])
        self.assertTrue(as_bool("enabled"))
        self.assertFalse(as_bool("disabled"))
        self.assertEqual(as_optional_int("22"), 22)
        self.assertIsNone(as_optional_int("not-a-port"))
        self.assertEqual(first_item([{"name": "first"}]), {"name": "first"})
        self.assertIsNone(first_item(["not-a-map"]))

    def test_resource_helpers_extract_provider_identifiers(self) -> None:
        self.assertEqual(
            last_path_segment("projects/demo/global/networks/tfstride-main"),
            "tfstride-main",
        )
        self.assertIsNone(last_path_segment(""))


class GcpResourceNormalizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.resources = _fixture_resources_by_address()

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

        self.assertEqual(normalized.category, ResourceCategory.NETWORK)
        self.assertEqual(normalized.vpc_id, "google_compute_network.main.id")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.REGION), "us-central1")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.CIDR_RANGE), "10.10.1.0/24")


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
                    "network_endpoint": [
                        {"instance": "google_compute_instance.web.id", "port": 8080}
                    ],
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
            backend_service.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_BACKEND_SERVICE_PROTOCOL),
            "HTTP",
        )
        self.assertEqual(
            backend_service.get_metadata_field(
                GcpResourceMetadata.LOAD_BALANCER_BACKEND_SERVICE_LOAD_BALANCING_SCHEME
            ),
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

        self.assertEqual([(rule.protocol, rule.from_port, rule.to_port) for rule in rules], [
            ("tcp", 443, 443),
            ("tcp", 8000, 8080),
            ("-1", None, None),
        ])
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
            [
                (rule.protocol, rule.from_port, rule.to_port, rule.cidr_blocks)
                for rule in normalized.network_rules
            ],
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

    def test_compute_instance_normalizer_preserves_network_and_identity_context(self) -> None:
        normalized = normalize_compute_instance(self.resources["google_compute_instance.web"])

        self.assertEqual(normalized.category, ResourceCategory.COMPUTE)
        self.assertEqual(normalized.subnet_ids, ("google_compute_subnetwork.app.id",))
        self.assertTrue(normalized.public_access_configured)
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.NETWORK_TAGS), ["web"])
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.ZONE), "us-central1-a")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNTS)[0]["email"],
            "tfstride-web@example.iam.gserviceaccount.com",
        )
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.OS_LOGIN_ENABLED))

    def test_compute_instance_normalizer_preserves_os_login_metadata(self) -> None:
        disabled = normalize_compute_instance(
            _terraform_resource(
                "google_compute_instance.app",
                "google_compute_instance",
                {
                    "name": "tfstride-app",
                    "metadata": {"enable-oslogin": "FALSE"},
                },
            )
        )
        enabled = normalize_compute_instance(
            _terraform_resource(
                "google_compute_instance.worker",
                "google_compute_instance",
                {
                    "name": "tfstride-worker",
                    "metadata": {"enable-oslogin": "true"},
                },
            )
        )

        self.assertTrue(disabled.has_metadata_field(GcpResourceMetadata.OS_LOGIN_ENABLED))
        self.assertFalse(disabled.get_metadata_field(GcpResourceMetadata.OS_LOGIN_ENABLED))
        self.assertTrue(enabled.get_metadata_field(GcpResourceMetadata.OS_LOGIN_ENABLED))

    def test_container_cluster_normalizer_preserves_gke_posture(self) -> None:
        normalized = normalize_container_cluster(
            _terraform_resource(
                "google_container_cluster.public",
                "google_container_cluster",
                {
                    "name": "tfstride-gke",
                    "project": "tfstride-demo",
                    "location": "us-central1",
                    "network": "google_compute_network.main.id",
                    "subnetwork": "google_compute_subnetwork.app.id",
                    "endpoint": "35.1.2.3",
                    "private_cluster_config": [
                        {"enable_private_endpoint": False, "enable_private_nodes": False}
                    ],
                    "master_authorized_networks_config": [
                        {"cidr_blocks": [{"display_name": "anywhere", "cidr_block": "0.0.0.0/0"}]}
                    ],
                    "node_config": [
                        {
                            "service_account": "123456789-compute@developer.gserviceaccount.com",
                            "oauth_scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                            "metadata": {"disable-legacy-endpoints": "false"},
                        }
                    ],
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.COMPUTE)
        self.assertEqual(normalized.vpc_id, "google_compute_network.main.id")
        self.assertEqual(normalized.subnet_ids, ("google_compute_subnetwork.app.id",))
        self.assertTrue(normalized.public_access_configured)
        self.assertTrue(normalized.public_exposure)
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.GKE_ENDPOINT), "35.1.2.3")
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.GKE_PRIVATE_ENDPOINT_ENABLED))
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.GKE_MASTER_AUTHORIZED_NETWORKS),
            [{"display_name": "anywhere", "cidr_block": "0.0.0.0/0"}],
        )
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.GKE_WORKLOAD_IDENTITY_ENABLED))
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.GKE_NODE_SERVICE_ACCOUNT),
            "123456789-compute@developer.gserviceaccount.com",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.GKE_NODE_OAUTH_SCOPES),
            ["https://www.googleapis.com/auth/cloud-platform"],
        )
        self.assertTrue(
            normalized.get_metadata_field(GcpResourceMetadata.GKE_LEGACY_METADATA_ENDPOINTS_ENABLED)
        )

    def test_container_node_pool_normalizer_preserves_node_identity(self) -> None:
        normalized = normalize_container_node_pool(
            _terraform_resource(
                "google_container_node_pool.app",
                "google_container_node_pool",
                {
                    "name": "app-pool",
                    "project": "tfstride-demo",
                    "location": "us-central1",
                    "cluster": "google_container_cluster.public.name",
                    "node_config": [
                        {
                            "service_account": "gke-nodes@tfstride-demo.iam.gserviceaccount.com",
                            "oauth_scopes": ["https://www.googleapis.com/auth/logging.write"],
                            "workload_metadata_config": [{"mode": "GKE_METADATA"}],
                            "metadata": {"disable-legacy-endpoints": "true"},
                        }
                    ],
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.COMPUTE)
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.GKE_NODE_SERVICE_ACCOUNT),
            "gke-nodes@tfstride-demo.iam.gserviceaccount.com",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.GKE_NODE_OAUTH_SCOPES),
            ["https://www.googleapis.com/auth/logging.write"],
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.GKE_NODE_METADATA_MODE), "GKE_METADATA")
        self.assertFalse(
            normalized.get_metadata_field(GcpResourceMetadata.GKE_LEGACY_METADATA_ENDPOINTS_ENABLED)
        )
        self.assertEqual(normalized.metadata_snapshot()["cluster"], "google_container_cluster.public.name")

    def test_storage_bucket_normalizer_preserves_bucket_posture(self) -> None:
        normalized = normalize_storage_bucket(self.resources["google_storage_bucket.logs"])

        self.assertEqual(normalized.category, ResourceCategory.DATA)
        self.assertEqual(normalized.identifier, "tfstride-logs")
        self.assertEqual(normalized.data_sensitivity, "sensitive")
        self.assertTrue(normalized.get_metadata_field(GcpResourceMetadata.UNIFORM_BUCKET_LEVEL_ACCESS))
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.GCS_VERSIONING_ENABLED))
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.GCS_VERSIONING_CONFIGURATION), {})
        self.assertIsNone(normalized.get_metadata_field(GcpResourceMetadata.GCS_DEFAULT_KMS_KEY_NAME))
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION))
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.GCS_ENCRYPTION_CONFIGURATION), {})
        self.assertTrue(normalized.storage_encrypted)
        self.assertEqual(normalized.metadata_snapshot()["location"], "US")

    def test_secret_manager_secret_normalizer_preserves_secret_context(self) -> None:
        normalized = normalize_secret_manager_secret(self.resources["google_secret_manager_secret.api_key"])

        self.assertEqual(normalized.category, ResourceCategory.DATA)
        self.assertEqual(normalized.identifier, "projects/tfstride-demo/secrets/tfstride-api-key")
        self.assertEqual(normalized.data_sensitivity, "sensitive")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.SECRET_ID), "tfstride-api-key")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertTrue(normalized.storage_encrypted)
        self.assertEqual(normalized.metadata_snapshot()["replication"], [{"auto": [{}]}])

    def test_kms_crypto_key_normalizer_preserves_key_context(self) -> None:
        normalized = normalize_kms_crypto_key(self.resources["google_kms_crypto_key.customer"])

        self.assertEqual(normalized.category, ResourceCategory.DATA)
        self.assertEqual(
            normalized.identifier,
            "projects/tfstride-demo/locations/global/keyRings/tfstride-app/cryptoKeys/tfstride-customer-key",
        )
        self.assertEqual(normalized.data_sensitivity, "sensitive")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.KMS_PURPOSE), "ENCRYPT_DECRYPT")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.KMS_ROTATION_PERIOD), "7776000s")
        self.assertTrue(normalized.storage_encrypted)

    def test_sql_database_instance_normalizer_preserves_database_posture(self) -> None:
        normalized = normalize_sql_database_instance(self.resources["google_sql_database_instance.app"])

        self.assertEqual(normalized.category, ResourceCategory.DATA)
        self.assertEqual(normalized.identifier, "tfstride-app-db")
        self.assertEqual(normalized.data_sensitivity, "sensitive")
        self.assertTrue(normalized.public_access_configured)
        self.assertTrue(normalized.public_exposure)
        self.assertTrue(normalized.direct_internet_reachable)
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.DATABASE_VERSION), "POSTGRES_15")
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.CLOUD_SQL_BACKUP_ENABLED))
        self.assertFalse(
            normalized.get_metadata_field(GcpResourceMetadata.CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED)
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.CLOUD_SQL_AUTHORIZED_NETWORKS),
            [{"name": "anywhere", "value": "0.0.0.0/0"}],
        )
        self.assertEqual(
            normalized.public_exposure_reasons,
            ["authorized network `anywhere` allows 0.0.0.0/0"],
        )

    def test_pubsub_topic_normalizer_preserves_event_surface_context(self) -> None:
        normalized = normalize_pubsub_topic(
            _terraform_resource(
                "google_pubsub_topic.events",
                "google_pubsub_topic",
                {
                    "name": "tfstride-events",
                    "project": "tfstride-demo",
                    "kms_key_name": "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/pubsub",
                    "labels": {"data": "customer"},
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.DATA)
        self.assertEqual(normalized.identifier, "tfstride-events")
        self.assertEqual(normalized.data_sensitivity, "sensitive")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE),
            "tfstride-events",
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertTrue(normalized.storage_encrypted)
        self.assertTrue(normalized.get_metadata_field(GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION))

    def test_pubsub_subscription_normalizer_preserves_topic_reference(self) -> None:
        normalized = normalize_pubsub_subscription(
            _terraform_resource(
                "google_pubsub_subscription.events",
                "google_pubsub_subscription",
                {
                    "name": "tfstride-events-sub",
                    "topic": "google_pubsub_topic.events.id",
                    "project": "tfstride-demo",
                    "ack_deadline_seconds": 20,
                    "retain_acked_messages": True,
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.DATA)
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_REFERENCE),
            "tfstride-events-sub",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE),
            "google_pubsub_topic.events.id",
        )
        self.assertTrue(normalized.metadata_snapshot()["retain_acked_messages"])

    def test_bigquery_dataset_and_table_normalizers_preserve_data_context(self) -> None:
        dataset = normalize_bigquery_dataset(
            _terraform_resource(
                "google_bigquery_dataset.analytics",
                "google_bigquery_dataset",
                {
                    "dataset_id": "tfstride_analytics",
                    "project": "tfstride-demo",
                    "location": "US",
                    "default_encryption_configuration": [
                        {"kms_key_name": "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/bq"}
                    ],
                },
            )
        )
        table = normalize_bigquery_table(
            _terraform_resource(
                "google_bigquery_table.events",
                "google_bigquery_table",
                {
                    "dataset_id": "google_bigquery_dataset.analytics.dataset_id",
                    "table_id": "events",
                    "project": "tfstride-demo",
                    "deletion_protection": True,
                },
            )
        )

        self.assertEqual(dataset.category, ResourceCategory.DATA)
        self.assertTrue(dataset.get_metadata_field(GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION))
        self.assertEqual(dataset.get_metadata_field(GcpResourceMetadata.BIGQUERY_DATASET_ID), "tfstride_analytics")
        self.assertEqual(
            dataset.get_metadata_field(GcpResourceMetadata.BIGQUERY_DEFAULT_KMS_KEY_NAME),
            "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/bq",
        )
        self.assertEqual(table.get_metadata_field(GcpResourceMetadata.BIGQUERY_TABLE_ID), "events")
        self.assertFalse(table.get_metadata_field(GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION))
        self.assertEqual(
            table.get_metadata_field(GcpResourceMetadata.BIGQUERY_DATASET_ID),
            "google_bigquery_dataset.analytics.dataset_id",
        )
        self.assertTrue(table.metadata_snapshot()["deletion_protection"])

    def test_sql_database_instance_normalizer_handles_private_backed_up_instance(self) -> None:
        normalized = normalize_sql_database_instance(
            _terraform_resource(
                "google_sql_database_instance.private",
                "google_sql_database_instance",
                {
                    "name": "private-db",
                    "database_version": "MYSQL_8_0",
                    "settings": [
                        {
                            "backup_configuration": [
                                {
                                    "enabled": True,
                                    "point_in_time_recovery_enabled": True,
                                }
                            ],
                            "ip_configuration": [
                                {
                                    "ipv4_enabled": False,
                                    "private_network": "google_compute_network.main.id",
                                    "authorized_networks": [],
                                }
                            ],
                        }
                    ],
                },
            )
        )

        self.assertEqual(normalized.vpc_id, "google_compute_network.main.id")
        self.assertFalse(normalized.public_access_configured)
        self.assertFalse(normalized.public_exposure)
        self.assertFalse(normalized.direct_internet_reachable)
        self.assertTrue(normalized.get_metadata_field(GcpResourceMetadata.CLOUD_SQL_BACKUP_ENABLED))
        self.assertTrue(
            normalized.get_metadata_field(GcpResourceMetadata.CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED)
        )

    def test_secret_manager_secret_iam_member_normalizer_preserves_binding_parts(self) -> None:
        normalized = normalize_secret_manager_secret_iam_member(
            self.resources["google_secret_manager_secret_iam_member.public_accessor"]
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(
            normalized.identifier,
            "google_secret_manager_secret.api_key.id:roles/secretmanager.secretAccessor:allAuthenticatedUsers",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SECRET_REFERENCE),
            "google_secret_manager_secret.api_key.id",
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_ROLE), "roles/secretmanager.secretAccessor")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBER), "allAuthenticatedUsers")

    def test_kms_crypto_key_iam_member_normalizer_preserves_binding_parts(self) -> None:
        normalized = normalize_kms_crypto_key_iam_member(
            self.resources["google_kms_crypto_key_iam_member.partner_decrypter"]
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.KMS_CRYPTO_KEY_REFERENCE),
            "google_kms_crypto_key.customer.id",
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_ROLE), "roles/cloudkms.cryptoKeyDecrypter")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBER),
            "serviceAccount:decryptor@partner-project.iam.gserviceaccount.com",
        )

    def test_kms_key_ring_iam_normalizers_preserve_binding_parts(self) -> None:
        key_ring = "projects/tfstride-demo/locations/global/keyRings/tfstride-app"
        member = normalize_kms_key_ring_iam_member(
            _terraform_resource(
                "google_kms_key_ring_iam_member.partner_decrypter",
                "google_kms_key_ring_iam_member",
                {
                    "key_ring_id": key_ring,
                    "role": "roles/cloudkms.cryptoKeyDecrypter",
                    "member": "serviceAccount:decryptor@partner-project.iam.gserviceaccount.com",
                },
            )
        )
        binding = normalize_kms_key_ring_iam_binding(
            _terraform_resource(
                "google_kms_key_ring_iam_binding.partner_decrypters",
                "google_kms_key_ring_iam_binding",
                {
                    "key_ring_id": key_ring,
                    "role": "roles/cloudkms.cryptoKeyDecrypter",
                    "members": [
                        "serviceAccount:decryptor@partner-project.iam.gserviceaccount.com",
                        "group:crypto@example.com",
                    ],
                },
            )
        )
        policy = normalize_kms_key_ring_iam_policy(
            _terraform_resource(
                "google_kms_key_ring_iam_policy.partner_policy",
                "google_kms_key_ring_iam_policy",
                {
                    "key_ring_id": key_ring,
                    "policy_data": {
                        "bindings": [
                            {
                                "role": "roles/cloudkms.cryptoKeyDecrypter",
                                "members": ["serviceAccount:decryptor@partner-project.iam.gserviceaccount.com"],
                            }
                        ]
                    },
                },
            )
        )

        self.assertEqual(member.category, ResourceCategory.IAM)
        self.assertEqual(member.get_metadata_field(GcpResourceMetadata.KMS_KEY_RING), key_ring)
        self.assertEqual(
            member.get_metadata_field(GcpResourceMetadata.IAM_MEMBER),
            "serviceAccount:decryptor@partner-project.iam.gserviceaccount.com",
        )
        self.assertEqual(binding.get_metadata_field(GcpResourceMetadata.KMS_KEY_RING), key_ring)
        self.assertEqual(
            binding.get_metadata_field(GcpResourceMetadata.IAM_MEMBERS),
            [
                "serviceAccount:decryptor@partner-project.iam.gserviceaccount.com",
                "group:crypto@example.com",
            ],
        )
        self.assertEqual(policy.get_metadata_field(GcpResourceMetadata.KMS_KEY_RING), key_ring)
        self.assertEqual(
            policy.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/cloudkms.cryptoKeyDecrypter",
                    "members": ["serviceAccount:decryptor@partner-project.iam.gserviceaccount.com"],
                }
            ],
        )

    def test_service_account_normalizer_preserves_identity_context(self) -> None:
        normalized = normalize_service_account(self.resources["google_service_account.web"])

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.identifier, "tfstride-web@example.iam.gserviceaccount.com")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_ACCOUNT_ID), "tfstride-web")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL),
            "tfstride-web@example.iam.gserviceaccount.com",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER),
            "serviceAccount:tfstride-web@example.iam.gserviceaccount.com",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_UNIQUE_ID),
            "100000000000000000001",
        )
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_DISABLED))

    def test_cloud_run_v2_service_normalizer_preserves_workload_identity(self) -> None:
        normalized = normalize_cloud_run_v2_service(
            _terraform_resource(
                "google_cloud_run_v2_service.api",
                "google_cloud_run_v2_service",
                {
                    "name": "tfstride-api",
                    "project": "tfstride-demo",
                    "location": "us-central1",
                    "ingress": "INGRESS_TRAFFIC_ALL",
                    "uri": "https://tfstride-api.run.app",
                    "template": [
                        {
                            "service_account": "tfstride-api@tfstride-demo.iam.gserviceaccount.com",
                        }
                    ],
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.COMPUTE)
        self.assertTrue(normalized.public_access_configured)
        self.assertFalse(normalized.vpc_enabled)
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE),
            "tfstride-api",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL),
            "tfstride-api@tfstride-demo.iam.gserviceaccount.com",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNTS),
            [{"email": "tfstride-api@tfstride-demo.iam.gserviceaccount.com"}],
        )

    def test_cloud_run_service_iam_member_normalizer_preserves_binding_parts(self) -> None:
        normalized = normalize_cloud_run_service_iam_member(
            _terraform_resource(
                "google_cloud_run_service_iam_member.public_invoker",
                "google_cloud_run_service_iam_member",
                {
                    "service": "tfstride-api",
                    "location": "us-central1",
                    "role": "roles/run.invoker",
                    "member": "allUsers",
                },
            )
        )

        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE),
            "tfstride-api",
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_ROLE), "roles/run.invoker")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBER), "allUsers")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/run.invoker", "members": ["allUsers"]}],
        )

    def test_cloud_run_iam_member_normalizer_preserves_condition(self) -> None:
        condition = {
            "title": "expires_soon",
            "description": "Temporary public launch access",
            'expression': 'request.time < timestamp("2026-07-01T00:00:00Z")',
        }
        normalized = normalize_cloud_run_service_iam_member(
            _terraform_resource(
                "google_cloud_run_v2_service_iam_member.public_invoker",
                "google_cloud_run_v2_service_iam_member",
                {
                    "name": "tfstride-api",
                    "location": "us-central1",
                    "role": "roles/run.invoker",
                    "member": "allUsers",
                    "condition": [condition],
                },
            )
        )

        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_CONDITION), condition)
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/run.invoker", "members": ["allUsers"], "condition": condition}],
        )

    def test_cloudfunctions_function_normalizer_preserves_workload_identity(self) -> None:
        normalized = normalize_cloudfunctions_function(
            _terraform_resource(
                "google_cloudfunctions_function.worker",
                "google_cloudfunctions_function",
                {
                    "name": "tfstride-worker",
                    "project": "tfstride-demo",
                    "region": "us-central1",
                    "runtime": "python312",
                    "trigger_http": True,
                    "service_account_email": "tfstride-worker@tfstride-demo.iam.gserviceaccount.com",
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.COMPUTE)
        self.assertTrue(normalized.public_access_configured)
        self.assertFalse(normalized.vpc_enabled)
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE),
            "tfstride-worker",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER),
            "serviceAccount:tfstride-worker@tfstride-demo.iam.gserviceaccount.com",
        )

    def test_cloudfunctions_function_iam_member_normalizer_preserves_binding_parts(self) -> None:
        normalized = normalize_cloudfunctions_function_iam_member(
            _terraform_resource(
                "google_cloudfunctions_function_iam_member.public_invoker",
                "google_cloudfunctions_function_iam_member",
                {
                    "cloud_function": "tfstride-worker",
                    "region": "us-central1",
                    "role": "roles/cloudfunctions.invoker",
                    "member": "allUsers",
                },
            )
        )

        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE),
            "tfstride-worker",
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_ROLE), "roles/cloudfunctions.invoker")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBER), "allUsers")

    def test_service_account_key_normalizer_preserves_key_context_without_secret_material(self) -> None:
        normalized = normalize_service_account_key(self.resources["google_service_account_key.web"])

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE),
            "google_service_account.web.email",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_ALGORITHM),
            "KEY_ALG_RSA_2048",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_PUBLIC_KEY_TYPE),
            "TYPE_X509_PEM_FILE",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_ID),
            "google_service_account.web.email",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_VALID_AFTER),
            "2026-01-01T00:00:00Z",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_KEY_VALID_BEFORE),
            "2027-01-01T00:00:00Z",
        )
        metadata = normalized.metadata_snapshot()
        self.assertNotIn("private_key", metadata)

    def test_service_account_iam_member_normalizer_preserves_binding_parts(self) -> None:
        normalized = normalize_service_account_iam_member(
            _terraform_resource(
                "google_service_account_iam_member.web_token_creator",
                "google_service_account_iam_member",
                {
                    "service_account_id": "google_service_account.web.name",
                    "role": "roles/iam.serviceAccountTokenCreator",
                    "member": "group:deploy@example.com",
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(
            normalized.identifier,
            "google_service_account.web.name:roles/iam.serviceAccountTokenCreator:group:deploy@example.com",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE),
            "google_service_account.web.name",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/iam.serviceAccountTokenCreator", "members": ["group:deploy@example.com"]}],
        )

    def test_service_account_iam_binding_normalizer_preserves_member_list(self) -> None:
        normalized = normalize_service_account_iam_binding(
            _terraform_resource(
                "google_service_account_iam_binding.web_users",
                "google_service_account_iam_binding",
                {
                    "service_account_id": "google_service_account.web.name",
                    "role": "roles/iam.serviceAccountUser",
                    "members": ["group:deploy@example.com", "user:alice@example.com"],
                },
            )
        )

        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBERS),
            ["group:deploy@example.com", "user:alice@example.com"],
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/iam.serviceAccountUser",
                    "members": ["group:deploy@example.com", "user:alice@example.com"],
                }
            ],
        )

    def test_service_account_iam_policy_normalizer_parses_policy_bindings(self) -> None:
        normalized = normalize_service_account_iam_policy(
            _terraform_resource(
                "google_service_account_iam_policy.web_policy",
                "google_service_account_iam_policy",
                {
                    "service_account_id": "google_service_account.web.name",
                    "policy_data": json.dumps(
                        {
                            "bindings": [
                                {
                                    "role": "roles/iam.serviceAccountUser",
                                    "members": ["group:deploy@example.com"],
                                }
                            ]
                        }
                    ),
                },
            )
        )

        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_REFERENCE),
            "google_service_account.web.name",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/iam.serviceAccountUser", "members": ["group:deploy@example.com"]}],
        )

    def test_pubsub_iam_normalizers_preserve_binding_parts(self) -> None:
        topic_member = normalize_pubsub_topic_iam_member(
            _terraform_resource(
                "google_pubsub_topic_iam_member.public_publisher",
                "google_pubsub_topic_iam_member",
                {
                    "topic": "google_pubsub_topic.events.name",
                    "role": "roles/pubsub.publisher",
                    "member": "allUsers",
                },
            )
        )
        subscription_binding = normalize_pubsub_subscription_iam_binding(
            _terraform_resource(
                "google_pubsub_subscription_iam_binding.public_subscribers",
                "google_pubsub_subscription_iam_binding",
                {
                    "subscription": "google_pubsub_subscription.events.name",
                    "role": "roles/pubsub.subscriber",
                    "members": ["allAuthenticatedUsers", "group:ops@example.com"],
                },
            )
        )

        self.assertEqual(
            topic_member.get_metadata_field(GcpResourceMetadata.PUBSUB_TOPIC_REFERENCE),
            "google_pubsub_topic.events.name",
        )
        self.assertEqual(topic_member.get_metadata_field(GcpResourceMetadata.IAM_MEMBER), "allUsers")
        self.assertEqual(
            subscription_binding.get_metadata_field(GcpResourceMetadata.PUBSUB_SUBSCRIPTION_REFERENCE),
            "google_pubsub_subscription.events.name",
        )
        self.assertEqual(
            subscription_binding.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/pubsub.subscriber",
                    "members": ["allAuthenticatedUsers", "group:ops@example.com"],
                }
            ],
        )

    def test_bigquery_iam_normalizers_preserve_binding_parts(self) -> None:
        dataset_member = normalize_bigquery_dataset_iam_member(
            _terraform_resource(
                "google_bigquery_dataset_iam_member.public_viewer",
                "google_bigquery_dataset_iam_member",
                {
                    "dataset_id": "google_bigquery_dataset.analytics.dataset_id",
                    "role": "roles/bigquery.dataViewer",
                    "member": "allUsers",
                },
            )
        )
        table_binding = normalize_bigquery_table_iam_binding(
            _terraform_resource(
                "google_bigquery_table_iam_binding.domain_owner",
                "google_bigquery_table_iam_binding",
                {
                    "table_id": "google_bigquery_table.events.table_id",
                    "role": "roles/bigquery.dataOwner",
                    "members": ["domain:example.com"],
                },
            )
        )

        self.assertEqual(
            dataset_member.get_metadata_field(GcpResourceMetadata.BIGQUERY_DATASET_REFERENCE),
            "google_bigquery_dataset.analytics.dataset_id",
        )
        self.assertEqual(dataset_member.get_metadata_field(GcpResourceMetadata.IAM_MEMBER), "allUsers")
        self.assertEqual(
            table_binding.get_metadata_field(GcpResourceMetadata.BIGQUERY_TABLE_REFERENCE),
            "google_bigquery_table.events.table_id",
        )
        self.assertEqual(
            table_binding.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/bigquery.dataOwner", "members": ["domain:example.com"]}],
        )

    def test_storage_bucket_iam_member_normalizer_preserves_binding_parts(self) -> None:
        normalized = normalize_storage_bucket_iam_member(
            _terraform_resource(
                "google_storage_bucket_iam_member.public_logs_reader",
                "google_storage_bucket_iam_member",
                {
                    "bucket": "google_storage_bucket.logs.name",
                    "role": "roles/storage.objectViewer",
                    "member": "allUsers",
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(
            normalized.identifier,
            "google_storage_bucket.logs.name:roles/storage.objectViewer:allUsers",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.BUCKET_NAME),
            "google_storage_bucket.logs.name",
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_ROLE), "roles/storage.objectViewer")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBER), "allUsers")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBERS), ["allUsers"])
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}],
        )

    def test_storage_bucket_iam_binding_normalizer_preserves_member_list(self) -> None:
        normalized = normalize_storage_bucket_iam_binding(
            _terraform_resource(
                "google_storage_bucket_iam_binding.logs_readers",
                "google_storage_bucket_iam_binding",
                {
                    "bucket": "tfstride-logs",
                    "role": "roles/storage.objectViewer",
                    "members": ["allUsers", "group:ops@example.com"],
                },
            )
        )

        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.BUCKET_NAME), "tfstride-logs")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBERS),
            ["allUsers", "group:ops@example.com"],
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/storage.objectViewer",
                    "members": ["allUsers", "group:ops@example.com"],
                }
            ],
        )

    def test_storage_bucket_iam_policy_normalizer_parses_policy_bindings(self) -> None:
        normalized = normalize_storage_bucket_iam_policy(
            _terraform_resource(
                "google_storage_bucket_iam_policy.logs_policy",
                "google_storage_bucket_iam_policy",
                {
                    "bucket": "tfstride-logs",
                    "policy_data": json.dumps(
                        {
                            "bindings": [
                                {
                                    "role": "roles/storage.objectViewer",
                                    "members": ["allUsers"],
                                }
                            ]
                        }
                    ),
                },
            )
        )

        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}],
        )

    def test_normalizer_models_public_load_balancer_frontend_reachability(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_compute_global_forwarding_rule.web",
                    "google_compute_global_forwarding_rule",
                    {
                        "name": "web-forwarding",
                        "load_balancing_scheme": "EXTERNAL_MANAGED",
                        "ip_address": "35.1.2.3",
                        "target": "google_compute_target_https_proxy.web.id",
                        "ports": ["443"],
                    },
                ),
                _terraform_resource(
                    "google_compute_target_https_proxy.web",
                    "google_compute_target_https_proxy",
                    {
                        "name": "web-proxy",
                        "url_map": "google_compute_url_map.web.id",
                    },
                ),
                _terraform_resource(
                    "google_compute_url_map.web",
                    "google_compute_url_map",
                    {
                        "name": "web-map",
                        "default_service": "google_compute_backend_service.run.id",
                        "path_matcher": [
                            {
                                "name": "assets",
                                "default_service": "google_compute_backend_service.run.id",
                                "path_rule": [
                                    {
                                        "paths": ["/assets/*"],
                                        "service": "google_compute_backend_bucket.assets.id",
                                    },
                                    {
                                        "paths": ["/vm/*"],
                                        "service": "google_compute_backend_service.compute.id",
                                    }
                                ],
                            }
                        ],
                    },
                ),
                _terraform_resource(
                    "google_compute_backend_service.run",
                    "google_compute_backend_service",
                    {
                        "name": "run-backend",
                        "protocol": "HTTP",
                        "load_balancing_scheme": "EXTERNAL_MANAGED",
                        "backend": [{"group": "google_compute_region_network_endpoint_group.run.id"}],
                    },
                ),
                _terraform_resource(
                    "google_compute_region_network_endpoint_group.run",
                    "google_compute_region_network_endpoint_group",
                    {
                        "name": "run-neg",
                        "region": "us-central1",
                        "network_endpoint_type": "SERVERLESS",
                        "cloud_run": [{"service": "google_cloud_run_v2_service.api.name"}],
                    },
                ),
                _terraform_resource(
                    "google_compute_backend_service.compute",
                    "google_compute_backend_service",
                    {
                        "name": "compute-backend",
                        "protocol": "HTTP",
                        "load_balancing_scheme": "EXTERNAL_MANAGED",
                        "backend": [{"group": "google_compute_network_endpoint_group.web.id"}],
                    },
                ),
                _terraform_resource(
                    "google_compute_network_endpoint_group.web",
                    "google_compute_network_endpoint_group",
                    {
                        "name": "web-neg",
                        "zone": "us-central1-a",
                        "network_endpoint_type": "GCE_VM_IP_PORT",
                        "network_endpoint": [{"instance": "google_compute_instance.web.id", "port": 8080}],
                    },
                ),
                _terraform_resource(
                    "google_compute_instance.web",
                    "google_compute_instance",
                    {
                        "name": "tfstride-web",
                        "network_interface": [{"network": "google_compute_network.main.id"}],
                    },
                ),
                _terraform_resource(
                    "google_cloud_run_v2_service.api",
                    "google_cloud_run_v2_service",
                    {
                        "name": "tfstride-api",
                        "location": "us-central1",
                        "ingress": "INGRESS_TRAFFIC_ALL",
                    },
                ),
                _terraform_resource(
                    "google_compute_backend_bucket.assets",
                    "google_compute_backend_bucket",
                    {"name": "assets-backend", "bucket_name": "tfstride-assets"},
                ),
                _terraform_resource(
                    "google_storage_bucket.assets",
                    "google_storage_bucket",
                    {"name": "tfstride-assets", "location": "US"},
                ),
            ]
        )
        forwarding_rule = inventory.get_by_address("google_compute_global_forwarding_rule.web")
        backend_service = inventory.get_by_address("google_compute_backend_service.run")
        neg = inventory.get_by_address("google_compute_region_network_endpoint_group.run")
        compute_backend_service = inventory.get_by_address("google_compute_backend_service.compute")
        compute_neg = inventory.get_by_address("google_compute_network_endpoint_group.web")
        instance = inventory.get_by_address("google_compute_instance.web")
        service = inventory.get_by_address("google_cloud_run_v2_service.api")
        backend_bucket = inventory.get_by_address("google_compute_backend_bucket.assets")
        bucket = inventory.get_by_address("google_storage_bucket.assets")

        self.assertIsNotNone(forwarding_rule)
        self.assertIsNotNone(backend_service)
        self.assertIsNotNone(neg)
        self.assertIsNotNone(compute_backend_service)
        self.assertIsNotNone(compute_neg)
        self.assertIsNotNone(instance)
        self.assertIsNotNone(service)
        self.assertIsNotNone(backend_bucket)
        self.assertIsNotNone(bucket)
        assert forwarding_rule is not None
        assert backend_service is not None
        assert neg is not None
        assert compute_backend_service is not None
        assert compute_neg is not None
        assert instance is not None
        assert service is not None
        assert backend_bucket is not None
        assert bucket is not None

        reachable_backends = forwarding_rule.get_metadata_field(
            GcpResourceMetadata.LOAD_BALANCER_REACHABLE_BACKENDS
        )
        self.assertGreaterEqual(
            {backend["backend"] for backend in reachable_backends},
            {
                "google_compute_backend_service.run",
                "google_compute_region_network_endpoint_group.run",
                "google_cloud_run_v2_service.api",
                "google_compute_backend_service.compute",
                "google_compute_network_endpoint_group.web",
                "google_compute_instance.web",
                "google_compute_backend_bucket.assets",
                "google_storage_bucket.assets",
            },
        )
        self.assertEqual(
            service.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_FRONTENDS),
            [
                {
                    "forwarding_rule": "google_compute_global_forwarding_rule.web",
                    "load_balancing_scheme": "EXTERNAL_MANAGED",
                    "ip_address": "35.1.2.3",
                    "ports": ["443"],
                    "path": [
                        "google_compute_global_forwarding_rule.web",
                        "google_compute_target_https_proxy.web",
                        "google_compute_url_map.web",
                        "google_compute_backend_service.run",
                        "google_compute_region_network_endpoint_group.run",
                        "google_cloud_run_v2_service.api",
                    ],
                }
            ],
        )
        self.assertEqual(
            bucket.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_FRONTENDS)[0]["path"],
            [
                "google_compute_global_forwarding_rule.web",
                "google_compute_target_https_proxy.web",
                "google_compute_url_map.web",
                "google_compute_backend_bucket.assets",
                "google_storage_bucket.assets",
            ],
        )
        self.assertEqual(
            instance.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_FRONTENDS)[0]["path"],
            [
                "google_compute_global_forwarding_rule.web",
                "google_compute_target_https_proxy.web",
                "google_compute_url_map.web",
                "google_compute_backend_service.compute",
                "google_compute_network_endpoint_group.web",
                "google_compute_instance.web",
            ],
        )
        for backend in (
            backend_service,
            neg,
            service,
            compute_backend_service,
            compute_neg,
            instance,
            backend_bucket,
            bucket,
        ):
            self.assertTrue(
                backend.get_metadata_field(GcpResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER)
            )
            self.assertEqual(
                backend.get_metadata_field(GcpResourceMetadata.INTERNET_FACING_LOAD_BALANCER_ADDRESSES),
                ["google_compute_global_forwarding_rule.web"],
            )
        self.assertEqual(
            backend_service.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_FRONTENDS)[0][
                "forwarding_rule"
            ],
            "google_compute_global_forwarding_rule.web",
        )
        self.assertEqual(
            neg.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_FRONTENDS)[0]["forwarding_rule"],
            "google_compute_global_forwarding_rule.web",
        )
        self.assertEqual(
            backend_bucket.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_FRONTENDS)[0][
                "forwarding_rule"
            ],
            "google_compute_global_forwarding_rule.web",
        )
        self.assertFalse(service.public_exposure)
        self.assertFalse(service.direct_internet_reachable)
        self.assertFalse(instance.public_exposure)
        self.assertFalse(instance.direct_internet_reachable)

    def test_normalizer_derives_public_cloud_run_exposure_from_invoker_iam(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_cloud_run_v2_service.api",
                    "google_cloud_run_v2_service",
                    {
                        "name": "tfstride-api",
                        "location": "us-central1",
                        "ingress": "INGRESS_TRAFFIC_ALL",
                        "template": [
                            {
                                "service_account": "tfstride-api@tfstride-demo.iam.gserviceaccount.com",
                            }
                        ],
                    },
                ),
                _terraform_resource(
                    "google_cloud_run_v2_service_iam_member.public_invoker",
                    "google_cloud_run_v2_service_iam_member",
                    {
                        "name": "tfstride-api",
                        "location": "us-central1",
                        "role": "roles/run.invoker",
                        "member": "allUsers",
                    },
                ),
            ]
        )
        service = inventory.get_by_address("google_cloud_run_v2_service.api")

        self.assertIsNotNone(service)
        assert service is not None
        self.assertTrue(service.public_exposure)
        self.assertTrue(service.direct_internet_reachable)
        self.assertEqual(
            service.public_exposure_reasons,
            ["google_cloud_run_v2_service_iam_member.public_invoker grants roles/run.invoker to allUsers"],
        )
        self.assertEqual(
            service.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/run.invoker",
                    "members": ["allUsers"],
                    "source": "google_cloud_run_v2_service_iam_member.public_invoker",
                }
            ],
        )

    def test_normalizer_keeps_serverless_private_without_public_invoker(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_cloudfunctions_function.worker",
                    "google_cloudfunctions_function",
                    {
                        "name": "tfstride-worker",
                        "region": "us-central1",
                        "trigger_http": True,
                        "service_account_email": "tfstride-worker@tfstride-demo.iam.gserviceaccount.com",
                    },
                )
            ]
        )
        function = inventory.get_by_address("google_cloudfunctions_function.worker")

        self.assertIsNotNone(function)
        assert function is not None
        self.assertTrue(function.public_access_configured)
        self.assertFalse(function.public_exposure)
        self.assertFalse(function.direct_internet_reachable)

    def test_normalizer_attaches_pubsub_and_bigquery_iam_bindings_to_targets(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_pubsub_topic.events",
                    "google_pubsub_topic",
                    {"name": "tfstride-events", "project": "tfstride-demo"},
                ),
                _terraform_resource(
                    "google_pubsub_topic_iam_member.public_publisher",
                    "google_pubsub_topic_iam_member",
                    {
                        "topic": "google_pubsub_topic.events.name",
                        "role": "roles/pubsub.publisher",
                        "member": "allUsers",
                    },
                ),
                _terraform_resource(
                    "google_bigquery_dataset.analytics",
                    "google_bigquery_dataset",
                    {"dataset_id": "tfstride_analytics", "project": "tfstride-demo"},
                ),
                _terraform_resource(
                    "google_bigquery_table.events",
                    "google_bigquery_table",
                    {
                        "dataset_id": "google_bigquery_dataset.analytics.dataset_id",
                        "table_id": "events",
                        "project": "tfstride-demo",
                    },
                ),
                _terraform_resource(
                    "google_bigquery_dataset_iam_member.public_viewer",
                    "google_bigquery_dataset_iam_member",
                    {
                        "dataset_id": "google_bigquery_dataset.analytics.dataset_id",
                        "role": "roles/bigquery.dataViewer",
                        "member": "allAuthenticatedUsers",
                    },
                ),
            ]
        )
        topic = inventory.get_by_address("google_pubsub_topic.events")
        dataset = inventory.get_by_address("google_bigquery_dataset.analytics")
        table = inventory.get_by_address("google_bigquery_table.events")

        self.assertIsNotNone(topic)
        self.assertIsNotNone(dataset)
        self.assertIsNotNone(table)
        assert topic is not None
        assert dataset is not None
        assert table is not None
        self.assertEqual(
            topic.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/pubsub.publisher",
                    "members": ["allUsers"],
                    "source": "google_pubsub_topic_iam_member.public_publisher",
                }
            ],
        )
        self.assertEqual(
            dataset.get_metadata_field(GcpResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES),
            ["google_bigquery_dataset_iam_member.public_viewer"],
        )
        self.assertEqual(table.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS), [])

    def test_normalizer_derives_public_bucket_exposure_from_bucket_iam_member(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_storage_bucket.logs",
                    "google_storage_bucket",
                    {"name": "tfstride-logs", "location": "US"},
                ),
                _terraform_resource(
                    "google_storage_bucket_iam_member.public_logs_reader",
                    "google_storage_bucket_iam_member",
                    {
                        "bucket": "google_storage_bucket.logs.name",
                        "role": "roles/storage.objectViewer",
                        "member": "allUsers",
                    },
                ),
            ]
        )
        bucket = inventory.get_by_address("google_storage_bucket.logs")

        self.assertIsNotNone(bucket)
        assert bucket is not None
        self.assertTrue(bucket.public_access_configured)
        self.assertTrue(bucket.public_exposure)
        self.assertTrue(bucket.direct_internet_reachable)
        self.assertEqual(
            bucket.public_exposure_reasons,
            [
                "google_storage_bucket_iam_member.public_logs_reader grants "
                "roles/storage.objectViewer to allUsers"
            ],
        )
        self.assertEqual(
            bucket.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/storage.objectViewer",
                    "members": ["allUsers"],
                    "source": "google_storage_bucket_iam_member.public_logs_reader",
                }
            ],
        )

    def test_normalizer_attaches_sensitive_resource_iam_bindings_to_targets(self) -> None:
        inventory = GcpNormalizer().normalize(list(self.resources.values()))
        secret = inventory.get_by_address("google_secret_manager_secret.api_key")
        key = inventory.get_by_address("google_kms_crypto_key.customer")

        self.assertIsNotNone(secret)
        self.assertIsNotNone(key)
        assert secret is not None
        assert key is not None
        self.assertEqual(
            secret.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/secretmanager.secretAccessor",
                    "members": ["allAuthenticatedUsers"],
                    "source": "google_secret_manager_secret_iam_member.public_accessor",
                }
            ],
        )
        self.assertEqual(
            secret.get_metadata_field(GcpResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES),
            ["google_secret_manager_secret_iam_member.public_accessor"],
        )
        self.assertEqual(
            key.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/cloudkms.cryptoKeyDecrypter",
                    "members": ["serviceAccount:decryptor@partner-project.iam.gserviceaccount.com"],
                    "source": "google_kms_crypto_key_iam_member.partner_decrypter",
                }
            ],
        )

    def test_normalizer_attaches_kms_key_ring_iam_bindings_to_crypto_keys(self) -> None:
        key_ring = "projects/tfstride-demo/locations/global/keyRings/tfstride-app"
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_kms_crypto_key.customer",
                    "google_kms_crypto_key",
                    {
                        "name": "tfstride-customer-key",
                        "id": f"{key_ring}/cryptoKeys/tfstride-customer-key",
                        "key_ring": key_ring,
                        "purpose": "ENCRYPT_DECRYPT",
                    },
                ),
                _terraform_resource(
                    "google_kms_key_ring_iam_binding.partner_decrypters",
                    "google_kms_key_ring_iam_binding",
                    {
                        "key_ring_id": key_ring,
                        "role": "roles/cloudkms.cryptoKeyDecrypter",
                        "members": ["serviceAccount:decryptor@partner-project.iam.gserviceaccount.com"],
                    },
                ),
            ]
        )

        key = inventory.get_by_address("google_kms_crypto_key.customer")

        self.assertIsNotNone(key)
        assert key is not None
        self.assertEqual(
            key.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/cloudkms.cryptoKeyDecrypter",
                    "members": ["serviceAccount:decryptor@partner-project.iam.gserviceaccount.com"],
                    "source": "google_kms_key_ring_iam_binding.partner_decrypters",
                }
            ],
        )
        self.assertEqual(
            key.get_metadata_field(GcpResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES),
            ["google_kms_key_ring_iam_binding.partner_decrypters"],
        )

    def test_public_access_prevention_suppresses_public_bucket_exposure(self) -> None:
        inventory = GcpNormalizer().normalize(
            [
                _terraform_resource(
                    "google_storage_bucket.logs",
                    "google_storage_bucket",
                    {
                        "name": "tfstride-logs",
                        "location": "US",
                        "public_access_prevention": "enforced",
                    },
                ),
                _terraform_resource(
                    "google_storage_bucket_iam_member.public_logs_reader",
                    "google_storage_bucket_iam_member",
                    {
                        "bucket": "tfstride-logs",
                        "role": "roles/storage.objectViewer",
                        "member": "allUsers",
                    },
                ),
            ]
        )
        bucket = inventory.get_by_address("google_storage_bucket.logs")

        self.assertIsNotNone(bucket)
        assert bucket is not None
        self.assertTrue(bucket.public_access_configured)
        self.assertFalse(bucket.public_exposure)
        self.assertFalse(bucket.direct_internet_reachable)
        self.assertEqual(bucket.public_exposure_reasons, [])

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
            [
                "compute instance has an external access config and matching firewall rules allow internet ingress"
            ],
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

    def test_org_policy_policy_normalizer_preserves_guardrail_rules(self) -> None:
        normalized = normalize_org_policy_policy(
            _terraform_resource(
                "google_org_policy_policy.storage_pap",
                "google_org_policy_policy",
                {
                    "name": "projects/tfstride-demo/policies/constraints/storage.publicAccessPrevention",
                    "parent": "projects/tfstride-demo",
                    "spec": [
                        {
                            "inherit_from_parent": False,
                            "rules": [
                                {
                                    "enforce": True,
                                    "condition": [{"expression": "resource.matchTag('env', 'prod')"}],
                                }
                            ],
                        }
                    ],
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.ORG_POLICY_CONSTRAINT),
            "constraints/storage.publicAccessPrevention",
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.ORG_POLICY_SCOPE), "projects/tfstride-demo")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.ORG_POLICY_SCOPE_TYPE), "project")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertTrue(normalized.get_metadata_field(GcpResourceMetadata.ORG_POLICY_ENFORCED))
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.ORG_POLICY_INHERIT_FROM_PARENT))
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.ORG_POLICY_RULES),
            [
                {
                    "enforced": True,
                    "condition": {"expression": "resource.matchTag('env', 'prod')"},
                }
            ],
        )

    def test_legacy_organization_policy_normalizers_preserve_guardrail_parts(self) -> None:
        org_policy = normalize_organization_policy(
            _terraform_resource(
                "google_organization_policy.allowed_domains",
                "google_organization_policy",
                {
                    "org_id": "1234567890",
                    "constraint": "constraints/iam.allowedPolicyMemberDomains",
                    "list_policy": [
                        {
                            "inherit_from_parent": False,
                            "allow": [{"values": ["C01abcd", "C02wxyz"]}],
                        }
                    ],
                },
            )
        )
        folder_policy = normalize_folder_organization_policy(
            _terraform_resource(
                "google_folder_organization_policy.disable_keys",
                "google_folder_organization_policy",
                {
                    "folder": "folders/12345",
                    "constraint": "constraints/iam.disableServiceAccountKeyCreation",
                    "boolean_policy": [{"enforced": True}],
                },
            )
        )
        project_policy = normalize_project_organization_policy(
            _terraform_resource(
                "google_project_organization_policy.external_ip",
                "google_project_organization_policy",
                {
                    "project": "tfstride-demo",
                    "constraint": "constraints/compute.vmExternalIpAccess",
                    "list_policy": [{"deny": [{"all": True}]}],
                },
            )
        )

        self.assertEqual(org_policy.get_metadata_field(GcpResourceMetadata.ORGANIZATION_ID), "1234567890")
        self.assertEqual(org_policy.get_metadata_field(GcpResourceMetadata.ORG_POLICY_SCOPE_TYPE), "organization")
        self.assertEqual(
            org_policy.get_metadata_field(GcpResourceMetadata.ORG_POLICY_ALLOWED_VALUES),
            ["C01abcd", "C02wxyz"],
        )
        self.assertFalse(org_policy.get_metadata_field(GcpResourceMetadata.ORG_POLICY_INHERIT_FROM_PARENT))
        self.assertEqual(folder_policy.get_metadata_field(GcpResourceMetadata.FOLDER_ID), "folders/12345")
        self.assertTrue(folder_policy.get_metadata_field(GcpResourceMetadata.ORG_POLICY_ENFORCED))
        self.assertEqual(project_policy.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertEqual(
            project_policy.get_metadata_field(GcpResourceMetadata.ORG_POLICY_RULES),
            [{"deny_all": True}],
        )

    def test_project_iam_custom_role_normalizer_preserves_permissions(self) -> None:
        normalized = normalize_project_iam_custom_role(
            _terraform_resource(
                "google_project_iam_custom_role.deployer",
                "google_project_iam_custom_role",
                {
                    "project": "tfstride-demo",
                    "role_id": "deployAdmin",
                    "title": "Deploy Admin",
                    "permissions": [
                        "iam.serviceAccounts.actAs",
                        "cloudfunctions.functions.update",
                    ],
                    "stage": "GA",
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.identifier, "projects/tfstride-demo/roles/deployAdmin")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.NAME),
            "projects/tfstride-demo/roles/deployAdmin",
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.CUSTOM_ROLE_ID), "deployAdmin")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS),
            ["iam.serviceAccounts.actAs", "cloudfunctions.functions.update"],
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.CUSTOM_ROLE_STAGE), "GA")

    def test_organization_iam_custom_role_normalizer_preserves_permissions(self) -> None:
        normalized = normalize_organization_iam_custom_role(
            _terraform_resource(
                "google_organization_iam_custom_role.audit",
                "google_organization_iam_custom_role",
                {
                    "org_id": "1234567890",
                    "role_id": "secretAudit",
                    "permissions": ["secretmanager.versions.access"],
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.identifier, "organizations/1234567890/roles/secretAudit")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.NAME),
            "organizations/1234567890/roles/secretAudit",
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.ORGANIZATION_ID), "1234567890")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.CUSTOM_ROLE_ID), "secretAudit")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS),
            ["secretmanager.versions.access"],
        )

    def test_organization_iam_member_normalizer_preserves_scope_and_binding(self) -> None:
        normalized = normalize_organization_iam_member(
            _terraform_resource(
                "google_organization_iam_member.owner",
                "google_organization_iam_member",
                {
                    "org_id": "1234567890",
                    "role": "roles/resourcemanager.organizationAdmin",
                    "member": "group:platform-admins@example.com",
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.ORGANIZATION_ID), "1234567890")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/resourcemanager.organizationAdmin",
                    "members": ["group:platform-admins@example.com"],
                }
            ],
        )

    def test_organization_iam_binding_normalizer_preserves_member_list(self) -> None:
        normalized = normalize_organization_iam_binding(
            _terraform_resource(
                "google_organization_iam_binding.viewer",
                "google_organization_iam_binding",
                {
                    "org_id": "1234567890",
                    "role": "roles/viewer",
                    "members": ["allAuthenticatedUsers", "group:ops@example.com"],
                },
            )
        )

        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.ORGANIZATION_ID), "1234567890")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBERS),
            ["allAuthenticatedUsers", "group:ops@example.com"],
        )

    def test_organization_iam_policy_normalizer_parses_policy_bindings(self) -> None:
        normalized = normalize_organization_iam_policy(
            _terraform_resource(
                "google_organization_iam_policy.policy",
                "google_organization_iam_policy",
                {
                    "org_id": "1234567890",
                    "policy_data": json.dumps(
                        {"bindings": [{"role": "roles/owner", "members": ["group:admins@example.com"]}]}
                    ),
                },
            )
        )

        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.ORGANIZATION_ID), "1234567890")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/owner", "members": ["group:admins@example.com"]}],
        )

    def test_folder_iam_normalizers_preserve_scope_and_bindings(self) -> None:
        member = normalize_folder_iam_member(
            _terraform_resource(
                "google_folder_iam_member.owner",
                "google_folder_iam_member",
                {
                    "folder": "folders/12345",
                    "role": "roles/resourcemanager.folderAdmin",
                    "member": "group:folder-admins@example.com",
                },
            )
        )
        binding = normalize_folder_iam_binding(
            _terraform_resource(
                "google_folder_iam_binding.viewer",
                "google_folder_iam_binding",
                {
                    "folder": "folders/12345",
                    "role": "roles/viewer",
                    "members": ["domain:example.com"],
                },
            )
        )
        policy = normalize_folder_iam_policy(
            _terraform_resource(
                "google_folder_iam_policy.policy",
                "google_folder_iam_policy",
                {
                    "folder": "folders/12345",
                    "policy_data": {"bindings": [{"role": "roles/editor", "members": ["group:admins@example.com"]}]},
                },
            )
        )

        self.assertEqual(member.get_metadata_field(GcpResourceMetadata.FOLDER_ID), "folders/12345")
        self.assertEqual(binding.get_metadata_field(GcpResourceMetadata.FOLDER_ID), "folders/12345")
        self.assertEqual(policy.get_metadata_field(GcpResourceMetadata.FOLDER_ID), "folders/12345")
        self.assertEqual(
            binding.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/viewer", "members": ["domain:example.com"]}],
        )
        self.assertEqual(
            policy.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/editor", "members": ["group:admins@example.com"]}],
        )

    def test_project_iam_member_normalizer_preserves_binding_parts(self) -> None:
        normalized = normalize_project_iam_member(self.resources["google_project_iam_member.web_viewer"])

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.identifier, "roles/viewer:serviceAccount:tfstride-web@example.iam.gserviceaccount.com")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_ROLE), "roles/viewer")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBER),
            "serviceAccount:tfstride-web@example.iam.gserviceaccount.com",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/viewer",
                    "members": ["serviceAccount:tfstride-web@example.iam.gserviceaccount.com"],
                }
            ],
        )

    def test_project_iam_binding_normalizer_preserves_member_list(self) -> None:
        normalized = normalize_project_iam_binding(
            _terraform_resource(
                "google_project_iam_binding.viewer",
                "google_project_iam_binding",
                {
                    "project": "tfstride-demo",
                    "role": "roles/viewer",
                    "members": ["allUsers", "group:ops@example.com"],
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_ROLE), "roles/viewer")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBERS),
            ["allUsers", "group:ops@example.com"],
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/viewer", "members": ["allUsers", "group:ops@example.com"]}],
        )

    def test_project_iam_policy_normalizer_parses_policy_bindings(self) -> None:
        normalized = normalize_project_iam_policy(
            _terraform_resource(
                "google_project_iam_policy.policy",
                "google_project_iam_policy",
                {
                    "project": "tfstride-demo",
                    "policy_data": json.dumps(
                        {
                            "bindings": [
                                {"role": "roles/viewer", "members": ["allUsers"]},
                                {"role": "roles/owner", "members": ["group:admins@example.com"]},
                            ]
                        }
                    ),
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {"role": "roles/viewer", "members": ["allUsers"]},
                {"role": "roles/owner", "members": ["group:admins@example.com"]},
            ],
        )


if __name__ == "__main__":
    unittest.main()