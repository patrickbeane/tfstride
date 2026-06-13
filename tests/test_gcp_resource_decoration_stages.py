from __future__ import annotations

import unittest
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, SecurityGroupRule
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_decoration.iam_bindings import (
    DecorateSensitiveIamBindingsStage,
)
from tfstride.providers.gcp.resource_decoration.load_balancer import (
    DeriveLoadBalancerReachabilityStage,
)
from tfstride.providers.gcp.resource_decoration.network_posture import DeriveNetworkPostureStage
from tfstride.providers.gcp.resource_decoration.public_exposure import DerivePublicExposureStage
from tfstride.providers.gcp.resource_index import GcpDecorationContext, GcpResourceIndexBuilder
from tfstride.providers.gcp.resource_types import GcpResourceType


def _gcp_resource(
    address: str,
    resource_type: str,
    category: ResourceCategory,
    *,
    identifier: str | None = None,
    vpc_id: str | None = None,
    subnet_ids: tuple[str, ...] = (),
    public_access_configured: bool = False,
    network_rules: list[SecurityGroupRule] | None = None,
    metadata: dict[Any, object] | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=address,
        provider="gcp",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        category=category,
        identifier=identifier,
        vpc_id=vpc_id,
        subnet_ids=subnet_ids,
        public_access_configured=public_access_configured,
        network_rules=network_rules or [],
        metadata=metadata,
    )


def _context(resources: list[NormalizedResource]) -> GcpDecorationContext:
    return GcpDecorationContext(index=GcpResourceIndexBuilder().build(resources))


def _network() -> NormalizedResource:
    return _gcp_resource(
        "google_compute_network.main",
        GcpResourceType.COMPUTE_NETWORK,
        ResourceCategory.NETWORK,
        identifier="projects/demo/global/networks/main",
        metadata={
            GcpResourceMetadata.NAME: "main",
            GcpResourceMetadata.SELF_LINK: "projects/demo/global/networks/main",
        },
    )


def _subnetwork(address: str) -> NormalizedResource:
    name = address.rsplit(".", 1)[-1]
    return _gcp_resource(
        address,
        GcpResourceType.COMPUTE_SUBNETWORK,
        ResourceCategory.NETWORK,
        identifier=f"projects/demo/regions/us-central1/subnetworks/{name}",
        vpc_id="google_compute_network.main.id",
        metadata={
            GcpResourceMetadata.NAME: name,
            GcpResourceMetadata.SELF_LINK: (
                f"projects/demo/regions/us-central1/subnetworks/{name}"
            ),
        },
    )


def _router() -> NormalizedResource:
    return _gcp_resource(
        "google_compute_router.main",
        GcpResourceType.COMPUTE_ROUTER,
        ResourceCategory.NETWORK,
        vpc_id="google_compute_network.main.id",
        metadata={GcpResourceMetadata.NAME: "main"},
    )


def _public_compute_instance(
    address: str = "google_compute_instance.web",
    *,
    folder_id: str | None = None,
) -> NormalizedResource:
    metadata: dict[Any, object] = {}
    if folder_id is not None:
        metadata[GcpResourceMetadata.FOLDER_ID] = folder_id
    return _gcp_resource(
        address,
        GcpResourceType.COMPUTE_INSTANCE,
        ResourceCategory.COMPUTE,
        vpc_id="google_compute_network.main.id",
        public_access_configured=True,
        metadata=metadata,
    )


def _public_ssh_rule() -> SecurityGroupRule:
    return SecurityGroupRule(
        direction="ingress",
        protocol="tcp",
        from_port=22,
        to_port=22,
        cidr_blocks=["0.0.0.0/0"],
    )


def _compute_firewall(
    address: str,
    *,
    action: str,
    priority: int,
) -> NormalizedResource:
    return _gcp_resource(
        address,
        GcpResourceType.COMPUTE_FIREWALL,
        ResourceCategory.NETWORK,
        vpc_id="google_compute_network.main.id",
        network_rules=[_public_ssh_rule()] if action == "allow" else [],
        metadata={
            GcpResourceMetadata.FIREWALL_DIRECTION: "ingress",
            GcpResourceMetadata.FIREWALL_PRIORITY: priority,
            GcpResourceMetadata.FIREWALL_ALLOW: (
                [{"protocol": "tcp", "ports": ["22"]}] if action == "allow" else []
            ),
            GcpResourceMetadata.FIREWALL_DENY: (
                [{"protocol": "tcp", "ports": ["22"]}] if action == "deny" else []
            ),
        },
    )


def _firewall_policy_rule(
    address: str,
    *,
    action: str,
    priority: int,
) -> NormalizedResource:
    return _gcp_resource(
        address,
        GcpResourceType.COMPUTE_FIREWALL_POLICY_RULE,
        ResourceCategory.NETWORK,
        network_rules=[_public_ssh_rule()] if action == "allow" else [],
        metadata={
            GcpResourceMetadata.FIREWALL_POLICY_REFERENCE: (
                "google_compute_firewall_policy.org.name"
            ),
            GcpResourceMetadata.FIREWALL_POLICY_ACTION: action,
            GcpResourceMetadata.FIREWALL_POLICY_DIRECTION: "ingress",
            GcpResourceMetadata.FIREWALL_POLICY_PRIORITY: priority,
        },
    )


def _firewall_policy_association() -> NormalizedResource:
    return _gcp_resource(
        "google_compute_firewall_policy_association.folder",
        GcpResourceType.COMPUTE_FIREWALL_POLICY_ASSOCIATION,
        ResourceCategory.NETWORK,
        metadata={
            GcpResourceMetadata.FIREWALL_POLICY_REFERENCE: (
                "google_compute_firewall_policy.org.name"
            ),
            GcpResourceMetadata.FIREWALL_POLICY_ATTACHMENT_TARGET: "folders/12345",
        },
    )


class GcpResourceDecorationStageTests(unittest.TestCase):
    def test_load_balancer_stage_stops_cycles_and_dedupes_backend_paths(self) -> None:
        forwarding_rule = _gcp_resource(
            "google_compute_global_forwarding_rule.web",
            GcpResourceType.COMPUTE_GLOBAL_FORWARDING_RULE,
            ResourceCategory.EDGE,
            public_access_configured=True,
            metadata={
                GcpResourceMetadata.FORWARDING_RULE_TARGET: (
                    "google_compute_target_https_proxy.web.id"
                ),
                GcpResourceMetadata.FORWARDING_RULE_LOAD_BALANCING_SCHEME: "EXTERNAL",
                GcpResourceMetadata.FORWARDING_RULE_IP_ADDRESS: "35.1.2.3",
            },
        )
        target_proxy = _gcp_resource(
            "google_compute_target_https_proxy.web",
            GcpResourceType.COMPUTE_TARGET_HTTPS_PROXY,
            ResourceCategory.EDGE,
            metadata={GcpResourceMetadata.LOAD_BALANCER_URL_MAP: "google_compute_url_map.web.id"},
        )
        url_map = _gcp_resource(
            "google_compute_url_map.web",
            GcpResourceType.COMPUTE_URL_MAP,
            ResourceCategory.EDGE,
            metadata={
                GcpResourceMetadata.LOAD_BALANCER_DEFAULT_SERVICE: (
                    "google_compute_backend_service.api.id"
                ),
                GcpResourceMetadata.LOAD_BALANCER_PATH_MATCHERS: [
                    {
                        "default_service": "google_compute_backend_service.api.id",
                        "path_rule": [
                            {"service": "google_compute_backend_service.api.id"},
                            {"service": "google_compute_backend_service.api.name"},
                        ],
                    }
                ],
            },
        )
        backend_service = _gcp_resource(
            "google_compute_backend_service.api",
            GcpResourceType.COMPUTE_BACKEND_SERVICE,
            ResourceCategory.EDGE,
            metadata={
                GcpResourceMetadata.LOAD_BALANCER_BACKENDS: [
                    {"group": "google_compute_network_endpoint_group.api.id"},
                    {"group": "google_compute_network_endpoint_group.api.name"},
                    {"group": "google_compute_url_map.web.id"},
                ]
            },
        )
        neg = _gcp_resource(
            "google_compute_network_endpoint_group.api",
            GcpResourceType.COMPUTE_NETWORK_ENDPOINT_GROUP,
            ResourceCategory.EDGE,
            metadata={
                GcpResourceMetadata.LOAD_BALANCER_SERVERLESS_ENDPOINTS: [
                    {"platform": "cloud_run", "service": "google_cloud_run_service.api.name"},
                    {"platform": "cloud_run", "service": "google_cloud_run_service.api.name"},
                ],
                GcpResourceMetadata.LOAD_BALANCER_NETWORK_ENDPOINTS: [
                    {"instance": "google_compute_backend_service.api.id"}
                ],
            },
        )
        cloud_run = _gcp_resource(
            "google_cloud_run_service.api",
            GcpResourceType.CLOUD_RUN_SERVICE,
            ResourceCategory.COMPUTE,
        )
        resources = [forwarding_rule, target_proxy, url_map, backend_service, neg, cloud_run]

        DeriveLoadBalancerReachabilityStage().apply(resources, _context(resources))

        self.assertEqual(
            [
                entry["backend"]
                for entry in forwarding_rule.get_metadata_field(
                    GcpResourceMetadata.LOAD_BALANCER_REACHABLE_BACKENDS
                )
            ],
            [
                "google_compute_backend_service.api",
                "google_compute_network_endpoint_group.api",
                "google_cloud_run_service.api",
            ],
        )
        self.assertTrue(
            cloud_run.get_metadata_field(
                GcpResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER
            )
        )

    def test_load_balancer_stage_marks_backend_buckets_and_neg_targets(self) -> None:
        forwarding_rule = _gcp_resource(
            "google_compute_global_forwarding_rule.web",
            GcpResourceType.COMPUTE_GLOBAL_FORWARDING_RULE,
            ResourceCategory.EDGE,
            public_access_configured=True,
            metadata={
                GcpResourceMetadata.FORWARDING_RULE_TARGET: "google_compute_url_map.web.id",
                GcpResourceMetadata.FORWARDING_RULE_LOAD_BALANCING_SCHEME: "EXTERNAL",
            },
        )
        url_map = _gcp_resource(
            "google_compute_url_map.web",
            GcpResourceType.COMPUTE_URL_MAP,
            ResourceCategory.EDGE,
            metadata={
                GcpResourceMetadata.LOAD_BALANCER_DEFAULT_SERVICE: (
                    "google_compute_backend_bucket.assets.id"
                ),
                GcpResourceMetadata.LOAD_BALANCER_PATH_MATCHERS: [
                    {
                        "path_rule": [
                            {"service": "google_compute_backend_service.functions.id"}
                        ]
                    }
                ],
            },
        )
        backend_bucket = _gcp_resource(
            "google_compute_backend_bucket.assets",
            GcpResourceType.COMPUTE_BACKEND_BUCKET,
            ResourceCategory.EDGE,
            metadata={GcpResourceMetadata.LOAD_BALANCER_BACKEND_BUCKET_NAME: "logs"},
        )
        bucket = _gcp_resource(
            "google_storage_bucket.logs",
            GcpResourceType.STORAGE_BUCKET,
            ResourceCategory.DATA,
            identifier="logs",
            metadata={GcpResourceMetadata.BUCKET_NAME: "logs"},
        )
        backend_service = _gcp_resource(
            "google_compute_backend_service.functions",
            GcpResourceType.COMPUTE_BACKEND_SERVICE,
            ResourceCategory.EDGE,
            metadata={
                GcpResourceMetadata.LOAD_BALANCER_BACKENDS: [
                    {"group": "google_compute_region_network_endpoint_group.fn.id"}
                ]
            },
        )
        neg = _gcp_resource(
            "google_compute_region_network_endpoint_group.fn",
            GcpResourceType.COMPUTE_REGION_NETWORK_ENDPOINT_GROUP,
            ResourceCategory.EDGE,
            metadata={
                GcpResourceMetadata.LOAD_BALANCER_SERVERLESS_ENDPOINTS: [
                    {
                        "platform": "cloud_function",
                        "function": "google_cloudfunctions_function.fn.name",
                    }
                ]
            },
        )
        function = _gcp_resource(
            "google_cloudfunctions_function.fn",
            GcpResourceType.CLOUDFUNCTIONS_FUNCTION,
            ResourceCategory.COMPUTE,
        )
        resources = [
            forwarding_rule,
            url_map,
            backend_bucket,
            bucket,
            backend_service,
            neg,
            function,
        ]

        DeriveLoadBalancerReachabilityStage().apply(resources, _context(resources))

        self.assertEqual(
            [
                entry["backend"]
                for entry in forwarding_rule.get_metadata_field(
                    GcpResourceMetadata.LOAD_BALANCER_REACHABLE_BACKENDS
                )
            ],
            [
                "google_compute_backend_bucket.assets",
                "google_storage_bucket.logs",
                "google_compute_backend_service.functions",
                "google_compute_region_network_endpoint_group.fn",
                "google_cloudfunctions_function.fn",
            ],
        )
        for backend in (bucket, function):
            self.assertTrue(
                backend.get_metadata_field(
                    GcpResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER
                )
            )

    def test_network_stage_applies_tagged_public_routes_to_matching_instances(self) -> None:
        network = _network()
        subnetwork = _subnetwork("google_compute_subnetwork.app")
        tagged_route = _gcp_resource(
            "google_compute_route.web_internet",
            GcpResourceType.COMPUTE_ROUTE,
            ResourceCategory.NETWORK,
            vpc_id="google_compute_network.main.id",
            metadata={
                GcpResourceMetadata.ROUTE_DEST_RANGE: "0.0.0.0/0",
                GcpResourceMetadata.ROUTE_NEXT_HOP_GATEWAY: "default-internet-gateway",
                GcpResourceMetadata.ROUTE_TAGS: ["web"],
            },
        )
        matching_instance = _gcp_resource(
            "google_compute_instance.web",
            GcpResourceType.COMPUTE_INSTANCE,
            ResourceCategory.COMPUTE,
            vpc_id="google_compute_network.main.id",
            subnet_ids=("google_compute_subnetwork.app.id",),
            metadata={
                GcpResourceMetadata.NETWORK_TAGS: ["web"],
                GcpResourceMetadata.NETWORK_INTERFACES: [
                    {
                        "network": "google_compute_network.main.id",
                        "subnetwork": "google_compute_subnetwork.app.id",
                    }
                ],
            },
        )
        unmatched_instance = _gcp_resource(
            "google_compute_instance.worker",
            GcpResourceType.COMPUTE_INSTANCE,
            ResourceCategory.COMPUTE,
            vpc_id="google_compute_network.main.id",
            subnet_ids=("google_compute_subnetwork.app.id",),
            metadata={GcpResourceMetadata.NETWORK_TAGS: ["worker"]},
        )
        resources = [network, subnetwork, tagged_route, matching_instance, unmatched_instance]

        DeriveNetworkPostureStage().apply(resources, _context(resources))

        self.assertFalse(subnetwork.has_public_route)
        self.assertFalse(subnetwork.is_public_subnet)
        self.assertFalse(matching_instance.in_public_subnet)
        self.assertTrue(matching_instance.has_public_route)
        self.assertFalse(unmatched_instance.has_public_route)

    def test_network_posture_stage_distinguishes_all_subnet_and_explicit_nat_modes(self) -> None:
        all_subnet_app = _subnetwork("google_compute_subnetwork.app")
        all_subnet_data = _subnetwork("google_compute_subnetwork.data")
        all_subnet_nat = _gcp_resource(
            "google_compute_router_nat.all",
            GcpResourceType.COMPUTE_ROUTER_NAT,
            ResourceCategory.NETWORK,
            metadata={
                "source_subnetwork_ip_ranges_to_nat": "ALL_SUBNETWORKS_ALL_IP_RANGES",
                GcpResourceMetadata.ROUTER_REFERENCE: "google_compute_router.main.name",
            },
        )
        all_subnet_resources = [
            _network(),
            all_subnet_app,
            all_subnet_data,
            _router(),
            all_subnet_nat,
        ]

        DeriveNetworkPostureStage().apply(
            all_subnet_resources,
            _context(all_subnet_resources),
        )

        self.assertTrue(all_subnet_app.has_nat_gateway_egress)
        self.assertTrue(all_subnet_data.has_nat_gateway_egress)

        explicit_app = _subnetwork("google_compute_subnetwork.app")
        explicit_data = _subnetwork("google_compute_subnetwork.data")
        explicit_nat = _gcp_resource(
            "google_compute_router_nat.explicit",
            GcpResourceType.COMPUTE_ROUTER_NAT,
            ResourceCategory.NETWORK,
            metadata={
                "source_subnetwork_ip_ranges_to_nat": "LIST_OF_SUBNETWORKS",
                GcpResourceMetadata.ROUTER_REFERENCE: "google_compute_router.main.name",
                GcpResourceMetadata.NAT_SUBNETWORKS: [
                    {"name": "google_compute_subnetwork.app.id"}
                ],
            },
        )
        explicit_resources = [_network(), explicit_app, explicit_data, _router(), explicit_nat]

        DeriveNetworkPostureStage().apply(explicit_resources, _context(explicit_resources))

        self.assertTrue(explicit_app.has_nat_gateway_egress)
        self.assertFalse(explicit_data.has_nat_gateway_egress)

    def test_public_exposure_stage_currently_ignores_higher_priority_compute_deny(
        self,
    ) -> None:
        instance = _public_compute_instance()
        allow = _compute_firewall(
            "google_compute_firewall.allow_ssh",
            action="allow",
            priority=1000,
        )
        deny = _compute_firewall(
            "google_compute_firewall.deny_ssh",
            action="deny",
            priority=900,
        )
        resources = [instance, allow, deny]

        DerivePublicExposureStage().apply(resources, _context(resources))

        self.assertTrue(instance.internet_ingress_capable)
        self.assertTrue(instance.public_exposure)
        self.assertEqual(
            instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS),
            ["google_compute_firewall.allow_ssh"],
        )

    def test_public_exposure_stage_currently_ignores_same_priority_compute_deny(
        self,
    ) -> None:
        instance = _public_compute_instance()
        allow = _compute_firewall(
            "google_compute_firewall.allow_ssh",
            action="allow",
            priority=1000,
        )
        deny = _compute_firewall(
            "google_compute_firewall.deny_ssh",
            action="deny",
            priority=1000,
        )
        resources = [instance, allow, deny]

        DerivePublicExposureStage().apply(resources, _context(resources))

        self.assertTrue(instance.internet_ingress_capable)
        self.assertTrue(instance.public_exposure)
        self.assertEqual(
            instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS),
            ["google_compute_firewall.allow_ssh"],
        )

    def test_public_exposure_stage_keeps_higher_priority_compute_allow_public(
        self,
    ) -> None:
        instance = _public_compute_instance()
        allow = _compute_firewall(
            "google_compute_firewall.allow_ssh",
            action="allow",
            priority=900,
        )
        deny = _compute_firewall(
            "google_compute_firewall.deny_ssh",
            action="deny",
            priority=1000,
        )
        resources = [instance, allow, deny]

        DerivePublicExposureStage().apply(resources, _context(resources))

        self.assertTrue(instance.internet_ingress_capable)
        self.assertTrue(instance.public_exposure)
        self.assertEqual(
            instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS),
            ["google_compute_firewall.allow_ssh"],
        )

    def test_public_exposure_stage_currently_ignores_hierarchical_policy_deny(
        self,
    ) -> None:
        instance = _public_compute_instance(folder_id="folders/12345")
        allow = _firewall_policy_rule(
            "google_compute_firewall_policy_rule.allow_ssh",
            action="allow",
            priority=1000,
        )
        deny = _firewall_policy_rule(
            "google_compute_firewall_policy_rule.deny_ssh",
            action="deny",
            priority=900,
        )
        association = _firewall_policy_association()
        resources = [instance, allow, deny, association]

        DerivePublicExposureStage().apply(resources, _context(resources))

        self.assertTrue(instance.internet_ingress_capable)
        self.assertTrue(instance.public_exposure)
        self.assertEqual(
            instance.get_metadata_field(GcpResourceMetadata.INTERNET_INGRESS_FIREWALLS),
            ["google_compute_firewall_policy_rule.allow_ssh"],
        )

    def test_public_exposure_stage_normalizes_bucket_iam_member_binding_and_policy(self) -> None:
        bucket = _gcp_resource(
            "google_storage_bucket.logs",
            GcpResourceType.STORAGE_BUCKET,
            ResourceCategory.DATA,
            identifier="logs",
            metadata={GcpResourceMetadata.BUCKET_NAME: "logs"},
        )
        member = _gcp_resource(
            "google_storage_bucket_iam_member.public_reader",
            GcpResourceType.STORAGE_BUCKET_IAM_MEMBER,
            ResourceCategory.IAM,
            metadata={
                GcpResourceMetadata.BUCKET_NAME: "logs",
                GcpResourceMetadata.IAM_ROLE: "roles/storage.objectViewer",
                GcpResourceMetadata.IAM_MEMBER: "allUsers",
            },
        )
        binding = _gcp_resource(
            "google_storage_bucket_iam_binding.authenticated_readers",
            GcpResourceType.STORAGE_BUCKET_IAM_BINDING,
            ResourceCategory.IAM,
            metadata={
                GcpResourceMetadata.BUCKET_NAME: "logs",
                GcpResourceMetadata.IAM_BINDINGS: [
                    {
                        "role": "roles/storage.legacyBucketReader",
                        "members": ["allAuthenticatedUsers", "user:reader@example.com"],
                    }
                ],
            },
        )
        policy = _gcp_resource(
            "google_storage_bucket_iam_policy.policy",
            GcpResourceType.STORAGE_BUCKET_IAM_POLICY,
            ResourceCategory.IAM,
            metadata={
                GcpResourceMetadata.BUCKET_NAME: "logs",
                GcpResourceMetadata.IAM_BINDINGS: [
                    {
                        "role": "roles/storage.objectViewer",
                        "members": ["allUsers", "group:ops@example.com"],
                    }
                ],
            },
        )
        resources = [bucket, member, binding, policy]

        DerivePublicExposureStage().apply(resources, _context(resources))

        self.assertTrue(bucket.public_access_configured)
        self.assertTrue(bucket.public_exposure)
        self.assertEqual(
            bucket.public_exposure_reasons,
            [
                "google_storage_bucket_iam_member.public_reader grants "
                "roles/storage.objectViewer to allUsers",
                "google_storage_bucket_iam_binding.authenticated_readers grants "
                "roles/storage.legacyBucketReader to allAuthenticatedUsers",
                "google_storage_bucket_iam_policy.policy grants "
                "roles/storage.objectViewer to allUsers",
            ],
        )

    def test_sensitive_iam_stage_normalizes_member_binding_and_policy_sources(self) -> None:
        secret = _gcp_resource(
            "google_secret_manager_secret.api_key",
            GcpResourceType.SECRET_MANAGER_SECRET,
            ResourceCategory.DATA,
            identifier="projects/demo/secrets/api-key",
            metadata={
                GcpResourceMetadata.SECRET_ID: "api-key",
                GcpResourceMetadata.SECRET_REFERENCE: "projects/demo/secrets/api-key",
            },
        )
        member = _gcp_resource(
            "google_secret_manager_secret_iam_member.reader",
            GcpResourceType.SECRET_MANAGER_SECRET_IAM_MEMBER,
            ResourceCategory.IAM,
            metadata={
                GcpResourceMetadata.SECRET_REFERENCE: "projects/demo/secrets/api-key",
                GcpResourceMetadata.IAM_ROLE: "roles/secretmanager.secretAccessor",
                GcpResourceMetadata.IAM_MEMBER: "serviceAccount:app@demo.iam.gserviceaccount.com",
                GcpResourceMetadata.IAM_CONDITION: {
                    "title": "expires",
                    "expression": "request.time < timestamp('2026-01-01T00:00:00Z')",
                },
            },
        )
        binding = _gcp_resource(
            "google_secret_manager_secret_iam_binding.viewers",
            GcpResourceType.SECRET_MANAGER_SECRET_IAM_BINDING,
            ResourceCategory.IAM,
            metadata={
                GcpResourceMetadata.SECRET_REFERENCE: "projects/demo/secrets/api-key",
                GcpResourceMetadata.IAM_BINDINGS: [
                    {
                        "role": "roles/secretmanager.viewer",
                        "members": ["group:ops@example.com", "user:reader@example.com"],
                    }
                ],
            },
        )
        policy = _gcp_resource(
            "google_secret_manager_secret_iam_policy.policy",
            GcpResourceType.SECRET_MANAGER_SECRET_IAM_POLICY,
            ResourceCategory.IAM,
            metadata={
                GcpResourceMetadata.SECRET_REFERENCE: "projects/demo/secrets/api-key",
                GcpResourceMetadata.IAM_BINDINGS: [
                    {
                        "role": "roles/secretmanager.secretAccessor",
                        "members": ["serviceAccount:policy@demo.iam.gserviceaccount.com"],
                    }
                ],
            },
        )
        resources = [secret, member, binding, policy]

        DecorateSensitiveIamBindingsStage().apply(resources, _context(resources))

        self.assertEqual(
            secret.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [
                {
                    "role": "roles/secretmanager.secretAccessor",
                    "members": ["serviceAccount:app@demo.iam.gserviceaccount.com"],
                    "source": "google_secret_manager_secret_iam_member.reader",
                    "condition": {
                        "title": "expires",
                        "expression": "request.time < timestamp('2026-01-01T00:00:00Z')",
                    },
                },
                {
                    "role": "roles/secretmanager.viewer",
                    "members": ["group:ops@example.com", "user:reader@example.com"],
                    "source": "google_secret_manager_secret_iam_binding.viewers",
                },
                {
                    "role": "roles/secretmanager.secretAccessor",
                    "members": ["serviceAccount:policy@demo.iam.gserviceaccount.com"],
                    "source": "google_secret_manager_secret_iam_policy.policy",
                },
            ],
        )
        self.assertEqual(
            secret.get_metadata_field(GcpResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES),
            [
                "google_secret_manager_secret_iam_member.reader",
                "google_secret_manager_secret_iam_binding.viewers",
                "google_secret_manager_secret_iam_policy.policy",
            ],
        )


if __name__ == "__main__":
    unittest.main()