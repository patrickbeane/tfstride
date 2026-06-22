from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import (
    GcpNormalizerTestCase,
    _terraform_resource,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer


class GcpLoadBalancerNormalizationTests(GcpNormalizerTestCase):
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
                                    },
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

        reachable_backends = forwarding_rule.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_REACHABLE_BACKENDS)
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
            self.assertTrue(backend.get_metadata_field(GcpResourceMetadata.FRONTED_BY_INTERNET_FACING_LOAD_BALANCER))
            self.assertEqual(
                backend.get_metadata_field(GcpResourceMetadata.INTERNET_FACING_LOAD_BALANCER_ADDRESSES),
                ["google_compute_global_forwarding_rule.web"],
            )
        self.assertEqual(
            backend_service.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_FRONTENDS)[0]["forwarding_rule"],
            "google_compute_global_forwarding_rule.web",
        )
        self.assertEqual(
            neg.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_FRONTENDS)[0]["forwarding_rule"],
            "google_compute_global_forwarding_rule.web",
        )
        self.assertEqual(
            backend_bucket.get_metadata_field(GcpResourceMetadata.LOAD_BALANCER_FRONTENDS)[0]["forwarding_rule"],
            "google_compute_global_forwarding_rule.web",
        )
        self.assertFalse(service.public_exposure)
        self.assertFalse(service.direct_internet_reachable)
        self.assertFalse(instance.public_exposure)
        self.assertFalse(instance.direct_internet_reachable)


if __name__ == "__main__":
    unittest.main()
