from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import (
    GcpNormalizerTestCase,
    _terraform_resource,
)
from tfstride.models import ResourceCategory
from tfstride.providers.gcp.compute_normalizers import normalize_compute_instance
from tfstride.providers.gcp.container_normalizers import (
    normalize_container_cluster,
    normalize_container_node_pool,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata


class GcpWorkloadNormalizerTests(GcpNormalizerTestCase):
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
                    "private_cluster_config": [{"enable_private_endpoint": False, "enable_private_nodes": False}],
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
        self.assertTrue(normalized.get_metadata_field(GcpResourceMetadata.GKE_LEGACY_METADATA_ENDPOINTS_ENABLED))

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
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.GKE_LEGACY_METADATA_ENDPOINTS_ENABLED))
        self.assertEqual(normalized.metadata_snapshot()["cluster"], "google_container_cluster.public.name")


if __name__ == "__main__":
    unittest.main()
