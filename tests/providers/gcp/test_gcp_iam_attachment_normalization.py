from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import (
    GcpNormalizerTestCase,
    _terraform_resource,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer


class GcpIamAttachmentNormalizationTests(GcpNormalizerTestCase):
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
            ["google_storage_bucket_iam_member.public_logs_reader grants roles/storage.objectViewer to allUsers"],
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


if __name__ == "__main__":
    unittest.main()
