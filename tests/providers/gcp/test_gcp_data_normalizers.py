from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import (
    GcpNormalizerTestCase,
    _terraform_resource,
)
from tfstride.models import ResourceCategory
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
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts import gcp_facts


class GcpDataNormalizerTests(GcpNormalizerTestCase):
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

    def test_storage_bucket_normalizer_preserves_retention_policy(self) -> None:
        normalized = normalize_storage_bucket(
            _terraform_resource(
                "google_storage_bucket.logs",
                "google_storage_bucket",
                {
                    "name": "tfstride-logs",
                    "project": "tfstride-demo",
                    "location": "US",
                    "versioning": [{"enabled": True}],
                    "retention_policy": [{"retention_period": 2_592_000, "is_locked": False}],
                },
            )
        )

        facts = gcp_facts(normalized)

        self.assertEqual(facts.gcs_retention_period_seconds, 2_592_000)
        self.assertFalse(facts.gcs_retention_policy_locked)
        self.assertEqual(
            facts.gcs_retention_policy_configuration,
            {"retention_period": 2_592_000, "is_locked": False},
        )
        self.assertEqual(facts.gcs_retention_policy_uncertainties, [])

    def test_storage_bucket_normalizer_preserves_short_retention_period(self) -> None:
        normalized = normalize_storage_bucket(
            _terraform_resource(
                "google_storage_bucket.logs",
                "google_storage_bucket",
                {
                    "name": "tfstride-logs",
                    "retention_policy": [{"retention_period": 3_600, "is_locked": False}],
                },
            )
        )

        facts = gcp_facts(normalized)

        self.assertEqual(facts.gcs_retention_period_seconds, 3_600)
        self.assertFalse(facts.gcs_retention_policy_locked)

    def test_storage_bucket_normalizer_preserves_retention_lock(self) -> None:
        normalized = normalize_storage_bucket(
            _terraform_resource(
                "google_storage_bucket.logs",
                "google_storage_bucket",
                {
                    "name": "tfstride-logs",
                    "retention_policy": [{"retention_period": 31_536_000, "is_locked": True}],
                },
            )
        )

        facts = gcp_facts(normalized)

        self.assertEqual(facts.gcs_retention_period_seconds, 31_536_000)
        self.assertTrue(facts.gcs_retention_policy_locked)
        self.assertEqual(
            facts.gcs_retention_policy_configuration,
            {"retention_period": 31_536_000, "is_locked": True},
        )

    def test_storage_bucket_normalizer_represents_missing_retention_policy(self) -> None:
        normalized = normalize_storage_bucket(
            _terraform_resource(
                "google_storage_bucket.logs",
                "google_storage_bucket",
                {"name": "tfstride-logs"},
            )
        )

        facts = gcp_facts(normalized)

        self.assertIsNone(facts.gcs_retention_period_seconds)
        self.assertIsNone(facts.gcs_retention_policy_locked)
        self.assertEqual(facts.gcs_retention_policy_configuration, {})
        self.assertEqual(facts.gcs_retention_policy_uncertainties, [])

    def test_storage_bucket_normalizer_preserves_unknown_retention_policy_fields(self) -> None:
        normalized = normalize_storage_bucket(
            _terraform_resource(
                "google_storage_bucket.logs",
                "google_storage_bucket",
                {"name": "tfstride-logs", "retention_policy": [{}]},
                unknown_values={"retention_policy": [{"retention_period": True, "is_locked": True}]},
            )
        )

        facts = gcp_facts(normalized)

        self.assertIsNone(facts.gcs_retention_period_seconds)
        self.assertIsNone(facts.gcs_retention_policy_locked)
        self.assertEqual(facts.gcs_retention_policy_configuration, {})
        self.assertEqual(
            facts.gcs_retention_policy_uncertainties,
            [
                "retention_policy.retention_period is unknown after planning",
                "retention_policy.is_locked is unknown after planning",
            ],
        )

    def test_storage_bucket_normalizer_preserves_unknown_retention_policy_block(self) -> None:
        normalized = normalize_storage_bucket(
            _terraform_resource(
                "google_storage_bucket.logs",
                "google_storage_bucket",
                {"name": "tfstride-logs"},
                unknown_values={"retention_policy": True},
            )
        )

        self.assertEqual(
            gcp_facts(normalized).gcs_retention_policy_uncertainties,
            ["retention_policy is unknown after planning"],
        )

    def test_secret_manager_secret_normalizer_preserves_secret_context(self) -> None:
        normalized = normalize_secret_manager_secret(self.resources["google_secret_manager_secret.api_key"])
        facts = gcp_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.DATA)
        self.assertEqual(normalized.identifier, "projects/tfstride-demo/secrets/tfstride-api-key")
        self.assertEqual(normalized.data_sensitivity, "sensitive")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.SECRET_ID), "tfstride-api-key")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.PROJECT), "tfstride-demo")
        self.assertTrue(normalized.storage_encrypted)
        self.assertEqual(facts.secret_manager_replication_mode, "automatic")
        self.assertEqual(facts.secret_manager_kms_key_names, [])
        self.assertEqual(facts.secret_manager_replication, {"mode": "automatic"})
        self.assertIsNone(facts.secret_manager_ttl)
        self.assertIsNone(facts.secret_manager_expire_time)
        self.assertIsNone(facts.secret_manager_version_destroy_ttl)
        self.assertFalse(facts.customer_managed_encryption)
        self.assertEqual(facts.secret_manager_posture_uncertainties, [])

    def test_secret_manager_secret_normalizer_preserves_lifecycle_posture(self) -> None:
        normalized = normalize_secret_manager_secret(
            _terraform_resource(
                "google_secret_manager_secret.api_key",
                "google_secret_manager_secret",
                {
                    "secret_id": "tfstride-api-key",
                    "project": "tfstride-demo",
                    "ttl": "2592000s",
                    "expire_time": "2026-12-31T00:00:00Z",
                    "version_destroy_ttl": "604800s",
                    "replication": [{"auto": [{}]}],
                },
            )
        )

        facts = gcp_facts(normalized)

        self.assertEqual(facts.secret_manager_ttl, "2592000s")
        self.assertEqual(facts.secret_manager_expire_time, "2026-12-31T00:00:00Z")
        self.assertEqual(facts.secret_manager_version_destroy_ttl, "604800s")
        self.assertEqual(facts.secret_manager_posture_uncertainties, [])

    def test_secret_manager_secret_normalizer_preserves_unknown_lifecycle_posture(self) -> None:
        normalized = normalize_secret_manager_secret(
            _terraform_resource(
                "google_secret_manager_secret.api_key",
                "google_secret_manager_secret",
                {
                    "secret_id": "tfstride-api-key",
                    "project": "tfstride-demo",
                    "replication": [{"auto": [{}]}],
                },
                unknown_values={
                    "ttl": True,
                    "expire_time": True,
                    "version_destroy_ttl": True,
                },
            )
        )

        facts = gcp_facts(normalized)

        self.assertIsNone(facts.secret_manager_ttl)
        self.assertIsNone(facts.secret_manager_expire_time)
        self.assertIsNone(facts.secret_manager_version_destroy_ttl)
        self.assertEqual(
            facts.secret_manager_posture_uncertainties,
            [
                "ttl is unknown after planning",
                "expire_time is unknown after planning",
                "version_destroy_ttl is unknown after planning",
            ],
        )

    def test_secret_manager_secret_normalizer_preserves_auto_cmek(self) -> None:
        normalized = normalize_secret_manager_secret(
            _terraform_resource(
                "google_secret_manager_secret.api_key",
                "google_secret_manager_secret",
                {
                    "secret_id": "tfstride-api-key",
                    "project": "tfstride-demo",
                    "replication": [
                        {
                            "auto": [
                                {
                                    "customer_managed_encryption": [
                                        {
                                            "kms_key_name": (
                                                "projects/tfstride-demo/locations/global/keyRings/app/"
                                                "cryptoKeys/secrets"
                                            )
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                },
            )
        )

        facts = gcp_facts(normalized)

        self.assertEqual(facts.secret_manager_replication_mode, "automatic")
        self.assertEqual(
            facts.secret_manager_kms_key_names,
            ["projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/secrets"],
        )
        self.assertEqual(
            facts.secret_manager_replication,
            {
                "mode": "automatic",
                "kms_key_names": ["projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/secrets"],
            },
        )
        self.assertTrue(facts.customer_managed_encryption)
        self.assertEqual(facts.secret_manager_posture_uncertainties, [])

    def test_secret_manager_secret_normalizer_preserves_user_managed_replica_cmek(self) -> None:
        normalized = normalize_secret_manager_secret(
            _terraform_resource(
                "google_secret_manager_secret.api_key",
                "google_secret_manager_secret",
                {
                    "secret_id": "tfstride-api-key",
                    "project": "tfstride-demo",
                    "replication": [
                        {
                            "user_managed": [
                                {
                                    "replicas": [
                                        {
                                            "location": "us-east1",
                                            "customer_managed_encryption": [
                                                {
                                                    "kms_key_name": (
                                                        "projects/tfstride-demo/locations/us-east1/keyRings/app/"
                                                        "cryptoKeys/secrets-east"
                                                    )
                                                }
                                            ],
                                        },
                                        {
                                            "location": "us-west1",
                                            "customer_managed_encryption": [
                                                {
                                                    "kms_key_name": (
                                                        "projects/tfstride-demo/locations/us-west1/keyRings/app/"
                                                        "cryptoKeys/secrets-west"
                                                    )
                                                }
                                            ],
                                        },
                                    ]
                                }
                            ]
                        }
                    ],
                },
            )
        )

        facts = gcp_facts(normalized)

        self.assertEqual(facts.secret_manager_replication_mode, "user_managed")
        self.assertEqual(
            facts.secret_manager_kms_key_names,
            [
                "projects/tfstride-demo/locations/us-east1/keyRings/app/cryptoKeys/secrets-east",
                "projects/tfstride-demo/locations/us-west1/keyRings/app/cryptoKeys/secrets-west",
            ],
        )
        self.assertEqual(
            facts.secret_manager_replication,
            {
                "mode": "user_managed",
                "replicas": [
                    {
                        "location": "us-east1",
                        "kms_key_names": [
                            "projects/tfstride-demo/locations/us-east1/keyRings/app/cryptoKeys/secrets-east"
                        ],
                    },
                    {
                        "location": "us-west1",
                        "kms_key_names": [
                            "projects/tfstride-demo/locations/us-west1/keyRings/app/cryptoKeys/secrets-west"
                        ],
                    },
                ],
                "kms_key_names": [
                    "projects/tfstride-demo/locations/us-east1/keyRings/app/cryptoKeys/secrets-east",
                    "projects/tfstride-demo/locations/us-west1/keyRings/app/cryptoKeys/secrets-west",
                ],
            },
        )
        self.assertTrue(facts.customer_managed_encryption)
        self.assertEqual(facts.secret_manager_posture_uncertainties, [])

    def test_secret_manager_secret_normalizer_preserves_unknown_cmek(self) -> None:
        normalized = normalize_secret_manager_secret(
            _terraform_resource(
                "google_secret_manager_secret.api_key",
                "google_secret_manager_secret",
                {
                    "secret_id": "tfstride-api-key",
                    "project": "tfstride-demo",
                    "replication": [{"auto": [{"customer_managed_encryption": [{}]}]}],
                },
                unknown_values={
                    "replication": [
                        {
                            "auto": [
                                {
                                    "customer_managed_encryption": [
                                        {"kms_key_name": True},
                                    ]
                                }
                            ]
                        }
                    ]
                },
            )
        )

        facts = gcp_facts(normalized)

        self.assertEqual(facts.secret_manager_replication_mode, "automatic")
        self.assertEqual(facts.secret_manager_kms_key_names, [])
        self.assertEqual(facts.secret_manager_replication, {"mode": "automatic"})
        self.assertIsNone(facts.customer_managed_encryption)
        self.assertEqual(
            facts.secret_manager_posture_uncertainties,
            ["replication.auto.customer_managed_encryption[0].kms_key_name is unknown after planning"],
        )

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
        facts = gcp_facts(normalized)
        self.assertEqual(facts.kms_purpose, "ENCRYPT_DECRYPT")
        self.assertEqual(facts.kms_rotation_period, "7776000s")
        self.assertIsNone(facts.kms_destroy_scheduled_duration)
        self.assertEqual(facts.kms_posture_uncertainties, [])
        self.assertTrue(normalized.storage_encrypted)

    def test_kms_crypto_key_normalizer_preserves_destroy_scheduled_duration(self) -> None:
        normalized = normalize_kms_crypto_key(
            _terraform_resource(
                "google_kms_crypto_key.customer",
                "google_kms_crypto_key",
                {
                    "name": "tfstride-customer-key",
                    "key_ring": "projects/tfstride-demo/locations/global/keyRings/tfstride-app",
                    "purpose": "ENCRYPT_DECRYPT",
                    "destroy_scheduled_duration": "604800s",
                },
            )
        )

        facts = gcp_facts(normalized)
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.KMS_DESTROY_SCHEDULED_DURATION),
            "604800s",
        )
        self.assertEqual(facts.kms_destroy_scheduled_duration, "604800s")
        self.assertEqual(facts.kms_posture_uncertainties, [])

    def test_kms_crypto_key_normalizer_preserves_unknown_rotation_period(self) -> None:
        normalized = normalize_kms_crypto_key(
            _terraform_resource(
                "google_kms_crypto_key.customer",
                "google_kms_crypto_key",
                {
                    "name": "tfstride-customer-key",
                    "key_ring": "projects/tfstride-demo/locations/global/keyRings/tfstride-app",
                    "purpose": "ENCRYPT_DECRYPT",
                },
                unknown_values={"rotation_period": True},
            )
        )

        facts = gcp_facts(normalized)
        self.assertIsNone(facts.kms_rotation_period)
        self.assertEqual(facts.kms_posture_uncertainties, ["rotation_period is unknown after planning"])

    def test_kms_crypto_key_normalizer_preserves_unknown_destroy_scheduled_duration(self) -> None:
        normalized = normalize_kms_crypto_key(
            _terraform_resource(
                "google_kms_crypto_key.customer",
                "google_kms_crypto_key",
                {
                    "name": "tfstride-customer-key",
                    "key_ring": "projects/tfstride-demo/locations/global/keyRings/tfstride-app",
                    "purpose": "ENCRYPT_DECRYPT",
                    "destroy_scheduled_duration": "86400s",
                },
                unknown_values={"destroy_scheduled_duration": True},
            )
        )

        facts = gcp_facts(normalized)
        self.assertIsNone(facts.kms_destroy_scheduled_duration)
        self.assertEqual(
            facts.kms_posture_uncertainties,
            ["destroy_scheduled_duration is unknown after planning"],
        )

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
        self.assertFalse(normalized.get_metadata_field(GcpResourceMetadata.CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED))
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
        self.assertTrue(normalized.get_metadata_field(GcpResourceMetadata.CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED))


if __name__ == "__main__":
    unittest.main()
