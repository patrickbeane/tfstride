from __future__ import annotations

import json
import unittest

from tests.providers.gcp.normalizer_support import (
    GcpNormalizerTestCase,
    _terraform_resource,
)
from tfstride.models import ResourceCategory
from tfstride.providers.gcp.iam_normalizers import (
    normalize_bigquery_dataset_iam_member,
    normalize_bigquery_table_iam_binding,
    normalize_kms_crypto_key_iam_member,
    normalize_kms_key_ring_iam_binding,
    normalize_kms_key_ring_iam_member,
    normalize_kms_key_ring_iam_policy,
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


class GcpResourceIamNormalizerTests(GcpNormalizerTestCase):
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
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_ROLE), "roles/secretmanager.secretAccessor"
        )
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
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_ROLE), "roles/cloudkms.cryptoKeyDecrypter"
        )
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


if __name__ == "__main__":
    unittest.main()
