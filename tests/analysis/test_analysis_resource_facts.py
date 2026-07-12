from __future__ import annotations

import unittest

from tfstride.analysis.resource_facts import analysis_facts
from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.resource_facts import (
    ProviderResourceFactDomains,
    ProviderResourceFactsRegistry,
)


def _resource(
    metadata: dict[str, object] | None = None,
    *,
    provider: str = "aws",
    resource_type: str = "aws_s3_bucket",
) -> NormalizedResource:
    return NormalizedResource(
        address=f"{resource_type}.logs",
        provider=provider,
        resource_type=resource_type,
        name="logs",
        category=ResourceCategory.DATA,
        metadata=metadata,
    )


class AnalysisFactsTests(unittest.TestCase):
    def test_reads_provider_backed_analysis_facts(self) -> None:
        resource = _resource(
            {
                AwsResourceMetadata.BUCKET_NAME: "logs",
                AwsResourceMetadata.BUCKET_ACL: "public-read",
                AwsResourceMetadata.PUBLIC_ACCESS_BLOCK: {"block_public_acls": True},
                AwsResourceMetadata.POLICY_DOCUMENT: {"Statement": [{"Effect": "Allow"}]},
                AwsResourceMetadata.TRUST_STATEMENTS: [{"Effect": "Allow"}],
                AwsResourceMetadata.ENGINE: "postgres",
                AwsResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES: ["aws_s3_bucket_policy.logs"],
            }
        )

        facts = analysis_facts(resource)

        self.assertIsInstance(facts, ProviderResourceFactDomains)
        self.assertEqual(facts.storage.bucket_name, "logs")
        self.assertEqual(facts.storage.bucket_acl, "public-read")
        self.assertEqual(facts.storage.public_access_block, {"block_public_acls": True})
        self.assertIsNone(facts.storage.uniform_bucket_level_access)
        self.assertIsNone(facts.storage.public_access_prevention)
        self.assertIsNone(facts.storage.versioning_enabled)
        self.assertIsNone(facts.storage.default_kms_key_name)
        self.assertIsNone(facts.storage.customer_managed_encryption)
        self.assertEqual(facts.iam.policy_document, {"Statement": [{"Effect": "Allow"}]})
        self.assertEqual(facts.iam.trust_statements, [{"Effect": "Allow"}])
        self.assertEqual(facts.sql.engine, "postgres")
        self.assertEqual(facts.iam.resource_policy_source_addresses, ["aws_s3_bucket_policy.logs"])
        self.assertIsNone(facts.iam.project)
        self.assertIsNone(facts.iam.resource_name)
        self.assertEqual(facts.iam.reference_values, [])
        self.assertIsNone(facts.iam.target_reference)
        self.assertEqual(facts.iam.bindings, [])
        self.assertIsNone(facts.iam.custom_role_id)
        self.assertEqual(facts.iam.custom_role_permissions, [])
        self.assertIsNone(facts.iam.organization_id)
        self.assertIsNone(facts.iam.folder_id)
        self.assertEqual(facts.sql.authorized_networks, [])
        self.assertIsNone(facts.sql.backup_enabled)
        self.assertIsNone(facts.sql.point_in_time_recovery_enabled)
        self.assertIsNone(facts.sql.ipv4_enabled)
        self.assertIsNone(facts.sql.private_network)
        self.assertIsNone(facts.sql.require_ssl)
        self.assertIsNone(facts.sql.ssl_mode)
        self.assertIsNone(facts.sql.deletion_protection)
        self.assertIsNone(facts.iam.service_account_email)
        self.assertIsNone(facts.iam.service_account_member)
        self.assertIsNone(facts.iam.service_account_reference)
        self.assertEqual(facts.workload.identity_members, [])
        self.assertEqual(facts.workload.identity_scopes, [])

    def test_gcp_resources_return_provider_owned_bucket_facts_with_neutral_defaults(self) -> None:
        resource = _resource(
            {
                GcpResourceMetadata.BUCKET_NAME: "logs",
                GcpResourceMetadata.POLICY_DOCUMENT: {
                    "bindings": [{"role": "roles/viewer", "members": ["user:ops@example.com"]}]
                },
            },
            provider="gcp",
            resource_type="google_storage_bucket",
        )

        facts = analysis_facts(resource)

        self.assertEqual(facts.storage.bucket_name, "logs")
        self.assertEqual(facts.storage.bucket_acl, "")
        self.assertIsNone(facts.storage.public_access_block)
        self.assertEqual(
            facts.iam.policy_document,
            {"bindings": [{"role": "roles/viewer", "members": ["user:ops@example.com"]}]},
        )
        self.assertEqual(facts.iam.trust_statements, [])
        self.assertIsNone(facts.sql.engine)
        self.assertEqual(facts.iam.resource_policy_source_addresses, [])
        self.assertIsNone(facts.iam.project)
        self.assertEqual(facts.iam.reference_values, ["logs"])
        self.assertEqual(facts.iam.target_reference, "logs")
        self.assertEqual(facts.iam.bindings, [])

    def test_gcp_storage_bucket_facts_read_provider_owned_posture_metadata(self) -> None:
        resource = _resource(
            {
                GcpResourceMetadata.BUCKET_NAME: "tfstride-logs",
                GcpResourceMetadata.UNIFORM_BUCKET_LEVEL_ACCESS: True,
                GcpResourceMetadata.PUBLIC_ACCESS_PREVENTION: "enforced",
                GcpResourceMetadata.GCS_VERSIONING_ENABLED: True,
                GcpResourceMetadata.GCS_DEFAULT_KMS_KEY_NAME: (
                    "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/gcs"
                ),
                GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION: True,
            },
            provider="gcp",
            resource_type="google_storage_bucket",
        )

        facts = analysis_facts(resource)

        self.assertEqual(facts.storage.bucket_name, "tfstride-logs")
        self.assertTrue(facts.storage.uniform_bucket_level_access)
        self.assertEqual(facts.storage.public_access_prevention, "enforced")
        self.assertTrue(facts.storage.versioning_enabled)
        self.assertEqual(
            facts.storage.default_kms_key_name,
            "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/gcs",
        )
        self.assertTrue(facts.storage.customer_managed_encryption)

    def test_gcp_sensitive_resource_facts_read_provider_owned_iam_metadata(self) -> None:
        resource = _resource(
            {
                GcpResourceMetadata.PROJECT: "tfstride-demo",
                GcpResourceMetadata.IAM_BINDINGS: [
                    {
                        "role": "roles/secretmanager.secretAccessor",
                        "members": ["allAuthenticatedUsers"],
                        "source": "google_secret_manager_secret_iam_member.public_accessor",
                    }
                ],
                GcpResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES: [
                    "google_secret_manager_secret_iam_member.public_accessor"
                ],
            },
            provider="gcp",
            resource_type="google_secret_manager_secret",
        )

        facts = analysis_facts(resource)

        self.assertEqual(facts.iam.project, "tfstride-demo")
        self.assertEqual(facts.iam.reference_values, [])
        self.assertIsNone(facts.iam.target_reference)
        self.assertEqual(
            facts.iam.bindings,
            [
                {
                    "role": "roles/secretmanager.secretAccessor",
                    "members": ["allAuthenticatedUsers"],
                    "source": "google_secret_manager_secret_iam_member.public_accessor",
                }
            ],
        )
        self.assertEqual(
            facts.iam.resource_policy_source_addresses,
            ["google_secret_manager_secret_iam_member.public_accessor"],
        )

    def test_gcp_organization_folder_facts_read_provider_owned_scope_metadata(self) -> None:
        resource = _resource(
            {
                GcpResourceMetadata.ORGANIZATION_ID: "1234567890",
                GcpResourceMetadata.FOLDER_ID: "folders/12345",
            },
            provider="gcp",
            resource_type="google_folder_iam_member",
        )

        facts = analysis_facts(resource)

        self.assertEqual(facts.iam.organization_id, "1234567890")
        self.assertEqual(facts.iam.folder_id, "folders/12345")

    def test_gcp_iam_target_facts_read_provider_owned_reference_metadata(self) -> None:
        resource = _resource(
            {GcpResourceMetadata.SECRET_REFERENCE: "google_secret_manager_secret.api.id"},
            provider="gcp",
            resource_type="google_secret_manager_secret_iam_member",
        )

        facts = analysis_facts(resource)

        self.assertEqual(facts.iam.reference_values, ["google_secret_manager_secret.api.id"])
        self.assertEqual(facts.iam.target_reference, "google_secret_manager_secret.api.id")

    def test_gcp_cloud_sql_facts_read_provider_owned_database_metadata(self) -> None:
        resource = _resource(
            {
                GcpResourceMetadata.DATABASE_VERSION: "POSTGRES_15",
                GcpResourceMetadata.CLOUD_SQL_AUTHORIZED_NETWORKS: [{"name": "anywhere", "value": "0.0.0.0/0"}],
                GcpResourceMetadata.CLOUD_SQL_BACKUP_ENABLED: False,
                GcpResourceMetadata.CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED: True,
                GcpResourceMetadata.CLOUD_SQL_IPV4_ENABLED: True,
                GcpResourceMetadata.CLOUD_SQL_PRIVATE_NETWORK: "google_compute_network.main.id",
                GcpResourceMetadata.CLOUD_SQL_REQUIRE_SSL: True,
                GcpResourceMetadata.CLOUD_SQL_SSL_MODE: "ENCRYPTED_ONLY",
                GcpResourceMetadata.DELETION_PROTECTION: True,
            },
            provider="gcp",
            resource_type="google_sql_database_instance",
        )

        facts = analysis_facts(resource)

        self.assertEqual(facts.sql.engine, "POSTGRES_15")
        self.assertEqual(facts.sql.authorized_networks, [{"name": "anywhere", "value": "0.0.0.0/0"}])
        self.assertFalse(facts.sql.backup_enabled)
        self.assertTrue(facts.sql.point_in_time_recovery_enabled)
        self.assertTrue(facts.sql.ipv4_enabled)
        self.assertEqual(facts.sql.private_network, "google_compute_network.main.id")
        self.assertTrue(facts.sql.require_ssl)
        self.assertEqual(facts.sql.ssl_mode, "ENCRYPTED_ONLY")
        self.assertTrue(facts.sql.deletion_protection)

    def test_gcp_compute_facts_read_workload_identity_metadata(self) -> None:
        resource = _resource(
            {
                GcpResourceMetadata.SERVICE_ACCOUNTS: [
                    {
                        "email": "tfstride-web@example.iam.gserviceaccount.com",
                        "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                    },
                    {
                        "email": "serviceAccount:worker@example.iam.gserviceaccount.com",
                        "scopes": ["https://www.googleapis.com/auth/devstorage.read_only"],
                    },
                ],
            },
            provider="gcp",
            resource_type="google_compute_instance",
        )

        facts = analysis_facts(resource)

        self.assertEqual(
            facts.workload.identity_members,
            [
                "serviceAccount:tfstride-web@example.iam.gserviceaccount.com",
                "serviceAccount:worker@example.iam.gserviceaccount.com",
            ],
        )
        self.assertEqual(
            facts.workload.identity_scopes,
            [
                "https://www.googleapis.com/auth/cloud-platform",
                "https://www.googleapis.com/auth/devstorage.read_only",
            ],
        )

    def test_gcp_service_account_facts_read_provider_owned_identity_metadata(self) -> None:
        resource = _resource(
            {
                GcpResourceMetadata.NAME: "projects/tfstride-demo/serviceAccounts/tfstride-web",
                GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL: "tfstride-web@example.iam.gserviceaccount.com",
                GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER: (
                    "serviceAccount:tfstride-web@example.iam.gserviceaccount.com"
                ),
            },
            provider="gcp",
            resource_type="google_service_account",
        )

        facts = analysis_facts(resource)

        self.assertEqual(
            facts.iam.resource_name,
            "projects/tfstride-demo/serviceAccounts/tfstride-web",
        )
        self.assertEqual(facts.iam.service_account_email, "tfstride-web@example.iam.gserviceaccount.com")
        self.assertEqual(
            facts.iam.service_account_member,
            "serviceAccount:tfstride-web@example.iam.gserviceaccount.com",
        )
        self.assertIsNone(facts.iam.service_account_reference)

    def test_returns_detached_collections(self) -> None:
        resource = _resource(
            {
                AwsResourceMetadata.POLICY_DOCUMENT: {"Statement": [{"Effect": "Allow"}]},
                AwsResourceMetadata.TRUST_STATEMENTS: [{"Effect": "Allow"}],
            }
        )
        facts = analysis_facts(resource)

        policy_document = facts.iam.policy_document
        trust_statements = facts.iam.trust_statements
        policy_document["Statement"].append({"Effect": "Deny"})
        trust_statements[0]["Effect"] = "Deny"

        self.assertEqual(facts.iam.policy_document, {"Statement": [{"Effect": "Allow"}]})
        self.assertEqual(facts.iam.trust_statements, [{"Effect": "Allow"}])

    def test_analysis_facts_returns_provider_resource_fact_domains(self) -> None:
        resource = _resource()

        facts = analysis_facts(resource)

        self.assertIsInstance(facts, ProviderResourceFactDomains)
        self.assertIsNotNone(facts.storage)
        self.assertIsNotNone(facts.iam)
        self.assertIsNotNone(facts.sql)
        self.assertIsNotNone(facts.compute)
        self.assertIsNotNone(facts.workload)

    def test_custom_registry_is_respected(self) -> None:
        calls: list[NormalizedResource] = []

        def custom_facts(resource: NormalizedResource) -> ProviderResourceFactDomains:
            calls.append(resource)
            return ProviderResourceFactDomains(
                storage=type("S", (), {"bucket_name": property(lambda _: "custom")})(),
                iam=type("I", (), {})(),
                sql=type("Q", (), {})(),
                compute=type("C", (), {})(),
                workload=type("W", (), {})(),
            )

        resource = _resource(provider="gcp", resource_type="google_storage_bucket")
        registry = ProviderResourceFactsRegistry([("gcp", custom_facts)])

        facts = analysis_facts(resource, facts_registry=registry)

        self.assertEqual(calls, [resource])
        self.assertEqual(facts.storage.bucket_name, "custom")


if __name__ == "__main__":
    unittest.main()
