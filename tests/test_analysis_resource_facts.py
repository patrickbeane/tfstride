from __future__ import annotations

import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tfstride.analysis.resource_facts import AnalysisResourceFacts, analysis_facts
from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.resource_facts import ProviderResourceFactsRegistry


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


@dataclass(frozen=True, slots=True)
class FakeProviderFacts:
    resource: NormalizedResource

    @property
    def bucket_name(self) -> str | None:
        return f"{self.resource.provider}-logs"

    @property
    def bucket_acl(self) -> str:
        return "private"

    @property
    def public_access_block(self) -> dict[str, bool] | None:
        return {"block_public_acls": True}

    @property
    def gcs_uniform_bucket_level_access(self) -> bool | None:
        return True

    @property
    def gcs_public_access_prevention(self) -> str | None:
        return "enforced"

    @property
    def gcs_versioning_enabled(self) -> bool | None:
        return True

    @property
    def gcs_default_kms_key_name(self) -> str | None:
        return "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/gcs"

    @property
    def customer_managed_encryption(self) -> bool | None:
        return True

    @property
    def policy_document(self) -> dict[str, Any]:
        return {"Statement": [{"Effect": "Allow"}]}

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        return [{"Effect": "Allow"}]

    @property
    def engine(self) -> str | None:
        return "spanner"

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return ["google_storage_bucket_iam_binding.logs"]

    @property
    def project(self) -> str | None:
        return "tfstride-demo"

    @property
    def resource_name(self) -> str | None:
        return "fake-resource"

    @property
    def reference_values(self) -> list[str]:
        return ["fake-resource", "google_service_account.fake.email"]

    @property
    def iam_target_reference(self) -> str | None:
        return "google_service_account.fake.email"

    @property
    def iam_bindings(self) -> list[dict[str, Any]]:
        return [{"role": "roles/viewer", "members": ["group:ops@example.com"]}]

    @property
    def custom_role_id(self) -> str | None:
        return "deployAdmin"

    @property
    def custom_role_permissions(self) -> list[str]:
        return ["iam.serviceAccounts.actAs"]

    @property
    def organization_id(self) -> str | None:
        return "1234567890"

    @property
    def folder_id(self) -> str | None:
        return "folders/12345"

    @property
    def cloud_sql_authorized_networks(self) -> list[dict[str, Any]]:
        return [{"name": "anywhere", "value": "0.0.0.0/0"}]

    @property
    def cloud_sql_backup_enabled(self) -> bool | None:
        return False

    @property
    def cloud_sql_point_in_time_recovery_enabled(self) -> bool | None:
        return True

    @property
    def cloud_sql_ipv4_enabled(self) -> bool | None:
        return True

    @property
    def cloud_sql_private_network(self) -> str | None:
        return "google_compute_network.main.id"

    @property
    def cloud_sql_require_ssl(self) -> bool | None:
        return True

    @property
    def cloud_sql_ssl_mode(self) -> str | None:
        return "ENCRYPTED_ONLY"

    @property
    def deletion_protection(self) -> bool | None:
        return True

    @property
    def service_account_email(self) -> str | None:
        return "fake@example.iam.gserviceaccount.com"

    @property
    def service_account_member(self) -> str | None:
        return "serviceAccount:fake@example.iam.gserviceaccount.com"

    @property
    def service_account_reference(self) -> str | None:
        return "google_service_account.fake.email"

    @property
    def workload_identity_members(self) -> list[str]:
        return ["serviceAccount:fake@example.iam.gserviceaccount.com"]

    @property
    def workload_identity_scopes(self) -> list[str]:
        return ["https://www.googleapis.com/auth/cloud-platform"]

    @property
    def gke_endpoint(self) -> str | None:
        return "35.1.2.3"

    @property
    def gke_private_endpoint_enabled(self) -> bool | None:
        return False

    @property
    def gke_private_nodes_enabled(self) -> bool | None:
        return False

    @property
    def gke_master_authorized_networks(self) -> list[dict[str, Any]]:
        return [{"display_name": "anywhere", "cidr_block": "0.0.0.0/0"}]

    @property
    def gke_workload_identity_enabled(self) -> bool | None:
        return False

    @property
    def gke_workload_identity_pool(self) -> str | None:
        return None

    @property
    def gke_node_service_account(self) -> str | None:
        return "123456789-compute@developer.gserviceaccount.com"

    @property
    def gke_node_oauth_scopes(self) -> list[str]:
        return ["https://www.googleapis.com/auth/cloud-platform"]

    @property
    def gke_node_metadata_mode(self) -> str | None:
        return "GCE_METADATA"

    @property
    def gke_legacy_metadata_endpoints_enabled(self) -> bool | None:
        return True


class AnalysisResourceFactsTests(unittest.TestCase):
    def test_reads_provider_backed_analysis_facts(self) -> None:
        resource = _resource(
            {
                "bucket": "logs",
                "acl": "public-read",
                "public_access_block": {"block_public_acls": True},
                "policy_document": {"Statement": [{"Effect": "Allow"}]},
                "trust_statements": [{"Effect": "Allow"}],
                "engine": "postgres",
                "resource_policy_source_addresses": ["aws_s3_bucket_policy.logs"],
            }
        )

        facts = analysis_facts(resource)

        self.assertIsInstance(facts, AnalysisResourceFacts)
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
        self.assertIsNone(facts.gke.endpoint)
        self.assertIsNone(facts.gke.private_endpoint_enabled)
        self.assertIsNone(facts.gke.private_nodes_enabled)
        self.assertEqual(facts.gke.master_authorized_networks, [])
        self.assertIsNone(facts.gke.workload_identity_enabled)
        self.assertIsNone(facts.gke.workload_identity_pool)
        self.assertIsNone(facts.gke.node_service_account)
        self.assertEqual(facts.gke.node_oauth_scopes, [])
        self.assertIsNone(facts.gke.node_metadata_mode)
        self.assertIsNone(facts.gke.legacy_metadata_endpoints_enabled)

    def test_gcp_resources_return_provider_owned_bucket_facts_with_neutral_defaults(self) -> None:
        resource = _resource(
            {
                "bucket": "logs",
                "acl": "public-read",
                "public_access_block": {"block_public_acls": True},
                "policy_document": {"Statement": [{"Effect": "Allow"}]},
                "trust_statements": [{"Effect": "Allow"}],
                "engine": "postgres",
                "resource_policy_source_addresses": ["google_storage_bucket_iam_binding.logs"],
            },
            provider="gcp",
            resource_type="google_storage_bucket",
        )

        facts = analysis_facts(resource)

        self.assertEqual(facts.storage.bucket_name, "logs")
        self.assertEqual(facts.storage.bucket_acl, "")
        self.assertIsNone(facts.storage.public_access_block)
        self.assertIsNone(facts.storage.uniform_bucket_level_access)
        self.assertIsNone(facts.storage.public_access_prevention)
        self.assertIsNone(facts.storage.versioning_enabled)
        self.assertIsNone(facts.storage.default_kms_key_name)
        self.assertIsNone(facts.storage.customer_managed_encryption)
        self.assertEqual(facts.iam.policy_document, {})
        self.assertEqual(facts.iam.trust_statements, [])
        self.assertIsNone(facts.sql.engine)
        self.assertEqual(facts.iam.resource_policy_source_addresses, [])
        self.assertIsNone(facts.iam.project)
        self.assertEqual(facts.iam.reference_values, ["logs"])
        self.assertEqual(facts.iam.target_reference, "logs")
        self.assertEqual(facts.iam.bindings, [])
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
        self.assertIsNone(facts.gke.endpoint)
        self.assertIsNone(facts.gke.private_endpoint_enabled)
        self.assertIsNone(facts.gke.private_nodes_enabled)
        self.assertEqual(facts.gke.master_authorized_networks, [])
        self.assertIsNone(facts.gke.workload_identity_enabled)
        self.assertIsNone(facts.gke.workload_identity_pool)
        self.assertIsNone(facts.gke.node_service_account)
        self.assertEqual(facts.gke.node_oauth_scopes, [])
        self.assertIsNone(facts.gke.node_metadata_mode)
        self.assertIsNone(facts.gke.legacy_metadata_endpoints_enabled)

    def test_gcp_storage_bucket_facts_read_provider_owned_posture_metadata(self) -> None:
        resource = _resource(
            {
                GcpResourceMetadata.BUCKET_NAME.key: "tfstride-logs",
                GcpResourceMetadata.UNIFORM_BUCKET_LEVEL_ACCESS.key: True,
                GcpResourceMetadata.PUBLIC_ACCESS_PREVENTION.key: "enforced",
                GcpResourceMetadata.GCS_VERSIONING_ENABLED.key: True,
                GcpResourceMetadata.GCS_DEFAULT_KMS_KEY_NAME.key: (
                    "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/gcs"
                ),
                GcpResourceMetadata.CUSTOMER_MANAGED_ENCRYPTION.key: True,
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
                GcpResourceMetadata.PROJECT.key: "tfstride-demo",
                GcpResourceMetadata.IAM_BINDINGS.key: [
                    {
                        "role": "roles/secretmanager.secretAccessor",
                        "members": ["allAuthenticatedUsers"],
                        "source": "google_secret_manager_secret_iam_member.public_accessor",
                    }
                ],
                GcpResourceMetadata.RESOURCE_POLICY_SOURCE_ADDRESSES.key: [
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
                GcpResourceMetadata.ORGANIZATION_ID.key: "1234567890",
                GcpResourceMetadata.FOLDER_ID.key: "folders/12345",
            },
            provider="gcp",
            resource_type="google_folder_iam_member",
        )

        facts = analysis_facts(resource)

        self.assertEqual(facts.iam.organization_id, "1234567890")
        self.assertEqual(facts.iam.folder_id, "folders/12345")

    def test_gcp_iam_target_facts_read_provider_owned_reference_metadata(self) -> None:
        resource = _resource(
            {GcpResourceMetadata.SECRET_REFERENCE.key: "google_secret_manager_secret.api.id"},
            provider="gcp",
            resource_type="google_secret_manager_secret_iam_member",
        )

        facts = analysis_facts(resource)

        self.assertEqual(facts.iam.reference_values, ["google_secret_manager_secret.api.id"])
        self.assertEqual(facts.iam.target_reference, "google_secret_manager_secret.api.id")

    def test_gcp_cloud_sql_facts_read_provider_owned_database_metadata(self) -> None:
        resource = _resource(
            {
                GcpResourceMetadata.DATABASE_VERSION.key: "POSTGRES_15",
                GcpResourceMetadata.CLOUD_SQL_AUTHORIZED_NETWORKS.key: [
                    {"name": "anywhere", "value": "0.0.0.0/0"}
                ],
                GcpResourceMetadata.CLOUD_SQL_BACKUP_ENABLED.key: False,
                GcpResourceMetadata.CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED.key: True,
                GcpResourceMetadata.CLOUD_SQL_IPV4_ENABLED.key: True,
                GcpResourceMetadata.CLOUD_SQL_PRIVATE_NETWORK.key: "google_compute_network.main.id",
                GcpResourceMetadata.CLOUD_SQL_REQUIRE_SSL.key: True,
                GcpResourceMetadata.CLOUD_SQL_SSL_MODE.key: "ENCRYPTED_ONLY",
                GcpResourceMetadata.DELETION_PROTECTION.key: True,
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


    def test_gcp_gke_facts_read_provider_owned_cluster_metadata(self) -> None:
        resource = _resource(
            {
                GcpResourceMetadata.GKE_ENDPOINT.key: "35.1.2.3",
                GcpResourceMetadata.GKE_PRIVATE_ENDPOINT_ENABLED.key: False,
                GcpResourceMetadata.GKE_PRIVATE_NODES_ENABLED.key: False,
                GcpResourceMetadata.GKE_MASTER_AUTHORIZED_NETWORKS.key: [
                    {"display_name": "anywhere", "cidr_block": "0.0.0.0/0"}
                ],
                GcpResourceMetadata.GKE_WORKLOAD_IDENTITY_ENABLED.key: False,
                GcpResourceMetadata.GKE_WORKLOAD_IDENTITY_POOL.key: None,
                GcpResourceMetadata.GKE_NODE_SERVICE_ACCOUNT.key: "123456789-compute@developer.gserviceaccount.com",
                GcpResourceMetadata.GKE_NODE_OAUTH_SCOPES.key: ["https://www.googleapis.com/auth/cloud-platform"],
                GcpResourceMetadata.GKE_NODE_METADATA_MODE.key: "GCE_METADATA",
                GcpResourceMetadata.GKE_LEGACY_METADATA_ENDPOINTS_ENABLED.key: True,
            },
            provider="gcp",
            resource_type="google_container_cluster",
        )

        facts = analysis_facts(resource)

        self.assertEqual(facts.gke.endpoint, "35.1.2.3")
        self.assertFalse(facts.gke.private_endpoint_enabled)
        self.assertFalse(facts.gke.private_nodes_enabled)
        self.assertEqual(
            facts.gke.master_authorized_networks,
            [{"display_name": "anywhere", "cidr_block": "0.0.0.0/0"}],
        )
        self.assertFalse(facts.gke.workload_identity_enabled)
        self.assertIsNone(facts.gke.workload_identity_pool)
        self.assertEqual(facts.gke.node_service_account, "123456789-compute@developer.gserviceaccount.com")
        self.assertEqual(facts.gke.node_oauth_scopes, ["https://www.googleapis.com/auth/cloud-platform"])
        self.assertEqual(facts.gke.node_metadata_mode, "GCE_METADATA")
        self.assertTrue(facts.gke.legacy_metadata_endpoints_enabled)

    def test_gcp_compute_facts_read_workload_identity_metadata(self) -> None:
        resource = _resource(
            {
                GcpResourceMetadata.SERVICE_ACCOUNTS.key: [
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
                GcpResourceMetadata.NAME.key: "projects/tfstride-demo/serviceAccounts/tfstride-web",
                GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL.key: "tfstride-web@example.iam.gserviceaccount.com",
                GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER.key: (
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

    def test_registered_provider_facts_are_used_without_analysis_branching(self) -> None:
        calls: list[NormalizedResource] = []

        def gcp_facts(resource: NormalizedResource) -> FakeProviderFacts:
            calls.append(resource)
            return FakeProviderFacts(resource)

        resource = _resource(provider="gcp", resource_type="google_storage_bucket")
        registry = ProviderResourceFactsRegistry([("gcp", gcp_facts)])

        facts = analysis_facts(resource, facts_registry=registry)

        self.assertEqual(calls, [resource])
        self.assertEqual(facts.storage.bucket_name, "gcp-logs")
        self.assertEqual(facts.storage.bucket_acl, "private")
        self.assertEqual(facts.storage.public_access_block, {"block_public_acls": True})
        self.assertTrue(facts.storage.uniform_bucket_level_access)
        self.assertEqual(facts.storage.public_access_prevention, "enforced")
        self.assertTrue(facts.storage.versioning_enabled)
        self.assertEqual(
            facts.storage.default_kms_key_name,
            "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/gcs",
        )
        self.assertEqual(facts.iam.policy_document, {"Statement": [{"Effect": "Allow"}]})
        self.assertEqual(facts.iam.trust_statements, [{"Effect": "Allow"}])
        self.assertEqual(facts.sql.engine, "spanner")
        self.assertEqual(
            facts.iam.resource_policy_source_addresses,
            ["google_storage_bucket_iam_binding.logs"],
        )
        self.assertEqual(facts.iam.project, "tfstride-demo")
        self.assertEqual(facts.iam.resource_name, "fake-resource")
        self.assertEqual(facts.iam.reference_values, ["fake-resource", "google_service_account.fake.email"])
        self.assertEqual(facts.iam.target_reference, "google_service_account.fake.email")
        self.assertEqual(facts.iam.bindings, [{"role": "roles/viewer", "members": ["group:ops@example.com"]}])
        self.assertEqual(facts.iam.custom_role_id, "deployAdmin")
        self.assertEqual(facts.iam.custom_role_permissions, ["iam.serviceAccounts.actAs"])
        self.assertEqual(facts.iam.organization_id, "1234567890")
        self.assertEqual(facts.iam.folder_id, "folders/12345")
        self.assertEqual(facts.sql.authorized_networks, [{"name": "anywhere", "value": "0.0.0.0/0"}])
        self.assertFalse(facts.sql.backup_enabled)
        self.assertTrue(facts.sql.point_in_time_recovery_enabled)
        self.assertEqual(facts.iam.service_account_email, "fake@example.iam.gserviceaccount.com")
        self.assertEqual(facts.iam.service_account_member, "serviceAccount:fake@example.iam.gserviceaccount.com")
        self.assertEqual(facts.iam.service_account_reference, "google_service_account.fake.email")
        self.assertEqual(facts.workload.identity_members, ["serviceAccount:fake@example.iam.gserviceaccount.com"])
        self.assertEqual(facts.workload.identity_scopes, ["https://www.googleapis.com/auth/cloud-platform"])
        self.assertEqual(facts.gke.endpoint, "35.1.2.3")
        self.assertFalse(facts.gke.private_endpoint_enabled)
        self.assertFalse(facts.gke.private_nodes_enabled)
        self.assertEqual(facts.gke.master_authorized_networks, [{"display_name": "anywhere", "cidr_block": "0.0.0.0/0"}])
        self.assertFalse(facts.gke.workload_identity_enabled)
        self.assertIsNone(facts.gke.workload_identity_pool)
        self.assertEqual(facts.gke.node_service_account, "123456789-compute@developer.gserviceaccount.com")
        self.assertEqual(facts.gke.node_oauth_scopes, ["https://www.googleapis.com/auth/cloud-platform"])
        self.assertEqual(facts.gke.node_metadata_mode, "GCE_METADATA")
        self.assertTrue(facts.gke.legacy_metadata_endpoints_enabled)

    def test_returns_detached_collections(self) -> None:
        resource = _resource(
            {
                "policy_document": {"Statement": [{"Effect": "Allow"}]},
                "trust_statements": [{"Effect": "Allow"}],
            }
        )
        facts = analysis_facts(resource)

        policy_document = facts.iam.policy_document
        trust_statements = facts.iam.trust_statements
        policy_document["Statement"].append({"Effect": "Deny"})
        trust_statements[0]["Effect"] = "Deny"

        self.assertEqual(facts.iam.policy_document, {"Statement": [{"Effect": "Allow"}]})
        self.assertEqual(facts.iam.trust_statements, [{"Effect": "Allow"}])

    def test_analysis_metadata_reads_are_centralized_in_facts_facade(self) -> None:
        analysis_root = Path(__file__).resolve().parents[1] / "src" / "tfstride" / "analysis"
        offenders: list[str] = []

        for path in sorted(analysis_root.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            if "ResourceMetadata" in text or "get_metadata_field(" in text:
                offenders.append(path.name)

        self.assertEqual(offenders, [])

    def test_analysis_resource_facts_does_not_import_aws_directly(self) -> None:
        analysis_root = Path(__file__).resolve().parents[1] / "src" / "tfstride" / "analysis"
        text = (analysis_root / "resource_facts.py").read_text(encoding="utf-8")

        self.assertNotIn("tfstride.providers.aws", text)
        self.assertNotIn('provider == "aws"', text)
        self.assertNotIn('provider != "aws"', text)


if __name__ == "__main__":
    unittest.main()