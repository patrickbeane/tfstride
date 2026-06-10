from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.constants import (
    GCP_BIGQUERY_DATASET_IAM_RESOURCE_TYPES,
    GCP_BIGQUERY_TABLE_IAM_RESOURCE_TYPES,
    GCP_CLOUD_FUNCTION_IAM_RESOURCE_TYPES,
    GCP_CLOUD_FUNCTION_RESOURCE_TYPES,
    GCP_CLOUD_RUN_IAM_RESOURCE_TYPES,
    GCP_CLOUD_RUN_RESOURCE_TYPES,
    GCP_CUSTOM_ROLE_RESOURCE_TYPES,
    GCP_FOLDER_IAM_RESOURCE_TYPES,
    GCP_IAM_GRANT_RESOURCE_TYPES,
    GCP_IAM_POLICY_RESOURCE_TYPES,
    GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES,
    GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES,
    GCP_ORGANIZATION_IAM_RESOURCE_TYPES,
    GCP_ORG_FOLDER_IAM_RESOURCE_TYPES,
    GCP_PROJECT_IAM_RESOURCE_TYPES,
    GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES,
    GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES,
    GCP_RESOURCE_IAM_RESOURCE_TYPES,
    GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES,
    GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES,
    GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES,
    GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES,
    PUBLIC_GCP_IAM_MEMBERS,
)
from tfstride.providers.gcp.limitations import GCP_LIMITATIONS
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import SUPPORTED_GCP_TYPES, GcpNormalizer
from tfstride.providers.gcp.plugin import gcp_provider_plugin
from tfstride.providers.gcp.resource_capabilities import GCP_RESOURCE_CAPABILITIES
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator
from tfstride.providers.gcp.resource_facts import GcpResourceFacts, gcp_facts
from tfstride.providers.resource_capabilities import ResourceCapability
from tfstride.resource_metadata import InventoryMetadata, MetadataField


def _terraform_resource(
    *,
    address: str,
    resource_type: str,
    provider_name: str = "registry.terraform.io/hashicorp/google",
) -> TerraformResource:
    return TerraformResource(
        address=address,
        mode="managed",
        resource_type=resource_type,
        name=address.rsplit(".", 1)[-1],
        provider_name=provider_name,
        values={},
    )


def _normalized_resource(provider: str = "gcp") -> NormalizedResource:
    return NormalizedResource(
        address="google_storage_bucket.logs",
        provider=provider,
        resource_type="google_storage_bucket",
        name="logs",
        category=ResourceCategory.DATA,
    )


def _metadata_field_names(namespace: type) -> set[str]:
    return {
        name
        for name, value in vars(namespace).items()
        if isinstance(value, MetadataField)
    }


class GcpProviderTests(unittest.TestCase):
    def test_plugin_describes_gcp_provider_contract(self) -> None:
        plugin = gcp_provider_plugin()

        self.assertEqual(plugin.provider, "gcp")
        self.assertIs(plugin.metadata_namespace, GcpResourceMetadata)
        self.assertEqual(plugin.supported_resource_types, SUPPORTED_GCP_TYPES)
        self.assertEqual(dict(plugin.resource_capabilities), dict(GCP_RESOURCE_CAPABILITIES))
        self.assertEqual(plugin.limitations, GCP_LIMITATIONS)
        self.assertIsInstance(plugin.create_normalizer(), GcpNormalizer)
        self.assertIsInstance(plugin.create_resource_decorator(), GcpResourceDecorator)
        self.assertEqual(
            plugin.resource_types_for_capability(ResourceCapability.WORKLOAD),
            frozenset(
                {
                    "google_cloud_run_service",
                    "google_cloud_run_v2_service",
                    "google_cloudfunctions_function",
                    "google_cloudfunctions2_function",
                    "google_compute_instance",
                }
            ),
        )
        self.assertTrue(plugin.supports_resource_type("google_cloud_run_service"))
        self.assertTrue(plugin.supports_resource_type("google_cloud_run_v2_service"))
        self.assertTrue(plugin.supports_resource_type("google_cloud_run_service_iam_member"))
        self.assertTrue(plugin.supports_resource_type("google_cloud_run_v2_service_iam_member"))
        self.assertTrue(plugin.supports_resource_type("google_cloudfunctions_function"))
        self.assertTrue(plugin.supports_resource_type("google_cloudfunctions2_function"))
        self.assertTrue(plugin.supports_resource_type("google_cloudfunctions_function_iam_member"))
        self.assertTrue(plugin.supports_resource_type("google_cloudfunctions2_function_iam_member"))
        self.assertTrue(plugin.supports_resource_type("google_compute_route"))
        self.assertTrue(plugin.supports_resource_type("google_compute_router"))
        self.assertTrue(plugin.supports_resource_type("google_compute_router_nat"))
        self.assertTrue(plugin.supports_resource_type("google_compute_forwarding_rule"))
        self.assertTrue(plugin.supports_resource_type("google_compute_global_forwarding_rule"))
        self.assertTrue(plugin.supports_resource_type("google_container_cluster"))
        self.assertTrue(plugin.supports_resource_type("google_container_node_pool"))
        self.assertTrue(plugin.supports_resource_type("google_service_account"))
        self.assertTrue(plugin.supports_resource_type("google_service_account_key"))
        self.assertTrue(plugin.supports_resource_type("google_secret_manager_secret"))
        self.assertTrue(plugin.supports_resource_type("google_secret_manager_secret_iam_member"))
        self.assertTrue(plugin.supports_resource_type("google_kms_crypto_key"))
        self.assertTrue(plugin.supports_resource_type("google_kms_crypto_key_iam_member"))
        self.assertTrue(plugin.supports_resource_type("google_kms_key_ring_iam_member"))
        self.assertTrue(plugin.supports_resource_type("google_kms_key_ring_iam_binding"))
        self.assertTrue(plugin.supports_resource_type("google_kms_key_ring_iam_policy"))
        self.assertTrue(plugin.supports_resource_type("google_folder_iam_member"))
        self.assertTrue(plugin.supports_resource_type("google_folder_iam_binding"))
        self.assertTrue(plugin.supports_resource_type("google_folder_iam_policy"))
        self.assertTrue(plugin.supports_resource_type("google_organization_iam_member"))
        self.assertTrue(plugin.supports_resource_type("google_organization_iam_binding"))
        self.assertTrue(plugin.supports_resource_type("google_organization_iam_policy"))
        self.assertTrue(plugin.supports_resource_type("google_sql_database_instance"))
        self.assertTrue(plugin.supports_resource_type("google_project_iam_binding"))
        self.assertTrue(plugin.supports_resource_type("google_project_iam_custom_role"))
        self.assertTrue(plugin.supports_resource_type("google_project_iam_policy"))
        self.assertTrue(plugin.supports_resource_type("google_organization_iam_custom_role"))
        self.assertTrue(plugin.supports_resource_type("google_storage_bucket"))
        self.assertTrue(plugin.supports_resource_type("google_storage_bucket_iam_member"))
        self.assertFalse(plugin.supports_resource_type("google_project_service"))

    def test_shared_gcp_constants_match_supported_resource_contract(self) -> None:
        self.assertEqual(PUBLIC_GCP_IAM_MEMBERS, frozenset({"allUsers", "allAuthenticatedUsers"}))
        self.assertEqual(
            GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES,
            GCP_CLOUD_RUN_RESOURCE_TYPES | GCP_CLOUD_FUNCTION_RESOURCE_TYPES,
        )
        self.assertEqual(
            GCP_ORG_FOLDER_IAM_RESOURCE_TYPES,
            GCP_ORGANIZATION_IAM_RESOURCE_TYPES | GCP_FOLDER_IAM_RESOURCE_TYPES,
        )
        self.assertEqual(
            GCP_RESOURCE_IAM_RESOURCE_TYPES,
            GCP_SERVICE_ACCOUNT_IAM_RESOURCE_TYPES
            | GCP_STORAGE_BUCKET_IAM_RESOURCE_TYPES
            | GCP_SECRET_MANAGER_SECRET_IAM_RESOURCE_TYPES
            | GCP_PUBSUB_TOPIC_IAM_RESOURCE_TYPES
            | GCP_PUBSUB_SUBSCRIPTION_IAM_RESOURCE_TYPES
            | GCP_BIGQUERY_DATASET_IAM_RESOURCE_TYPES
            | GCP_BIGQUERY_TABLE_IAM_RESOURCE_TYPES
            | GCP_KMS_CRYPTO_KEY_IAM_RESOURCE_TYPES
            | GCP_KMS_KEY_RING_IAM_RESOURCE_TYPES
            | GCP_CLOUD_RUN_IAM_RESOURCE_TYPES
            | GCP_CLOUD_FUNCTION_IAM_RESOURCE_TYPES,
        )
        self.assertEqual(
            GCP_IAM_GRANT_RESOURCE_TYPES,
            GCP_PROJECT_IAM_RESOURCE_TYPES
            | GCP_ORGANIZATION_IAM_RESOURCE_TYPES
            | GCP_FOLDER_IAM_RESOURCE_TYPES
            | GCP_RESOURCE_IAM_RESOURCE_TYPES,
        )
        self.assertEqual(
            GCP_IAM_POLICY_RESOURCE_TYPES,
            GCP_IAM_GRANT_RESOURCE_TYPES | GCP_CUSTOM_ROLE_RESOURCE_TYPES,
        )
        self.assertLessEqual(GCP_SERVERLESS_WORKLOAD_RESOURCE_TYPES, SUPPORTED_GCP_TYPES)
        self.assertLessEqual(GCP_IAM_GRANT_RESOURCE_TYPES, SUPPORTED_GCP_TYPES)
        self.assertLessEqual(GCP_IAM_POLICY_RESOURCE_TYPES, SUPPORTED_GCP_TYPES)

    def test_metadata_namespace_exposes_gcp_owned_fields(self) -> None:
        self.assertGreaterEqual(
            _metadata_field_names(GcpResourceMetadata),
            {
                "NAME",
                "SELF_LINK",
                "PROJECT",
                "REGION",
                "ZONE",
                "NETWORK",
                "NETWORK_TAGS",
                "FIREWALL_ALLOW",
                "FIREWALL_TARGET_SERVICE_ACCOUNTS",
                "FIREWALL_SOURCE_SERVICE_ACCOUNTS",
                "ROUTE_DEST_RANGE",
                "ROUTE_NEXT_HOP_GATEWAY",
                "ROUTE_NEXT_HOP_INSTANCE",
                "ROUTE_NEXT_HOP_IP",
                "ROUTE_NEXT_HOP_ILB",
                "ROUTE_NEXT_HOP_VPN_TUNNEL",
                "ROUTE_TAGS",
                "ROUTER_REFERENCE",
                "NAT_SUBNETWORKS",
                "FORWARDING_RULE_IP_ADDRESS",
                "FORWARDING_RULE_LOAD_BALANCING_SCHEME",
                "FORWARDING_RULE_TARGET",
                "FORWARDING_RULE_BACKEND_SERVICE",
                "FORWARDING_RULE_PORTS",
                "FORWARDING_RULE_SOURCE_IP_RANGES",
                "NETWORK_INTERFACES",
                "SERVICE_ACCOUNTS",
                "INTERNET_INGRESS_FIREWALLS",
                "IAM_ROLE",
                "IAM_MEMBER",
                "IAM_CONDITION",
                "IAM_MEMBERS",
                "CUSTOM_ROLE_ID",
                "CUSTOM_ROLE_PERMISSIONS",
                "CUSTOM_ROLE_STAGE",
                "ORGANIZATION_ID",
                "FOLDER_ID",
                "IAM_BINDINGS",
                "BUCKET_NAME",
                "GCS_DEFAULT_KMS_KEY_NAME",
                "GCS_VERSIONING_ENABLED",
                "GCS_VERSIONING_CONFIGURATION",
                "GCS_ENCRYPTION_CONFIGURATION",
                "DATABASE_VERSION",
                "CLOUD_SQL_PRIVATE_NETWORK",
                "CLOUD_SQL_SSL_MODE",
                "CLOUD_SQL_IPV4_ENABLED",
                "CLOUD_SQL_BACKUP_ENABLED",
                "CLOUD_SQL_POINT_IN_TIME_RECOVERY_ENABLED",
                "CLOUD_SQL_REQUIRE_SSL",
                "CLOUD_SQL_AUTHORIZED_NETWORKS",
                "CLOUD_SQL_BACKUP_CONFIGURATION",
                "CLOUD_SQL_IP_CONFIGURATION",
                "DELETION_PROTECTION",
                "SECRET_ID",
                "SECRET_REFERENCE",
                "KMS_CRYPTO_KEY_REFERENCE",
                "KMS_KEY_RING",
                "KMS_PURPOSE",
                "KMS_ROTATION_PERIOD",
                "RESOURCE_POLICY_SOURCE_ADDRESSES",
                "SERVICE_ACCOUNT_ACCOUNT_ID",
                "SERVICE_ACCOUNT_EMAIL",
                "SERVICE_ACCOUNT_MEMBER",
                "SERVICE_ACCOUNT_REFERENCE",
                "CLOUD_RUN_SERVICE_REFERENCE",
                "CLOUD_FUNCTION_REFERENCE",
                "SERVERLESS_INGRESS",
                "SERVICE_ACCOUNT_UNIQUE_ID",
                "SERVICE_ACCOUNT_KEY_ALGORITHM",
                "SERVICE_ACCOUNT_PUBLIC_KEY_TYPE",
                "SERVICE_ACCOUNT_DISABLED",
                "OS_LOGIN_ENABLED",
                "GKE_ENDPOINT",
                "GKE_PRIVATE_ENDPOINT_ENABLED",
                "GKE_PRIVATE_NODES_ENABLED",
                "GKE_MASTER_AUTHORIZED_NETWORKS",
                "GKE_WORKLOAD_IDENTITY_ENABLED",
                "GKE_WORKLOAD_IDENTITY_POOL",
                "GKE_NODE_SERVICE_ACCOUNT",
                "GKE_NODE_OAUTH_SCOPES",
                "GKE_NODE_METADATA_MODE",
                "GKE_LEGACY_METADATA_ENDPOINTS_ENABLED",
            },
        )

    def test_resource_facts_start_with_neutral_analysis_defaults(self) -> None:
        facts = gcp_facts(_normalized_resource())

        self.assertIsInstance(facts, GcpResourceFacts)
        self.assertIsNone(facts.bucket_name)
        self.assertEqual(facts.bucket_acl, "")
        self.assertIsNone(facts.public_access_block)
        self.assertEqual(facts.policy_document, {})
        self.assertEqual(facts.trust_statements, [])
        self.assertIsNone(facts.engine)
        self.assertEqual(facts.resource_policy_source_addresses, [])
        self.assertIsNone(facts.project)
        self.assertEqual(facts.iam_bindings, [])
        self.assertEqual(facts.cloud_sql_authorized_networks, [])
        self.assertIsNone(facts.cloud_sql_backup_enabled)
        self.assertIsNone(facts.cloud_sql_point_in_time_recovery_enabled)
        self.assertEqual(facts.network_tags, [])
        self.assertEqual(facts.internet_ingress_firewalls, [])
        self.assertIsNone(facts.iam_role)
        self.assertIsNone(facts.iam_member)
        self.assertIsNone(facts.custom_role_id)
        self.assertEqual(facts.custom_role_permissions, [])
        self.assertIsNone(facts.organization_id)
        self.assertIsNone(facts.folder_id)
        self.assertIsNone(facts.os_login_enabled)
        self.assertIsNone(facts.service_account_email)
        self.assertIsNone(facts.service_account_member)
        self.assertIsNone(facts.service_account_reference)
        self.assertEqual(facts.workload_identity_members, [])
        self.assertEqual(facts.workload_identity_scopes, [])
        self.assertIsNone(facts.gke_endpoint)
        self.assertIsNone(facts.gke_private_endpoint_enabled)
        self.assertIsNone(facts.gke_private_nodes_enabled)
        self.assertEqual(facts.gke_master_authorized_networks, [])
        self.assertIsNone(facts.gke_workload_identity_enabled)
        self.assertIsNone(facts.gke_workload_identity_pool)
        self.assertIsNone(facts.gke_node_service_account)
        self.assertEqual(facts.gke_node_oauth_scopes, [])
        self.assertIsNone(facts.gke_node_metadata_mode)
        self.assertIsNone(facts.gke_legacy_metadata_endpoints_enabled)

    def test_normalizer_reports_resource_ownership(self) -> None:
        normalizer = GcpNormalizer()

        self.assertTrue(
            normalizer.owns_resource(
                _terraform_resource(
                    address="google_storage_bucket.logs",
                    resource_type="google_storage_bucket",
                )
            )
        )
        self.assertTrue(
            normalizer.owns_resource(
                _terraform_resource(
                    address="google_compute_instance.web",
                    resource_type="google_compute_instance",
                    provider_name="registry.terraform.io/hashicorp/google-beta",
                )
            )
        )
        self.assertFalse(
            normalizer.owns_resource(
                _terraform_resource(
                    address="aws_s3_bucket.logs",
                    resource_type="aws_s3_bucket",
                    provider_name="registry.terraform.io/hashicorp/aws",
                )
            )
        )

    def test_normalizer_normalizes_supported_gcp_resources_and_tracks_unsupported(self) -> None:
        resources = [
            _terraform_resource(
                address="google_storage_bucket.logs",
                resource_type="google_storage_bucket",
            ),
            _terraform_resource(
                address="google_compute_instance.web",
                resource_type="google_compute_instance",
                provider_name="registry.terraform.io/hashicorp/google-beta",
            ),
            _terraform_resource(
                address="google_service_account.web",
                resource_type="google_service_account",
            ),
            _terraform_resource(
                address="google_project_service.compute",
                resource_type="google_project_service",
            ),
            _terraform_resource(
                address="aws_s3_bucket.logs",
                resource_type="aws_s3_bucket",
                provider_name="registry.terraform.io/hashicorp/aws",
            ),
        ]

        inventory = GcpNormalizer().normalize(resources)

        self.assertEqual(inventory.provider, "gcp")
        self.assertEqual(
            [resource.address for resource in inventory.resources],
            ["google_storage_bucket.logs", "google_compute_instance.web", "google_service_account.web"],
        )
        self.assertEqual(inventory.unsupported_resources, ["google_project_service.compute"])
        self.assertEqual(
            InventoryMetadata.SUPPORTED_RESOURCE_TYPES.get(inventory.metadata),
            sorted(SUPPORTED_GCP_TYPES),
        )
        self.assertEqual(InventoryMetadata.TOTAL_INPUT_RESOURCES.get(inventory.metadata), 5)
        self.assertEqual(InventoryMetadata.PROVIDER_RESOURCE_COUNT.get(inventory.metadata), 4)
        self.assertEqual(InventoryMetadata.NORMALIZED_RESOURCE_COUNT.get(inventory.metadata), 3)
        self.assertEqual(
            InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.get(inventory.metadata),
            {"google_project_service": 1},
        )

    def test_normalizer_recognizes_google_resource_type_prefix_without_provider_suffix(self) -> None:
        resource = _terraform_resource(
            address="google_project_service.compute",
            resource_type="google_project_service",
            provider_name="registry.example.com/custom/provider",
        )

        inventory = GcpNormalizer().normalize([resource])

        self.assertEqual(inventory.unsupported_resources, ["google_project_service.compute"])
        self.assertEqual(InventoryMetadata.PROVIDER_RESOURCE_COUNT.get(inventory.metadata), 1)


if __name__ == "__main__":
    unittest.main()