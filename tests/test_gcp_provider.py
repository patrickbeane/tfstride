from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
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
            frozenset({"google_compute_instance"}),
        )
        self.assertTrue(plugin.supports_resource_type("google_service_account"))
        self.assertTrue(plugin.supports_resource_type("google_service_account_key"))
        self.assertTrue(plugin.supports_resource_type("google_secret_manager_secret"))
        self.assertTrue(plugin.supports_resource_type("google_secret_manager_secret_iam_member"))
        self.assertTrue(plugin.supports_resource_type("google_kms_crypto_key"))
        self.assertTrue(plugin.supports_resource_type("google_kms_crypto_key_iam_member"))
        self.assertTrue(plugin.supports_resource_type("google_sql_database_instance"))
        self.assertTrue(plugin.supports_resource_type("google_storage_bucket"))
        self.assertTrue(plugin.supports_resource_type("google_storage_bucket_iam_member"))
        self.assertFalse(plugin.supports_resource_type("google_project_service"))

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
                "NETWORK_INTERFACES",
                "SERVICE_ACCOUNTS",
                "INTERNET_INGRESS_FIREWALLS",
                "IAM_ROLE",
                "IAM_MEMBER",
                "IAM_MEMBERS",
                "IAM_BINDINGS",
                "BUCKET_NAME",
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
                "SERVICE_ACCOUNT_UNIQUE_ID",
                "SERVICE_ACCOUNT_KEY_ALGORITHM",
                "SERVICE_ACCOUNT_PUBLIC_KEY_TYPE",
                "SERVICE_ACCOUNT_DISABLED",
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
        self.assertIsNone(facts.service_account_email)
        self.assertIsNone(facts.service_account_member)
        self.assertIsNone(facts.service_account_reference)

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