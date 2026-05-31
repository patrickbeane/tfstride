from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory, TerraformResource
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import SUPPORTED_GCP_TYPES, GcpNormalizer
from tfstride.providers.gcp.plugin import gcp_provider_plugin
from tfstride.providers.gcp.resource_facts import GcpResourceFacts, gcp_facts
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
        self.assertEqual(dict(plugin.resource_capabilities), {})
        self.assertIsInstance(plugin.create_normalizer(), GcpNormalizer)
        self.assertIsNone(plugin.create_resource_decorator())
        self.assertFalse(plugin.supports_resource_type("google_storage_bucket"))

    def test_metadata_namespace_starts_empty(self) -> None:
        self.assertEqual(_metadata_field_names(GcpResourceMetadata), set())

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

    def test_normalizer_tracks_recognized_gcp_resources_as_unsupported(self) -> None:
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
                address="aws_s3_bucket.logs",
                resource_type="aws_s3_bucket",
                provider_name="registry.terraform.io/hashicorp/aws",
            ),
        ]

        inventory = GcpNormalizer().normalize(resources)

        self.assertEqual(inventory.provider, "gcp")
        self.assertEqual(inventory.resources, ())
        self.assertEqual(
            inventory.unsupported_resources,
            ["google_compute_instance.web", "google_storage_bucket.logs"],
        )
        self.assertEqual(InventoryMetadata.SUPPORTED_RESOURCE_TYPES.get(inventory.metadata), [])
        self.assertEqual(InventoryMetadata.TOTAL_INPUT_RESOURCES.get(inventory.metadata), 3)
        self.assertEqual(InventoryMetadata.PROVIDER_RESOURCE_COUNT.get(inventory.metadata), 2)
        self.assertEqual(InventoryMetadata.NORMALIZED_RESOURCE_COUNT.get(inventory.metadata), 0)
        self.assertEqual(
            InventoryMetadata.UNSUPPORTED_RESOURCE_TYPES.get(inventory.metadata),
            {"google_compute_instance": 1, "google_storage_bucket": 1},
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