from __future__ import annotations

import unittest
from pathlib import Path

from tfstride.app import TfStride
from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.aws.limitations import AWS_LIMITATIONS
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES, AwsNormalizer
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.aws.resource_facts import AwsResourceFacts
from tfstride.providers.gcp.limitations import GCP_LIMITATIONS
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import SUPPORTED_GCP_TYPES, GcpNormalizer
from tfstride.providers.gcp.resource_facts import GcpResourceFacts
from tfstride.providers.resource_capabilities import ResourceCapability
from tfstride.providers.catalog import (
    DEFAULT_PROVIDER,
    default_provider_limitations,
    default_provider_plugins,
    default_provider_registry,
    default_resource_capability_registry,
    default_resource_facts_registry,
)


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"
FIXTURE_PATH = FIXTURES_DIR / "sample_aws_plan.json"


class ProviderCatalogTests(unittest.TestCase):
    def test_default_registry_registers_builtin_providers(self) -> None:
        registry = default_provider_registry()

        self.assertEqual(DEFAULT_PROVIDER, "aws")
        self.assertEqual(registry.providers(), ("aws", "gcp"))
        self.assertIsInstance(registry.get(DEFAULT_PROVIDER), AwsNormalizer)
        self.assertIsInstance(registry.get("gcp"), GcpNormalizer)

    def test_default_provider_plugins_describe_builtin_provider_contracts(self) -> None:
        plugins = {plugin.provider: plugin for plugin in default_provider_plugins()}
        aws_plugin = plugins["aws"]
        gcp_plugin = plugins["gcp"]

        self.assertEqual(tuple(plugins), ("aws", "gcp"))
        self.assertIs(aws_plugin.metadata_namespace, AwsResourceMetadata)
        self.assertEqual(aws_plugin.supported_resource_types, frozenset(SUPPORTED_AWS_TYPES))
        self.assertEqual(aws_plugin.limitations, AWS_LIMITATIONS)
        self.assertIsInstance(aws_plugin.create_normalizer(), AwsNormalizer)
        self.assertIsInstance(aws_plugin.create_resource_decorator(), AwsResourceDecorator)
        self.assertIs(gcp_plugin.metadata_namespace, GcpResourceMetadata)
        self.assertEqual(gcp_plugin.supported_resource_types, SUPPORTED_GCP_TYPES)
        self.assertEqual(gcp_plugin.limitations, GCP_LIMITATIONS)
        self.assertIsInstance(gcp_plugin.create_normalizer(), GcpNormalizer)
        self.assertIsNone(gcp_plugin.create_resource_decorator())

    def test_default_provider_limitations_register_builtin_provider_caveats(self) -> None:
        limitations = default_provider_limitations()

        self.assertEqual(limitations["aws"], AWS_LIMITATIONS)
        self.assertEqual(limitations["gcp"], GCP_LIMITATIONS)

    def test_default_resource_facts_registry_registers_builtin_providers(self) -> None:
        registry = default_resource_facts_registry()
        aws_resource = TfStride().analyze_plan(FIXTURE_PATH).inventory.resources[0]
        gcp_resource = NormalizedResource(
            address="google_storage_bucket.logs",
            provider="gcp",
            resource_type="google_storage_bucket",
            name="logs",
            category=ResourceCategory.DATA,
        )

        self.assertEqual(registry.providers(), ("aws", "gcp"))
        self.assertIsInstance(registry.facts_for(aws_resource), AwsResourceFacts)
        self.assertIsInstance(registry.facts_for(gcp_resource), GcpResourceFacts)

    def test_default_resource_capability_registry_registers_builtin_providers(self) -> None:
        registry = default_resource_capability_registry()
        aws_resource = NormalizedResource(
            address="aws_instance.web",
            provider="aws",
            resource_type="aws_instance",
            name="web",
            category=ResourceCategory.COMPUTE,
        )
        gcp_resource = NormalizedResource(
            address="google_compute_instance.web",
            provider="gcp",
            resource_type="google_compute_instance",
            name="web",
            category=ResourceCategory.COMPUTE,
        )

        self.assertEqual(registry.providers(), ("aws", "gcp"))
        self.assertTrue(registry.has_capability(aws_resource, ResourceCapability.WORKLOAD))
        self.assertFalse(registry.has_capability(gcp_resource, ResourceCapability.WORKLOAD))

    def test_app_uses_catalog_default_provider(self) -> None:
        result = TfStride().analyze_plan(FIXTURE_PATH)

        self.assertEqual(result.inventory.provider, DEFAULT_PROVIDER)
        self.assertGreater(len(result.inventory.resources), 0)


if __name__ == "__main__":
    unittest.main()