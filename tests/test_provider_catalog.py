from __future__ import annotations

import unittest
from pathlib import Path

from tfstride.app import TfStride
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES, AwsNormalizer
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.aws.resource_facts import AwsResourceFacts
from tfstride.providers.catalog import (
    DEFAULT_PROVIDER,
    default_provider_plugins,
    default_provider_registry,
    default_resource_facts_registry,
)


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"
FIXTURE_PATH = FIXTURES_DIR / "sample_aws_plan.json"


class ProviderCatalogTests(unittest.TestCase):
    def test_default_registry_registers_aws_provider(self) -> None:
        registry = default_provider_registry()

        self.assertEqual(DEFAULT_PROVIDER, "aws")
        self.assertEqual(registry.providers(), ("aws",))
        self.assertIsInstance(registry.get(DEFAULT_PROVIDER), AwsNormalizer)

    def test_default_provider_plugins_describe_aws_provider_contract(self) -> None:
        (plugin,) = default_provider_plugins()

        self.assertEqual(plugin.provider, "aws")
        self.assertIs(plugin.metadata_namespace, AwsResourceMetadata)
        self.assertEqual(plugin.supported_resource_types, frozenset(SUPPORTED_AWS_TYPES))
        self.assertIsInstance(plugin.create_normalizer(), AwsNormalizer)
        self.assertIsInstance(plugin.create_resource_decorator(), AwsResourceDecorator)

    def test_default_resource_facts_registry_registers_aws_provider(self) -> None:
        registry = default_resource_facts_registry()
        resource = TfStride().analyze_plan(FIXTURE_PATH).inventory.resources[0]

        self.assertEqual(registry.providers(), ("aws",))
        self.assertIsInstance(registry.facts_for(resource), AwsResourceFacts)

    def test_app_uses_catalog_default_provider(self) -> None:
        result = TfStride().analyze_plan(FIXTURE_PATH)

        self.assertEqual(result.inventory.provider, DEFAULT_PROVIDER)
        self.assertGreater(len(result.inventory.resources), 0)


if __name__ == "__main__":
    unittest.main()