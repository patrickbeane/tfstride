from __future__ import annotations

import unittest
from pathlib import Path

from tfstride.app import TfStride
from tfstride.providers.aws.normalizer import AwsNormalizer
from tfstride.providers.catalog import DEFAULT_PROVIDER, default_provider_registry


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"
FIXTURE_PATH = FIXTURES_DIR / "sample_aws_plan.json"


class ProviderCatalogTests(unittest.TestCase):
    def test_default_registry_registers_aws_provider(self) -> None:
        registry = default_provider_registry()

        self.assertEqual(DEFAULT_PROVIDER, "aws")
        self.assertEqual(registry.providers(), ("aws",))
        self.assertIsInstance(registry.get(DEFAULT_PROVIDER), AwsNormalizer)

    def test_app_uses_catalog_default_provider(self) -> None:
        result = TfStride().analyze_plan(FIXTURE_PATH)

        self.assertEqual(result.inventory.provider, DEFAULT_PROVIDER)
        self.assertGreater(len(result.inventory.resources), 0)


if __name__ == "__main__":
    unittest.main()