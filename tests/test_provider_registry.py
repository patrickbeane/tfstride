from __future__ import annotations

import unittest

from tfstride.models import ResourceInventory, TerraformResource
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.registry import ProviderNotRegisteredError, ProviderRegistry, ProviderRegistryError


class RecordingNormalizer(ProviderNormalizer):
    def __init__(self, provider: str) -> None:
        self.provider = provider
        self.calls: list[list[TerraformResource]] = []

    def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
        self.calls.append(resources)
        return ResourceInventory(provider=self.provider.strip().lower(), resources=[])


class ProviderRegistryTests(unittest.TestCase):
    def test_registers_and_returns_normalizers_by_provider_name(self) -> None:
        aws = RecordingNormalizer("AWS")
        registry = ProviderRegistry([aws])

        self.assertIs(registry.get(" aws "), aws)
        self.assertEqual(registry.providers(), ("aws",))

    def test_normalize_delegates_to_registered_provider(self) -> None:
        aws = RecordingNormalizer("aws")
        resource = TerraformResource(
            address="aws_instance.web",
            mode="managed",
            resource_type="aws_instance",
            name="web",
            provider_name="registry.terraform.io/hashicorp/aws",
            values={},
        )

        inventory = ProviderRegistry([aws]).normalize("aws", [resource])

        self.assertEqual(inventory.provider, "aws")
        self.assertEqual(aws.calls, [[resource]])

    def test_rejects_duplicate_provider_registration(self) -> None:
        registry = ProviderRegistry([RecordingNormalizer("aws")])

        with self.assertRaises(ProviderRegistryError):
            registry.register(RecordingNormalizer("AWS"))

    def test_rejects_empty_provider_names(self) -> None:
        registry = ProviderRegistry()

        with self.assertRaises(ProviderRegistryError):
            registry.register(RecordingNormalizer(" "))

    def test_missing_provider_lookup_raises_specific_error(self) -> None:
        registry = ProviderRegistry()

        with self.assertRaises(ProviderNotRegisteredError):
            registry.get("aws")


if __name__ == "__main__":
    unittest.main()