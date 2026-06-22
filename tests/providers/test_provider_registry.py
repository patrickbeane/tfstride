from __future__ import annotations

import unittest

from tfstride.models import ResourceInventory, TerraformResource
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.registry import (
    ProviderNotRegisteredError,
    ProviderRegistry,
    ProviderRegistryError,
    ProviderSelectionError,
)


class RecordingNormalizer(ProviderNormalizer):
    def __init__(self, provider: str, owned_prefix: str | None = None) -> None:
        self.provider = provider
        self.owned_prefix = owned_prefix
        self.calls: list[list[TerraformResource]] = []

    def owns_resource(self, resource: TerraformResource) -> bool:
        return self.owned_prefix is not None and resource.resource_type.startswith(self.owned_prefix)

    def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
        self.calls.append(resources)
        return ResourceInventory(provider=self.provider.strip().lower(), resources=[])


def _resource(
    resource_type: str = "aws_instance",
    *,
    provider_name: str = "registry.terraform.io/hashicorp/aws",
) -> TerraformResource:
    return TerraformResource(
        address=f"{resource_type}.example",
        mode="managed",
        resource_type=resource_type,
        name="example",
        provider_name=provider_name,
        values={},
    )


class ProviderRegistryTests(unittest.TestCase):
    def test_registers_and_returns_normalizers_by_provider_name(self) -> None:
        aws = RecordingNormalizer("AWS")
        registry = ProviderRegistry([aws])

        self.assertIs(registry.get(" aws "), aws)
        self.assertEqual(registry.providers(), ("aws",))

    def test_normalize_delegates_to_registered_provider(self) -> None:
        aws = RecordingNormalizer("aws")
        resource = _resource()

        inventory = ProviderRegistry([aws]).normalize("aws", [resource])

        self.assertEqual(inventory.provider, "aws")
        self.assertEqual(aws.calls, [[resource]])

    def test_detect_provider_uses_normalizer_resource_ownership(self) -> None:
        aws = RecordingNormalizer("aws", owned_prefix="aws_")
        gcp = RecordingNormalizer("gcp", owned_prefix="google_")
        registry = ProviderRegistry([aws, gcp])

        self.assertEqual(registry.detect_provider([_resource("google_storage_bucket")]), "gcp")
        self.assertEqual(
            registry.provider_resource_counts([_resource("google_storage_bucket")]),
            {"aws": 0, "gcp": 1},
        )

    def test_normalize_detected_delegates_to_detected_provider(self) -> None:
        aws = RecordingNormalizer("aws", owned_prefix="aws_")
        gcp = RecordingNormalizer("gcp", owned_prefix="google_")
        resource = _resource("google_storage_bucket")

        inventory = ProviderRegistry([aws, gcp]).normalize_detected([resource])

        self.assertEqual(inventory.provider, "gcp")
        self.assertEqual(aws.calls, [])
        self.assertEqual(gcp.calls, [[resource]])

    def test_detect_provider_falls_back_to_default_provider_without_matches(self) -> None:
        aws = RecordingNormalizer("aws", owned_prefix="aws_")
        registry = ProviderRegistry([aws])
        resource = _resource("random_resource", provider_name="registry.example.com/custom/provider")

        inventory = registry.normalize_detected([resource], default_provider="aws")

        self.assertEqual(inventory.provider, "aws")
        self.assertEqual(aws.calls, [[resource]])

    def test_detect_provider_rejects_multiple_matching_providers(self) -> None:
        aws = RecordingNormalizer("aws", owned_prefix="aws_")
        gcp = RecordingNormalizer("gcp", owned_prefix="google_")
        registry = ProviderRegistry([aws, gcp])

        with self.assertRaises(ProviderSelectionError):
            registry.detect_provider([_resource("aws_instance"), _resource("google_storage_bucket")])

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
