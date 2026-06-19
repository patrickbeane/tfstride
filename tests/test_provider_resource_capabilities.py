from __future__ import annotations

import unittest

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.resource_capabilities import (
    ProviderResourceCapabilityRegistry,
    ProviderResourceCapabilityRegistryError,
    ResourceCapability,
)


def _resource(
    resource_type: str,
    *,
    provider: str = "aws",
    metadata: dict[str, object] | None = None,
) -> NormalizedResource:
    return NormalizedResource(
        address=f"{resource_type}.example",
        provider=provider,
        resource_type=resource_type,
        name="example",
        category=ResourceCategory.COMPUTE,
        metadata=metadata,
    )


class ProviderResourceCapabilityRegistryTests(unittest.TestCase):
    def test_registers_provider_capabilities_and_classifies_resources(self) -> None:
        registry = ProviderResourceCapabilityRegistry(
            [
                (
                    " AWS ",
                    {
                        ResourceCapability.WORKLOAD: frozenset({"aws_instance"}),
                        ResourceCapability.DATABASE: frozenset({"aws_db_instance"}),
                    },
                ),
                (
                    "gcp",
                    {
                        ResourceCapability.WORKLOAD: frozenset({"google_compute_instance"}),
                    },
                ),
            ]
        )

        self.assertEqual(registry.providers(), ("aws", "gcp"))
        self.assertEqual(
            registry.resource_types(ResourceCapability.WORKLOAD),
            frozenset({"aws_instance", "google_compute_instance"}),
        )
        self.assertEqual(
            registry.resource_types_for_provider("aws", ResourceCapability.DATABASE),
            frozenset({"aws_db_instance"}),
        )
        self.assertTrue(registry.has_capability(_resource("aws_instance"), ResourceCapability.WORKLOAD))
        self.assertFalse(
            registry.has_capability(_resource("aws_instance", provider="gcp"), ResourceCapability.WORKLOAD)
        )
        self.assertEqual(
            registry.capabilities_for(_resource("aws_db_instance")),
            frozenset({ResourceCapability.DATABASE}),
        )

    def test_accepts_capability_values_as_strings(self) -> None:
        registry = ProviderResourceCapabilityRegistry([("aws", {"workload": frozenset({"aws_instance"})})])

        self.assertTrue(registry.has_capability(_resource("aws_instance"), "workload"))

    def test_rejects_duplicate_provider_registration(self) -> None:
        registry = ProviderResourceCapabilityRegistry([("aws", {})])

        with self.assertRaises(ProviderResourceCapabilityRegistryError):
            registry.register("AWS", {})

    def test_rejects_empty_provider_names(self) -> None:
        with self.assertRaises(ProviderResourceCapabilityRegistryError):
            ProviderResourceCapabilityRegistry([(" ", {})])

    def test_rejects_empty_resource_type_names(self) -> None:
        with self.assertRaises(ProviderResourceCapabilityRegistryError):
            ProviderResourceCapabilityRegistry([("aws", {ResourceCapability.WORKLOAD: frozenset({" "})})])

    def test_rejects_non_mapping_capabilities(self) -> None:
        registry = ProviderResourceCapabilityRegistry()

        with self.assertRaises(ProviderResourceCapabilityRegistryError):
            registry.register("aws", object())

    def test_rejects_string_resource_type_collections(self) -> None:
        with self.assertRaises(ProviderResourceCapabilityRegistryError):
            ProviderResourceCapabilityRegistry([("aws", {ResourceCapability.WORKLOAD: "aws_instance"})])

    def test_rejects_unknown_capabilities(self) -> None:
        with self.assertRaises(ProviderResourceCapabilityRegistryError):
            ProviderResourceCapabilityRegistry([("aws", {"not-a-capability": frozenset({"aws_instance"})})])


if __name__ == "__main__":
    unittest.main()
