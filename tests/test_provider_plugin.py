from __future__ import annotations

import unittest
from dataclasses import dataclass
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory, ResourceInventory, TerraformResource
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.plugin import (
    ProviderPlugin,
    ProviderPluginError,
    provider_limitations_from_plugins,
    provider_registry_from_plugins,
    resource_capability_registry_from_plugins,
    resource_facts_registry_from_plugins,
)
from tfstride.providers.resource_capabilities import ResourceCapability
from tfstride.providers.resource_facts import ProviderResourceFactDomains


class FakeMetadata:
    pass


class RecordingNormalizer(ProviderNormalizer):
    def __init__(self, provider: str = "aws") -> None:
        self.provider = provider
        self.calls: list[list[TerraformResource]] = []

    def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
        self.calls.append(resources)
        return ResourceInventory(provider=self.provider.strip().lower(), resources=[])


@dataclass(frozen=True, slots=True)
class RecordingFacts:
    resource: NormalizedResource

    @property
    def bucket_name(self) -> str | None:
        return f"{self.resource.provider}-bucket"

    @property
    def bucket_acl(self) -> str:
        return "private"

    @property
    def public_access_block(self) -> dict[str, bool] | None:
        return None

    @property
    def policy_document(self) -> dict[str, Any]:
        return {}

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        return []

    @property
    def engine(self) -> str | None:
        return None

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return []


class RecordingDecorator:
    def __init__(self) -> None:
        self.calls: list[list[NormalizedResource]] = []

    def decorate(self, resources: list[NormalizedResource]) -> None:
        self.calls.append(resources)


def _facts(resource: NormalizedResource) -> ProviderResourceFactDomains:
    facts = RecordingFacts(resource)
    return ProviderResourceFactDomains(
        storage=facts,
        iam=facts,
        sql=facts,
        gke=facts,
        compute=facts,
        workload=facts,
    )


def _resource(provider: str = "aws") -> NormalizedResource:
    return NormalizedResource(
        address="example.resource",
        provider=provider,
        resource_type="example_resource",
        name="resource",
        category=ResourceCategory.DATA,
    )


def _plugin(
    *,
    provider: str = " AWS ",
    normalizer_provider: str = "aws",
    limitations: tuple[str, ...] = (" limitation ",),
) -> ProviderPlugin:
    return ProviderPlugin(
        provider=provider,
        normalizer_factory=lambda: RecordingNormalizer(normalizer_provider),
        resource_facts_factory=_facts,
        metadata_namespace=FakeMetadata,
        supported_resource_types=frozenset({" example_resource "}),
        resource_capabilities={
            ResourceCapability.WORKLOAD: frozenset({" example_resource "}),
        },
        limitations=limitations,
        resource_decorator_factory=RecordingDecorator,
    )


class ProviderPluginTests(unittest.TestCase):
    def test_plugin_normalizes_provider_and_resource_types(self) -> None:
        plugin = _plugin()

        self.assertEqual(plugin.provider, "aws")
        self.assertEqual(plugin.supported_resource_types, frozenset({"example_resource"}))
        self.assertEqual(
            plugin.resource_types_for_capability(ResourceCapability.WORKLOAD),
            frozenset({"example_resource"}),
        )
        self.assertIs(plugin.metadata_namespace, FakeMetadata)
        self.assertEqual(plugin.limitations, ("limitation",))
        self.assertIs(plugin.facts_registry_entry()[1], _facts)

    def test_plugin_creates_normalizer_and_resource_decorator(self) -> None:
        plugin = _plugin()

        normalizer = plugin.create_normalizer()
        decorator = plugin.create_resource_decorator()

        self.assertIsInstance(normalizer, RecordingNormalizer)
        self.assertIsInstance(decorator, RecordingDecorator)

    def test_plugin_classifies_supported_resource_types(self) -> None:
        plugin = _plugin()

        self.assertTrue(plugin.supports_resource_type(" example_resource "))
        self.assertFalse(plugin.supports_resource_type("unsupported_resource"))

    def test_plugin_helpers_build_runtime_registries(self) -> None:
        plugin = _plugin()
        resource = _resource("aws")

        provider_registry = provider_registry_from_plugins([plugin])
        facts_registry = resource_facts_registry_from_plugins([plugin])
        limitation_registry = provider_limitations_from_plugins([plugin])

        self.assertEqual(provider_registry.providers(), ("aws",))
        self.assertEqual(facts_registry.providers(), ("aws",))
        self.assertEqual(limitation_registry, {"aws": ("limitation",)})
        self.assertIsInstance(provider_registry.get("aws"), RecordingNormalizer)
        self.assertEqual(facts_registry.facts_for(resource).storage.bucket_name, "aws-bucket")

    def test_plugin_helper_builds_resource_capability_registry(self) -> None:
        plugin = _plugin()
        registry = resource_capability_registry_from_plugins([plugin])

        self.assertEqual(registry.providers(), ("aws",))
        self.assertTrue(
            registry.has_capability(_resource("aws"), ResourceCapability.WORKLOAD)
        )

    def test_plugin_rejects_normalizer_provider_mismatch(self) -> None:
        plugin = _plugin(provider="aws", normalizer_provider="gcp")

        with self.assertRaises(ProviderPluginError):
            plugin.create_normalizer()

    def test_plugin_rejects_empty_provider_name(self) -> None:
        with self.assertRaises(ProviderPluginError):
            _plugin(provider=" ")

    def test_plugin_rejects_non_callable_normalizer_factory(self) -> None:
        with self.assertRaises(ProviderPluginError):
            ProviderPlugin(
                provider="aws",
                normalizer_factory=None,
                resource_facts_factory=_facts,
                metadata_namespace=FakeMetadata,
                supported_resource_types=frozenset(),
            )

    def test_plugin_rejects_non_callable_facts_factory(self) -> None:
        with self.assertRaises(ProviderPluginError):
            ProviderPlugin(
                provider="aws",
                normalizer_factory=lambda: RecordingNormalizer(),
                resource_facts_factory=None,
                metadata_namespace=FakeMetadata,
                supported_resource_types=frozenset(),
            )

    def test_plugin_rejects_non_type_metadata_namespace(self) -> None:
        with self.assertRaises(ProviderPluginError):
            ProviderPlugin(
                provider="aws",
                normalizer_factory=lambda: RecordingNormalizer(),
                resource_facts_factory=_facts,
                metadata_namespace=object(),
                supported_resource_types=frozenset(),
            )

    def test_plugin_rejects_empty_supported_resource_type_names(self) -> None:
        with self.assertRaises(ProviderPluginError):
            ProviderPlugin(
                provider="aws",
                normalizer_factory=lambda: RecordingNormalizer(),
                resource_facts_factory=_facts,
                metadata_namespace=FakeMetadata,
                supported_resource_types=frozenset({" "}),
            )

    def test_plugin_rejects_empty_capability_resource_type_names(self) -> None:
        with self.assertRaises(ProviderPluginError):
            ProviderPlugin(
                provider="aws",
                normalizer_factory=lambda: RecordingNormalizer(),
                resource_facts_factory=_facts,
                metadata_namespace=FakeMetadata,
                supported_resource_types=frozenset(),
                resource_capabilities={ResourceCapability.WORKLOAD: frozenset({" "})},
            )

    def test_plugin_rejects_empty_limitations(self) -> None:
        with self.assertRaises(ProviderPluginError):
            _plugin(limitations=(" ",))


if __name__ == "__main__":
    unittest.main()