from __future__ import annotations

import unittest
from dataclasses import dataclass
from typing import Any

from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.resource_facts import (
    NeutralProviderResourceFacts,
    ProviderResourceFactsNotRegisteredError,
    ProviderResourceFactsRegistry,
    ProviderResourceFactsRegistryError,
)


def _resource(provider: str = "aws") -> NormalizedResource:
    return NormalizedResource(
        address="example.resource",
        provider=provider,
        resource_type="example_resource",
        name="resource",
        category=ResourceCategory.DATA,
    )


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
        return {"block_public_acls": True}

    @property
    def policy_document(self) -> dict[str, Any]:
        return {"Statement": []}

    @property
    def trust_statements(self) -> list[dict[str, Any]]:
        return [{"Effect": "Allow"}]

    @property
    def engine(self) -> str | None:
        return "postgres"

    @property
    def resource_policy_source_addresses(self) -> list[str]:
        return ["example.policy"]


class ProviderResourceFactsRegistryTests(unittest.TestCase):
    def test_registers_and_returns_factories_by_provider_name(self) -> None:
        def factory(resource: NormalizedResource) -> RecordingFacts:
            return RecordingFacts(resource)

        registry = ProviderResourceFactsRegistry([("AWS", factory)])

        self.assertIs(registry.get(" aws "), factory)
        self.assertEqual(registry.providers(), ("aws",))

    def test_facts_for_delegates_to_registered_provider_factory(self) -> None:
        calls: list[NormalizedResource] = []

        def factory(resource: NormalizedResource) -> RecordingFacts:
            calls.append(resource)
            return RecordingFacts(resource)

        resource = _resource("aws")
        facts = ProviderResourceFactsRegistry([("aws", factory)]).facts_for(resource)

        self.assertEqual(calls, [resource])
        self.assertIsInstance(facts, RecordingFacts)
        self.assertEqual(facts.bucket_name, "aws-bucket")

    def test_facts_for_returns_neutral_facts_for_unregistered_providers(self) -> None:
        resource = _resource("gcp")
        facts = ProviderResourceFactsRegistry().facts_for(resource)

        self.assertIsInstance(facts, NeutralProviderResourceFacts)
        self.assertIsNone(facts.bucket_name)
        self.assertEqual(facts.bucket_acl, "")
        self.assertIsNone(facts.public_access_block)
        self.assertEqual(facts.policy_document, {})
        self.assertEqual(facts.trust_statements, [])
        self.assertIsNone(facts.engine)
        self.assertEqual(facts.resource_policy_source_addresses, [])

    def test_rejects_duplicate_provider_registration(self) -> None:
        def factory(resource: NormalizedResource) -> RecordingFacts:
            return RecordingFacts(resource)

        registry = ProviderResourceFactsRegistry([("aws", factory)])

        with self.assertRaises(ProviderResourceFactsRegistryError):
            registry.register("AWS", factory)

    def test_rejects_empty_provider_names(self) -> None:
        def factory(resource: NormalizedResource) -> RecordingFacts:
            return RecordingFacts(resource)

        with self.assertRaises(ProviderResourceFactsRegistryError):
            ProviderResourceFactsRegistry([(" ", factory)])

    def test_rejects_non_callable_factories(self) -> None:
        registry = ProviderResourceFactsRegistry()

        with self.assertRaises(ProviderResourceFactsRegistryError):
            registry.register("aws", object())

    def test_missing_provider_lookup_raises_specific_error(self) -> None:
        registry = ProviderResourceFactsRegistry()

        with self.assertRaises(ProviderResourceFactsNotRegisteredError):
            registry.get("aws")


if __name__ == "__main__":
    unittest.main()