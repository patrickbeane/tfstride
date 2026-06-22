from __future__ import annotations

import unittest
from dataclasses import dataclass
from typing import Any

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.rule_definitions import RuleContribution, RuleDefinition, RuleEvaluationContext
from tfstride.analysis.rule_registry import RuleMetadata, RuleRegistry
from tfstride.models import (
    Finding,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
    StrideCategory,
    TerraformResource,
)
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.plugin import (
    ProviderPlugin,
    ProviderPluginError,
    analysis_index_factories_by_provider_from_plugins,
    boundary_contributors_by_provider_from_plugins,
    boundary_contributors_from_plugins,
    provider_limitations_from_plugins,
    provider_registry_from_plugins,
    resource_capability_registry_from_plugins,
    resource_facts_registry_from_plugins,
    rule_contribution_from_plugins,
    rule_metadata_from_plugins,
)
from tfstride.providers.resource_capabilities import ResourceCapability
from tfstride.providers.resource_facts import ProviderResourceFactDomains


class FakeMetadata:
    pass


RULE_METADATA = RuleMetadata(
    rule_id="test-provider-rule",
    title="Test provider rule",
    category=StrideCategory.SPOOFING,
    recommended_mitigation="Fix the provider test issue.",
)


def _detector(context: RuleEvaluationContext, rule_id: str) -> list[Finding]:
    return []


def _rule_metadata() -> tuple[RuleMetadata, ...]:
    return (RULE_METADATA,)


def _rule_contribution(finding_factory: FindingFactory) -> RuleContribution:
    return RuleContribution(((RuleDefinition(RULE_METADATA, _detector),),))


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


@dataclass(frozen=True, slots=True)
class RecordingAnalysisIndexes:
    provider: str


def _analysis_indexes(inventory: ResourceInventory) -> RecordingAnalysisIndexes:
    return RecordingAnalysisIndexes(inventory.provider)


class RecordingBoundaryContributor:
    def contribute(self, context) -> None:
        return None


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
    rule_metadata_factory=_rule_metadata,
    rule_contribution_factory=_rule_contribution,
    boundary_contributor_factory=RecordingBoundaryContributor,
    analysis_index_factory=_analysis_indexes,
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
        rule_metadata_factory=rule_metadata_factory,
        rule_contribution_factory=rule_contribution_factory,
        boundary_contributor_factory=boundary_contributor_factory,
        analysis_index_factory=analysis_index_factory,
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
        self.assertIs(plugin.rule_metadata_factory, _rule_metadata)
        self.assertIs(plugin.rule_contribution_factory, _rule_contribution)
        self.assertIs(plugin.boundary_contributor_factory, RecordingBoundaryContributor)
        self.assertIs(plugin.analysis_index_factory, _analysis_indexes)

    def test_plugin_creates_normalizer_and_resource_decorator(self) -> None:
        plugin = _plugin()

        normalizer = plugin.create_normalizer()
        decorator = plugin.create_resource_decorator()

        self.assertIsInstance(normalizer, RecordingNormalizer)
        self.assertIsInstance(decorator, RecordingDecorator)

    def test_plugin_creates_boundary_contributor_when_factory_is_configured(self) -> None:
        plugin = _plugin()

        self.assertIsInstance(plugin.create_boundary_contributor(), RecordingBoundaryContributor)

    def test_plugin_creates_analysis_index_extension_when_factory_is_configured(self) -> None:
        plugin = _plugin()
        inventory = ResourceInventory(provider="aws", resources=[])

        self.assertEqual(
            plugin.create_analysis_index_extension(inventory),
            RecordingAnalysisIndexes("aws"),
        )

    def test_plugin_creates_rule_metadata_when_factory_is_configured(self) -> None:
        plugin = _plugin()

        self.assertEqual(plugin.create_rule_metadata(), (RULE_METADATA,))

    def test_plugin_creates_rule_contribution_when_factory_is_configured(self) -> None:
        plugin = _plugin()

        contribution = plugin.create_rule_contribution(FindingFactory(RuleRegistry([RULE_METADATA])))

        self.assertIsNotNone(contribution)
        self.assertEqual(contribution.rule_groups[0][0].metadata.rule_id, "test-provider-rule")

    def test_plugin_allows_missing_rule_metadata_factory(self) -> None:
        plugin = _plugin(rule_metadata_factory=None)

        self.assertEqual(plugin.create_rule_metadata(), ())

    def test_plugin_allows_missing_rule_contribution_factory(self) -> None:
        plugin = _plugin(rule_contribution_factory=None)

        self.assertIsNone(plugin.create_rule_contribution(FindingFactory(RuleRegistry([RULE_METADATA]))))

    def test_plugin_allows_missing_boundary_contributor_factory(self) -> None:
        plugin = _plugin(boundary_contributor_factory=None)

        self.assertIsNone(plugin.create_boundary_contributor())

    def test_plugin_allows_missing_analysis_index_factory(self) -> None:
        plugin = _plugin(analysis_index_factory=None)

        self.assertIsNone(plugin.create_analysis_index_extension(ResourceInventory(provider="aws", resources=[])))

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
        boundary_contributors = boundary_contributors_from_plugins([plugin])
        boundary_contributors_by_provider = boundary_contributors_by_provider_from_plugins([plugin])
        analysis_index_factories = analysis_index_factories_by_provider_from_plugins([plugin])
        rule_contribution = rule_contribution_from_plugins(
            [plugin],
            FindingFactory(RuleRegistry([RULE_METADATA])),
        )
        rule_metadata = rule_metadata_from_plugins([plugin])

        self.assertEqual(provider_registry.providers(), ("aws",))
        self.assertEqual(facts_registry.providers(), ("aws",))
        self.assertEqual(limitation_registry, {"aws": ("limitation",)})
        self.assertIsInstance(boundary_contributors[0], RecordingBoundaryContributor)
        self.assertIsInstance(boundary_contributors_by_provider["aws"][0], RecordingBoundaryContributor)
        self.assertEqual(
            analysis_index_factories["aws"](ResourceInventory(provider="aws", resources=[])),
            RecordingAnalysisIndexes("aws"),
        )
        self.assertEqual(rule_contribution.rule_groups[0][0].metadata.rule_id, "test-provider-rule")
        self.assertEqual(rule_metadata, (RULE_METADATA,))
        self.assertIsInstance(provider_registry.get("aws"), RecordingNormalizer)
        self.assertEqual(facts_registry.facts_for(resource).storage.bucket_name, "aws-bucket")

    def test_boundary_contributor_helper_can_filter_by_provider(self) -> None:
        aws_plugin = _plugin(provider="aws")
        gcp_plugin = _plugin(provider="gcp")

        contributors = boundary_contributors_from_plugins([aws_plugin, gcp_plugin], provider=" GCP ")

        self.assertEqual(len(contributors), 1)
        self.assertIsInstance(contributors[0], RecordingBoundaryContributor)

    def test_plugin_helper_builds_resource_capability_registry(self) -> None:
        plugin = _plugin()
        registry = resource_capability_registry_from_plugins([plugin])

        self.assertEqual(registry.providers(), ("aws",))
        self.assertTrue(registry.has_capability(_resource("aws"), ResourceCapability.WORKLOAD))

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

    def test_plugin_rejects_non_callable_rule_metadata_factory(self) -> None:
        with self.assertRaises(ProviderPluginError):
            ProviderPlugin(
                provider="aws",
                normalizer_factory=lambda: RecordingNormalizer(),
                resource_facts_factory=_facts,
                metadata_namespace=FakeMetadata,
                supported_resource_types=frozenset(),
                rule_metadata_factory=object(),
            )

    def test_plugin_rejects_non_callable_rule_contribution_factory(self) -> None:
        with self.assertRaises(ProviderPluginError):
            ProviderPlugin(
                provider="aws",
                normalizer_factory=lambda: RecordingNormalizer(),
                resource_facts_factory=_facts,
                metadata_namespace=FakeMetadata,
                supported_resource_types=frozenset(),
                rule_contribution_factory=object(),
            )

    def test_plugin_rejects_non_callable_boundary_contributor_factory(self) -> None:
        with self.assertRaises(ProviderPluginError):
            ProviderPlugin(
                provider="aws",
                normalizer_factory=lambda: RecordingNormalizer(),
                resource_facts_factory=_facts,
                metadata_namespace=FakeMetadata,
                supported_resource_types=frozenset(),
                boundary_contributor_factory=object(),
            )

    def test_plugin_rejects_non_callable_analysis_index_factory(self) -> None:
        with self.assertRaises(ProviderPluginError):
            ProviderPlugin(
                provider="aws",
                normalizer_factory=lambda: RecordingNormalizer(),
                resource_facts_factory=_facts,
                metadata_namespace=FakeMetadata,
                supported_resource_types=frozenset(),
                analysis_index_factory=object(),
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
