from __future__ import annotations

import unittest
from pathlib import Path

from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.rule_registry import DEFAULT_RULE_REGISTRY
from tfstride.app import TfStride
from tfstride.models import NormalizedResource, ResourceCategory
from tfstride.providers.aws.boundaries import AwsBoundaryContributor
from tfstride.providers.aws.limitations import AWS_LIMITATIONS
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES, AwsNormalizer
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.aws.resource_facts import AwsIamFacts, AwsSqlFacts, AwsStorageFacts
from tfstride.providers.aws.rule_catalog import AWS_RULE_METADATA
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.catalog import (
    DEFAULT_PROVIDER,
    default_provider_boundary_contributor_factories_by_provider,
    default_provider_boundary_contributors,
    default_provider_boundary_contributors_by_provider,
    default_provider_limitations,
    default_provider_plugins,
    default_provider_registry,
    default_provider_rule_metadata,
    default_resource_capability_registry,
    default_resource_facts_registry,
    default_rule_contribution,
)
from tfstride.providers.gcp.boundaries import GcpBoundaryContributor
from tfstride.providers.gcp.limitations import GCP_LIMITATIONS
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import SUPPORTED_GCP_TYPES, GcpNormalizer
from tfstride.providers.gcp.resource_capabilities import GCP_RESOURCE_CAPABILITIES
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator
from tfstride.providers.gcp.resource_facts import GcpResourceFacts
from tfstride.providers.gcp.rule_catalog import GCP_RULE_METADATA
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS
from tfstride.providers.resource_capabilities import ResourceCapability

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"
FIXTURE_PATH = FIXTURES_DIR / "aws" / "sample_aws_plan.json"


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
        self.assertEqual(aws_plugin.create_rule_metadata(), AWS_RULE_METADATA)
        self.assertEqual(
            tuple(
                tuple(rule.metadata.rule_id for rule in rule_group)
                for rule_group in aws_plugin.create_rule_contribution(FindingFactory(DEFAULT_RULE_REGISTRY)).rule_groups
            ),
            AWS_RULE_GROUP_IDS,
        )
        self.assertIs(gcp_plugin.metadata_namespace, GcpResourceMetadata)
        self.assertEqual(gcp_plugin.supported_resource_types, SUPPORTED_GCP_TYPES)
        self.assertEqual(dict(gcp_plugin.resource_capabilities), dict(GCP_RESOURCE_CAPABILITIES))
        self.assertEqual(gcp_plugin.limitations, GCP_LIMITATIONS)
        self.assertIsInstance(gcp_plugin.create_normalizer(), GcpNormalizer)
        self.assertIsInstance(gcp_plugin.create_resource_decorator(), GcpResourceDecorator)
        self.assertEqual(gcp_plugin.create_rule_metadata(), GCP_RULE_METADATA)
        self.assertIsInstance(aws_plugin.create_boundary_contributor(), AwsBoundaryContributor)
        self.assertIsInstance(gcp_plugin.create_boundary_contributor(), GcpBoundaryContributor)
        self.assertEqual(
            tuple(
                tuple(rule.metadata.rule_id for rule in rule_group)
                for rule_group in gcp_plugin.create_rule_contribution(FindingFactory(DEFAULT_RULE_REGISTRY)).rule_groups
            ),
            GCP_RULE_GROUP_IDS,
        )

    def test_default_provider_rule_metadata_merges_builtin_provider_catalogs(self) -> None:
        self.assertEqual(default_provider_rule_metadata(), AWS_RULE_METADATA + GCP_RULE_METADATA)

    def test_default_boundary_contributors_register_builtin_provider_contributors(self) -> None:
        contributors = default_provider_boundary_contributors()
        contributors_by_provider = default_provider_boundary_contributors_by_provider()
        factories_by_provider = default_provider_boundary_contributor_factories_by_provider()

        self.assertIsInstance(contributors[0], AwsBoundaryContributor)
        self.assertIsInstance(contributors[1], GcpBoundaryContributor)
        self.assertIsInstance(default_provider_boundary_contributors("aws")[0], AwsBoundaryContributor)
        self.assertIsInstance(default_provider_boundary_contributors("gcp")[0], GcpBoundaryContributor)
        self.assertEqual(default_provider_boundary_contributors("azure"), ())
        self.assertIsInstance(contributors_by_provider["aws"][0], AwsBoundaryContributor)
        self.assertIsInstance(contributors_by_provider["gcp"][0], GcpBoundaryContributor)
        self.assertIsInstance(factories_by_provider["aws"][0](), AwsBoundaryContributor)
        self.assertIsInstance(factories_by_provider["gcp"][0](), GcpBoundaryContributor)

    def test_default_rule_contribution_merges_builtin_provider_rules(self) -> None:
        contribution = default_rule_contribution(FindingFactory(DEFAULT_RULE_REGISTRY))
        rule_ids_by_group = tuple(tuple(rule.metadata.rule_id for rule in group) for group in contribution.rule_groups)

        self.assertEqual(tuple(len(rule_group) for rule_group in rule_ids_by_group), (27, 2, 2, 12, 3, 2))
        self.assertEqual(
            {rule_id for rule_group in rule_ids_by_group for rule_id in rule_group},
            DEFAULT_RULE_REGISTRY.known_rule_ids(),
        )

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

        aws_facts = registry.facts_for(aws_resource)

        self.assertEqual(registry.providers(), ("aws", "gcp"))
        self.assertIsInstance(aws_facts.storage, AwsStorageFacts)
        self.assertIsInstance(aws_facts.iam, AwsIamFacts)
        self.assertIsInstance(aws_facts.sql, AwsSqlFacts)
        self.assertIsInstance(registry.facts_for(gcp_resource).storage, GcpResourceFacts)

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
        gcp_bucket = NormalizedResource(
            address="google_storage_bucket.logs",
            provider="gcp",
            resource_type="google_storage_bucket",
            name="logs",
            category=ResourceCategory.DATA,
        )

        self.assertEqual(registry.providers(), ("aws", "gcp"))
        self.assertTrue(registry.has_capability(aws_resource, ResourceCapability.WORKLOAD))
        self.assertTrue(registry.has_capability(gcp_resource, ResourceCapability.WORKLOAD))
        self.assertTrue(registry.has_capability(gcp_resource, ResourceCapability.PUBLIC_COMPUTE))
        self.assertTrue(registry.has_capability(gcp_bucket, ResourceCapability.OBJECT_STORAGE))

    def test_app_uses_catalog_default_provider(self) -> None:
        result = TfStride().analyze_plan(FIXTURE_PATH)

        self.assertEqual(result.inventory.provider, DEFAULT_PROVIDER)
        self.assertGreater(len(result.inventory.resources), 0)


if __name__ == "__main__":
    unittest.main()
