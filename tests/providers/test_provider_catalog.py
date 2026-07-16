from __future__ import annotations

import unittest

from tests.helpers.paths import FIXTURES_DIR
from tfstride.analysis.finding_factory import FindingFactory
from tfstride.analysis.rule_registry import default_rule_registry
from tfstride.app import TfStride
from tfstride.models import NormalizedResource, ResourceCategory, ResourceInventory
from tfstride.providers.aws.boundaries import AwsBoundaryContributor
from tfstride.providers.aws.limitations import AWS_LIMITATIONS
from tfstride.providers.aws.metadata import AwsResourceMetadata
from tfstride.providers.aws.normalizer import SUPPORTED_AWS_TYPES, AwsNormalizer
from tfstride.providers.aws.resource_decorator import AwsResourceDecorator
from tfstride.providers.aws.rule_catalog import AWS_RULE_METADATA
from tfstride.providers.aws.rules import AWS_RULE_GROUP_IDS
from tfstride.providers.azure.boundaries import AzureBoundaryContributor
from tfstride.providers.azure.limitations import AZURE_LIMITATIONS
from tfstride.providers.azure.metadata import AzureResourceMetadata
from tfstride.providers.azure.normalizer import SUPPORTED_AZURE_TYPES, AzureNormalizer
from tfstride.providers.azure.observations import observe_azure_posture
from tfstride.providers.azure.resource_capabilities import AZURE_RESOURCE_CAPABILITIES
from tfstride.providers.azure.resource_decorator import AzureResourceDecorator
from tfstride.providers.azure.rule_catalog import AZURE_RULE_METADATA
from tfstride.providers.azure.rules import AZURE_RULE_GROUP_IDS
from tfstride.providers.catalog import (
    DEFAULT_PROVIDER,
    default_provider_analysis_index_factories_by_provider,
    default_provider_analysis_index_factory,
    default_provider_boundary_contributor_factories_by_provider,
    default_provider_boundary_contributors,
    default_provider_boundary_contributors_by_provider,
    default_provider_limitations,
    default_provider_observation_factories_by_provider,
    default_provider_plugins,
    default_provider_registry,
    default_provider_rule_metadata,
    default_resource_capability_registry,
    default_rule_contribution,
)
from tfstride.providers.gcp.analysis_indexes import GcpAnalysisIndexes
from tfstride.providers.gcp.boundaries import GcpBoundaryContributor
from tfstride.providers.gcp.limitations import GCP_LIMITATIONS
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import SUPPORTED_GCP_TYPES, GcpNormalizer
from tfstride.providers.gcp.resource_capabilities import GCP_RESOURCE_CAPABILITIES
from tfstride.providers.gcp.resource_decorator import GcpResourceDecorator
from tfstride.providers.gcp.rule_catalog import GCP_RULE_METADATA
from tfstride.providers.gcp.rules import GCP_RULE_GROUP_IDS
from tfstride.providers.resource_capabilities import ResourceCapability

FIXTURE_PATH = FIXTURES_DIR / "aws" / "sample_aws_plan.json"


class ProviderCatalogTests(unittest.TestCase):
    def test_default_registry_registers_builtin_providers(self) -> None:
        registry = default_provider_registry()

        self.assertEqual(DEFAULT_PROVIDER, "aws")
        self.assertEqual(registry.providers(), ("aws", "gcp", "azure"))
        self.assertIsInstance(registry.get(DEFAULT_PROVIDER), AwsNormalizer)
        self.assertIsInstance(registry.get("gcp"), GcpNormalizer)
        self.assertIsInstance(registry.get("azure"), AzureNormalizer)

    def test_default_provider_plugins_are_cached(self) -> None:
        first = default_provider_plugins()
        second = default_provider_plugins()

        self.assertIs(first, second)
        self.assertEqual(tuple(plugin.provider for plugin in first), ("aws", "gcp", "azure"))
        for first_plugin, second_plugin in zip(first, second, strict=True):
            self.assertIs(first_plugin, second_plugin)

    def test_cached_plugins_build_fresh_runtime_registries(self) -> None:
        first_provider_registry = default_provider_registry()
        second_provider_registry = default_provider_registry()
        first_capability_registry = default_resource_capability_registry()
        second_capability_registry = default_resource_capability_registry()

        self.assertIsNot(first_provider_registry, second_provider_registry)
        self.assertIsNot(first_provider_registry.get("aws"), second_provider_registry.get("aws"))
        self.assertIsNot(first_provider_registry.get("gcp"), second_provider_registry.get("gcp"))
        self.assertIsNot(first_provider_registry.get("azure"), second_provider_registry.get("azure"))
        self.assertIsNot(first_capability_registry, second_capability_registry)
        self.assertEqual(first_capability_registry.providers(), second_capability_registry.providers())

    def test_default_provider_plugins_describe_builtin_provider_contracts(self) -> None:
        registry = default_rule_registry()
        plugins = {plugin.provider: plugin for plugin in default_provider_plugins()}
        aws_plugin = plugins["aws"]
        gcp_plugin = plugins["gcp"]
        azure_plugin = plugins["azure"]

        self.assertEqual(tuple(plugins), ("aws", "gcp", "azure"))
        self.assertIs(aws_plugin.metadata_namespace, AwsResourceMetadata)
        self.assertEqual(aws_plugin.supported_resource_types, frozenset(SUPPORTED_AWS_TYPES))
        self.assertEqual(aws_plugin.limitations, AWS_LIMITATIONS)
        self.assertIsInstance(aws_plugin.create_normalizer(), AwsNormalizer)
        self.assertIsInstance(aws_plugin.create_resource_decorator(), AwsResourceDecorator)
        self.assertEqual(aws_plugin.create_rule_metadata(), AWS_RULE_METADATA)
        self.assertEqual(
            tuple(
                tuple(rule.metadata.rule_id for rule in rule_group)
                for rule_group in aws_plugin.create_rule_contribution(FindingFactory(registry)).rule_groups
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
        self.assertIsNone(aws_plugin.create_analysis_index_extension(ResourceInventory(provider="aws", resources=[])))
        self.assertIsInstance(gcp_plugin.create_boundary_contributor(), GcpBoundaryContributor)
        self.assertIsInstance(
            gcp_plugin.create_analysis_index_extension(ResourceInventory(provider="gcp", resources=[])),
            GcpAnalysisIndexes,
        )
        self.assertEqual(
            tuple(
                tuple(rule.metadata.rule_id for rule in rule_group)
                for rule_group in gcp_plugin.create_rule_contribution(FindingFactory(registry)).rule_groups
            ),
            GCP_RULE_GROUP_IDS,
        )
        self.assertIs(azure_plugin.metadata_namespace, AzureResourceMetadata)
        self.assertEqual(azure_plugin.supported_resource_types, SUPPORTED_AZURE_TYPES)
        self.assertEqual(dict(azure_plugin.resource_capabilities), dict(AZURE_RESOURCE_CAPABILITIES))
        self.assertEqual(azure_plugin.limitations, AZURE_LIMITATIONS)
        self.assertIsInstance(azure_plugin.create_normalizer(), AzureNormalizer)
        self.assertIsInstance(azure_plugin.create_resource_decorator(), AzureResourceDecorator)
        self.assertEqual(azure_plugin.create_rule_metadata(), AZURE_RULE_METADATA)
        self.assertEqual(
            tuple(
                tuple(rule.metadata.rule_id for rule in rule_group)
                for rule_group in azure_plugin.create_rule_contribution(FindingFactory(registry)).rule_groups
            ),
            AZURE_RULE_GROUP_IDS,
        )
        self.assertIsInstance(azure_plugin.create_boundary_contributor(), AzureBoundaryContributor)
        self.assertIs(azure_plugin.observation_factory, observe_azure_posture)
        self.assertIsNone(
            azure_plugin.create_analysis_index_extension(ResourceInventory(provider="azure", resources=[]))
        )

    def test_default_provider_rule_metadata_merges_builtin_provider_catalogs(self) -> None:
        self.assertEqual(
            default_provider_rule_metadata(),
            AWS_RULE_METADATA + GCP_RULE_METADATA + AZURE_RULE_METADATA,
        )

    def test_default_analysis_index_factories_register_provider_extensions(self) -> None:
        factories = default_provider_analysis_index_factories_by_provider()

        self.assertEqual(tuple(factories), ("gcp",))
        self.assertIs(default_provider_analysis_index_factory(" GCP "), factories["gcp"])
        self.assertIsNone(default_provider_analysis_index_factory("aws"))
        self.assertIsNone(default_provider_analysis_index_factory("azure"))
        self.assertIsInstance(
            factories["gcp"](ResourceInventory(provider="gcp", resources=[])),
            GcpAnalysisIndexes,
        )

    def test_default_boundary_contributors_register_builtin_provider_contributors(self) -> None:
        contributors = default_provider_boundary_contributors()
        contributors_by_provider = default_provider_boundary_contributors_by_provider()
        factories_by_provider = default_provider_boundary_contributor_factories_by_provider()

        self.assertIsInstance(contributors[0], AwsBoundaryContributor)
        self.assertIsInstance(contributors[1], GcpBoundaryContributor)
        self.assertIsInstance(contributors[2], AzureBoundaryContributor)
        self.assertIsInstance(default_provider_boundary_contributors("aws")[0], AwsBoundaryContributor)
        self.assertIsInstance(default_provider_boundary_contributors("gcp")[0], GcpBoundaryContributor)
        self.assertIsInstance(default_provider_boundary_contributors("azure")[0], AzureBoundaryContributor)
        self.assertIsInstance(contributors_by_provider["aws"][0], AwsBoundaryContributor)
        self.assertIsInstance(contributors_by_provider["gcp"][0], GcpBoundaryContributor)
        self.assertIsInstance(contributors_by_provider["azure"][0], AzureBoundaryContributor)
        self.assertIsInstance(factories_by_provider["aws"][0](), AwsBoundaryContributor)
        self.assertIsInstance(factories_by_provider["gcp"][0](), GcpBoundaryContributor)
        self.assertIsInstance(factories_by_provider["azure"][0](), AzureBoundaryContributor)

    def test_default_observation_factories_register_only_contributing_providers(self) -> None:
        factories = default_provider_observation_factories_by_provider()

        self.assertEqual(tuple(factories), ("aws", "azure"))
        self.assertTrue(callable(factories["aws"][0]))
        self.assertIs(factories["azure"][0], observe_azure_posture)

    def test_default_rule_contribution_merges_builtin_provider_rules(self) -> None:
        registry = default_rule_registry()
        contribution = default_rule_contribution(FindingFactory(registry))
        rule_ids_by_group = tuple(tuple(rule.metadata.rule_id for rule in group) for group in contribution.rule_groups)

        self.assertEqual(tuple(len(rule_group) for rule_group in rule_ids_by_group), (212, 2, 2, 14, 3, 2))
        self.assertEqual(
            {rule_id for rule_group in rule_ids_by_group for rule_id in rule_group},
            registry.known_rule_ids(),
        )

    def test_default_provider_limitations_register_builtin_provider_caveats(self) -> None:
        limitations = default_provider_limitations()

        self.assertEqual(limitations["aws"], AWS_LIMITATIONS)
        self.assertEqual(limitations["gcp"], GCP_LIMITATIONS)
        self.assertEqual(limitations["azure"], AZURE_LIMITATIONS)

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
        azure_resource = NormalizedResource(
            address="azurerm_storage_account.logs",
            provider="azure",
            resource_type="azurerm_storage_account",
            name="logs",
            category=ResourceCategory.DATA,
        )
        azure_virtual_machine = NormalizedResource(
            address="azurerm_linux_virtual_machine.web",
            provider="azure",
            resource_type="azurerm_linux_virtual_machine",
            name="web",
            category=ResourceCategory.COMPUTE,
        )
        azure_network_security_group = NormalizedResource(
            address="azurerm_network_security_group.web",
            provider="azure",
            resource_type="azurerm_network_security_group",
            name="web",
            category=ResourceCategory.NETWORK,
        )
        azure_key_vault = NormalizedResource(
            address="azurerm_key_vault.application",
            provider="azure",
            resource_type="azurerm_key_vault",
            name="application",
            category=ResourceCategory.DATA,
        )
        azure_managed_identity = NormalizedResource(
            address="azurerm_user_assigned_identity.deploy",
            provider="azure",
            resource_type="azurerm_user_assigned_identity",
            name="deploy",
            category=ResourceCategory.IAM,
        )
        azure_web_app = NormalizedResource(
            address="azurerm_linux_web_app.app",
            provider="azure",
            resource_type="azurerm_linux_web_app",
            name="app",
            category=ResourceCategory.COMPUTE,
        )

        self.assertEqual(registry.providers(), ("aws", "gcp", "azure"))
        self.assertTrue(registry.has_capability(aws_resource, ResourceCapability.WORKLOAD))
        self.assertTrue(registry.has_capability(gcp_resource, ResourceCapability.WORKLOAD))
        self.assertTrue(registry.has_capability(gcp_resource, ResourceCapability.PUBLIC_COMPUTE))
        self.assertTrue(registry.has_capability(gcp_bucket, ResourceCapability.OBJECT_STORAGE))
        self.assertTrue(registry.has_capability(azure_resource, ResourceCapability.DATA_STORE))
        self.assertTrue(registry.has_capability(azure_resource, ResourceCapability.PUBLIC_EDGE))
        self.assertTrue(registry.has_capability(azure_resource, ResourceCapability.OBJECT_STORAGE))
        self.assertTrue(registry.has_capability(azure_virtual_machine, ResourceCapability.WORKLOAD))
        self.assertTrue(
            registry.has_capability(azure_virtual_machine, ResourceCapability.SECURITY_GROUP_BACKED_WORKLOAD)
        )
        self.assertTrue(registry.has_capability(azure_virtual_machine, ResourceCapability.PUBLIC_COMPUTE))
        self.assertTrue(registry.has_capability(azure_virtual_machine, ResourceCapability.PUBLIC_EDGE))
        self.assertTrue(registry.has_capability(azure_key_vault, ResourceCapability.DATA_STORE))
        self.assertTrue(registry.has_capability(azure_key_vault, ResourceCapability.PUBLIC_EDGE))
        self.assertTrue(registry.has_capability(azure_key_vault, ResourceCapability.SECRET_STORE))
        self.assertTrue(registry.has_capability(azure_key_vault, ResourceCapability.CONTROL_PLANE_SENSITIVE_DATA_STORE))
        self.assertTrue(registry.has_capability(azure_key_vault, ResourceCapability.KEY_MANAGEMENT))
        self.assertTrue(registry.has_capability(azure_key_vault, ResourceCapability.SENSITIVE_RESOURCE_POLICY))
        self.assertTrue(registry.has_capability(azure_managed_identity, ResourceCapability.IDENTITY_ROLE))
        self.assertTrue(registry.has_capability(azure_web_app, ResourceCapability.WORKLOAD))
        self.assertTrue(registry.has_capability(azure_web_app, ResourceCapability.PUBLIC_EDGE))
        self.assertTrue(
            registry.has_capability(azure_network_security_group, ResourceCapability.NETWORK_SECURITY_GROUP)
        )

    def test_app_uses_catalog_default_provider(self) -> None:
        result = TfStride().analyze_plan(FIXTURE_PATH)

        self.assertEqual(result.inventory.provider, DEFAULT_PROVIDER)
        self.assertGreater(len(result.inventory.resources), 0)


if __name__ == "__main__":
    unittest.main()
