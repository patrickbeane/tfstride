from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tests.integration.analysis_support import (
    AZURE_FIXTURE_PATH,
    AZURE_SAFE_FIXTURE_PATH,
    FIXTURE_PATH,
    GCP_FIXTURE_PATH,
    TFSIntegrationTestCase,
)
from tfstride.analysis.boundaries import detect_trust_boundaries
from tfstride.analysis.coverage import build_analysis_coverage
from tfstride.analysis.indexes import AnalysisIndexes, AnalysisIndexExtensionFactory, build_analysis_indexes
from tfstride.analysis.preparation import PreparedAnalysis, prepare_analysis
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.app import TfStride
from tfstride.models import (
    BoundaryType,
    Observation,
    ResourceInventory,
    TerraformResource,
)
from tfstride.providers.aws.analysis_indexes import AwsAnalysisIndexes
from tfstride.providers.base import ProviderNormalizer
from tfstride.providers.gcp.analysis_indexes import GcpAnalysisIndexes, build_gcp_analysis_indexes
from tfstride.providers.registry import ProviderNotRegisteredError, ProviderRegistry, ProviderSelectionError


class ProviderSelectionIntegrationTests(TFSIntegrationTestCase):
    def test_analysis_resolves_normalizer_through_provider_registry(self) -> None:
        class RecordingNormalizer(ProviderNormalizer):
            provider = "aws"

            def __init__(self) -> None:
                self.calls: list[list[TerraformResource]] = []

            def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
                self.calls.append(resources)
                return ResourceInventory(provider="aws", resources=[])

        normalizer = RecordingNormalizer()
        engine = TfStride(provider_registry=ProviderRegistry([normalizer]))

        result = engine.analyze_plan(FIXTURE_PATH)

        self.assertEqual(len(normalizer.calls), 1)
        self.assertGreater(len(normalizer.calls[0]), 0)
        self.assertEqual(result.inventory.provider, "aws")
        self.assertEqual(result.inventory.resources, ())
        self.assertEqual(result.findings, [])

    def test_analysis_builds_indexes_once_after_normalization_and_shares_them(self) -> None:
        for provider, fixture_path in (
            ("aws", FIXTURE_PATH),
            ("gcp", GCP_FIXTURE_PATH),
            ("azure", AZURE_FIXTURE_PATH),
        ):
            with self.subTest(provider=provider):
                self._assert_analysis_preparation_lifecycle(provider, fixture_path)

    def _assert_analysis_preparation_lifecycle(self, provider: str, fixture_path: Path) -> None:
        engine = TfStride()
        normalizer = engine.provider_registry.get(provider)
        normalize_resources = normalizer.normalize
        events: list[str] = []
        normalized_inventories: list[ResourceInventory] = []
        built_indexes: list[AnalysisIndexes] = []

        def record_normalization(resources: list[TerraformResource]) -> ResourceInventory:
            inventory = normalize_resources(resources)
            normalized_inventories.append(inventory)
            events.append("normalization_complete")
            return inventory

        def record_index_build(
            inventory: ResourceInventory,
            *,
            provider_extension_factory: AnalysisIndexExtensionFactory | None = None,
        ) -> AnalysisIndexes:
            self.assertEqual(events, ["normalization_complete"])
            self.assertIs(inventory, normalized_inventories[0])
            events.append("analysis_index_build")
            indexes = build_analysis_indexes(inventory, provider_extension_factory=provider_extension_factory)
            built_indexes.append(indexes)
            return indexes

        with (
            patch.object(normalizer, "normalize", side_effect=record_normalization) as normalize,
            patch(
                "tfstride.analysis.preparation.build_analysis_indexes", side_effect=record_index_build
            ) as build_indexes,
            # Count fallback builds in consumers as part of the same application run.
            patch("tfstride.analysis.boundaries.core.build_analysis_indexes", build_indexes),
            patch("tfstride.analysis.stride_rules.build_analysis_indexes", build_indexes),
            patch("tfstride.analysis.rule_definitions.build_analysis_indexes", build_indexes),
            patch(
                "tfstride.analysis.indexes._default_provider_extension_factory",
                side_effect=AssertionError("Application index factories must be selected explicitly."),
            ),
            patch(
                "tfstride.analysis.preparation.detect_trust_boundaries",
                wraps=detect_trust_boundaries,
            ) as detect_boundaries,
            patch.object(
                engine._rule_engine,
                "evaluate",
                wraps=engine._rule_engine.evaluate,
            ) as evaluate,
        ):
            result = engine.analyze_plan(fixture_path)

        normalize.assert_called_once()
        build_indexes.assert_called_once()
        detect_boundaries.assert_called_once()
        evaluate.assert_called_once()
        self.assertEqual(events, ["normalization_complete", "analysis_index_build"])
        self.assertEqual(result.inventory.provider, provider)
        self.assertIs(result.inventory, normalized_inventories[0])
        self.assertIs(detect_boundaries.call_args.args[0], result.inventory)
        self.assertIs(evaluate.call_args.args[0], result.inventory)
        self.assertIs(detect_boundaries.call_args.kwargs["indexes"], built_indexes[0])
        self.assertIs(evaluate.call_args.kwargs["analysis_indexes"], built_indexes[0])
        self.assertIs(evaluate.call_args.args[1], result.trust_boundaries)

    def test_repeated_analysis_prepares_fresh_state_across_providers(self) -> None:
        engine = TfStride()
        prepared_runs: list[PreparedAnalysis] = []
        cases = (
            ("aws", FIXTURE_PATH),
            ("gcp", GCP_FIXTURE_PATH),
            ("azure", AZURE_FIXTURE_PATH),
            ("aws", FIXTURE_PATH),
        )

        def record_preparation(*args, **kwargs) -> PreparedAnalysis:
            prepared = prepare_analysis(*args, **kwargs)
            prepared_runs.append(prepared)
            return prepared

        with (
            patch("tfstride.app.prepare_analysis", side_effect=record_preparation) as prepare,
            patch.object(engine._rule_engine, "evaluate", wraps=engine._rule_engine.evaluate) as evaluate,
        ):
            results = [engine.analyze_plan(fixture_path) for _, fixture_path in cases]

        self.assertEqual(prepare.call_count, len(cases))
        self.assertEqual(len({id(prepared) for prepared in prepared_runs}), len(cases))
        self.assertEqual(len({id(prepared.indexes) for prepared in prepared_runs}), len(cases))
        self.assertEqual(len({id(prepared.indexes.role_index) for prepared in prepared_runs}), len(cases))
        self.assertEqual(len({id(prepared.boundaries) for prepared in prepared_runs}), len(cases))
        for (provider, _), prepared, result, evaluation in zip(
            cases, prepared_runs, results, evaluate.call_args_list, strict=True
        ):
            with self.subTest(provider=provider):
                self.assertEqual(prepared.inventory.provider, provider)
                self.assertEqual(prepared.rule_set.provider, provider)
                self.assertIs(prepared.inventory, result.inventory)
                self.assertIs(prepared.boundaries, result.trust_boundaries)
                self.assertIs(evaluation.kwargs["analysis_indexes"], prepared.indexes)
                self.assertIs(evaluation.kwargs["rule_set"], prepared.rule_set)
                self.assertTrue(
                    all(
                        resource.provider == provider
                        for candidates in prepared.indexes.role_index.resources_by_reference.values()
                        for resource in candidates
                    )
                )
                self.assertTrue(
                    all(rule_id.startswith(f"{provider}-") for rule_id in result.analysis_coverage.rules.enabled_rules)
                )

        self.assertIsInstance(prepared_runs[0].indexes.provider_extension, AwsAnalysisIndexes)
        self.assertIsInstance(prepared_runs[1].indexes.provider_extension, GcpAnalysisIndexes)
        self.assertIsNone(prepared_runs[2].indexes.provider_extension)
        self.assertIsInstance(prepared_runs[3].indexes.provider_extension, AwsAnalysisIndexes)
        self.assertIsNot(prepared_runs[0].indexes.provider_extension, prepared_runs[3].indexes.provider_extension)
        self.assertIs(prepared_runs[0].rule_set, prepared_runs[3].rule_set)
        self.assertEqual(results[0].findings, results[3].findings)
        self.assertEqual(results[0].trust_boundaries, results[3].trust_boundaries)
        self.assertEqual(results[0].analysis_coverage, results[3].analysis_coverage)

    def test_analysis_selects_index_factory_for_normalized_provider(self) -> None:
        extensions: list[GcpAnalysisIndexes] = []

        def build_custom_indexes(inventory: ResourceInventory) -> GcpAnalysisIndexes:
            extension = build_gcp_analysis_indexes(inventory)
            extensions.append(extension)
            return extension

        unused_factory = Mock(side_effect=AssertionError("Factory selected for the wrong provider."))
        for requested_provider, fixture_path in (
            (None, GCP_FIXTURE_PATH),
            (" GCP ", FIXTURE_PATH),
        ):
            with self.subTest(requested_provider=requested_provider):
                index_factory = Mock(side_effect=build_custom_indexes)
                engine = TfStride(
                    provider=requested_provider,
                    provider_analysis_index_factories={
                        " AWS ": unused_factory,
                        " GCP ": index_factory,
                    },
                )

                with (
                    patch(
                        "tfstride.analysis.indexes._default_provider_extension_factory",
                        side_effect=AssertionError("Configured factories must not fall back to the catalog."),
                    ),
                    patch(
                        "tfstride.analysis.preparation.detect_trust_boundaries",
                        wraps=detect_trust_boundaries,
                    ) as detect_boundaries,
                    patch.object(
                        engine._rule_engine,
                        "evaluate",
                        wraps=engine._rule_engine.evaluate,
                    ) as evaluate,
                ):
                    result = engine.analyze_plan(fixture_path)

                self.assertEqual(result.inventory.provider, "gcp")
                index_factory.assert_called_once()
                self.assertIs(index_factory.call_args.args[0], result.inventory)
                unused_factory.assert_not_called()
                boundary_indexes = detect_boundaries.call_args.kwargs["indexes"]
                rule_indexes = evaluate.call_args.kwargs["analysis_indexes"]
                self.assertIs(boundary_indexes, rule_indexes)
                self.assertIs(rule_indexes.provider_extension, extensions[-1])

    def test_analysis_factory_mapping_can_omit_provider_extensions(self) -> None:
        unused_factory = Mock(side_effect=AssertionError("Factory selected for the wrong provider."))
        for factories in ({}, {" GCP ": None}, {"aws": unused_factory}):
            with self.subTest(factories=factories):
                engine = TfStride(provider_analysis_index_factories=factories)

                with (
                    patch(
                        "tfstride.analysis.indexes._default_provider_extension_factory",
                        side_effect=AssertionError("An absent extension must not fall back to the catalog."),
                    ),
                    patch.object(
                        engine._rule_engine,
                        "evaluate",
                        wraps=engine._rule_engine.evaluate,
                    ) as evaluate,
                ):
                    result = engine.analyze_plan(GCP_FIXTURE_PATH)

                self.assertEqual(result.inventory.provider, "gcp")
                self.assertIsNone(evaluate.call_args.kwargs["analysis_indexes"].provider_extension)
                unused_factory.assert_not_called()

    def test_analysis_propagates_configured_index_factory_failure(self) -> None:
        index_factory = Mock(side_effect=RuntimeError("index factory failed"))
        engine = TfStride(provider_analysis_index_factories={"gcp": index_factory})

        with self.assertRaisesRegex(RuntimeError, "index factory failed"):
            engine.analyze_plan(GCP_FIXTURE_PATH)

        index_factory.assert_called_once()

    def test_analysis_uses_same_active_registry_for_evaluation_and_coverage(self) -> None:
        engine = TfStride()

        with (
            patch.object(
                engine._rule_engine,
                "evaluate",
                wraps=engine._rule_engine.evaluate,
            ) as evaluate,
            patch(
                "tfstride.app.build_analysis_coverage",
                wraps=build_analysis_coverage,
            ) as build_coverage,
        ):
            result = engine.analyze_plan(FIXTURE_PATH)

        evaluation_rule_set = evaluate.call_args.kwargs["rule_set"]
        coverage_registry = build_coverage.call_args.kwargs["rule_registry"]

        self.assertIs(evaluation_rule_set, engine._rule_engine.rule_set_for("aws"))
        self.assertIs(coverage_registry, evaluation_rule_set.registry)
        self.assertEqual(result.analysis_coverage.rules.registered_rule_count, 104)
        self.assertEqual(len(result.analysis_coverage.rules.enabled_rules), 104)
        self.assertTrue(all(rule_id.startswith("aws-") for rule_id in result.analysis_coverage.rules.enabled_rules))

    def test_analysis_selects_boundary_contributors_for_normalized_provider(self) -> None:
        class RecordingNormalizer(ProviderNormalizer):
            def __init__(self, provider: str) -> None:
                self.provider = provider

            def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
                return ResourceInventory(provider=self.provider, resources=[])

        class RecordingBoundaryContributor:
            def __init__(self, provider: str) -> None:
                self.provider = provider
                self.calls = 0

            def contribute(self, context) -> None:
                self.calls += 1
                context.add_boundary(
                    BoundaryType.CROSS_ACCOUNT_OR_ROLE,
                    f"{self.provider}:source",
                    f"{self.provider}:target",
                    f"{self.provider} contributor selected.",
                    "Selected after provider normalization.",
                )

        aws_contributor = RecordingBoundaryContributor("aws")
        gcp_contributor = RecordingBoundaryContributor("gcp")
        engine = TfStride(
            provider="gcp",
            provider_registry=ProviderRegistry([RecordingNormalizer("gcp")]),
            provider_boundary_contributor_factories={
                " AWS ": (lambda: aws_contributor,),
                " GCP ": (lambda: gcp_contributor,),
            },
        )

        result = engine.analyze_plan(FIXTURE_PATH)

        self.assertEqual(result.inventory.provider, "gcp")
        self.assertEqual(aws_contributor.calls, 0)
        self.assertEqual(gcp_contributor.calls, 1)
        self.assertEqual(
            [boundary.identifier for boundary in result.trust_boundaries],
            ["cross-account-or-role-access:gcp:source->gcp:target"],
        )

    def test_analysis_selects_observation_factories_for_normalized_provider(self) -> None:
        class RecordingNormalizer(ProviderNormalizer):
            provider = "gcp"

            def normalize(self, resources: list[TerraformResource]) -> ResourceInventory:
                return ResourceInventory(provider=self.provider, resources=[])

        calls: list[str] = []

        def observation_factory(provider: str):
            def build(inventory: ResourceInventory) -> list[Observation]:
                calls.append(provider)
                return [
                    Observation(
                        title=f"{provider} observation",
                        observation_id=f"{provider}-observation",
                        affected_resources=[inventory.provider],
                        rationale="Selected after provider normalization.",
                    )
                ]

            return build

        engine = TfStride(
            provider="gcp",
            provider_registry=ProviderRegistry([RecordingNormalizer()]),
            provider_observation_factories={
                " AWS ": (observation_factory("aws"),),
                " GCP ": (observation_factory("gcp"),),
            },
        )

        result = engine.analyze_plan(FIXTURE_PATH)

        self.assertEqual(calls, ["gcp"])
        self.assertEqual([observation.observation_id for observation in result.observations], ["gcp-observation"])

    def test_analysis_raises_when_default_provider_is_not_registered(self) -> None:
        engine = TfStride(provider_registry=ProviderRegistry())

        with self.assertRaises(ProviderNotRegisteredError):
            engine.analyze_plan(FIXTURE_PATH)

    def test_analysis_auto_selects_gcp_provider_for_google_plan(self) -> None:
        payload = {
            "terraform_version": "1.8.5",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "google_storage_bucket.logs",
                            "mode": "managed",
                            "type": "google_storage_bucket",
                            "name": "logs",
                            "provider_name": "registry.terraform.io/hashicorp/google",
                            "values": {
                                "name": "logs",
                                "uniform_bucket_level_access": True,
                                "public_access_prevention": "enforced",
                                "versioning": [{"enabled": True}],
                                "retention_policy": [{"retention_period": 2_592_000, "is_locked": True}],
                                "encryption": [
                                    {
                                        "default_kms_key_name": (
                                            "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/gcs"
                                        )
                                    }
                                ],
                            },
                        },
                    ]
                }
            },
        }

        result = self._analyze_payload(payload)

        self.assertEqual(result.inventory.provider, "gcp")
        self.assertEqual(len(result.inventory.resources), 1)
        self.assertEqual(result.inventory.resources[0].address, "google_storage_bucket.logs")
        self.assertEqual(result.inventory.unsupported_resources, [])
        self.assertEqual(result.findings, [])
        self.assertEqual(result.analysis_coverage.rules.registered_rule_count, 97)
        self.assertEqual(len(result.analysis_coverage.rules.enabled_rules), 97)
        self.assertTrue(all(rule_id.startswith("gcp-") for rule_id in result.analysis_coverage.rules.enabled_rules))
        self.assertIn("GCP support covers a curated set", result.limitations[0])

    def test_analysis_auto_selects_azure_storage_provider(self) -> None:
        payload = {
            "terraform_version": "1.8.5",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "azurerm_storage_account.logs",
                            "mode": "managed",
                            "type": "azurerm_storage_account",
                            "name": "logs",
                            "provider_name": "registry.terraform.io/hashicorp/azurerm",
                            "values": {
                                "name": "tfstridelogs",
                                "allow_nested_items_to_be_public": False,
                                "shared_access_key_enabled": False,
                                "min_tls_version": "TLS1_2",
                                "public_network_access_enabled": False,
                                "network_rules": [{"default_action": "Deny"}],
                                "infrastructure_encryption_enabled": True,
                                "customer_managed_key": [
                                    {
                                        "key_vault_key_id": "azurerm_key_vault_key.storage.id",
                                        "user_assigned_identity_id": "azurerm_user_assigned_identity.storage.id",
                                    }
                                ],
                                "blob_properties": [
                                    {
                                        "versioning_enabled": True,
                                        "delete_retention_policy": [{"days": 30}],
                                        "container_delete_retention_policy": [{"days": 14}],
                                        "restore_policy": [{"days": 7}],
                                    }
                                ],
                            },
                        },
                        {
                            "address": "azurerm_monitor_diagnostic_setting.logs",
                            "mode": "managed",
                            "type": "azurerm_monitor_diagnostic_setting",
                            "name": "logs",
                            "provider_name": "registry.terraform.io/hashicorp/azurerm",
                            "values": {
                                "name": "logs-audit",
                                "target_resource_id": "azurerm_storage_account.logs.id",
                                "log_analytics_workspace_id": "azurerm_log_analytics_workspace.security.id",
                                "enabled_log": [{"category_group": "audit"}],
                            },
                        },
                    ]
                }
            },
        }

        result = self._analyze_payload(payload)

        self.assertEqual(result.inventory.provider, "azure")
        self.assertEqual(
            [resource.address for resource in result.inventory.resources],
            ["azurerm_storage_account.logs", "azurerm_monitor_diagnostic_setting.logs"],
        )
        self.assertEqual(result.inventory.unsupported_resources, [])
        self.assertEqual(result.analysis_coverage.resources.total_resources, 2)
        self.assertEqual(result.analysis_coverage.resources.provider_resources, 2)
        self.assertEqual(result.analysis_coverage.resources.normalized_resources, 2)
        self.assertEqual(result.analysis_coverage.resources.unsupported_resources, 0)
        self.assertEqual(result.analysis_coverage.resources.unsupported_resource_types, {})
        self.assertEqual(result.trust_boundaries, [])
        self.assertEqual(result.findings, [])
        self.assertEqual(result.analysis_coverage.rules.registered_rule_count, 116)
        self.assertEqual(len(result.analysis_coverage.rules.enabled_rules), 116)
        self.assertTrue(all(rule_id.startswith("azure-") for rule_id in result.analysis_coverage.rules.enabled_rules))
        self.assertIn("Azure support covers a curated AzureRM set", result.limitations[0])

    def test_analysis_accepts_explicit_azure_provider_for_fixture(self) -> None:
        result = TfStride(provider="azure").analyze_plan(AZURE_SAFE_FIXTURE_PATH)

        self.assertEqual(result.inventory.provider, "azure")
        self.assertEqual(len(result.inventory.resources), 4)
        self.assertEqual(result.inventory.unsupported_resources, [])
        self.assertEqual(result.findings, [])

    def test_analysis_rejects_mixed_provider_plans_without_explicit_provider(self) -> None:
        payload = {
            "terraform_version": "1.8.5",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_instance.web",
                            "mode": "managed",
                            "type": "aws_instance",
                            "name": "web",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {},
                        },
                        {
                            "address": "google_storage_bucket.logs",
                            "mode": "managed",
                            "type": "google_storage_bucket",
                            "name": "logs",
                            "provider_name": "registry.terraform.io/hashicorp/google",
                            "values": {},
                        },
                    ]
                }
            },
        }

        with self.assertRaises(ProviderSelectionError):
            self._analyze_payload(payload)

    def test_tfs_exposes_read_only_configuration_without_public_rule_engine(self) -> None:
        registry = ProviderRegistry()
        rule_policy = RulePolicy(enabled_rule_ids=frozenset())
        engine = TfStride(provider_registry=registry, rule_policy=rule_policy)

        self.assertIs(engine.provider_registry, registry)
        self.assertEqual(engine.provider, "auto")
        self.assertIs(engine.rule_policy, rule_policy)
        self.assertFalse(hasattr(engine, "rule_engine"))
        with self.assertRaises(AttributeError):
            engine.provider_registry = ProviderRegistry()
        with self.assertRaises(AttributeError):
            engine.provider = "aws"
        with self.assertRaises(AttributeError):
            engine.rule_policy = None


if __name__ == "__main__":
    unittest.main()
