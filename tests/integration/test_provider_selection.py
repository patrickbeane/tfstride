from __future__ import annotations

import unittest

from tests.integration.analysis_support import (
    AZURE_SAFE_FIXTURE_PATH,
    FIXTURE_PATH,
    TFSIntegrationTestCase,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.app import TfStride
from tfstride.models import (
    BoundaryType,
    Observation,
    ResourceInventory,
    TerraformResource,
)
from tfstride.providers.base import ProviderNormalizer
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
                                "encryption": [
                                    {
                                        "default_kms_key_name": (
                                            "projects/tfstride-demo/locations/global/keyRings/app/cryptoKeys/gcs"
                                        )
                                    }
                                ],
                            },
                        }
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
        self.assertIn("GCP support currently provides initial inventory normalization", result.limitations[0])

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
                        }
                    ]
                }
            },
        }

        result = self._analyze_payload(payload)

        self.assertEqual(result.inventory.provider, "azure")
        self.assertEqual(
            [resource.address for resource in result.inventory.resources],
            ["azurerm_storage_account.logs"],
        )
        self.assertEqual(result.inventory.unsupported_resources, [])
        self.assertEqual(result.analysis_coverage.resources.total_resources, 1)
        self.assertEqual(result.analysis_coverage.resources.provider_resources, 1)
        self.assertEqual(result.analysis_coverage.resources.normalized_resources, 1)
        self.assertEqual(result.analysis_coverage.resources.unsupported_resources, 0)
        self.assertEqual(result.analysis_coverage.resources.unsupported_resource_types, {})
        self.assertEqual(result.trust_boundaries, [])
        self.assertEqual(result.findings, [])
        self.assertIn("covers AzureRM storage posture", result.limitations[0])

    def test_analysis_accepts_explicit_azure_provider_for_fixture(self) -> None:
        result = TfStride(provider="azure").analyze_plan(AZURE_SAFE_FIXTURE_PATH)

        self.assertEqual(result.inventory.provider, "azure")
        self.assertEqual(len(result.inventory.resources), 3)
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
