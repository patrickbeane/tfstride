from __future__ import annotations

import unittest
from collections import Counter

from tests.integration.analysis_support import (
    AZURE_SAFE_FIXTURE_PATH,
    AZURE_STORAGE_FIXTURE_PATH,
    AZURE_STORAGE_UNKNOWN_FIXTURE_PATH,
)
from tfstride.app import TfStride
from tfstride.models import BoundaryType
from tfstride.reporting.markdown import render_markdown


class AzureStorageAnalysisIntegrationTests(unittest.TestCase):
    def test_safe_fixture_auto_detects_azure_and_has_no_findings(self) -> None:
        result = TfStride().analyze_plan(AZURE_SAFE_FIXTURE_PATH)

        self.assertEqual(result.inventory.provider, "azure")
        self.assertEqual(len(result.inventory.resources), 3)
        self.assertEqual(result.inventory.unsupported_resources, [])
        self.assertEqual(result.trust_boundaries, [])
        self.assertEqual(result.findings, [])
        self.assertEqual(result.analysis_coverage.resources.total_resources, 3)
        self.assertEqual(result.analysis_coverage.resources.provider_resources, 3)
        self.assertEqual(result.analysis_coverage.resources.normalized_resources, 3)
        self.assertEqual(result.analysis_coverage.resources.unsupported_resources, 0)
        self.assertEqual(result.analysis_coverage.resources.unsupported_resource_types, {})

    def test_storage_fixture_emits_locked_storage_posture_findings(self) -> None:
        result = TfStride().analyze_plan(AZURE_STORAGE_FIXTURE_PATH)

        self.assertEqual(result.inventory.provider, "azure")
        self.assertEqual(
            [finding.rule_id for finding in result.findings],
            [
                "azure-storage-account-shared-key-enabled",
                "azure-storage-account-nested-public-access-enabled",
                "azure-storage-account-minimum-tls-below-1-2",
                "azure-storage-account-public-network-unrestricted",
                "azure-storage-container-public-access",
            ],
        )
        self.assertEqual(
            Counter(finding.severity.value for finding in result.findings),
            Counter({"medium": 3, "high": 2}),
        )
        self.assertEqual(len(result.trust_boundaries), 1)
        self.assertEqual(result.trust_boundaries[0].boundary_type, BoundaryType.INTERNET_TO_SERVICE)
        self.assertEqual(
            result.trust_boundaries[0].identifier,
            "internet-to-service:internet->azurerm_storage_account.assets",
        )

    def test_storage_fixture_reports_supported_and_unsupported_coverage(self) -> None:
        result = TfStride().analyze_plan(AZURE_STORAGE_FIXTURE_PATH)
        coverage = result.analysis_coverage.resources

        self.assertEqual(len(result.inventory.resources), 3)
        self.assertEqual(result.inventory.unsupported_resources, ["azurerm_storage_share.legacy"])
        self.assertEqual(coverage.total_resources, 4)
        self.assertEqual(coverage.provider_resources, 4)
        self.assertEqual(coverage.normalized_resources, 3)
        self.assertEqual(coverage.unsupported_resources, 1)
        self.assertEqual(coverage.unsupported_resource_types, {"azurerm_storage_share": 1})

    def test_unknown_storage_posture_is_observed_without_exposure_findings(self) -> None:
        result = TfStride().analyze_plan(AZURE_STORAGE_UNKNOWN_FIXTURE_PATH)

        self.assertEqual(result.inventory.provider, "azure")
        self.assertEqual(result.trust_boundaries, [])
        self.assertEqual(result.findings, [])
        self.assertEqual(len(result.observations), 2)
        observations_by_resource = {
            observation.affected_resources[0]: observation for observation in result.observations
        }
        account_observation = observations_by_resource["azurerm_storage_account.pending"]
        container_observation = observations_by_resource["azurerm_storage_container.pending"]
        account_evidence = {item.key: item.values for item in account_observation.evidence}
        container_evidence = {item.key: item.values for item in container_observation.evidence}

        self.assertEqual(account_observation.observation_id, "azure-storage-exposure-posture-unknown")
        self.assertEqual(account_observation.category, "analysis-uncertainty")
        self.assertIn(
            "public_network_access_enabled is unknown after planning",
            account_evidence["unknown_storage_posture"],
        )
        self.assertIn(
            "azurerm_storage_account_network_rules.pending: default_action is unknown after planning",
            account_evidence["unknown_storage_posture"],
        )
        self.assertEqual(
            container_evidence["unknown_storage_posture"],
            ["container_access_type is unknown after planning"],
        )

    def test_azure_storage_reports_are_deterministic(self) -> None:
        engine = TfStride()

        for fixture_path in (
            AZURE_SAFE_FIXTURE_PATH,
            AZURE_STORAGE_FIXTURE_PATH,
            AZURE_STORAGE_UNKNOWN_FIXTURE_PATH,
        ):
            with self.subTest(fixture=fixture_path.name):
                first = render_markdown(engine.analyze_plan(fixture_path))
                second = render_markdown(engine.analyze_plan(fixture_path))

                self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
