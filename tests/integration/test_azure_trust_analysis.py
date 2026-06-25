from __future__ import annotations

import unittest

from tests.integration.analysis_support import AZURE_COMPUTE_FIXTURE_PATH
from tfstride.analysis.boundaries.core import detect_trust_boundaries
from tfstride.app import TfStride
from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import BoundaryType
from tfstride.providers.azure.boundaries import AzureBoundaryContributor
from tfstride.providers.azure.normalizer import AzureNormalizer


class AzureTrustAnalysisIntegrationTests(unittest.TestCase):
    def test_compute_fixture_emits_stable_internet_to_service_boundary(self) -> None:
        result = TfStride().analyze_plan(AZURE_COMPUTE_FIXTURE_PATH)

        self.assertEqual(len(result.trust_boundaries), 1)
        boundary = result.trust_boundaries[0]
        self.assertEqual(boundary.boundary_type, BoundaryType.INTERNET_TO_SERVICE)
        self.assertEqual(boundary.source, "internet")
        self.assertEqual(boundary.target, "azurerm_linux_virtual_machine.web")
        self.assertEqual(
            boundary.identifier,
            "internet-to-service:internet->azurerm_linux_virtual_machine.web",
        )

    def test_azure_contributor_uses_provider_specific_exposure_evidence(self) -> None:
        inventory = AzureNormalizer().normalize(load_terraform_plan(AZURE_COMPUTE_FIXTURE_PATH).resources)

        boundaries = detect_trust_boundaries(
            inventory,
            contributors=(AzureBoundaryContributor(),),
        )

        self.assertEqual(len(boundaries), 1)
        self.assertIn("public-IP path", boundaries[0].rationale)
        self.assertIn("subnet/NIC NSG decisions", boundaries[0].rationale)


if __name__ == "__main__":
    unittest.main()
