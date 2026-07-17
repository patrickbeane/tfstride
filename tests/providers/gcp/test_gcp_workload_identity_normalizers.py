from __future__ import annotations

from tests.providers.gcp.normalizer_support import GcpNormalizerTestCase, _terraform_resource
from tfstride.models import ResourceCategory
from tfstride.providers.coercion import STATE_ENABLED, STATE_UNKNOWN
from tfstride.providers.gcp.iam_workload_identity_normalizers import (
    normalize_workload_identity_pool,
    normalize_workload_identity_pool_provider,
)
from tfstride.providers.gcp.normalizer import SUPPORTED_GCP_TYPES, GcpNormalizer
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType


class GcpWorkloadIdentityNormalizerTests(GcpNormalizerTestCase):
    def test_workload_identity_pool_preserves_mode_and_disabled_state(self) -> None:
        normalized = normalize_workload_identity_pool(
            _terraform_resource(
                "google_iam_workload_identity_pool.external",
                GcpResourceType.WORKLOAD_IDENTITY_POOL,
                {
                    "id": "projects/tfstride-demo/locations/global/workloadIdentityPools/external",
                    "name": "external",
                    "workload_identity_pool_id": "external",
                    "mode": "FEDERATION_ONLY",
                    "disabled": False,
                },
            )
        )
        facts = gcp_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(
            normalized.identifier,
            "projects/tfstride-demo/locations/global/workloadIdentityPools/external",
        )
        self.assertEqual(facts.workload_identity_pool_id, "external")
        self.assertEqual(facts.workload_identity_pool_mode, "FEDERATION_ONLY")
        self.assertEqual(facts.workload_identity_pool_state, STATE_ENABLED)
        self.assertEqual(facts.workload_identity_pool_disabled_state, STATE_ENABLED)
        self.assertEqual(facts.workload_identity_pool_posture_uncertainties, [])

        disabled = normalize_workload_identity_pool(
            _terraform_resource(
                "google_iam_workload_identity_pool.disabled",
                GcpResourceType.WORKLOAD_IDENTITY_POOL,
                {"workload_identity_pool_id": "disabled", "disabled": True},
            )
        )
        self.assertEqual(gcp_facts(disabled).workload_identity_pool_state, "disabled")

    def test_oidc_provider_preserves_federation_configuration(self) -> None:
        normalized = normalize_workload_identity_pool_provider(
            _terraform_resource(
                "google_iam_workload_identity_pool_provider.github",
                GcpResourceType.WORKLOAD_IDENTITY_POOL_PROVIDER,
                {
                    "id": "projects/tfstride-demo/locations/global/workloadIdentityPools/external/providers/github",
                    "name": "github",
                    "workload_identity_pool_id": "external",
                    "workload_identity_pool_provider_id": "github",
                    "disabled": False,
                    "oidc": [
                        {
                            "issuer_uri": "https://token.actions.githubusercontent.com",
                            "allowed_audiences": ["sts.googleapis.com", "tfstride"],
                        }
                    ],
                    "attribute_mapping": {
                        "google.subject": "assertion.sub",
                        "attribute.repository": "assertion.repository",
                    },
                    "attribute_condition": "assertion.repository_owner == 'tfstride'",
                },
            )
        )
        facts = gcp_facts(normalized)

        self.assertEqual(normalized.category, ResourceCategory.IAM)
        self.assertEqual(facts.workload_identity_pool_id, "external")
        self.assertEqual(facts.workload_identity_pool_provider_id, "github")
        self.assertEqual(facts.workload_identity_pool_provider_type, "oidc")
        self.assertEqual(facts.workload_identity_pool_provider_state, STATE_ENABLED)
        self.assertEqual(
            facts.workload_identity_pool_provider_issuer_uri,
            "https://token.actions.githubusercontent.com",
        )
        self.assertEqual(facts.workload_identity_pool_provider_allowed_audiences, ["sts.googleapis.com", "tfstride"])
        self.assertEqual(
            facts.workload_identity_pool_provider_attribute_mappings,
            {
                "attribute.repository": "assertion.repository",
                "google.subject": "assertion.sub",
            },
        )
        self.assertEqual(
            facts.workload_identity_pool_provider_attribute_condition,
            "assertion.repository_owner == 'tfstride'",
        )
        self.assertEqual(facts.workload_identity_pool_posture_uncertainties, [])

    def test_aws_provider_preserves_account_configuration(self) -> None:
        normalized = normalize_workload_identity_pool_provider(
            _terraform_resource(
                "google_iam_workload_identity_pool_provider.aws",
                GcpResourceType.WORKLOAD_IDENTITY_POOL_PROVIDER,
                {
                    "workload_identity_pool_id": "external",
                    "workload_identity_pool_provider_id": "aws",
                    "disabled": False,
                    "aws": [{"account_id": "123456789012"}],
                },
            )
        )
        facts = gcp_facts(normalized)

        self.assertEqual(facts.workload_identity_pool_provider_type, "aws")
        self.assertEqual(facts.workload_identity_pool_provider_aws_account_id, "123456789012")
        self.assertIsNone(facts.workload_identity_pool_provider_issuer_uri)
        self.assertEqual(facts.workload_identity_pool_provider_allowed_audiences, [])
        self.assertEqual(facts.workload_identity_pool_posture_uncertainties, [])

    def test_unknown_federation_values_remain_unknown_with_evidence(self) -> None:
        normalized = normalize_workload_identity_pool_provider(
            _terraform_resource(
                "google_iam_workload_identity_pool_provider.unknown",
                GcpResourceType.WORKLOAD_IDENTITY_POOL_PROVIDER,
                {},
                unknown_values={
                    "disabled": True,
                    "workload_identity_pool_id": True,
                    "workload_identity_pool_provider_id": True,
                    "oidc": True,
                    "attribute_mapping": True,
                    "attribute_condition": True,
                },
            )
        )
        facts = gcp_facts(normalized)

        self.assertEqual(facts.workload_identity_pool_provider_state, STATE_UNKNOWN)
        self.assertEqual(facts.workload_identity_pool_provider_type, "oidc")
        self.assertIsNone(facts.workload_identity_pool_id)
        self.assertEqual(facts.workload_identity_pool_provider_allowed_audiences, [])
        self.assertEqual(facts.workload_identity_pool_provider_attribute_mappings, {})
        self.assertGreaterEqual(len(facts.workload_identity_pool_posture_uncertainties), 4)
        self.assertTrue(
            any("issuer_uri" in uncertainty for uncertainty in facts.workload_identity_pool_posture_uncertainties)
        )

    def test_normalizer_registers_both_workload_identity_resource_types(self) -> None:
        resources = [
            _terraform_resource(
                "google_iam_workload_identity_pool.external",
                GcpResourceType.WORKLOAD_IDENTITY_POOL,
                {"name": "external", "disabled": False},
            ),
            _terraform_resource(
                "google_iam_workload_identity_pool_provider.github",
                GcpResourceType.WORKLOAD_IDENTITY_POOL_PROVIDER,
                {"workload_identity_pool_id": "external", "oidc": [{}]},
            ),
        ]

        inventory = GcpNormalizer().normalize(resources)

        self.assertEqual(
            {resource.address for resource in inventory.resources}, {resource.address for resource in resources}
        )
        self.assertEqual(inventory.unsupported_resources, [])
        self.assertIn(GcpResourceType.WORKLOAD_IDENTITY_POOL, SUPPORTED_GCP_TYPES)
        self.assertIn(GcpResourceType.WORKLOAD_IDENTITY_POOL_PROVIDER, SUPPORTED_GCP_TYPES)
