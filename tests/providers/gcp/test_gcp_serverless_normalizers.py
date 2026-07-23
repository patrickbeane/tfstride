from __future__ import annotations

import unittest

from tests.providers.gcp.normalizer_support import (
    GcpNormalizerTestCase,
    _terraform_resource,
)
from tfstride.models import ResourceCategory
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.serverless_normalizers import (
    normalize_cloud_run_service_iam_member,
    normalize_cloud_run_v2_service,
    normalize_cloudfunctions_function,
    normalize_cloudfunctions_function_iam_member,
)


class GcpServerlessNormalizerTests(GcpNormalizerTestCase):
    def test_cloud_run_v2_service_normalizer_preserves_workload_identity(self) -> None:
        normalized = normalize_cloud_run_v2_service(
            _terraform_resource(
                "google_cloud_run_v2_service.api",
                "google_cloud_run_v2_service",
                {
                    "name": "tfstride-api",
                    "project": "tfstride-demo",
                    "location": "us-central1",
                    "ingress": "INGRESS_TRAFFIC_ALL",
                    "invoker_iam_disabled": True,
                    "uri": "https://tfstride-api.run.app",
                    "template": [
                        {
                            "service_account": "tfstride-api@tfstride-demo.iam.gserviceaccount.com",
                        }
                    ],
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.COMPUTE)
        self.assertTrue(normalized.public_access_configured)
        self.assertFalse(normalized.vpc_enabled)
        self.assertTrue(gcp_facts(normalized).cloud_run_invoker_iam_disabled)
        self.assertEqual(gcp_facts(normalized).serverless_ingress, "INGRESS_TRAFFIC_ALL")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE),
            "tfstride-api",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_EMAIL),
            "tfstride-api@tfstride-demo.iam.gserviceaccount.com",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNTS),
            [{"email": "tfstride-api@tfstride-demo.iam.gserviceaccount.com"}],
        )

    def test_cloud_run_v2_service_preserves_unknown_invoker_iam_check(self) -> None:
        normalized = normalize_cloud_run_v2_service(
            _terraform_resource(
                "google_cloud_run_v2_service.api",
                "google_cloud_run_v2_service",
                {
                    "name": "tfstride-api",
                    "location": "us-central1",
                    "ingress": "INGRESS_TRAFFIC_ALL",
                    "template": [{}],
                },
                unknown_values={"invoker_iam_disabled": True},
            )
        )

        self.assertIsNone(gcp_facts(normalized).cloud_run_invoker_iam_disabled)

    def test_cloud_run_service_iam_member_normalizer_preserves_binding_parts(self) -> None:
        normalized = normalize_cloud_run_service_iam_member(
            _terraform_resource(
                "google_cloud_run_service_iam_member.public_invoker",
                "google_cloud_run_service_iam_member",
                {
                    "service": "tfstride-api",
                    "location": "us-central1",
                    "role": "roles/run.invoker",
                    "member": "allUsers",
                },
            )
        )

        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.CLOUD_RUN_SERVICE_REFERENCE),
            "tfstride-api",
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_ROLE), "roles/run.invoker")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBER), "allUsers")
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/run.invoker", "members": ["allUsers"]}],
        )

    def test_cloud_run_iam_member_normalizer_preserves_condition(self) -> None:
        condition = {
            "title": "expires_soon",
            "description": "Temporary public launch access",
            "expression": 'request.time < timestamp("2026-07-01T00:00:00Z")',
        }
        normalized = normalize_cloud_run_service_iam_member(
            _terraform_resource(
                "google_cloud_run_v2_service_iam_member.public_invoker",
                "google_cloud_run_v2_service_iam_member",
                {
                    "name": "tfstride-api",
                    "location": "us-central1",
                    "role": "roles/run.invoker",
                    "member": "allUsers",
                    "condition": [condition],
                },
            )
        )

        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_CONDITION), condition)
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.IAM_BINDINGS),
            [{"role": "roles/run.invoker", "members": ["allUsers"], "condition": condition}],
        )

    def test_cloudfunctions_function_normalizer_preserves_workload_identity(self) -> None:
        normalized = normalize_cloudfunctions_function(
            _terraform_resource(
                "google_cloudfunctions_function.worker",
                "google_cloudfunctions_function",
                {
                    "name": "tfstride-worker",
                    "project": "tfstride-demo",
                    "region": "us-central1",
                    "runtime": "python312",
                    "trigger_http": True,
                    "service_account_email": "tfstride-worker@tfstride-demo.iam.gserviceaccount.com",
                },
            )
        )

        self.assertEqual(normalized.category, ResourceCategory.COMPUTE)
        self.assertTrue(normalized.public_access_configured)
        self.assertFalse(normalized.vpc_enabled)
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE),
            "tfstride-worker",
        )
        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.SERVICE_ACCOUNT_MEMBER),
            "serviceAccount:tfstride-worker@tfstride-demo.iam.gserviceaccount.com",
        )

    def test_cloudfunctions_function_iam_member_normalizer_preserves_binding_parts(self) -> None:
        normalized = normalize_cloudfunctions_function_iam_member(
            _terraform_resource(
                "google_cloudfunctions_function_iam_member.public_invoker",
                "google_cloudfunctions_function_iam_member",
                {
                    "cloud_function": "tfstride-worker",
                    "region": "us-central1",
                    "role": "roles/cloudfunctions.invoker",
                    "member": "allUsers",
                },
            )
        )

        self.assertEqual(
            normalized.get_metadata_field(GcpResourceMetadata.CLOUD_FUNCTION_REFERENCE),
            "tfstride-worker",
        )
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_ROLE), "roles/cloudfunctions.invoker")
        self.assertEqual(normalized.get_metadata_field(GcpResourceMetadata.IAM_MEMBER), "allUsers")


if __name__ == "__main__":
    unittest.main()
