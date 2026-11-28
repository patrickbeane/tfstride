"""A workload's bucket-topology destruction results must not depend on the other workloads in the plan.

Per-bucket IAM facts are shared across workloads while the decoration stage runs. These cases compare
each workload decorated alongside the others with the same workload decorated alone, so shared state
cannot leak one workload's evaluation into another's.
"""

from __future__ import annotations

import unittest
from typing import Any

from tests.helpers.gcp_gcs_plan import (
    CASES,
    _bucket,
    _bucket_grant,
    _project_grant,
    _workload,
    build_gcs_case,
    service_account_member,
)
from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.models import NormalizedResource, TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_types import GcpResourceType

_FIELD_PREFIX = "cloud_run_gcs_bucket_topology_destruction"


def _overlapping_manager_resources() -> list[TerraformResource]:
    """Several buckets whose IAM managers are clean, overlapping, authoritative, or unresolved."""
    return [
        *(_workload(index) for index in range(3)),
        _workload(3, unknown_identity=True),
        *(_bucket(index) for index in range(4)),
        # b0: independent additive grants.
        _bucket_grant("b0w0", 0, 0, "roles/storage.admin"),
        _bucket_grant("b0w1", 1, 0, "roles/storage.admin"),
        # b1: an authoritative binding overlaps an additive member for one role.
        _terraform_resource(
            "google_storage_bucket_iam_binding.b1",
            GcpResourceType.STORAGE_BUCKET_IAM_BINDING,
            {
                "bucket": "google_storage_bucket.b1.name",
                "role": "roles/storage.objectAdmin",
                "members": [service_account_member(0)],
            },
        ),
        _bucket_grant("b1w1", 1, 1, "roles/storage.objectAdmin"),
        # b2: an authoritative policy overlaps an additive member.
        _terraform_resource(
            "google_storage_bucket_iam_policy.b2",
            GcpResourceType.STORAGE_BUCKET_IAM_POLICY,
            {
                "bucket": "google_storage_bucket.b2.name",
                "policy_data": (
                    '{"bindings":[{"role":"roles/storage.admin","members":["' + service_account_member(2) + '"]}]}'
                ),
            },
        ),
        _bucket_grant("b2w0", 0, 2, "roles/storage.admin"),
        # b3: a manager whose bucket target cannot be resolved.
        _terraform_resource(
            "google_storage_bucket_iam_member.unresolved",
            GcpResourceType.STORAGE_BUCKET_IAM_MEMBER,
            {"role": "roles/storage.admin", "member": service_account_member(1)},
            unknown_values={"bucket": True},
        ),
        # Project scope applies to every bucket.
        _project_grant("project_admin", 1, "roles/storage.admin"),
        _project_grant("project_other", 3, "roles/storage.admin"),
    ]


def _topology_results(resource: NormalizedResource) -> dict[str, Any]:
    return {key: value for key, value in resource.metadata_snapshot().items() if key.startswith(_FIELD_PREFIX)}


def _workload_results(resources: list[TerraformResource]) -> dict[str, dict[str, Any]]:
    inventory = GcpNormalizer().normalize(resources)
    return {
        resource.address: _topology_results(resource)
        for resource in inventory.resources
        if resource.resource_type == GcpResourceType.CLOUD_RUN_V2_SERVICE
    }


class GcpGcsTopologyWorkloadIndependenceTests(unittest.TestCase):
    def _assert_independent(self, resources: list[TerraformResource]) -> dict[str, dict[str, Any]]:
        together = _workload_results(resources)
        self.assertTrue(together)
        for address, expected in together.items():
            alone_resources = [
                resource
                for resource in resources
                if resource.resource_type != GcpResourceType.CLOUD_RUN_V2_SERVICE or resource.address == address
            ]
            with self.subTest(workload=address):
                self.assertEqual(_workload_results(alone_resources), {address: expected})
        return together

    def test_each_characterization_case_is_independent_of_other_workloads(self) -> None:
        for case in CASES:
            with self.subTest(case=case):
                self._assert_independent(build_gcs_case(case))

    def test_overlapping_and_unresolved_managers_are_independent_of_other_workloads(self) -> None:
        results = self._assert_independent(_overlapping_manager_resources())

        paths = [
            path
            for fields in results.values()
            for key, values in fields.items()
            if key.endswith("_paths")
            for path in values
        ]
        uncertainties = [
            message
            for fields in results.values()
            for key, values in fields.items()
            if key.endswith("_uncertainties")
            for message in values
        ]
        self.assertTrue(paths, "scenario should produce destruction paths")
        joined = "\n".join(uncertainties)
        self.assertIn("is ambiguous because", joined)
        self.assertIn("scope is unresolved", joined)
        self.assertTrue(any("Cloud Run service account is unresolved" in message for message in uncertainties))

    def test_workload_results_do_not_depend_on_workload_order(self) -> None:
        resources = _overlapping_manager_resources()
        reordered = [
            *reversed([item for item in resources if item.resource_type == GcpResourceType.CLOUD_RUN_V2_SERVICE]),
            *(item for item in resources if item.resource_type != GcpResourceType.CLOUD_RUN_V2_SERVICE),
        ]

        self.assertEqual(_workload_results(reordered), _workload_results(resources))


if __name__ == "__main__":
    unittest.main()
