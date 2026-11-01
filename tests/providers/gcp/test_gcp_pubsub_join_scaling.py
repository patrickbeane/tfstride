"""Guard the work the GCP Pub/Sub path stages do when joining workloads to targets.

The topology-destruction and message-removal stages join every Cloud Run workload
to every Pub/Sub target through IAM resources. The IAM scope of a resource for a
target and the manager ambiguity of a target do not depend on the workload, so
that work must be done once per target, not once per workload. These tests count
calls to the two functions that do it, which is deterministic where wall-clock
timing is not, and assert that the counts stay independent of the number of
workloads and grow no faster than targets times IAM resources.
"""

from __future__ import annotations

import unittest
from unittest import mock

from tests.helpers.gcp_pubsub_plan import PROJECT, build_pubsub_plan
from tests.providers.gcp.normalizer_support import _terraform_resource
from tfstride.models import TerraformResource
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_decoration import (
    cloud_run_pubsub_message_removal_paths as message_removal,
)
from tfstride.providers.gcp.resource_decoration import (
    cloud_run_pubsub_topology_destruction_paths as topology_destruction,
)
from tfstride.providers.gcp.resource_types import GcpResourceType

_STAGE_MODULES = {
    "topology_destruction": topology_destruction,
    "message_removal": message_removal,
}


def _extra_workloads(count: int, *, first_index: int = 1000) -> list[TerraformResource]:
    return [
        _terraform_resource(
            f"google_cloud_run_v2_service.extra{index}",
            GcpResourceType.CLOUD_RUN_V2_SERVICE,
            {
                "name": f"extra{index}",
                "project": PROJECT,
                "location": "us-central1",
                "template": [{"service_account": f"extra{index}@{PROJECT}.iam.gserviceaccount.com"}],
            },
        )
        for index in range(first_index, first_index + count)
    ]


def _count_join_work(resources: list[TerraformResource]) -> dict[str, int]:
    """Normalize `resources` and return how often each stage resolved scopes and ambiguity."""

    counts: dict[str, int] = {}
    patches = []
    for stage, module in _STAGE_MODULES.items():
        for function in ("_iam_scope", "_iam_manager_ambiguities"):
            patches.append(
                (f"{stage}.{function}", mock.patch.object(module, function, wraps=getattr(module, function)))
            )
    started = [(key, patch.start()) for key, patch in patches]
    try:
        GcpNormalizer().normalize(resources)
        counts = {key: wrapper.call_count for key, wrapper in started}
    finally:
        for _key, patch in patches:
            patch.stop()
    return counts


def _pubsub_target_count(resources: list[TerraformResource]) -> tuple[int, int]:
    topics = sum(1 for resource in resources if resource.resource_type == GcpResourceType.PUBSUB_TOPIC)
    subscriptions = sum(1 for resource in resources if resource.resource_type == GcpResourceType.PUBSUB_SUBSCRIPTION)
    return topics, subscriptions


class GcpPubsubJoinScalingTests(unittest.TestCase):
    def test_join_work_does_not_grow_with_the_number_of_workloads(self) -> None:
        base = build_pubsub_plan(12)
        baseline = _count_join_work(base)
        self.assertTrue(all(count > 0 for count in baseline.values()), baseline)

        with_extra_workloads = _count_join_work([*base, *_extra_workloads(30)])

        self.assertEqual(with_extra_workloads, baseline)

    def test_manager_ambiguity_is_computed_once_per_target(self) -> None:
        resources = build_pubsub_plan(12)
        topics, subscriptions = _pubsub_target_count(resources)

        counts = _count_join_work(resources)

        self.assertLessEqual(counts["topology_destruction._iam_manager_ambiguities"], topics + subscriptions)
        self.assertLessEqual(counts["message_removal._iam_manager_ambiguities"], subscriptions)

    def test_scope_resolution_is_bounded_by_targets_times_iam_resources(self) -> None:
        resources = build_pubsub_plan(24)
        topics, subscriptions = _pubsub_target_count(resources)
        iam_resources = sum(1 for resource in resources if "_iam_" in resource.resource_type)

        counts = _count_join_work(resources)

        # Each target resolves every IAM resource's scope at most twice: once for the
        # manager-ambiguity check and once for the grant index. No workload factor.
        self.assertLessEqual(counts["topology_destruction._iam_scope"], 2 * (topics + subscriptions) * iam_resources)
        self.assertLessEqual(counts["message_removal._iam_scope"], 2 * subscriptions * iam_resources)

    def test_total_join_work_grows_at_most_quadratically_in_plan_size(self) -> None:
        small = _count_join_work(build_pubsub_plan(24))
        large = _count_join_work(build_pubsub_plan(48))

        for key, small_count in small.items():
            # Doubling the plan multiplies targets times IAM resources by four. A per-workload
            # factor on top of that would push the ratio toward eight.
            self.assertLess(large[key] / small_count, 6, key)


if __name__ == "__main__":
    unittest.main()
