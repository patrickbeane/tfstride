from __future__ import annotations

import unittest
from dataclasses import replace
from unittest.mock import patch

from tests.helpers.gcp_gcs_plan import CUSTOM_ROLE, build_benchmark_resources, build_gcs_case
from tfstride.providers.gcp import custom_role_index, gcs_grant_evaluation
from tfstride.providers.gcp.gcs_grant_evaluation import GcsGrantConstraintContext
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.normalizer import GcpNormalizer
from tfstride.providers.gcp.resource_decoration.cloud_run_gcs_access_paths import (
    ModelCloudRunGcsAccessPathsStage,
    current_cloud_run_gcs_access_paths,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_gcs_bucket_topology_destruction_paths import (
    ModelCloudRunGcsBucketTopologyDestructionPathsStage,
    current_cloud_run_gcs_bucket_topology_destruction_paths,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_gcs_object_deletion_paths import (
    ModelCloudRunGcsObjectDeletionPathsStage,
)
from tfstride.providers.gcp.resource_decoration.cloud_run_gcs_protected_data_convergence import (
    ModelCloudRunGcsProtectedDataConvergenceStage,
)
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_index import GcpDecorationContext, GcpResourceIndexBuilder
from tfstride.providers.gcp.resource_types import GCP_CLOUD_RUN_RESOURCE_TYPES


class GcpGcsDecorationContextTests(unittest.TestCase):
    def test_each_stage_builds_one_context_and_one_set_of_indexes_as_workloads_grow(self) -> None:
        stages = (
            ModelCloudRunGcsAccessPathsStage(),
            ModelCloudRunGcsObjectDeletionPathsStage(),
            ModelCloudRunGcsBucketTopologyDestructionPathsStage(),
            ModelCloudRunGcsProtectedDataConvergenceStage(),
        )
        for workloads in (1, 4, 12):
            resources = GcpNormalizer().normalize(build_benchmark_resources(workloads, "gcs")).resources
            context = GcpDecorationContext(GcpResourceIndexBuilder().build(resources))
            expected = [resource.metadata_snapshot() for resource in resources]
            for stage in stages:
                with (
                    self.subTest(workloads=workloads, stage=stage.name),
                    patch.object(GcsGrantConstraintContext, "build", wraps=GcsGrantConstraintContext.build) as builds,
                    patch.object(
                        GcpResourceIndexBuilder, "build", autospec=True, side_effect=GcpResourceIndexBuilder.build
                    ) as indexes,
                    patch.object(
                        custom_role_index,
                        "build_resource_reference_index",
                        wraps=custom_role_index.build_resource_reference_index,
                    ) as roles,
                    patch.object(
                        gcs_grant_evaluation,
                        "project_reference_index",
                        wraps=gcs_grant_evaluation.project_reference_index,
                    ) as projects,
                ):
                    stage.apply(resources, context)
                    self.assertEqual(builds.call_count, 1)
                    self.assertEqual(indexes.call_count, 1)
                    self.assertEqual(roles.call_count, 1)
                    self.assertEqual(projects.call_count, 1)
                    self.assertEqual([resource.metadata_snapshot() for resource in resources], expected)

    def test_stages_without_buckets_or_workloads_construct_no_contexts(self) -> None:
        cases = {
            "no_buckets": build_gcs_case("no_buckets"),
            "no_workloads": [
                resource
                for resource in build_benchmark_resources(2, "gcs")
                if resource.resource_type not in GCP_CLOUD_RUN_RESOURCE_TYPES
            ],
        }
        for case, plan in cases.items():
            resources = GcpNormalizer().normalize(plan).resources
            context = GcpDecorationContext(GcpResourceIndexBuilder().build(resources))
            expected = [resource.metadata_snapshot() for resource in resources]
            for stage in (
                ModelCloudRunGcsAccessPathsStage(),
                ModelCloudRunGcsObjectDeletionPathsStage(),
                ModelCloudRunGcsBucketTopologyDestructionPathsStage(),
                ModelCloudRunGcsProtectedDataConvergenceStage(),
            ):
                with (
                    self.subTest(case=case, stage=stage.name),
                    patch.object(
                        GcsGrantConstraintContext, "build", side_effect=AssertionError("unexpected grant context")
                    ),
                ):
                    stage.apply(resources, context)
                    self.assertEqual([resource.metadata_snapshot() for resource in resources], expected)

    def test_stages_and_standalone_helpers_rebuild_after_custom_role_changes(self) -> None:
        for stage, field in (
            (ModelCloudRunGcsAccessPathsStage(), "cloud_run_gcs_access_paths"),
            (ModelCloudRunGcsObjectDeletionPathsStage(), "cloud_run_gcs_object_deletion_paths"),
            (ModelCloudRunGcsBucketTopologyDestructionPathsStage(), "cloud_run_gcs_bucket_topology_destruction_paths"),
        ):
            with self.subTest(stage=stage.name):
                plan = build_gcs_case("mixed")
                local_grant = next(
                    resource for resource in plan if resource.address == "google_storage_bucket_iam_member.local"
                )
                local_grant.values["role"] = CUSTOM_ROLE
                inventory = GcpNormalizer().normalize(plan)
                resources = inventory.resources
                workload = inventory.get_by_address("google_cloud_run_v2_service.w0")
                role = inventory.get_by_address("google_project_iam_custom_role.storage_operator")
                bucket = inventory.get_by_address("google_storage_bucket.b0")
                assert workload is not None and role is not None and bucket is not None
                context = GcpDecorationContext(GcpResourceIndexBuilder().build(resources))
                stage.apply(resources, context)
                self.assertTrue(workload.metadata_snapshot()[field])
                self.assertTrue(current_cloud_run_gcs_access_paths(workload, resources))
                self.assertTrue(
                    current_cloud_run_gcs_bucket_topology_destruction_paths(workload, bucket, resources, context)
                )

                gcp_facts(role).set(GcpResourceMetadata.CUSTOM_ROLE_PERMISSIONS, ["resourcemanager.projects.get"])
                stage.apply(resources, context)
                self.assertEqual(workload.metadata_snapshot()[field], [])
                self.assertEqual(current_cloud_run_gcs_access_paths(workload, resources), [])
                self.assertEqual(
                    current_cloud_run_gcs_bucket_topology_destruction_paths(workload, bucket, resources, context), []
                )

    def test_standalone_helpers_rebuild_reference_indexes_after_role_ambiguity_is_added(self) -> None:
        inventory = GcpNormalizer().normalize(build_gcs_case("mixed"))
        resources = inventory.resources
        workload = inventory.get_by_address("google_cloud_run_v2_service.w2")
        role = inventory.get_by_address("google_project_iam_custom_role.storage_operator")
        bucket = inventory.get_by_address("google_storage_bucket.b0")
        assert workload is not None and role is not None and bucket is not None
        context = GcpDecorationContext(GcpResourceIndexBuilder().build(resources))
        self.assertTrue(current_cloud_run_gcs_access_paths(workload, resources))
        self.assertTrue(current_cloud_run_gcs_bucket_topology_destruction_paths(workload, bucket, resources, context))
        duplicate = replace(role, address="google_project_iam_custom_role.duplicate", metadata=role.metadata_snapshot())
        resources = [*resources, duplicate]
        self.assertEqual(current_cloud_run_gcs_access_paths(workload, resources), [])
        self.assertEqual(
            current_cloud_run_gcs_bucket_topology_destruction_paths(workload, bucket, resources, context), []
        )

    def test_current_path_helpers_accept_prepared_dependencies_without_rebuilding(self) -> None:
        inventory = GcpNormalizer().normalize(build_gcs_case("mixed"))
        resources = inventory.resources
        workload = inventory.get_by_address("google_cloud_run_v2_service.w2")
        bucket = inventory.get_by_address("google_storage_bucket.b0")
        assert workload is not None and bucket is not None
        prepared = GcsGrantConstraintContext.build(resources)
        context = GcpDecorationContext(prepared.index)
        expected_access = current_cloud_run_gcs_access_paths(workload, resources)
        expected_topology = current_cloud_run_gcs_bucket_topology_destruction_paths(
            workload, bucket, resources, context
        )
        self.assertTrue(expected_access)
        self.assertTrue(expected_topology)
        with patch.object(GcsGrantConstraintContext, "build", side_effect=AssertionError("unexpected grant context")):
            self.assertEqual(
                current_cloud_run_gcs_access_paths(workload, resources, grant_context=prepared), expected_access
            )
            self.assertEqual(
                current_cloud_run_gcs_bucket_topology_destruction_paths(
                    workload, bucket, resources, context, grant_context=prepared
                ),
                expected_topology,
            )


if __name__ == "__main__":
    unittest.main()
