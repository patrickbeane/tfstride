"""Pin GCS output before context reuse; constructor counts are historical ceilings.

    .venv/bin/python -m tests.providers.gcp.test_gcp_gcs_evaluation_characterization --write

Regenerate the output golden only for reviewed behavior changes. Optimizations
may reduce the construction counts without changing the recorded outputs.
"""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from typing import Any

from tests.helpers.gcp_gcs_evaluation import analyze_with_counts, plan_file, plan_payload
from tests.helpers.gcp_gcs_plan import (
    CASES,
    CUSTOM_ROLE,
    build_benchmark_resources,
    build_gcs_candidate_resources,
    build_gcs_case,
)
from tests.helpers.paths import GOLDEN_DIR
from tfstride.app import TfStride
from tfstride.input.terraform_plan import load_terraform_plan
from tfstride.models import AnalysisResult
from tfstride.reporting.json_report import build_json_report_payload

SNAPSHOT_PATH = GOLDEN_DIR / "gcp_gcs_evaluation_snapshot.json"
COUNTS_PATH = GOLDEN_DIR / "gcp_gcs_context_construction_baseline.json"
_RECORD_KEYS = (
    "rule_id",
    "affected_resources",
    "boundary_type",
    "source",
    "target",
    "operation",
    "bucket_address",
    "key_address",
    "iam_resource_address",
    "role",
    "grant_basis",
    "access_state",
    "access_classes",
    "matched_permissions",
    "permission_constraints",
    "resource_scope",
)


def _record(value: dict[str, Any]) -> dict[str, Any]:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return {
        **{key: value[key] for key in _RECORD_KEYS if key in value},
        "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def _snapshot(result: AnalysisResult) -> dict[str, Any]:
    report = build_json_report_payload(result)
    return {
        # Read actual keys so omission of a formerly empty metadata field is detected.
        "workloads": {
            resource.address: {
                key: [_record(item) if isinstance(item, dict) else item for item in values]
                for key, values in resource.metadata_snapshot().items()
                if key.startswith("cloud_run_gcs_")
            }
            for resource in result.inventory.resources
            if resource.resource_type == "google_cloud_run_v2_service"
        },
        # Keep sequence order and hash complete records, including evidence and severity.
        "findings": [_record(dict(finding)) for finding in report["findings"]],
        "trust_boundaries": [_record(dict(boundary)) for boundary in report["trust_boundaries"]],
        "operation_gaps": report["operation_gaps"],
    }


def capture_cases() -> tuple[dict[str, Any], dict[str, dict[str, int]]]:
    snapshots: dict[str, Any] = {}
    counts: dict[str, dict[str, int]] = {}
    engine = TfStride()
    for case in CASES:
        with plan_file(build_gcs_case(case)) as path:
            result, counts[case] = analyze_with_counts(path, engine)
        snapshots[case] = _snapshot(result)
    return snapshots, counts


class GcpGcsEvaluationCharacterizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.snapshots, cls.counts = capture_cases()

    def test_outputs_match_pre_optimization_snapshot(self) -> None:
        expected = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(self.snapshots, expected)

    def test_constructor_work_stays_within_recorded_baseline(self) -> None:
        baseline = json.loads(COUNTS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(set(self.counts), set(baseline))
        for case, measured in self.counts.items():
            with self.subTest(case=case):
                self.assertLessEqual(measured["gcs_context_builds"], 6)
            for constructor, count in measured.items():
                with self.subTest(case=case, constructor=constructor):
                    self.assertLessEqual(count, baseline[case][constructor])

    def test_instrumentation_preserves_analysis_output(self) -> None:
        with plan_file(build_gcs_case("mixed")) as path:
            result = TfStride().analyze_plan(path)
        self.assertEqual(_snapshot(result), self.snapshots["mixed"])

    def test_plan_ingestion_preserves_unknown_values(self) -> None:
        for case in ("no_buckets", "unknown_deny", "conditional_unknown"):
            resources = build_gcs_case(case)
            with self.subTest(case=case), plan_file(resources) as path:
                loaded = load_terraform_plan(path).resources
                self.assertEqual(
                    {resource.address: resource.unknown_values for resource in loaded},
                    {resource.address: resource.unknown_values for resource in resources},
                )
                self.assertTrue(any(resource.unknown_values for resource in loaded))

    def test_empty_targets_preserve_empty_metadata_and_identity_uncertainty(self) -> None:
        self.assertEqual(self.counts["no_buckets"]["gcs_context_builds"], 0)
        workloads = self.snapshots["no_buckets"]["workloads"]
        for metadata in workloads.values():
            for key in (
                "cloud_run_gcs_access_paths",
                "cloud_run_gcs_object_deletion_paths",
                "cloud_run_gcs_bucket_topology_destruction_paths",
                "cloud_run_gcs_protected_data_convergences",
            ):
                self.assertEqual(metadata[key], [])
        unknown = workloads["google_cloud_run_v2_service.w2"]
        self.assertIn(
            "google_cloud_run_v2_service.w2: Cloud Run service account is unresolved",
            unknown["cloud_run_gcs_access_path_uncertainties"],
        )

    def test_bucket_free_analysis_constructs_no_grant_contexts_as_workloads_grow(self) -> None:
        engine = TfStride()
        for workloads in (10, 30):
            with self.subTest(workloads=workloads), plan_file(build_benchmark_resources(workloads, "pubsub")) as path:
                result, counts = analyze_with_counts(path, engine)
                self.assertTrue(result.findings)
                self.assertEqual(counts["gcs_context_builds"], 0)

    def test_full_gcs_analysis_has_bounded_context_construction_as_workloads_grow(self) -> None:
        engine = TfStride()
        for workloads in (1, 4, 12):
            with self.subTest(workloads=workloads), plan_file(build_benchmark_resources(workloads, "gcs")) as path:
                result, counts = analyze_with_counts(path, engine)
                self.assertTrue(result.findings)
                # Four decoration stages, one rule preparation, and one gap collection.
                self.assertLessEqual(counts["gcs_context_builds"], 6)

    def test_context_builds_remain_bounded_as_targets_per_workload_increase(self) -> None:
        engine = TfStride()
        required_rules = {
            "gcp-public-workload-sensitive-data-access",
            "gcp-public-cloud-run-gcs-mutation-access",
            "gcp-public-cloud-run-gcs-object-disruption",
            "gcp-public-cloud-run-gcs-bucket-topology-disruption",
        }
        for workloads, buckets in ((1, 1), (1, 6), (4, 6)):
            with (
                self.subTest(workloads=workloads, buckets=buckets),
                plan_file(build_gcs_candidate_resources(workloads, buckets)) as path,
            ):
                result, counts = analyze_with_counts(path, engine)
                self.assertLessEqual(counts["gcs_context_builds"], 6)
                self.assertLessEqual(counts["gcp_resource_index_builds"], 13)
                snapshot = _snapshot(result)
                self.assertEqual(len(snapshot["workloads"]), workloads)
                expected_targets = {f"google_storage_bucket.b{index}" for index in range(buckets)}
                for workload_address, metadata in snapshot["workloads"].items():
                    for field in (
                        "cloud_run_gcs_access_paths",
                        "cloud_run_gcs_object_deletion_paths",
                        "cloud_run_gcs_bucket_topology_destruction_paths",
                    ):
                        self.assertEqual({item["bucket_address"] for item in metadata[field]}, expected_targets, field)
                    finding_rules = {
                        finding.rule_id for finding in result.findings if workload_address in finding.affected_resources
                    }
                    self.assertTrue(required_rules <= finding_rules, workload_address)

    def test_reused_engine_matches_all_characterization_cases_at_the_same_plan_path(self) -> None:
        expected = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
        engine = TfStride()
        with plan_file(build_gcs_case("mixed")) as path:
            for case in (
                "mixed",
                "no_buckets",
                "protected_data",
                "conditional_unknown",
                "unknown_deny",
                "deny",
                "mixed",
            ):
                with self.subTest(case=case):
                    path.write_text(json.dumps(plan_payload(build_gcs_case(case))), encoding="utf-8")
                    result, counts = analyze_with_counts(path, engine)
                    self.assertEqual(_snapshot(result), expected[case])
                    if case == "no_buckets":
                        self.assertEqual(counts["gcs_context_builds"], 0)
                    else:
                        self.assertLessEqual(counts["gcs_context_builds"], 6)

    def test_reused_engine_observes_and_reverses_grant_deny_and_custom_role_edits(self) -> None:
        engine = TfStride()
        expected = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
        for change, case, workload_name in (
            ("grant", "mixed", "w0"),
            ("deny", "deny", "w1"),
            ("custom_role", "mixed", "w2"),
        ):
            with self.subTest(change=change), plan_file(build_gcs_case(case)) as path:
                before = _snapshot(engine.analyze_plan(path))
                self.assertEqual(before, expected[case])
                workload_address = f"google_cloud_run_v2_service.{workload_name}"
                self.assertTrue(before["workloads"][workload_address]["cloud_run_gcs_object_deletion_paths"])
                resources = build_gcs_case(case)
                by_address = {resource.address: resource for resource in resources}
                if change == "grant":
                    by_address["google_storage_bucket_iam_member.local"].values["role"] = "roles/storage.objectViewer"
                elif change == "deny":
                    rule = by_address["google_iam_deny_policy.create"].values["rules"][0]["deny_rule"][0]
                    rule["denied_permissions"] = ["storage.googleapis.com/objects.delete"]
                else:
                    by_address["google_project_iam_custom_role.storage_operator"].values["permissions"] = [
                        "storage.objects.get"
                    ]
                path.write_text(json.dumps(plan_payload(resources)), encoding="utf-8")
                changed = _snapshot(engine.analyze_plan(path))
                self.assertEqual(changed, _snapshot(TfStride().analyze_plan(path)))
                self.assertNotEqual(changed, before)
                metadata = changed["workloads"][workload_address]
                self.assertEqual(metadata["cloud_run_gcs_object_deletion_paths"], [])
                self.assertTrue(metadata["cloud_run_gcs_access_paths"])

                path.write_text(json.dumps(plan_payload(build_gcs_case(case))), encoding="utf-8")
                self.assertEqual(_snapshot(engine.analyze_plan(path)), before)

    def test_mixed_case_exercises_local_inherited_custom_and_disruption_paths(self) -> None:
        workloads = self.snapshots["mixed"]["workloads"]
        access = [path for metadata in workloads.values() for path in metadata["cloud_run_gcs_access_paths"]]
        self.assertIn("storage_bucket_iam", {path["grant_basis"] for path in access})
        self.assertTrue(any(path["role"] == CUSTOM_ROLE for path in access))
        inherited = workloads["google_cloud_run_v2_service.w1"]["cloud_run_gcs_access_paths"]
        self.assertEqual(
            {path["bucket_address"] for path in inherited}, {"google_storage_bucket.b0", "google_storage_bucket.b1"}
        )
        self.assertTrue(all(path["grant_basis"] != "storage_bucket_iam" for path in inherited))
        for field in ("cloud_run_gcs_object_deletion_paths", "cloud_run_gcs_bucket_topology_destruction_paths"):
            self.assertTrue(any(metadata[field] for metadata in workloads.values()), field)

    def test_conditional_and_unknown_case_stays_distinct_from_unconditional_grants(self) -> None:
        workloads = self.snapshots["conditional_unknown"]["workloads"]
        paths = workloads["google_cloud_run_v2_service.w0"]["cloud_run_gcs_access_paths"]
        self.assertEqual(len(paths), 2)
        self.assertEqual({path["access_state"] for path in paths}, {"conditional"})
        self.assertNotEqual(paths[0]["sha256"], paths[1]["sha256"])
        messages = [
            message
            for metadata in workloads.values()
            for key, values in metadata.items()
            if key.endswith("uncertainties")
            for message in values
        ]
        self.assertTrue(any("unresolved" in message or "unknown" in message for message in messages))
        self.assertTrue(self.snapshots["conditional_unknown"]["operation_gaps"]["records"])

    def test_known_deny_removes_create_permission_and_preserves_independent_read_access(self) -> None:
        access = self.snapshots["deny"]["workloads"]["google_cloud_run_v2_service.w1"]["cloud_run_gcs_access_paths"]
        self.assertEqual(len(access), 2)
        for path in access:
            self.assertIn("storage.objects.get", path["matched_permissions"])
            self.assertNotIn("storage.objects.create", path["matched_permissions"])
            self.assertTrue(
                any(
                    decision["permission"] == "storage.objects.create" and decision["state"] == "denied"
                    for decision in path["permission_constraints"]
                )
            )

    def test_unknown_deny_suppresses_paths_and_preserves_uncertainty(self) -> None:
        for metadata in self.snapshots["unknown_deny"]["workloads"].values():
            self.assertEqual(metadata["cloud_run_gcs_access_paths"], [])
            self.assertEqual(metadata["cloud_run_gcs_object_deletion_paths"], [])
            self.assertTrue(metadata["cloud_run_gcs_access_path_uncertainties"])
        self.assertTrue(self.snapshots["unknown_deny"]["operation_gaps"]["records"])

    def test_protected_data_case_has_positive_convergence(self) -> None:
        workload = self.snapshots["protected_data"]["workloads"]["google_cloud_run_v2_service.w0"]
        self.assertEqual(len(workload["cloud_run_gcs_protected_data_convergences"]), 1)
        self.assertTrue(self.snapshots["protected_data"]["findings"])

    def test_case_builders_produce_fresh_deterministic_plans(self) -> None:
        for case in CASES:
            with self.subTest(case=case):
                first = build_gcs_case(case)
                expected = plan_payload(build_gcs_case(case))
                self.assertEqual(plan_payload(first), expected)
                first[0].values.clear()
                self.assertEqual(plan_payload(build_gcs_case(case)), expected)


if __name__ == "__main__":
    if "--write" in sys.argv:
        snapshots, counts = capture_cases()
        SNAPSHOT_PATH.write_text(json.dumps(snapshots, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        COUNTS_PATH.write_text(json.dumps(counts, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"Wrote {SNAPSHOT_PATH} and {COUNTS_PATH}")
    else:
        unittest.main()
