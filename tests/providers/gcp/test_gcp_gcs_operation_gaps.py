from __future__ import annotations

import json
import unittest
from dataclasses import replace

from tests.providers.gcp.normalizer_support import _terraform_resource
from tests.providers.gcp.test_gcp_cloud_run_gcs_access_paths import (
    _BUCKET_ADDRESS,
    _BUCKET_NAME,
    _IAM_ADDRESS,
    _WORKLOAD_ADDRESS,
    _bucket,
    _bucket_iam_member,
    _cloud_run,
    _custom_role,
    _normalize,
)
from tests.providers.gcp.test_gcp_gcs_grant_ancestry import _grant, _hierarchy
from tests.providers.gcp.test_gcp_inherited_gcs_custom_roles import _role
from tests.providers.gcp.test_gcp_project_gcs_grants import _deny, _project_grant
from tfstride.analysis.operation_gaps import OperationGapEvidenceState
from tfstride.models import AnalysisResult
from tfstride.providers.catalog import default_provider_operation_gap_factories_by_provider
from tfstride.providers.gcp.gcs_operation_gaps import (
    GCS_ACCESS,
    GCS_BUCKET_TOPOLOGY,
    GCS_GAP_FAMILIES,
    GCS_MUTATION,
    GCS_OBJECT_DELETION,
    collect_gcs_operation_gaps,
)
from tfstride.providers.gcp.metadata import GcpResourceMetadata
from tfstride.providers.gcp.resource_facts import gcp_facts
from tfstride.providers.gcp.resource_types import GcpResourceType
from tfstride.reporting.json_report import render_json
from tfstride.reporting.markdown import render_markdown


def _gap_signature(results):
    return {(gap.family, gap.operation, gap.target_address, gap.scope, gap.reason_code) for gap in results.records}


class GcpGcsOperationGapTests(unittest.TestCase):
    def test_plugin_registers_only_gcp_families_and_complete_grants_are_quiet(self):
        inventory = _normalize([_cloud_run(), _bucket(), _bucket_iam_member()])
        before = dict(inventory.get_by_address(_WORKLOAD_ADDRESS).metadata)
        results = collect_gcs_operation_gaps(inventory)
        self.assertEqual(set(results.reporting_families), set(GCS_GAP_FAMILIES))
        self.assertEqual(results.records, ())
        self.assertEqual(dict(inventory.get_by_address(_WORKLOAD_ADDRESS).metadata), before)
        factories = default_provider_operation_gap_factories_by_provider()
        self.assertEqual(factories["gcp"][0](inventory), results)

    def test_condition_preserves_exact_operation_scope_and_safe_report_explanation(self):
        sentinel = "SECRET-CONDITION-EXPRESSION"
        inventory = _normalize(
            [
                _cloud_run(),
                _bucket(),
                _bucket_iam_member(
                    role="roles/storage.objectCreator",
                    condition={"title": "limited", "expression": sentinel},
                ),
            ]
        )
        results = collect_gcs_operation_gaps(inventory)
        self.assertEqual(
            _gap_signature(results),
            {
                (family, "storage.objects.create", _BUCKET_ADDRESS, f"gs://{_BUCKET_NAME}", "iam_condition_unresolved")
                for family in (GCS_ACCESS, GCS_MUTATION)
            },
        )
        self.assertEqual({gap.evidence_state for gap in results.records}, {OperationGapEvidenceState.CONDITIONAL})
        self.assertTrue(all(gap.resource_address == _WORKLOAD_ADDRESS for gap in results.records))
        self.assertTrue(all(gap.provenance[0].resource_address == _IAM_ADDRESS for gap in results.records))
        report = AnalysisResult("GCS gaps", "plan.json", "plan.json", inventory, [], [], operation_gaps=results)
        payload = json.loads(render_json(report))
        self.assertEqual(payload["analysis_coverage"]["references"]["unresolved_reference_count"], 0)
        self.assertEqual(payload["summary"]["active_findings"], 0)
        self.assertNotIn(sentinel, json.dumps(payload["operation_gaps"]))
        self.assertIn("binding condition", payload["operation_gaps"]["records"][0]["next_step"])
        self.assertIn("## Analysis Gaps", render_markdown(report))
        self.assertNotIn(sentinel, render_markdown(report))

    def test_missing_ancestry_is_specific_to_a_matching_ancestor_grant(self):
        missing = _normalize([_cloud_run(), _bucket(), _grant(scope="folders/100")])
        gaps = collect_gcs_operation_gaps(missing)
        self.assertEqual({gap.reason_code for gap in gaps.records}, {"grant_ancestry_unresolved"})
        self.assertEqual({gap.operation for gap in gaps.records}, {"storage.objects.create"})
        self.assertEqual({gap.family for gap in gaps.records}, {GCS_ACCESS, GCS_MUTATION})
        resolved = _normalize([_cloud_run(), _bucket(), *_hierarchy(), _grant(scope="folders/100")])
        self.assertEqual(collect_gcs_operation_gaps(resolved).records, ())
        unrelated = _grant(scope="folders/100")
        unrelated.values["member"] = "serviceAccount:unrelated@example.com"
        self.assertEqual(collect_gcs_operation_gaps(_normalize([_cloud_run(), _bucket(), unrelated])).records, ())

    def test_unknown_deny_is_local_to_its_permission_and_known_deny_is_quiet(self):
        base = [_cloud_run(), _bucket(), _bucket_iam_member(role="roles/storage.objectAdmin")]
        unknown = _deny(
            permission="storage.googleapis.com/objects.delete",
            unknown={"rules": [{"deny_rule": [{"denied_principals": True}]}]},
        )
        gaps = collect_gcs_operation_gaps(_normalize([*base, unknown]))
        self.assertEqual({gap.operation for gap in gaps.records}, {"storage.objects.delete"})
        self.assertEqual({gap.family for gap in gaps.records}, {GCS_ACCESS, GCS_OBJECT_DELETION})
        self.assertEqual({gap.reason_code for gap in gaps.records}, {"deny_rule_unresolved"})
        self.assertTrue(all(gap.provenance[0].resource_address == unknown.address for gap in gaps.records))
        self.assertEqual(
            collect_gcs_operation_gaps(
                _normalize([*base, _deny(permission="storage.googleapis.com/objects.delete")])
            ).records,
            (),
        )

    def test_deny_dominates_unresolved_ancestry_and_unknown_deny_is_preserved(self):
        grant = _grant(scope="folders/100")
        unresolved = _deny(
            permission="storage.googleapis.com/objects.create",
            unknown={"rules": [{"deny_rule": [{"denied_principals": True}]}]},
        )
        uncertain = collect_gcs_operation_gaps(_normalize([_cloud_run(), _bucket(), grant, unresolved]))
        self.assertEqual(
            {gap.reason_code for gap in uncertain.records},
            {"grant_ancestry_unresolved", "deny_rule_unresolved"},
        )
        self.assertEqual({gap.operation for gap in uncertain.records}, {"storage.objects.create"})
        denied = collect_gcs_operation_gaps(
            _normalize([_cloud_run(), _bucket(), grant, _deny(permission="storage.googleapis.com/objects.create")])
        )
        self.assertEqual(denied.records, ())

    def test_custom_role_ownership_and_lifecycle_keep_known_permissions_local(self):
        for unknown, reason in (
            ("org_id", "custom_role_ownership_unresolved"),
            ("stage", "custom_role_lifecycle_unresolved"),
        ):
            with self.subTest(unknown=unknown):
                role = _role(permissions=["storage.objects.delete", "storage.buckets.delete"], unknown={unknown: True})
                resources = [_cloud_run(), _bucket(), *_hierarchy(), role, _grant(role=role.values["name"])]
                results = collect_gcs_operation_gaps(_normalize(resources))
                self.assertEqual({gap.reason_code for gap in results.records}, {reason})
                self.assertEqual(
                    {gap.operation for gap in results.records}, {"storage.objects.delete", "storage.buckets.delete"}
                )
                self.assertEqual(
                    {gap.family for gap in results.records}, {GCS_ACCESS, GCS_OBJECT_DELETION, GCS_BUCKET_TOPOLOGY}
                )
                self.assertTrue(all(gap.provenance[0].resource_address == role.address for gap in results.records))
                repaired = replace(role, unknown_values={})
                self.assertEqual(
                    collect_gcs_operation_gaps(
                        _normalize([_cloud_run(), _bucket(), *_hierarchy(), repaired, _grant(role=role.values["name"])])
                    ).records,
                    (),
                )

    def test_bucket_local_custom_role_lifecycle_is_scoped_to_its_operations(self):
        role = _custom_role(permissions=["storage.objects.create"])
        uncertain_role = replace(role, unknown_values={"stage": True})
        resources = [_cloud_run(), _bucket(), uncertain_role, _bucket_iam_member(role=role.values["name"])]
        uncertain = collect_gcs_operation_gaps(_normalize(resources))
        self.assertEqual({gap.reason_code for gap in uncertain.records}, {"custom_role_lifecycle_unresolved"})
        self.assertEqual({gap.operation for gap in uncertain.records}, {"storage.objects.create"})
        self.assertEqual({gap.family for gap in uncertain.records}, {GCS_ACCESS, GCS_MUTATION})
        self.assertEqual(
            collect_gcs_operation_gaps(
                _normalize([_cloud_run(), _bucket(), role, _bucket_iam_member(role=role.values["name"])])
            ).records,
            (),
        )

    def test_object_wildcard_does_not_extend_a_gap_to_bucket_deletion(self):
        role = _custom_role(permissions=["storage.objects.*"])
        uncertain_role = replace(role, unknown_values={"stage": True})
        gaps = collect_gcs_operation_gaps(
            _normalize([_cloud_run(), _bucket(), uncertain_role, _bucket_iam_member(role=role.values["name"])])
        )
        self.assertEqual({gap.reason_code for gap in gaps.records}, {"custom_role_lifecycle_unresolved"})
        self.assertNotIn(GCS_BUCKET_TOPOLOGY, {gap.family for gap in gaps.records})
        self.assertTrue(all(gap.operation and gap.operation.startswith("storage.objects.") for gap in gaps.records))

    def test_missing_custom_role_or_policy_document_does_not_invent_permissions(self):
        missing_role = collect_gcs_operation_gaps(
            _normalize([_cloud_run(), _bucket(), *_hierarchy(), _grant(role="organizations/10/roles/missing")])
        )
        self.assertEqual({gap.reason_code for gap in missing_role.records}, {"custom_role_definition_unavailable"})
        self.assertTrue(all(gap.operation is None for gap in missing_role.records))
        policy = _project_grant(kind=GcpResourceType.PROJECT_IAM_POLICY, unknown={"policy_data": True})
        unavailable = collect_gcs_operation_gaps(_normalize([_cloud_run(), _bucket(), policy]))
        self.assertEqual({gap.reason_code for gap in unavailable.records}, {"iam_policy_document_unavailable"})
        self.assertTrue(
            all(gap.operation is None and gap.target_address == _BUCKET_ADDRESS for gap in unavailable.records)
        )
        self.assertTrue(all(gap.provenance[0].evidence_kind.value == "policy_document" for gap in unavailable.records))

    def test_inactive_or_unrelated_custom_role_permissions_do_not_create_generic_gaps(self):
        for role in (
            _role(deleted=True, permissions=["storage.objects.delete"]),
            _role(unknown={"stage": True}, permissions=["logging.sinks.delete"]),
        ):
            with self.subTest(role=role.values):
                resources = [_cloud_run(), _bucket(), *_hierarchy(), role, _grant(role=role.values["name"])]
                self.assertEqual(collect_gcs_operation_gaps(_normalize(resources)).records, ())

    def test_current_evaluation_removes_and_introduces_conditional_gap(self):
        inventory = _normalize([_cloud_run(), _bucket(), _bucket_iam_member(role="roles/storage.objectCreator")])
        source = inventory.get_by_address(_IAM_ADDRESS)
        self.assertIsNotNone(source)
        assert source is not None
        initial = collect_gcs_operation_gaps(inventory)
        self.assertEqual(initial.records, ())
        original = gcp_facts(source).bindings
        gcp_facts(source).set(
            GcpResourceMetadata.IAM_BINDINGS,
            [
                {**binding, "condition": {"title": "limited", "expression": "SECRET"}, "condition_state": "configured"}
                for binding in original
            ],
        )
        self.assertEqual(
            {gap.reason_code for gap in collect_gcs_operation_gaps(inventory).records}, {"iam_condition_unresolved"}
        )
        gcp_facts(source).set(GcpResourceMetadata.IAM_BINDINGS, original)
        self.assertEqual(collect_gcs_operation_gaps(inventory).records, ())

    def test_unrelated_bucket_and_non_cloud_run_resources_do_not_create_generic_warnings(self):
        unrelated_policy = _project_grant(
            project="another-project", kind=GcpResourceType.PROJECT_IAM_POLICY, unknown={"policy_data": True}
        )
        other_bucket = _terraform_resource(
            "google_storage_bucket.other",
            GcpResourceType.STORAGE_BUCKET,
            {"name": "other-data", "project": "another-project", "location": "US"},
        )
        inventory = _normalize([_cloud_run(), _bucket(), _bucket_iam_member(), unrelated_policy, other_bucket])
        gaps = collect_gcs_operation_gaps(inventory)
        self.assertEqual({gap.target_address for gap in gaps.records}, {other_bucket.address})
        self.assertEqual({gap.reason_code for gap in gaps.records}, {"iam_policy_document_unavailable"})
        self.assertEqual(collect_gcs_operation_gaps(_normalize([_bucket(), unrelated_policy])).records, ())
