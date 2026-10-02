from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError, replace
from itertools import permutations

from tfstride.analysis.coverage import build_analysis_coverage
from tfstride.analysis.operation_gaps import (
    OperationGap,
    OperationGapEvidenceKind,
    OperationGapEvidenceState,
    OperationGapFamily,
    OperationGapProvenance,
    OperationGapResults,
)
from tfstride.filtering import apply_finding_filters
from tfstride.models import AnalysisResult, ResourceInventory

_FAMILY = OperationGapFamily("aws", "s3_mutation")
_OTHER_FAMILY = OperationGapFamily("aws", "s3_object_deletion")
_POLICY = OperationGapProvenance(
    resource_address="aws_iam_role.runtime",
    evidence_kind=OperationGapEvidenceKind.POLICY_DOCUMENT,
    field_path=("inline_policy", 0, "policy"),
)
_REFERENCE = OperationGapProvenance(
    resource_address="aws_ecs_task_definition.app",
    evidence_kind=OperationGapEvidenceKind.CONFIGURATION_REFERENCE,
    field_path=("task_role_arn",),
)


def _gap() -> OperationGap:
    return OperationGap(
        family=_FAMILY,
        resource_address="aws_ecs_task_definition.app",
        relationship="runtime_identity_to_storage",
        operation="s3:PutObject",
        target_address="aws_s3_bucket.data",
        reason_code="policy_document_unavailable",
        evidence_state=OperationGapEvidenceState.MISSING,
        provenance=(_POLICY,),
    )


class OperationGapTests(unittest.TestCase):
    def test_permutations_and_duplicate_reports_preserve_gaps_and_all_provenance(self) -> None:
        original = _gap()
        alternative = replace(original, provenance=(_REFERENCE, _POLICY, _REFERENCE))
        other = replace(original, operation="s3:PutObjectAcl")
        expected = OperationGapResults((_FAMILY,), (original, alternative, other))

        for records in permutations((original, alternative, other, original)):
            with self.subTest(records=records):
                actual = OperationGapResults((_FAMILY, _FAMILY), records)
                self.assertEqual(actual, expected)
                self.assertEqual(len(actual.records), 2)
                self.assertEqual(actual.reporting_families, (_FAMILY,))
                self.assertEqual(set(actual.records[0].provenance), {_POLICY, _REFERENCE})
                self.assertEqual(len(actual.records[0].provenance), 2)
        self.assertEqual(original.provenance, (_POLICY,))

    def test_distinct_security_questions_do_not_deduplicate(self) -> None:
        original = _gap()
        alternatives = (
            replace(original, family=_OTHER_FAMILY),
            replace(original, family=OperationGapFamily("other_provider", _FAMILY.name)),
            replace(original, resource_address="aws_ecs_task_definition.other"),
            replace(original, target_address="aws_s3_bucket.other"),
            replace(original, target_address=None),
            replace(original, operation="s3:DeleteObject"),
            replace(original, operation=None),
            replace(original, relationship="runtime_identity_attachment"),
            replace(original, reason_code="policy_document_incomplete"),
            replace(original, evidence_state=OperationGapEvidenceState.UNKNOWN),
        )
        for alternative in alternatives:
            with self.subTest(alternative=alternative):
                results = OperationGapResults((_FAMILY, alternative.family), (alternative, original))
                self.assertEqual(len(results.records), 2)
                self.assertEqual(
                    results,
                    OperationGapResults((alternative.family, _FAMILY), (original, alternative)),
                )

    def test_unrelated_family_does_not_change_existing_gap(self) -> None:
        original = _gap()
        unrelated = replace(original, family=_OTHER_FAMILY, operation="s3:DeleteObject")
        before = OperationGapResults((_FAMILY,), (original,))
        after = OperationGapResults((_OTHER_FAMILY, _FAMILY), (unrelated, original))
        self.assertEqual(tuple(gap for gap in after.records if gap.family == _FAMILY), before.records)

    def test_empty_results_distinguish_no_reporting_from_a_producer_that_ran(self) -> None:
        absent = OperationGapResults()
        reported = OperationGapResults((_FAMILY,))
        self.assertEqual(absent.records, ())
        self.assertEqual(reported.records, ())
        self.assertEqual(absent.reporting_families, ())
        self.assertEqual(reported.reporting_families, (_FAMILY,))
        self.assertNotEqual(absent, reported)
        self.assertNotIn(_OTHER_FAMILY, reported.reporting_families)

    def test_gaps_cannot_silently_register_reporting_coverage(self) -> None:
        with self.assertRaisesRegex(ValueError, "no reporting coverage"):
            OperationGapResults(records=(_gap(),))
        with self.assertRaisesRegex(ValueError, "no reporting coverage"):
            OperationGapResults((_OTHER_FAMILY,), (_gap(),))

    def test_fresh_evaluation_does_not_accumulate_previous_gaps(self) -> None:
        previous = OperationGapResults((_FAMILY,), (_gap(),))
        current = OperationGapResults((_FAMILY,))
        repeated = OperationGapResults(previous.reporting_families, previous.records)
        self.assertEqual(current.records, ())
        self.assertEqual(previous, repeated)
        self.assertEqual(len(previous.records), 1)
        with self.assertRaises(FrozenInstanceError):
            previous.records = ()
        with self.assertRaises(FrozenInstanceError):
            previous.records[0].reason_code = "changed"

    def test_provenance_paths_are_stable_with_field_names_and_sequence_indexes(self) -> None:
        locations = tuple(
            replace(_POLICY, field_path=("inline_policy", segment, "policy")) for segment in (10, 2, "policy")
        )
        gap = replace(_gap(), provenance=locations)
        self.assertEqual([p.field_path[1] for p in gap.provenance], ["policy", 2, 10])
        self.assertEqual(gap, replace(gap, provenance=tuple(reversed(locations))))

    def test_provenance_has_no_raw_value_or_metadata_attachment(self) -> None:
        sentinel = "SECRET-SENTINEL-do-not-serialize"
        for forbidden in ("value", "planned_value", "policy_document", "condition_values", "metadata", "expression"):
            with self.subTest(field=forbidden), self.assertRaises(TypeError):
                OperationGapProvenance(
                    resource_address=_POLICY.resource_address,
                    evidence_kind=_POLICY.evidence_kind,
                    **{forbidden: sentinel},
                )
        for path in ((sentinel,), ("${var.secret}",), (-1,), (True,)):
            with self.subTest(path=path), self.assertRaises(ValueError):
                replace(_POLICY, field_path=path)

    def test_states_do_not_accept_authorization_decisions(self) -> None:
        for state in ("allowed", "denied", "complete", "not_granted"):
            with self.subTest(state=state), self.assertRaises(ValueError):
                replace(_gap(), evidence_state=state)

    def test_contract_requires_codes_and_exact_operations(self) -> None:
        for changes in (
            {"reason_code": "Policy contains secret value"},
            {"relationship": ""},
            {"operation": "s3:Get*"},
            {"operation": ""},
            {"resource_address": ""},
            {"target_address": "target\nraw policy"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(_gap(), **changes)
        with self.assertRaises(ValueError):
            OperationGapFamily("aws", "")

    def test_gap_results_are_separate_from_findings_and_reference_coverage(self) -> None:
        inventory = ResourceInventory(provider="aws", resources=[])
        result = AnalysisResult(
            title="Operation gap contract",
            analyzed_file="plan.json",
            analyzed_path="plan.json",
            inventory=inventory,
            trust_boundaries=[],
            findings=[],
            analysis_coverage=build_analysis_coverage(inventory),
            operation_gaps=OperationGapResults((_FAMILY,), (_gap(),)),
        )
        filtered = apply_finding_filters(result)
        self.assertEqual(filtered.findings, [])
        self.assertEqual(filtered.observations, [])
        self.assertEqual(filtered.suppressed_findings, [])
        self.assertEqual(filtered.baselined_findings, [])
        self.assertEqual(filtered.analysis_coverage.references.unresolved_reference_count, 0)
        self.assertEqual(filtered.filter_summary["total_findings"], 0)
        self.assertEqual(filtered.operation_gaps, result.operation_gaps)
        self.assertEqual(len(filtered.operation_gaps.records), 1)

    def test_existing_analysis_result_construction_does_not_claim_reporting_coverage(self) -> None:
        result = AnalysisResult(
            title="Existing caller",
            analyzed_file="plan.json",
            analyzed_path="plan.json",
            inventory=ResourceInventory(provider="aws", resources=[]),
            trust_boundaries=[],
            findings=[],
        )
        self.assertEqual(result.operation_gaps, OperationGapResults())
