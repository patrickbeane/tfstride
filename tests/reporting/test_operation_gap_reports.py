from __future__ import annotations

import json
import unittest
from dataclasses import dataclass, field, replace
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.providers.aws.test_aws_ecs_s3_access_paths import (
    _BUCKET_ARN,
    _TASK_ROLE_ARN,
    _role,
    _role_policy_attachment,
    _statement,
)
from tests.providers.aws.test_aws_s3_broad_grants import _resources
from tfstride.analysis.operation_gaps import (
    OperationGap,
    OperationGapEvidenceKind,
    OperationGapEvidenceState,
    OperationGapFamily,
    OperationGapProvenance,
    OperationGapResults,
)
from tfstride.analysis.rule_registry import RulePolicy
from tfstride.app import TfStride
from tfstride.filtering import apply_finding_filters
from tfstride.models import AnalysisResult, NormalizedResource, ResourceCategory, ResourceInventory
from tfstride.reporting.json_report import build_json_report_payload, render_json
from tfstride.reporting.markdown import render_markdown
from tfstride.reporting.operation_gaps import serialize_operation_gaps
from tfstride.reporting.sarif import SARIF_ANALYSIS_GAP_RULE_ID, render_sarif

_FAMILY = OperationGapFamily("aws", "ecs_s3_mutation")
_POLICY_SENTINEL = "POLICY-BODY-SENTINEL-never-in-gaps"
_SECRET_SENTINEL = "SECRET-VALUE-SENTINEL-never-in-gaps"
_METADATA_SENTINEL = "ARBITRARY-METADATA-SENTINEL-never-in-gaps"


def _gap() -> OperationGap:
    return OperationGap(
        family=_FAMILY,
        resource_address="aws_ecs_task_definition.orders",
        relationship="runtime_identity_to_storage",
        operation="s3:PutObject",
        target_address="aws_s3_bucket.orders",
        scope=f"{_BUCKET_ARN}/public/*",
        reason_code="policy_condition_unresolved",
        evidence_state=OperationGapEvidenceState.CONDITIONAL,
        provenance=(
            OperationGapProvenance(
                "aws_iam_role.orders_task", OperationGapEvidenceKind.POLICY_DOCUMENT, ("inline_policy", 0, "policy")
            ),
        ),
    )


def _result(gaps: OperationGapResults) -> AnalysisResult:
    return AnalysisResult(
        title="Gap reporting",
        analyzed_file="plan.json",
        analyzed_path="plan.json",
        inventory=ResourceInventory(provider="aws", resources=[]),
        findings=[],
        trust_boundaries=[],
        operation_gaps=gaps,
    )


def _analyze(statements, *, boundary=False, missing_policy=False) -> AnalysisResult:
    resources = _resources(actions="s3:PutObject", resource=f"{_BUCKET_ARN}/public/*")
    resources[2] = _role("orders_task", _TASK_ROLE_ARN, statements)
    if boundary:
        resources[2].values["permissions_boundary"] = "arn:aws:iam::111122223333:policy/boundary"
    if missing_policy:
        resources.append(_role_policy_attachment(_TASK_ROLE_ARN, "arn:aws:iam::111122223333:policy/external"))
    plan = {
        "terraform_version": "1.9.0",
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": resource.address,
                        "mode": resource.mode,
                        "type": resource.resource_type,
                        "name": resource.name,
                        "provider_config_key": resource.provider_config_key,
                        "expressions": {},
                    }
                    for resource in resources
                ]
            }
        },
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": resource.address,
                        "mode": resource.mode,
                        "type": resource.resource_type,
                        "name": resource.name,
                        "provider_name": resource.provider_name,
                        "values": resource.values,
                    }
                    for resource in resources
                ]
            }
        },
    }
    with TemporaryDirectory() as temp:
        path = Path(temp) / "plan.json"
        path.write_text(json.dumps(plan), encoding="utf-8")
        return TfStride(rule_policy=RulePolicy(enabled_rule_ids=frozenset())).analyze_plan(path)


class OperationGapReportTests(unittest.TestCase):
    def test_sarif_reports_gap_as_severity_free_review_separate_from_findings(self):
        gap = _gap()
        result = _result(OperationGapResults((_FAMILY,), (gap,)))
        run = json.loads(render_sarif(result))["runs"][0]

        self.assertEqual(result.findings, [])
        self.assertEqual(
            run["properties"]["operation_gap_reporting_families"], [{"provider": "aws", "name": _FAMILY.name}]
        )
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)
        rule = run["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["id"], SARIF_ANALYSIS_GAP_RULE_ID)
        self.assertEqual(rule["defaultConfiguration"], {"level": "none"})
        self.assertEqual(rule["properties"]["tags"], ["analysis-gap", "coverage"])

        self.assertEqual(len(run["results"]), 1)
        diagnostic = run["results"][0]
        self.assertEqual(diagnostic["ruleId"], SARIF_ANALYSIS_GAP_RULE_ID)
        self.assertEqual(diagnostic["ruleIndex"], 0)
        self.assertEqual(diagnostic["kind"], "review")
        self.assertEqual(diagnostic["level"], "none")
        self.assertNotIn("severity", diagnostic)
        self.assertNotIn("severity", diagnostic["properties"])
        self.assertNotIn("stride_category", diagnostic["properties"])
        self.assertIn("Could not assess s3:PutObject", diagnostic["message"]["text"])
        self.assertIn("A policy condition affecting this operation", diagnostic["message"]["text"])
        self.assertEqual(diagnostic["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "plan.json")
        self.assertEqual(diagnostic["locations"][0]["logicalLocations"][0]["fullyQualifiedName"], gap.resource_address)
        self.assertEqual(
            diagnostic["relatedLocations"][0]["logicalLocations"][0]["fullyQualifiedName"], gap.target_address
        )
        properties = diagnostic["properties"]
        self.assertEqual(properties["result_type"], "analysis_gap")
        self.assertEqual(properties["family"], {"provider": "aws", "name": _FAMILY.name})
        for key in (
            "resource_address",
            "relationship",
            "operation",
            "target_address",
            "scope",
            "reason_code",
            "evidence_state",
            "provenance",
        ):
            self.assertEqual(properties[key], serialize_operation_gaps(result.operation_gaps)["records"][0][key])

    def test_sarif_retains_findings_and_gaps_as_distinct_results(self):
        from tests.helpers.paths import FIXTURES_DIR

        finding_result = TfStride().analyze_plan(FIXTURES_DIR / "aws" / "sample_aws_plan.json")
        finding_count = len(finding_result.findings)
        finding_result.operation_gaps = OperationGapResults((_FAMILY,), (_gap(),))
        run = json.loads(render_sarif(finding_result))["runs"][0]

        self.assertEqual(len(run["results"]), finding_count + 1)
        self.assertEqual(run["results"][-1]["ruleId"], SARIF_ANALYSIS_GAP_RULE_ID)
        self.assertEqual(run["results"][-1]["ruleIndex"], len(run["tool"]["driver"]["rules"]) - 1)
        self.assertTrue(all(item["ruleId"] != SARIF_ANALYSIS_GAP_RULE_ID for item in run["results"][:-1]))
        self.assertTrue(all(item["level"] in {"error", "warning", "note"} for item in run["results"][:-1]))

    def test_sarif_preserves_missing_operation_and_target_without_inventing_associations(self):
        gap = replace(_gap(), operation=None, target_address=None, scope=None)
        run = json.loads(render_sarif(_result(OperationGapResults((_FAMILY,), (gap,)))))["runs"][0]
        diagnostic = run["results"][0]

        self.assertNotIn("relatedLocations", diagnostic)
        self.assertEqual(diagnostic["properties"]["relationship"], gap.relationship)
        self.assertIsNone(diagnostic["properties"]["operation"])
        self.assertIsNone(diagnostic["properties"]["target_address"])
        self.assertIsNone(diagnostic["properties"]["scope"])

    def test_zero_findings_and_zero_unresolved_references_still_explain_boundary_gap(self):
        result = _analyze([_statement("Allow", "s3:PutObject", f"{_BUCKET_ARN}/public/*")], boundary=True)
        payload = json.loads(render_json(apply_finding_filters(result)))
        self.assertEqual(payload["summary"]["active_findings"], 0)
        self.assertEqual(payload["summary"]["total_findings"], 0)
        self.assertEqual(payload["analysis_coverage"]["references"]["unresolved_reference_count"], 0)
        gaps = payload["operation_gaps"]
        self.assertEqual(len(gaps["reporting_families"]), 5)
        self.assertEqual(len(gaps["records"]), 2)
        for gap in gaps["records"]:
            self.assertEqual(gap["resource_address"], "aws_ecs_task_definition.orders")
            self.assertEqual(gap["target_address"], "aws_s3_bucket.orders")
            self.assertEqual(gap["operation"], "s3:PutObject")
            self.assertEqual(gap["scope"], f"{_BUCKET_ARN}/public/*")
            self.assertEqual(gap["reason_code"], "permissions_boundary_intersection_unmodeled")
            self.assertIn("not modeled", gap["explanation"])
            self.assertIn("Review the boundary together with the identity and bucket policies", gap["next_step"])
            self.assertEqual(gap["provenance"][0]["field_path"], ["permissions_boundary"])
        markdown = render_markdown(result)
        self.assertIn("**0 findings**", markdown)
        self.assertIn("Recorded unresolved modeled references: `0`", markdown)
        self.assertIn("2 modeled relationships could not be fully assessed", markdown)
        self.assertIn("`s3:PutObject`", markdown)
        self.assertIn(f"`{_BUCKET_ARN}/public/*`", markdown)
        self.assertIn("aws_iam_role.orders_task.permissions_boundary", markdown)
        self.assertLess(markdown.index("## Analysis Gaps"), markdown.index("## Findings"))
        self.assertNotIn("s3:GetObject", markdown)

    def test_fully_evaluated_denial_is_not_a_reported_gap(self):
        result = _analyze(
            [_statement("Allow", "s3:PutObject", "*"), _statement("Deny", "s3:PutObject", "*")], boundary=True
        )
        payload = json.loads(render_json(result))
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["operation_gaps"]["records"], [])
        self.assertEqual(len(payload["operation_gaps"]["reporting_families"]), 5)
        self.assertNotIn("## Analysis Gaps", render_markdown(result))

    def test_missing_document_does_not_invent_an_operation_target_or_scope(self):
        result = _analyze(None, missing_policy=True)
        gaps = json.loads(render_json(result))["operation_gaps"]["records"]
        self.assertTrue(gaps)
        for gap in gaps:
            self.assertEqual(gap["reason_code"], "identity_policy_document_unavailable")
            self.assertIsNone(gap["operation"])
            self.assertIsNone(gap["target_address"])
            self.assertIsNone(gap["scope"])
            self.assertIn("attached policy document", gap["next_step"])
        markdown = render_markdown(result)
        self.assertIn("Operation undetermined", markdown)
        self.assertIn("No unique modeled target established", markdown)
        self.assertNotIn("scope `", markdown)

    def test_absent_producers_and_empty_results_do_not_claim_universal_coverage(self):
        absent = _result(OperationGapResults())
        ran = _result(OperationGapResults((_FAMILY,)))
        self.assertEqual(json.loads(render_json(absent))["operation_gaps"], {"reporting_families": [], "records": []})
        self.assertEqual(
            json.loads(render_json(ran))["operation_gaps"]["reporting_families"],
            [{"provider": "aws", "name": "ecs_s3_mutation"}],
        )
        self.assertNotIn("## Analysis Gaps", render_markdown(absent))
        self.assertNotIn("## Analysis Gaps", render_markdown(ran))
        for result, expected_families in ((absent, []), (ran, [{"provider": "aws", "name": _FAMILY.name}])):
            with self.subTest(result=result):
                run = json.loads(render_sarif(result))["runs"][0]
                self.assertEqual(run["results"], [])
                self.assertEqual(run["tool"]["driver"]["rules"], [])
                self.assertEqual(run["properties"]["operation_gap_reporting_families"], expected_families)

    def test_unknown_reason_or_provider_has_safe_generic_explanation(self):
        for gap in (
            replace(_gap(), reason_code="future_reason"),
            replace(_gap(), family=OperationGapFamily("future_provider", "operations")),
        ):
            with self.subTest(gap=gap):
                payload = serialize_operation_gaps(OperationGapResults((gap.family,), (gap,)))["records"][0]
                self.assertEqual(payload["reason_code"], gap.reason_code)
                self.assertEqual(
                    payload["explanation"], "The reporting family could not complete this relationship assessment."
                )
                self.assertIn("Review the referenced evidence locations", payload["next_step"])

    def test_order_deduplication_and_detached_provenance_survive_serialization(self):
        first = _gap()
        other = replace(first, scope=f"{_BUCKET_ARN}/private/*")
        results = OperationGapResults((_FAMILY,), (first, other, first))
        reordered = OperationGapResults((_FAMILY, _FAMILY), (other, first))
        self.assertEqual(render_json(_result(results)), render_json(_result(reordered)))
        self.assertEqual(render_markdown(_result(results)), render_markdown(_result(reordered)))
        self.assertEqual(render_sarif(_result(results)), render_sarif(_result(reordered)))
        payload = serialize_operation_gaps(results)
        self.assertEqual(len(payload["records"]), 2)
        payload["records"][0]["provenance"][0]["field_path"].append("mutated")
        self.assertEqual(results.records[0].provenance[0].field_path, ("inline_policy", 0, "policy"))

    def test_new_internal_fields_cannot_silently_expand_gap_serialization(self):
        @dataclass(frozen=True)
        class InternalGap(OperationGap):
            policy_body: str = _POLICY_SENTINEL
            secret_value: str = _SECRET_SENTINEL
            metadata: dict = field(default_factory=lambda: {"arbitrary": _METADATA_SENTINEL}, compare=False)

        @dataclass(frozen=True)
        class InternalProvenance(OperationGapProvenance):
            value: str = _SECRET_SENTINEL

        base = _gap()
        gap = InternalGap(
            family=base.family,
            resource_address=base.resource_address,
            relationship=base.relationship,
            reason_code=base.reason_code,
            evidence_state=base.evidence_state,
            provenance=(InternalProvenance("aws_iam_role.orders_task", OperationGapEvidenceKind.POLICY_DOCUMENT),),
        )
        result = _result(OperationGapResults((_FAMILY,), (gap,)))
        for rendered in (render_json(result), render_markdown(result), render_sarif(result)):
            for sentinel in (_POLICY_SENTINEL, _SECRET_SENTINEL, _METADATA_SENTINEL):
                with self.subTest(sentinel=sentinel):
                    self.assertNotIn(sentinel, rendered)
        record = build_json_report_payload(result)["operation_gaps"]["records"][0]
        self.assertEqual(
            set(record),
            {
                "family",
                "resource_address",
                "relationship",
                "operation",
                "target_address",
                "scope",
                "reason_code",
                "evidence_state",
                "provenance",
                "explanation",
                "next_step",
            },
        )
        self.assertEqual(set(record["provenance"][0]), {"resource_address", "evidence_kind", "field_path"})

    def test_gap_output_does_not_look_up_policy_bodies_secrets_or_arbitrary_metadata(self):
        result = _analyze(
            [
                _statement(
                    "Allow",
                    "s3:PutObject",
                    f"{_BUCKET_ARN}/public/*",
                    condition={"StringEquals": {"aws:SourceVpc": _SECRET_SENTINEL}},
                )
            ]
        )
        unrelated = NormalizedResource(
            address="aws_s3_bucket.unrelated",
            provider="aws",
            resource_type="aws_s3_bucket",
            name="unrelated",
            category=ResourceCategory.DATA,
            metadata={"policy_document": {"raw": _POLICY_SENTINEL}, "arbitrary": _METADATA_SENTINEL},
        )
        result.inventory = ResourceInventory(provider="aws", resources=[*result.inventory.resources, unrelated])
        payload = json.loads(render_json(result))
        self.assertTrue(payload["operation_gaps"]["records"])
        # The legacy inventory intentionally exports policies/metadata. The new
        # gap section must never traverse or copy that evidence into its output.
        for sentinel in (_POLICY_SENTINEL, _SECRET_SENTINEL, _METADATA_SENTINEL):
            with self.subTest(sentinel=sentinel):
                self.assertIn(sentinel, json.dumps(payload["inventory"]))
                self.assertNotIn(sentinel, json.dumps(payload["operation_gaps"]))
                self.assertNotIn(sentinel, render_markdown(result))
                self.assertNotIn(sentinel, render_sarif(result))
        self.assertIn("intended request context", payload["operation_gaps"]["records"][0]["next_step"])

    def test_markdown_keeps_scope_and_resource_markup_literal(self):
        gap = replace(_gap(), scope=f"{_BUCKET_ARN}/`[link](https://example.invalid)<script>/*")
        markdown = render_markdown(_result(OperationGapResults((_FAMILY,), (gap,))))
        self.assertIn(f"scope ``{gap.scope}``", markdown)
