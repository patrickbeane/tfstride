from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cloud_threat_modeler.analysis.rule_registry import RulePolicy
from cloud_threat_modeler.app import CloudThreatModeler
from cloud_threat_modeler.filtering import apply_finding_filters, render_baseline
from cloud_threat_modeler.models import Severity
from cloud_threat_modeler.reporting.json_report import JsonReportRenderer, REPORT_FORMAT_VERSION, REPORT_KIND
from cloud_threat_modeler.reporting.markdown import MarkdownReportRenderer
from cloud_threat_modeler.reporting.sarif import SarifReportRenderer


ROOT = Path(__file__).resolve().parents[1]
BASELINE_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_baseline_plan.json"
FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_plan.json"
SAFE_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_safe_plan.json"
NIGHTMARE_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_nightmare_plan.json"
ALB_EC2_RDS_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_alb_ec2_rds_plan.json"
LAMBDA_DEPLOY_ROLE_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_lambda_deploy_role_plan.json"
CROSS_ACCOUNT_TRUST_UNCONSTRAINED_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_cross_account_trust_unconstrained_plan.json"
CROSS_ACCOUNT_TRUST_CONSTRAINED_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_cross_account_trust_constrained_plan.json"
EXAMPLES_DIR = ROOT / "examples"


class MarkdownReportRendererTests(unittest.TestCase):
    def test_report_contains_summary_findings_and_limitations(self) -> None:
        engine = CloudThreatModeler()
        result = engine.analyze_plan(FIXTURE_PATH)
        report = MarkdownReportRenderer().render(result)

        self.assertIn("# Cloud Threat Model Report", report)
        self.assertIn("## Summary", report)
        self.assertIn("## Discovered Trust Boundaries", report)
        self.assertIn("## Findings", report)
        self.assertIn("### High", report)
        self.assertIn("### Medium", report)
        self.assertIn("- Severity reasoning:", report)
        self.assertIn("- Evidence:", report)
        self.assertIn("Cross-account or broad role trust lacks narrowing conditions", report)
        self.assertIn("trust narrowing", report)
        self.assertIn("security group rules", report)
        self.assertIn("## Limitations / Unsupported Resources", report)
        self.assertIn("aws_cloudwatch_log_group.processor", report)

    def test_report_renders_unconstrained_trust_evidence(self) -> None:
        engine = CloudThreatModeler()
        result = engine.analyze_plan(CROSS_ACCOUNT_TRUST_UNCONSTRAINED_FIXTURE_PATH)
        report = MarkdownReportRenderer().render(result)

        self.assertIn("Cross-account or broad role trust lacks narrowing conditions", report)
        self.assertIn("supported narrowing conditions present: false", report)
        self.assertIn("supported narrowing condition keys: none", report)

    def test_report_renders_controls_observed_section(self) -> None:
        engine = CloudThreatModeler()
        safe_report = MarkdownReportRenderer().render(engine.analyze_plan(SAFE_FIXTURE_PATH))
        constrained_trust_report = MarkdownReportRenderer().render(
            engine.analyze_plan(CROSS_ACCOUNT_TRUST_CONSTRAINED_FIXTURE_PATH)
        )

        self.assertIn("## Controls Observed", safe_report)
        self.assertIn("S3 public access is reduced by a public access block", safe_report)
        self.assertIn("RDS instance is private and storage encrypted", safe_report)
        self.assertIn("## Controls Observed", constrained_trust_report)
        self.assertIn(
            "Cross-account or broad role trust is narrowed by assume-role conditions",
            constrained_trust_report,
        )
        self.assertIn(
            "supported narrowing condition keys: aws:SourceAccount, aws:SourceArn, sts:ExternalId",
            constrained_trust_report,
        )

    def test_checked_in_example_reports_match_renderer_output(self) -> None:
        engine = CloudThreatModeler()
        scenarios = {
            BASELINE_FIXTURE_PATH: EXAMPLES_DIR / "baseline_report.md",
            SAFE_FIXTURE_PATH: EXAMPLES_DIR / "safe_report.md",
            FIXTURE_PATH: EXAMPLES_DIR / "sample_report.md",
            NIGHTMARE_FIXTURE_PATH: EXAMPLES_DIR / "nightmare_report.md",
            ALB_EC2_RDS_FIXTURE_PATH: EXAMPLES_DIR / "alb_ec2_rds_report.md",
            LAMBDA_DEPLOY_ROLE_FIXTURE_PATH: EXAMPLES_DIR / "lambda_deploy_role_report.md",
        }

        for fixture_path, report_path in scenarios.items():
            with self.subTest(fixture=fixture_path.name):
                expected = engine.render_markdown_report(fixture_path)
                actual = report_path.read_text(encoding="utf-8")
                self.assertEqual(actual, expected)

    def test_report_surfaces_suppressed_and_baselined_counts_when_filters_apply(self) -> None:
        engine = CloudThreatModeler()
        raw_result = engine.analyze_plan(FIXTURE_PATH)

        with tempfile.TemporaryDirectory() as tmp_dir:
            suppressions_path = Path(tmp_dir) / "suppressions.json"
            baseline_path = Path(tmp_dir) / "baseline.json"
            suppressions_path.write_text(
                json.dumps(
                    {
                        "version": "1.0",
                        "suppressions": [
                            {
                                "rule_id": "aws-database-permissive-ingress",
                                "reason": "Accepted for test coverage.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            unsuppressed_result = apply_finding_filters(raw_result, suppressions_path=suppressions_path)
            baseline_path.write_text(render_baseline(unsuppressed_result.findings[:2]), encoding="utf-8")
            filtered_result = apply_finding_filters(
                raw_result,
                suppressions_path=suppressions_path,
                baseline_path=baseline_path,
            )

        report = MarkdownReportRenderer().render(filtered_result)
        self.assertIn("- Active findings after filters:", report)
        self.assertIn("- Suppressed findings: `1`", report)
        self.assertIn("- Baselined findings: `2`", report)

    def test_report_mentions_when_severity_is_overridden_by_config(self) -> None:
        engine = CloudThreatModeler(
            rule_policy=RulePolicy(severity_overrides={"aws-iam-wildcard-permissions": Severity.LOW})
        )
        result = engine.analyze_plan(BASELINE_FIXTURE_PATH)
        report = MarkdownReportRenderer().render(result)

        self.assertIn("overridden by config", report)


class SarifReportRendererTests(unittest.TestCase):
    def test_sarif_report_contains_rules_results_and_finding_metadata(self) -> None:
        engine = CloudThreatModeler()
        result = engine.analyze_plan(FIXTURE_PATH)
        report = SarifReportRenderer().render(result)
        payload = json.loads(report)

        self.assertEqual(payload["version"], "2.1.0")
        self.assertIn("$schema", payload)
        self.assertEqual(len(payload["runs"]), 1)

        run = payload["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "cloud-threat-modeler")
        self.assertTrue(run["tool"]["driver"]["rules"])
        self.assertEqual(len(run["results"]), len(result.findings))

        database_result = next(
            sarif_result
            for sarif_result in run["results"]
            if sarif_result["ruleId"] == "aws-database-permissive-ingress"
        )
        self.assertEqual(database_result["level"], "error")
        self.assertEqual(database_result["message"]["text"], "Database is reachable from overly permissive sources")
        self.assertEqual(database_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], str(FIXTURE_PATH))
        self.assertEqual(database_result["properties"]["severity"], "high")
        self.assertTrue(database_result["properties"]["evidence"])
        self.assertEqual(database_result["properties"]["severity_reasoning"]["final_score"], 6)

        trust_result = next(
            sarif_result
            for sarif_result in run["results"]
            if sarif_result["ruleId"] == "aws-role-trust-missing-narrowing"
        )
        self.assertEqual(trust_result["level"], "warning")
        self.assertEqual(
            trust_result["message"]["text"],
            "Cross-account or broad role trust lacks narrowing conditions",
        )
        self.assertTrue(trust_result["properties"]["evidence"])

    def test_app_can_render_sarif_report(self) -> None:
        engine = CloudThreatModeler()
        report = engine.render_sarif_report(FIXTURE_PATH)
        payload = json.loads(report)

        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(payload["runs"][0]["tool"]["driver"]["name"], "cloud-threat-modeler")


class JsonReportRendererTests(unittest.TestCase):
    def test_json_report_contains_inventory_findings_and_filter_summary(self) -> None:
        engine = CloudThreatModeler()
        result = engine.analyze_plan(FIXTURE_PATH)
        report = JsonReportRenderer().render(result)
        payload = json.loads(report)

        self.assertEqual(payload["kind"], REPORT_KIND)
        self.assertEqual(payload["version"], REPORT_FORMAT_VERSION)
        self.assertEqual(payload["tool"]["name"], "cloud-threat-modeler")
        self.assertEqual(payload["summary"]["active_findings"], 9)
        self.assertEqual(payload["summary"]["total_findings"], 9)
        self.assertEqual(payload["inventory"]["provider"], "aws")
        self.assertEqual(len(payload["findings"]), 9)
        self.assertTrue(payload["findings"][0]["fingerprint"].startswith("sha256:"))

    def test_json_report_contract_exposes_stable_ui_sections(self) -> None:
        engine = CloudThreatModeler()
        payload = json.loads(JsonReportRenderer().render(engine.analyze_plan(FIXTURE_PATH)))

        self.assertEqual(
            list(payload),
            [
                "kind",
                "version",
                "tool",
                "title",
                "analyzed_file",
                "analyzed_path",
                "summary",
                "filtering",
                "inventory",
                "trust_boundaries",
                "findings",
                "suppressed_findings",
                "baselined_findings",
                "observations",
                "limitations",
            ],
        )
        self.assertEqual(
            list(payload["summary"]),
            [
                "normalized_resources",
                "unsupported_resources",
                "trust_boundaries",
                "active_findings",
                "total_findings",
                "suppressed_findings",
                "baselined_findings",
                "severity_counts",
            ],
        )
        self.assertEqual(
            payload["summary"]["severity_counts"],
            {"high": 3, "medium": 6, "low": 0},
        )
        self.assertEqual(
            list(payload["inventory"]),
            ["provider", "unsupported_resources", "metadata", "resources"],
        )
        self.assertEqual(
            list(payload["findings"][0]),
            [
                "fingerprint",
                "title",
                "rule_id",
                "category",
                "severity",
                "affected_resources",
                "trust_boundary_id",
                "rationale",
                "recommended_mitigation",
                "evidence",
                "severity_reasoning",
            ],
        )

    def test_json_report_sorts_inventory_resources_and_trust_boundaries_for_stable_consumers(self) -> None:
        engine = CloudThreatModeler()
        payload = json.loads(JsonReportRenderer().render(engine.analyze_plan(FIXTURE_PATH)))

        resource_addresses = [resource["address"] for resource in payload["inventory"]["resources"]]
        boundary_ids = [boundary["identifier"] for boundary in payload["trust_boundaries"]]

        self.assertEqual(resource_addresses, sorted(resource_addresses))
        self.assertEqual(boundary_ids, sorted(boundary_ids))

    def test_json_report_includes_suppressed_and_baselined_findings(self) -> None:
        engine = CloudThreatModeler()
        raw_result = engine.analyze_plan(FIXTURE_PATH)

        with tempfile.TemporaryDirectory() as tmp_dir:
            suppressions_path = Path(tmp_dir) / "suppressions.json"
            baseline_path = Path(tmp_dir) / "baseline.json"
            suppressions_path.write_text(
                json.dumps(
                    {
                        "version": "1.0",
                        "suppressions": [
                            {
                                "rule_id": "aws-database-permissive-ingress",
                                "reason": "Accepted for test coverage.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            unsuppressed_result = apply_finding_filters(raw_result, suppressions_path=suppressions_path)
            baseline_path.write_text(render_baseline(unsuppressed_result.findings[:2]), encoding="utf-8")
            filtered_result = apply_finding_filters(
                raw_result,
                suppressions_path=suppressions_path,
                baseline_path=baseline_path,
            )

        payload = json.loads(JsonReportRenderer().render(filtered_result))
        self.assertEqual(payload["summary"]["total_findings"], 9)
        self.assertEqual(payload["summary"]["suppressed_findings"], 1)
        self.assertEqual(payload["summary"]["baselined_findings"], 2)
        self.assertEqual(len(payload["suppressed_findings"]), 1)
        self.assertEqual(len(payload["baselined_findings"]), 2)

    def test_json_report_serializes_policy_statement_conditions(self) -> None:
        payload = {
            "format_version": "1.2",
            "terraform_version": "1.8.5",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_lambda_permission.invoke",
                            "mode": "managed",
                            "type": "aws_lambda_permission",
                            "name": "invoke",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "id": "permission-1",
                                "statement_id": "allow-events",
                                "action": "lambda:InvokeFunction",
                                "function_name": "processor",
                                "principal": "events.amazonaws.com",
                                "source_arn": "arn:aws:events:us-east-1:111122223333:rule/release-trigger",
                                "source_account": "111122223333",
                            },
                        }
                    ]
                }
            },
        }

        engine = CloudThreatModeler()
        with tempfile.TemporaryDirectory() as tmp_dir:
            plan_path = Path(tmp_dir) / "plan.json"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")
            result = engine.analyze_plan(plan_path)

        rendered = json.loads(JsonReportRenderer().render(result))
        lambda_permission = next(
            resource
            for resource in rendered["inventory"]["resources"]
            if resource["address"] == "aws_lambda_permission.invoke"
        )

        self.assertEqual(
            lambda_permission["policy_statements"][0]["conditions"],
            [
                {
                    "operator": "ArnLike",
                    "key": "aws:SourceArn",
                    "values": ["arn:aws:events:us-east-1:111122223333:rule/release-trigger"],
                },
                {
                    "operator": "StringEquals",
                    "key": "aws:SourceAccount",
                    "values": ["111122223333"],
                },
            ],
        )


if __name__ == "__main__":
    unittest.main()
