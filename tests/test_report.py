from __future__ import annotations

import json
import unittest
from pathlib import Path

from cloud_threat_modeler.app import CloudThreatModeler
from cloud_threat_modeler.reporting.markdown import MarkdownReportRenderer
from cloud_threat_modeler.reporting.sarif import SarifReportRenderer


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_plan.json"
SAFE_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_safe_plan.json"
NIGHTMARE_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_nightmare_plan.json"
ALB_EC2_RDS_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_alb_ec2_rds_plan.json"
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
        self.assertIn("security group rules", report)
        self.assertIn("## Limitations / Unsupported Resources", report)
        self.assertIn("aws_cloudwatch_log_group.processor", report)

    def test_checked_in_example_reports_match_renderer_output(self) -> None:
        engine = CloudThreatModeler()
        scenarios = {
            SAFE_FIXTURE_PATH: EXAMPLES_DIR / "safe_report.md",
            FIXTURE_PATH: EXAMPLES_DIR / "sample_report.md",
            NIGHTMARE_FIXTURE_PATH: EXAMPLES_DIR / "nightmare_report.md",
            ALB_EC2_RDS_FIXTURE_PATH: EXAMPLES_DIR / "alb_ec2_rds_report.md",
        }

        for fixture_path, report_path in scenarios.items():
            with self.subTest(fixture=fixture_path.name):
                expected = engine.render_markdown_report(fixture_path)
                actual = report_path.read_text(encoding="utf-8")
                self.assertEqual(actual, expected)


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

    def test_app_can_render_sarif_report(self) -> None:
        engine = CloudThreatModeler()
        report = engine.render_sarif_report(FIXTURE_PATH)
        payload = json.loads(report)

        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(payload["runs"][0]["tool"]["driver"]["name"], "cloud-threat-modeler")


if __name__ == "__main__":
    unittest.main()
