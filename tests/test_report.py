from __future__ import annotations

import unittest
from pathlib import Path

from cloud_threat_modeler.app import CloudThreatModeler
from cloud_threat_modeler.reporting.markdown import MarkdownReportRenderer


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_plan.json"
SAFE_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_safe_plan.json"
NIGHTMARE_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_nightmare_plan.json"
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
        self.assertIn("## Limitations / Unsupported Resources", report)
        self.assertIn("aws_cloudwatch_log_group.processor", report)

    def test_checked_in_example_reports_match_renderer_output(self) -> None:
        engine = CloudThreatModeler()
        scenarios = {
            SAFE_FIXTURE_PATH: EXAMPLES_DIR / "safe_report.md",
            FIXTURE_PATH: EXAMPLES_DIR / "sample_report.md",
            NIGHTMARE_FIXTURE_PATH: EXAMPLES_DIR / "nightmare_report.md",
        }

        for fixture_path, report_path in scenarios.items():
            with self.subTest(fixture=fixture_path.name):
                expected = engine.render_markdown_report(fixture_path)
                actual = report_path.read_text(encoding="utf-8")
                self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
