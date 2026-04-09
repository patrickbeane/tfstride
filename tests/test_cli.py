from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from cloud_threat_modeler.cli import INPUT_ERROR_EXIT_CODE, POLICY_VIOLATION_EXIT_CODE, main
from cloud_threat_modeler.config import CONFIG_FILENAME


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "sample_aws_plan.json"
SAFE_FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "sample_aws_safe_plan.json"
CROSS_ACCOUNT_TRUST_UNCONSTRAINED_FIXTURE_PATH = (
    Path(__file__).resolve().parents[1] / "fixtures" / "sample_aws_cross_account_trust_unconstrained_plan.json"
)


class CliTests(unittest.TestCase):
    def test_cli_writes_markdown_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "report.md"
            exit_code = main([str(FIXTURE_PATH), "--output", str(output_path), "--title", "Sample Threat Model"])

            self.assertEqual(exit_code, 0)
            report = output_path.read_text(encoding="utf-8")

        self.assertIn("# Sample Threat Model", report)
        self.assertIn("Database is reachable from overly permissive sources", report)

    def test_cli_fail_on_threshold_returns_policy_exit_code(self) -> None:
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()

        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            exit_code = main([str(FIXTURE_PATH), "--fail-on", "high"])

        self.assertEqual(exit_code, POLICY_VIOLATION_EXIT_CODE)
        self.assertIn("## Findings", stdout_buffer.getvalue())
        self.assertIn("Policy gate failed", stderr_buffer.getvalue())
        self.assertIn("3 high", stderr_buffer.getvalue())

    def test_cli_fail_on_high_does_not_fail_safe_fixture(self) -> None:
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()

        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            exit_code = main([str(SAFE_FIXTURE_PATH), "--fail-on", "high"])

        self.assertEqual(exit_code, 0)
        self.assertIn("## Findings", stdout_buffer.getvalue())
        self.assertEqual("", stderr_buffer.getvalue())

    def test_cli_fail_on_threshold_still_writes_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "report.md"
            stderr_buffer = io.StringIO()

            with redirect_stderr(stderr_buffer):
                exit_code = main([str(FIXTURE_PATH), "--output", str(output_path), "--fail-on", "medium"])

            self.assertEqual(exit_code, POLICY_VIOLATION_EXIT_CODE)
            self.assertTrue(output_path.exists())
            self.assertIn("Policy gate failed", stderr_buffer.getvalue())
            self.assertIn("6 medium", stderr_buffer.getvalue())

    def test_cli_can_write_sarif_alongside_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "report.md"
            sarif_output_path = Path(tmp_dir) / "report.sarif"

            exit_code = main(
                [
                    str(FIXTURE_PATH),
                    "--output",
                    str(output_path),
                    "--sarif-output",
                    str(sarif_output_path),
                ]
            )

            self.assertEqual(exit_code, 0)
            self.assertTrue(output_path.exists())
            self.assertTrue(sarif_output_path.exists())

            sarif_payload = json.loads(sarif_output_path.read_text(encoding="utf-8"))
            self.assertEqual(sarif_payload["version"], "2.1.0")
            self.assertEqual(sarif_payload["runs"][0]["tool"]["driver"]["name"], "cloud-threat-modeler")

    def test_cli_can_write_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_output_path = Path(tmp_dir) / "report.json"

            exit_code = main(
                [
                    str(FIXTURE_PATH),
                    "--quiet",
                    "--json-output",
                    str(json_output_path),
                ]
            )

            self.assertEqual(exit_code, 0)
            self.assertTrue(json_output_path.exists())

            payload = json.loads(json_output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["tool"]["name"], "cloud-threat-modeler")
            self.assertEqual(payload["summary"]["active_findings"], 9)
            self.assertEqual(payload["summary"]["total_findings"], 9)
            self.assertEqual(len(payload["findings"]), 9)
            self.assertEqual(payload["findings"][0]["fingerprint"].split(":")[0], "sha256")

    def test_cli_quiet_suppresses_stdout_but_preserves_success_exit_code(self) -> None:
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()

        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            exit_code = main([str(SAFE_FIXTURE_PATH), "--quiet"])

        self.assertEqual(exit_code, 0)
        self.assertEqual("", stdout_buffer.getvalue())
        self.assertEqual("", stderr_buffer.getvalue())

    def test_cli_quiet_still_emits_policy_gate_failure_on_stderr(self) -> None:
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()

        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            exit_code = main([str(FIXTURE_PATH), "--quiet", "--fail-on", "high"])

        self.assertEqual(exit_code, POLICY_VIOLATION_EXIT_CODE)
        self.assertEqual("", stdout_buffer.getvalue())
        self.assertIn("Policy gate failed", stderr_buffer.getvalue())

    def test_cli_can_write_and_reuse_baseline_for_new_findings_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            baseline_path = Path(tmp_dir) / "baseline.json"
            stderr_buffer = io.StringIO()

            first_exit_code = main([str(FIXTURE_PATH), "--quiet", "--baseline-output", str(baseline_path)])
            self.assertEqual(first_exit_code, 0)
            self.assertTrue(baseline_path.exists())

            baseline_payload = json.loads(baseline_path.read_text(encoding="utf-8"))
            self.assertEqual(len(baseline_payload["findings"]), 9)

            with redirect_stderr(stderr_buffer):
                second_exit_code = main(
                    [
                        str(FIXTURE_PATH),
                        "--quiet",
                        "--fail-on",
                        "high",
                        "--baseline",
                        str(baseline_path),
                    ]
                )

        self.assertEqual(second_exit_code, 0)
        self.assertEqual("", stderr_buffer.getvalue())

    def test_cli_suppressions_can_filter_findings_before_policy_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            suppressions_path = Path(tmp_dir) / "suppressions.json"
            suppressions_path.write_text(
                json.dumps(
                    {
                        "version": "1.0",
                        "suppressions": [
                            {
                                "id": "accept-trust-expansion",
                                "rule_id": "aws-role-trust-expansion",
                                "reason": "Legacy cross-account trust is accepted for this fixture.",
                            },
                            {
                                "id": "accept-missing-narrowing",
                                "rule_id": "aws-role-trust-missing-narrowing",
                                "reason": "Legacy cross-account trust is accepted for this fixture.",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            stderr_buffer = io.StringIO()

            with redirect_stderr(stderr_buffer):
                exit_code = main(
                    [
                        str(CROSS_ACCOUNT_TRUST_UNCONSTRAINED_FIXTURE_PATH),
                        "--quiet",
                        "--fail-on",
                        "medium",
                        "--suppressions",
                        str(suppressions_path),
                    ]
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual("", stderr_buffer.getvalue())

    def test_cli_rejects_non_plan_json_with_input_error_exit_code(self) -> None:
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()

        with tempfile.TemporaryDirectory() as tmp_dir:
            invalid_plan_path = Path(tmp_dir) / "not-a-plan.json"
            invalid_plan_path.write_text('{"planned_values":{"root_module":{"resources":[]}}}', encoding="utf-8")

            with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
                exit_code = main([str(invalid_plan_path), "--quiet"])

        self.assertEqual(exit_code, INPUT_ERROR_EXIT_CODE)
        self.assertEqual("", stdout_buffer.getvalue())
        self.assertIn("Input error:", stderr_buffer.getvalue())
        self.assertIn("missing `terraform_version`", stderr_buffer.getvalue())

    def test_cli_rejects_invalid_suppressions_file_with_input_error_exit_code(self) -> None:
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()

        with tempfile.TemporaryDirectory() as tmp_dir:
            suppressions_path = Path(tmp_dir) / "suppressions.json"
            suppressions_path.write_text('{"suppressions":[{"reason":"missing selectors"}]}', encoding="utf-8")

            with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
                exit_code = main([str(FIXTURE_PATH), "--quiet", "--suppressions", str(suppressions_path)])

        self.assertEqual(exit_code, INPUT_ERROR_EXIT_CODE)
        self.assertEqual("", stdout_buffer.getvalue())
        self.assertIn("Input error:", stderr_buffer.getvalue())
        self.assertIn("must define at least one selector", stderr_buffer.getvalue())

    def test_cli_auto_discovers_config_and_applies_fail_on_and_severity_overrides(self) -> None:
        stderr_buffer = io.StringIO()

        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / CONFIG_FILENAME
            json_output_path = Path(tmp_dir) / "report.json"
            config_path.write_text(
                "\n".join(
                    [
                        'fail_on = "medium"',
                        "",
                        "[rules]",
                        'disable = ["aws-private-data-transitive-exposure"]',
                        "",
                        "[rules.severity_overrides]",
                        'aws-iam-wildcard-permissions = "low"',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            current_working_directory = os.getcwd()
            try:
                os.chdir(tmp_dir)
                with redirect_stderr(stderr_buffer):
                    exit_code = main(
                        [
                            str(SAFE_FIXTURE_PATH),
                            "--quiet",
                            "--json-output",
                            str(json_output_path),
                        ]
                    )
            finally:
                os.chdir(current_working_directory)

            payload = json.loads(json_output_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual("", stderr_buffer.getvalue())
        self.assertEqual(payload["summary"]["severity_counts"], {"high": 0, "medium": 0, "low": 1})
        self.assertEqual(payload["findings"][0]["severity"], "low")
        self.assertEqual(payload["findings"][0]["severity_reasoning"]["computed_severity"], "medium")


if __name__ == "__main__":
    unittest.main()
