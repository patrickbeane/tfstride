from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from cloud_threat_modeler.cli import POLICY_VIOLATION_EXIT_CODE, main


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "sample_aws_plan.json"
SAFE_FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "sample_aws_safe_plan.json"


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
            self.assertIn("5 medium", stderr_buffer.getvalue())

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


if __name__ == "__main__":
    unittest.main()
