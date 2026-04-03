from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cloud_threat_modeler.cli import main


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "sample_aws_plan.json"


class CliTests(unittest.TestCase):
    def test_cli_writes_markdown_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "report.md"
            exit_code = main([str(FIXTURE_PATH), "--output", str(output_path), "--title", "Sample Threat Model"])

            self.assertEqual(exit_code, 0)
            report = output_path.read_text(encoding="utf-8")

        self.assertIn("# Sample Threat Model", report)
        self.assertIn("Database is reachable from overly permissive sources", report)


if __name__ == "__main__":
    unittest.main()
