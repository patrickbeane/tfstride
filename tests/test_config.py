from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

from tfstride.config import CONFIG_FILENAME, ProjectConfigLoadError, load_project_config
from tfstride.models import Severity


class ProjectConfigTests(unittest.TestCase):
    def test_load_project_config_resolves_relative_paths_and_rule_settings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / CONFIG_FILENAME
            config_path.write_text(
                textwrap.dedent(
                    """
                    version = "1.0"
                    title = "Team Threat Model"
                    fail_on = "medium"
                    baseline = "baseline.json"
                    suppressions = "suppressions.json"

                    [rules]
                    disable = ["aws-role-trust-expansion"]

                    [rules.severity_overrides]
                    aws-workload-role-sensitive-permissions = "low"
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            config = load_project_config(path=config_path)

        self.assertEqual(config.title, "Team Threat Model")
        self.assertEqual(config.fail_on, Severity.MEDIUM)
        self.assertEqual(config.baseline_path, str((Path(tmp_dir) / "baseline.json").resolve()))
        self.assertEqual(config.suppressions_path, str((Path(tmp_dir) / "suppressions.json").resolve()))
        self.assertIsNotNone(config.rule_policy.enabled_rule_ids)
        self.assertNotIn("aws-role-trust-expansion", config.rule_policy.enabled_rule_ids)
        self.assertEqual(
            config.rule_policy.severity_overrides["aws-workload-role-sensitive-permissions"],
            Severity.LOW,
        )

    def test_load_project_config_rejects_unknown_rule_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / CONFIG_FILENAME
            config_path.write_text(
                textwrap.dedent(
                    """
                    [rules]
                    disable = ["aws-does-not-exist"]
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(ProjectConfigLoadError):
                load_project_config(path=config_path)


if __name__ == "__main__":
    unittest.main()
