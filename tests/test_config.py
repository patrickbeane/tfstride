from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

from tfstride.config import CONFIG_FILENAME, ProjectConfigLoadError, load_project_config
from tfstride.coverage_policy import CoverageCheck
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
                    provider = "gcp"
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
        self.assertEqual(config.provider, "gcp")
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

    def test_load_project_config_reads_coverage_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / CONFIG_FILENAME
            config_path.write_text(
                textwrap.dedent(
                    """
                    [coverage]
                    fail_on = ["no-resources", "unsupported-resources"]
                    allow_unsupported_types = ["aws_foo"]
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            config = load_project_config(path=config_path)

        self.assertEqual(
            config.coverage_policy.checks,
            frozenset({CoverageCheck.NO_RESOURCES, CoverageCheck.UNSUPPORTED_RESOURCES}),
        )
        self.assertEqual(config.coverage_policy.allowed_unsupported_types, frozenset({"aws_foo"}))

    def test_load_project_config_defaults_to_no_coverage_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / CONFIG_FILENAME
            config_path.write_text('title = "No Coverage"\n', encoding="utf-8")

            config = load_project_config(path=config_path)

        self.assertEqual(config.coverage_policy.checks, frozenset())
        self.assertEqual(config.coverage_policy.allowed_unsupported_types, frozenset())

    def test_load_project_config_rejects_invalid_coverage_settings(self) -> None:
        invalid_configs = {
            "unknown check": ('[coverage]\nfail_on = ["everything"]\n', "`coverage.fail_on[0]`"),
            "non-array checks": ('[coverage]\nfail_on = "no-resources"\n', "`coverage.fail_on` must be an array"),
            "non-string type": (
                "[coverage]\nallow_unsupported_types = [1]\n",
                "`coverage.allow_unsupported_types[0]`",
            ),
            "unknown key": ("[coverage]\nfail = []\n", "Unknown coverage key(s)"),
            "non-table": ('coverage = "yes"\n', "`coverage` must be a TOML table"),
        }
        for name, (content, expected_message) in invalid_configs.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp_dir:
                config_path = Path(tmp_dir) / CONFIG_FILENAME
                config_path.write_text(content, encoding="utf-8")

                with self.assertRaises(ProjectConfigLoadError) as context:
                    load_project_config(path=config_path)

                self.assertIn(expected_message, str(context.exception))


if __name__ == "__main__":
    unittest.main()
