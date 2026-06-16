from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from tfstride.cli import (
    INPUT_ERROR_EXIT_CODE,
    POLICY_VIOLATION_EXIT_CODE,
    RULE_CATALOG_KIND,
    RULE_CATALOG_VERSION,
    main,
)
from tfstride.config import CONFIG_FILENAME
from tfstride.filtering import (
    FindingFilterLoadError,
    load_baseline_fingerprints,
    load_suppressions,
)

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "aws" / "sample_aws_plan.json"
BASELINE_FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "aws" / "sample_aws_baseline_plan.json"
SAFE_FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "aws" / "sample_aws_safe_plan.json"
GCP_FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "gcp" / "sample_gcp_plan.json"
CROSS_ACCOUNT_TRUST_UNCONSTRAINED_FIXTURE_PATH = (
    Path(__file__).resolve().parents[1] / "fixtures" / "aws" / "sample_aws_cross_account_trust_unconstrained_plan.json"
)


class CliTests(unittest.TestCase):
    def test_cli_lists_rules_without_plan(self) -> None:
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()

        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            exit_code = main(["--list-rules"])

        output = stdout_buffer.getvalue()

        self.assertEqual(exit_code, 0)
        self.assertEqual("", stderr_buffer.getvalue())
        self.assertIn("tfSTRIDE Rules", output)
        self.assertIn("- aws-public-compute-broad-ingress", output)
        self.assertIn("  STRIDE: Spoofing", output)
        self.assertIn("  Enabled by default: yes", output)
        self.assertIn("  Severity factors: internet_exposure, lateral_movement, blast_radius", output)
        self.assertIn("  Mitigation: Restrict ingress to expected client ports", output)
        self.assertIn("- aws-role-trust-missing-narrowing", output)
        self.assertIn("- gcp-sensitive-resource-iam-external-access", output)
        self.assertIn("- gcp-pubsub-public-access", output)
        self.assertIn("- gcp-bigquery-public-access", output)
        self.assertIn("- gcp-cloud-sql-public-authorized-network", output)
        self.assertIn("- gcp-cloud-sql-backup-disabled", output)
        self.assertIn("- gcp-cloud-sql-public-ip-without-private-network", output)
        self.assertIn("- gcp-cloud-sql-ssl-not-required", output)
        self.assertIn("- gcp-cloud-sql-point-in-time-recovery-disabled", output)
        self.assertIn("- gcp-cloud-sql-deletion-protection-disabled", output)
        self.assertIn("- gcp-gcs-public-access", output)
        self.assertIn("- gcp-gcs-uniform-bucket-level-access-disabled", output)
        self.assertIn("- gcp-gcs-public-access-prevention-not-enforced", output)
        self.assertIn("- gcp-gcs-versioning-disabled", output)
        self.assertIn("- gcp-gcs-customer-managed-encryption-missing", output)
        self.assertIn("- gcp-public-compute-broad-ingress", output)
        self.assertIn("- gcp-compute-os-login-disabled", output)
        self.assertIn("- gcp-gke-public-control-plane", output)
        self.assertIn("- gcp-gke-broad-authorized-networks", output)
        self.assertIn("- gcp-gke-workload-identity-disabled", output)
        self.assertIn("- gcp-gke-legacy-metadata-endpoints-enabled", output)
        self.assertIn("- gcp-gke-broad-node-service-account", output)
        self.assertIn("- gcp-cloud-run-public-invoker", output)
        self.assertIn("- gcp-cloud-functions-public-invoker", output)
        self.assertIn("- gcp-public-workload-sensitive-data-access", output)
        self.assertIn("- gcp-service-account-iam-broad-principal", output)
        self.assertIn("- gcp-service-account-iam-privileged-role", output)
        self.assertIn("- gcp-service-account-key-hygiene", output)
        self.assertIn("- gcp-service-account-key-effective-access", output)
        self.assertIn("- gcp-org-folder-iam-broad-principal", output)
        self.assertIn("- gcp-org-folder-iam-privileged-role", output)
        self.assertIn("- gcp-project-iam-broad-principal", output)
        self.assertIn("- gcp-project-iam-privileged-role", output)
        self.assertIn("- gcp-inherited-iam-sensitive-resource-access", output)
        self.assertIn("- gcp-inherited-iam-blast-radius", output)
        self.assertTrue(output.endswith("\n"))

    def test_cli_lists_rules_as_json_without_plan(self) -> None:
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()

        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            exit_code = main(["--list-rules", "--json"])

        payload = json.loads(stdout_buffer.getvalue())
        first_rule = payload["rules"][0]

        self.assertEqual(exit_code, 0)
        self.assertEqual("", stderr_buffer.getvalue())
        self.assertEqual(payload["kind"], RULE_CATALOG_KIND)
        self.assertEqual(payload["version"], RULE_CATALOG_VERSION)
        self.assertGreater(len(payload["rules"]), 0)
        self.assertEqual(first_rule["rule_id"], "aws-public-compute-broad-ingress")
        self.assertEqual(first_rule["title"], "Internet-exposed compute service permits overly broad ingress")
        self.assertEqual(first_rule["category"], "Spoofing")
        self.assertIs(first_rule["enabled_by_default"], True)
        self.assertEqual(first_rule["tags"], ["aws", "network", "compute", "internet"])
        self.assertEqual(first_rule["severity_factors"], ["internet_exposure", "lateral_movement", "blast_radius"])
        self.assertIn("Restrict ingress to expected client ports", first_rule["recommended_mitigation"])

    def test_cli_rejects_json_without_list_rules(self) -> None:
        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()

        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            with self.assertRaises(SystemExit) as raised:
                main([str(SAFE_FIXTURE_PATH), "--json"])

        self.assertEqual(raised.exception.code, 2)
        self.assertEqual("", stdout_buffer.getvalue())
        self.assertIn("argument --json: only valid with --list-rules", stderr_buffer.getvalue())

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
            self.assertEqual(sarif_payload["runs"][0]["tool"]["driver"]["name"], "tfstride")

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
            self.assertEqual(payload["tool"]["name"], "tfstride")
            self.assertEqual(payload["summary"]["active_findings"], 9)
            self.assertEqual(payload["summary"]["total_findings"], 9)
            self.assertEqual(len(payload["findings"]), 9)
            self.assertEqual(payload["findings"][0]["fingerprint"].split(":")[0], "sha256")

    def test_cli_provider_option_can_select_gcp_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_output_path = Path(tmp_dir) / "report.json"

            exit_code = main(
                [
                    str(GCP_FIXTURE_PATH),
                    "--provider",
                    "gcp",
                    "--quiet",
                    "--json-output",
                    str(json_output_path),
                ]
            )

            report = json.loads(json_output_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(report["inventory"]["provider"], "gcp")
        self.assertEqual(len(report["inventory"]["resources"]), 22)
        self.assertEqual(report["inventory"]["unsupported_resources"], ["google_logging_project_sink.processor"])
        self.assertEqual(report["summary"]["active_findings"], 19)
        self.assertIn("GCP support currently provides initial inventory normalization", report["limitations"][0])

    def test_cli_reports_mixed_provider_plans_as_input_error(self) -> None:
        payload = {
            "terraform_version": "1.8.5",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_instance.web",
                            "mode": "managed",
                            "type": "aws_instance",
                            "name": "web",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {},
                        },
                        {
                            "address": "google_storage_bucket.logs",
                            "mode": "managed",
                            "type": "google_storage_bucket",
                            "name": "logs",
                            "provider_name": "registry.terraform.io/hashicorp/google",
                            "values": {},
                        },
                    ]
                }
            },
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            plan_path = Path(tmp_dir) / "plan.json"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")
            stdout_buffer = io.StringIO()
            stderr_buffer = io.StringIO()

            with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
                exit_code = main([str(plan_path), "--quiet"])

        self.assertEqual(exit_code, INPUT_ERROR_EXIT_CODE)
        self.assertEqual("", stdout_buffer.getvalue())
        self.assertIn("multiple registered providers", stderr_buffer.getvalue())

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

    def test_cli_applies_suppressions_once_before_baseline_filtering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            suppressions_path = Path(tmp_dir) / "suppressions.json"
            baseline_path = Path(tmp_dir) / "baseline.json"
            json_output_path = Path(tmp_dir) / "report.json"
            suppressions_path.write_text(
                json.dumps(
                    {
                        "version": "1.0",
                        "suppressions": [
                            {
                                "id": "accept-database-ingress",
                                "rule_id": "aws-database-permissive-ingress",
                                "reason": "Accepted for test coverage.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            first_exit_code = main(
                [
                    str(FIXTURE_PATH),
                    "--quiet",
                    "--suppressions",
                    str(suppressions_path),
                    "--baseline-output",
                    str(baseline_path),
                ]
            )
            second_exit_code = main(
                [
                    str(FIXTURE_PATH),
                    "--quiet",
                    "--suppressions",
                    str(suppressions_path),
                    "--baseline",
                    str(baseline_path),
                    "--json-output",
                    str(json_output_path),
                ]
            )

            payload = json.loads(json_output_path.read_text(encoding="utf-8"))

        self.assertEqual(first_exit_code, 0)
        self.assertEqual(second_exit_code, 0)
        self.assertEqual(payload["summary"]["total_findings"], 9)
        self.assertEqual(payload["summary"]["active_findings"], 0)
        self.assertEqual(payload["summary"]["suppressed_findings"], 1)
        self.assertEqual(payload["summary"]["baselined_findings"], 8)
        self.assertEqual(len(payload["suppressed_findings"]), 1)
        self.assertEqual(len(payload["baselined_findings"]), 8)

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

    def test_filter_loaders_accept_missing_or_current_format_versions(self) -> None:
        baseline_payloads = [
            {"findings": [{"fingerprint": "sha256:one"}]},
            {"version": "1.0", "findings": [{"fingerprint": "sha256:one"}]},
        ]
        suppression_payloads = [
            {"suppressions": [{"id": "s1", "rule_id": "aws-iam-wildcard-permissions", "reason": "accepted"}]},
            {
                "version": "1.0",
                "suppressions": [{"id": "s1", "rule_id": "aws-iam-wildcard-permissions", "reason": "accepted"}],
            },
        ]

        with tempfile.TemporaryDirectory() as tmp_dir:
            for index, payload in enumerate(baseline_payloads):
                with self.subTest(kind="baseline", index=index):
                    baseline_path = Path(tmp_dir) / f"baseline-{index}.json"
                    baseline_path.write_text(json.dumps(payload), encoding="utf-8")

                    self.assertEqual(load_baseline_fingerprints(baseline_path), {"sha256:one"})

            for index, payload in enumerate(suppression_payloads):
                with self.subTest(kind="suppressions", index=index):
                    suppressions_path = Path(tmp_dir) / f"suppressions-{index}.json"
                    suppressions_path.write_text(json.dumps(payload), encoding="utf-8")

                    suppressions = load_suppressions(suppressions_path)

                    self.assertEqual(len(suppressions), 1)
                    self.assertEqual(suppressions[0].rule_id, "aws-iam-wildcard-permissions")

    def test_filter_loaders_reject_unsupported_format_versions(self) -> None:
        payloads = [
            ("baseline", {"version": "2.0", "findings": []}, load_baseline_fingerprints),
            ("suppressions", {"version": "2.0", "suppressions": []}, load_suppressions),
        ]

        with tempfile.TemporaryDirectory() as tmp_dir:
            for label, payload, loader in payloads:
                with self.subTest(label=label):
                    path = Path(tmp_dir) / f"{label}.json"
                    path.write_text(json.dumps(payload), encoding="utf-8")

                    with self.assertRaises(FindingFilterLoadError) as context:
                        loader(path)

                    self.assertIn(f"Unsupported {label} version `2.0`", str(context.exception))

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
                            str(BASELINE_FIXTURE_PATH),
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