from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tfstride.analysis.rule_registry import RulePolicy
from tfstride.app import TfStride
from tfstride.filtering import apply_finding_filters, render_baseline
from tfstride.models import (
    AnalysisResult,
    NormalizedResource,
    ResourceCategory,
    ResourceInventory,
    Severity,
)
from tfstride.providers.aws.resource_facts import aws_facts
from tfstride.providers.gcp.normalizer import SUPPORTED_GCP_TYPES
from tfstride.reporting.json_report import (
    REPORT_FORMAT_VERSION,
    REPORT_KIND,
    build_json_report_payload,
    render_json,
)
from tfstride.reporting.markdown import render_markdown
from tfstride.reporting.sarif import render_sarif


ROOT = Path(__file__).resolve().parents[1]
BASELINE_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_baseline_plan.json"
FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_plan.json"
SAFE_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_safe_plan.json"
NIGHTMARE_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_nightmare_plan.json"
ALB_EC2_RDS_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_alb_ec2_rds_plan.json"
LAMBDA_DEPLOY_ROLE_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_lambda_deploy_role_plan.json"
GCP_FIXTURE_PATH = ROOT / "fixtures" / "sample_gcp_plan.json"
CROSS_ACCOUNT_TRUST_UNCONSTRAINED_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_cross_account_trust_unconstrained_plan.json"
CROSS_ACCOUNT_TRUST_CONSTRAINED_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_cross_account_trust_constrained_plan.json"
EXAMPLES_DIR = ROOT / "examples"


class MarkdownReportTests(unittest.TestCase):
    def test_report_contains_summary_findings_and_limitations(self) -> None:
        engine = TfStride()
        result = engine.analyze_plan(FIXTURE_PATH)
        report = render_markdown(result)

        self.assertIn("# tfSTRIDE Threat Model Report", report)
        self.assertIn("## Summary", report)
        self.assertIn("## Analysis Coverage", report)
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

    def test_report_renders_analysis_coverage_for_auditing(self) -> None:
        engine = TfStride()
        report = render_markdown(engine.analyze_plan(FIXTURE_PATH))

        self.assertIn("- Terraform resources seen: `24`", report)
        self.assertIn("- Provider resources considered: `24`", report)
        self.assertIn("- Registered rules: `31`", report)
        self.assertIn("- Unresolved in-plan references: `0`", report)
        self.assertIn("- Unsupported resource types:", report)
        self.assertIn("  - `aws_cloudwatch_log_group`: `1`", report)
        self.assertIn("- Findings by rule:", report)
        self.assertIn("  - `aws-database-permissive-ingress`: `1`", report)

    def test_report_renders_unconstrained_trust_evidence(self) -> None:
        engine = TfStride()
        result = engine.analyze_plan(CROSS_ACCOUNT_TRUST_UNCONSTRAINED_FIXTURE_PATH)
        report = render_markdown(result)

        self.assertIn("Cross-account or broad role trust lacks narrowing conditions", report)
        self.assertIn("supported narrowing conditions present: false", report)
        self.assertIn("supported narrowing condition keys: none", report)

    def test_report_renders_controls_observed_section(self) -> None:
        engine = TfStride()
        safe_report = render_markdown(engine.analyze_plan(SAFE_FIXTURE_PATH))
        constrained_trust_report = render_markdown(
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
        engine = TfStride()
        scenarios = {
            BASELINE_FIXTURE_PATH: EXAMPLES_DIR / "baseline_report.md",
            SAFE_FIXTURE_PATH: EXAMPLES_DIR / "safe_report.md",
            FIXTURE_PATH: EXAMPLES_DIR / "sample_report.md",
            NIGHTMARE_FIXTURE_PATH: EXAMPLES_DIR / "nightmare_report.md",
            ALB_EC2_RDS_FIXTURE_PATH: EXAMPLES_DIR / "alb_ec2_rds_report.md",
            LAMBDA_DEPLOY_ROLE_FIXTURE_PATH: EXAMPLES_DIR / "lambda_deploy_role_report.md",
            GCP_FIXTURE_PATH: EXAMPLES_DIR / "gcp_inventory_report.md",
        }

        for fixture_path, report_path in scenarios.items():
            with self.subTest(fixture=fixture_path.name):
                expected = render_markdown(engine.analyze_plan(fixture_path))
                actual = report_path.read_text(encoding="utf-8")
                self.assertEqual(actual, expected)

    def test_report_surfaces_suppressed_and_baselined_counts_when_filters_apply(self) -> None:
        engine = TfStride()
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
            filtered_result = apply_finding_filters(unsuppressed_result, baseline_path=baseline_path)

        report = render_markdown(filtered_result)
        self.assertIn("- Active findings after filters:", report)
        self.assertIn("- Suppressed findings: `1`", report)
        self.assertIn("- Baselined findings: `2`", report)

    def test_report_mentions_when_severity_is_overridden_by_config(self) -> None:
        engine = TfStride(
            rule_policy=RulePolicy(severity_overrides={"aws-iam-wildcard-permissions": Severity.LOW})
        )
        result = engine.analyze_plan(BASELINE_FIXTURE_PATH)
        report = render_markdown(result)

        self.assertIn("overridden by config", report)


class SarifReportTests(unittest.TestCase):
    def test_sarif_report_contains_rules_results_and_finding_metadata(self) -> None:
        engine = TfStride()
        result = engine.analyze_plan(FIXTURE_PATH)
        report = render_sarif(result)
        payload = json.loads(report)

        self.assertEqual(payload["version"], "2.1.0")
        self.assertIn("$schema", payload)
        self.assertEqual(len(payload["runs"]), 1)

        run = payload["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "tfstride")
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

    def test_sarif_function_renders_from_analysis_result(self) -> None:
        engine = TfStride()
        report = render_sarif(engine.analyze_plan(FIXTURE_PATH))
        payload = json.loads(report)

        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(payload["runs"][0]["tool"]["driver"]["name"], "tfstride")


class JsonReportTests(unittest.TestCase):
    def test_report_functions_render_from_an_analysis_result(self) -> None:
        engine = TfStride()
        result = engine.analyze_plan(FIXTURE_PATH)

        self.assertEqual(json.loads(render_json(result)), build_json_report_payload(result))
        self.assertEqual(json.loads(render_sarif(result))["version"], "2.1.0")
        self.assertIn("# tfSTRIDE Threat Model Report", render_markdown(result))

    def test_json_report_auto_selects_gcp_inventory_fixture(self) -> None:
        engine = TfStride()
        payload = json.loads(render_json(engine.analyze_plan(GCP_FIXTURE_PATH)))

        self.assertEqual(payload["inventory"]["provider"], "gcp")
        self.assertEqual(payload["summary"]["normalized_resources"], 14)
        self.assertEqual(payload["summary"]["unsupported_resources"], 0)
        self.assertEqual(payload["summary"]["trust_boundaries"], 3)
        self.assertEqual(payload["summary"]["active_findings"], 12)
        self.assertEqual(payload["summary"]["severity_counts"], {"high": 2, "medium": 10, "low": 0})
        self.assertEqual(payload["inventory"]["unsupported_resources"], [])
        self.assertEqual(
            payload["inventory"]["metadata"]["supported_resource_types"],
            sorted(SUPPORTED_GCP_TYPES),
        )
        self.assertEqual(payload["analysis_coverage"]["resources"]["normalized_resources"], 14)
        self.assertEqual(payload["analysis_coverage"]["resources"]["unsupported_resources"], 0)
        self.assertEqual(
            [resource["address"] for resource in payload["inventory"]["resources"]],
            [
                "google_compute_firewall.public_ssh",
                "google_compute_instance.web",
                "google_compute_network.main",
                "google_compute_subnetwork.app",
                "google_kms_crypto_key.customer",
                "google_kms_crypto_key_iam_member.partner_decrypter",
                "google_project_iam_member.web_viewer",
                "google_secret_manager_secret.api_key",
                "google_secret_manager_secret_iam_member.public_accessor",
                "google_service_account.web",
                "google_service_account_key.web",
                "google_sql_database_instance.app",
                "google_storage_bucket.logs",
                "google_storage_bucket_iam_member.public_logs_reader",
            ],
        )
        self.assertEqual(payload["analysis_coverage"]["resources"]["unsupported_resource_types"], {})
        self.assertEqual(
            payload["trust_boundaries"][0]["identifier"],
            "internet-to-service:internet->google_compute_instance.web",
        )
        self.assertEqual(payload["trust_boundaries"][0]["boundary_type"], "internet-to-service")
        self.assertEqual(
            {finding["rule_id"] for finding in payload["findings"]},
            {
                "gcp-cloud-sql-backup-disabled",
                "gcp-cloud-sql-deletion-protection-disabled",
                "gcp-cloud-sql-public-authorized-network",
                "gcp-cloud-sql-public-ip-without-private-network",
                "gcp-cloud-sql-ssl-not-required",
                "gcp-gcs-customer-managed-encryption-missing",
                "gcp-gcs-public-access",
                "gcp-gcs-public-access-prevention-not-enforced",
                "gcp-gcs-versioning-disabled",
                "gcp-sensitive-resource-iam-external-access",
                "gcp-public-compute-broad-ingress",
            },
        )
        self.assertEqual(
            {finding["severity"] for finding in payload["findings"]},
            {"high", "medium"},
        )
        self.assertEqual(
            {finding["trust_boundary_id"] for finding in payload["findings"]},
            {
                None,
                "internet-to-service:internet->google_compute_instance.web",
                "internet-to-service:internet->google_sql_database_instance.app",
                "internet-to-service:internet->google_storage_bucket.logs",
            },
        )

    def test_json_report_contains_inventory_findings_and_filter_summary(self) -> None:
        engine = TfStride()
        result = engine.analyze_plan(FIXTURE_PATH)
        report = render_json(result)
        payload = json.loads(report)

        self.assertEqual(payload["kind"], REPORT_KIND)
        self.assertEqual(payload["version"], REPORT_FORMAT_VERSION)
        self.assertEqual(payload["tool"]["name"], "tfstride")
        self.assertEqual(payload["summary"]["active_findings"], 9)
        self.assertEqual(payload["summary"]["total_findings"], 9)
        self.assertEqual(payload["inventory"]["provider"], "aws")
        self.assertEqual(len(payload["findings"]), 9)
        self.assertTrue(payload["findings"][0]["fingerprint"].startswith("sha256:"))

    def test_json_report_uses_metadata_snapshots(self) -> None:
        resource = NormalizedResource(
            address="aws_s3_bucket.logs",
            provider="aws",
            resource_type="aws_s3_bucket",
            name="logs",
            category=ResourceCategory.DATA,
            metadata={"policy_document": {"Statement": [{"Effect": "Allow"}]}},
        )
        inventory = ResourceInventory(
            provider="aws",
            resources=[resource],
            metadata={"primary_account_id": "111122223333"},
        )
        result = AnalysisResult(
            title="Snapshot test",
            analyzed_file="plan.json",
            analyzed_path="plan.json",
            inventory=inventory,
            trust_boundaries=[],
            findings=[],
        )

        payload = build_json_report_payload(result)
        aws_facts(resource).set_policy_document({"Statement": [{"Effect": "Deny"}]})
        inventory.primary_account_id = "444455556666"

        self.assertEqual(payload["inventory"]["metadata"]["primary_account_id"], "111122223333")
        self.assertEqual(
            payload["inventory"]["resources"][0]["metadata"]["policy_document"],
            {"Statement": [{"Effect": "Allow"}]},
        )

    def test_json_report_contract_exposes_stable_ui_sections(self) -> None:
        engine = TfStride()
        payload = json.loads(render_json(engine.analyze_plan(FIXTURE_PATH)))

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
                "analysis_coverage",
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
            list(payload["analysis_coverage"]),
            ["resources", "rules", "references"],
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

    def test_json_report_serializes_typed_policy_principal_entries(self) -> None:
        engine = TfStride()
        payload = json.loads(render_json(engine.analyze_plan(FIXTURE_PATH)))
        resources_with_policies = [
            resource
            for resource in payload["inventory"]["resources"]
            if resource["policy_statements"]
        ]

        self.assertTrue(resources_with_policies)
        policy_statement = resources_with_policies[0]["policy_statements"][0]
        self.assertEqual(
            list(policy_statement),
            ["effect", "actions", "resources", "principals", "principal_entries", "conditions"],
        )
        self.assertIn("principal_entries", policy_statement)

    def test_json_report_sorts_inventory_resources_and_trust_boundaries_for_stable_consumers(self) -> None:
        engine = TfStride()
        payload = json.loads(render_json(engine.analyze_plan(FIXTURE_PATH)))

        resource_addresses = [resource["address"] for resource in payload["inventory"]["resources"]]
        boundary_ids = [boundary["identifier"] for boundary in payload["trust_boundaries"]]

        self.assertEqual(resource_addresses, sorted(resource_addresses))
        self.assertEqual(boundary_ids, sorted(boundary_ids))

    def test_json_report_includes_analysis_coverage_for_auditing(self) -> None:
        engine = TfStride()
        payload = json.loads(render_json(engine.analyze_plan(FIXTURE_PATH)))

        coverage = payload["analysis_coverage"]

        self.assertEqual(coverage["resources"]["total_resources"], 24)
        self.assertEqual(coverage["resources"]["provider_resources"], 24)
        self.assertEqual(coverage["resources"]["normalized_resources"], 23)
        self.assertEqual(coverage["resources"]["unsupported_resources"], 1)
        self.assertEqual(
            coverage["resources"]["unsupported_resource_types"],
            {"aws_cloudwatch_log_group": 1},
        )
        self.assertEqual(coverage["rules"]["registered_rule_count"], 31)
        self.assertIn("aws-database-permissive-ingress", coverage["rules"]["enabled_rules"])
        self.assertEqual(coverage["rules"]["disabled_rules"], [])
        self.assertEqual(coverage["rules"]["severity_overrides"], {})
        self.assertEqual(coverage["rules"]["finding_counts_by_rule"]["aws-database-permissive-ingress"], 1)
        self.assertEqual(coverage["references"]["unresolved_reference_count"], 0)
        self.assertEqual(coverage["references"]["unresolved_references"], [])

    def test_json_report_includes_suppressed_and_baselined_findings(self) -> None:
        engine = TfStride()
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
            filtered_result = apply_finding_filters(unsuppressed_result, baseline_path=baseline_path)

        payload = json.loads(render_json(filtered_result))
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

        engine = TfStride()
        with tempfile.TemporaryDirectory() as tmp_dir:
            plan_path = Path(tmp_dir) / "plan.json"
            plan_path.write_text(json.dumps(payload), encoding="utf-8")
            result = engine.analyze_plan(plan_path)

        rendered = json.loads(render_json(result))
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