from __future__ import annotations

import importlib.util
import json
import unittest
from copy import deepcopy
from dataclasses import dataclass, field
from unittest import mock

from tests.helpers.paths import FIXTURES_DIR
from tfstride.analysis.operation_gaps import (
    OperationGap,
    OperationGapEvidenceKind,
    OperationGapEvidenceState,
    OperationGapFamily,
    OperationGapProvenance,
    OperationGapResults,
)
from tfstride.models import AnalysisResult, ResourceInventory
from tfstride.reporting.json_report import render_json
from tfstride.reporting.markdown import render_markdown
from tfstride.reporting.sarif import render_sarif

FASTAPI_DEPS_AVAILABLE = all(
    importlib.util.find_spec(name) is not None for name in ("fastapi", "httpx2", "jinja2", "multipart")
)

if FASTAPI_DEPS_AVAILABLE:
    from fastapi.testclient import TestClient

    from apps.dashboard import main as dashboard_main
    from apps.dashboard import routes as dashboard_routes
    from apps.dashboard import scenarios as dashboard_scenarios
    from apps.dashboard import uploads as dashboard_uploads
    from apps.dashboard import view_models as dashboard_view_models
    from apps.dashboard.main import app as dashboard_app


BASELINE_FIXTURE_PATH = FIXTURES_DIR / "aws" / "sample_aws_baseline_plan.json"
ECS_FARGATE_FIXTURE_PATH = FIXTURES_DIR / "aws" / "sample_aws_ecs_fargate_plan.json"
FIXTURE_PATH = FIXTURES_DIR / "aws" / "sample_aws_plan.json"
GCP_FIXTURE_PATH = FIXTURES_DIR / "gcp" / "sample_gcp_plan.json"
AZURE_SAFE_FIXTURE_PATH = FIXTURES_DIR / "azure" / "sample_azure_safe_plan.json"
AZURE_STORAGE_FIXTURE_PATH = FIXTURES_DIR / "azure" / "sample_azure_storage_plan.json"
AZURE_FIXTURE_PATH = FIXTURES_DIR / "azure" / "sample_azure_plan.json"
AZURE_NIGHTMARE_FIXTURE_PATH = FIXTURES_DIR / "azure" / "sample_azure_nightmare_plan.json"
SAFE_FIXTURE_PATH = FIXTURES_DIR / "aws" / "sample_aws_safe_plan.json"
NIGHTMARE_FIXTURE_PATH = FIXTURES_DIR / "aws" / "sample_aws_nightmare_plan.json"
_GAP_FAMILY = OperationGapFamily("aws", "ecs_s3_mutation")


def _dashboard_gap_result(*, include_gap: bool = True) -> AnalysisResult:
    gap = OperationGap(
        family=_GAP_FAMILY,
        resource_address="aws_ecs_task_definition.orders",
        relationship="runtime_identity_to_storage",
        operation="s3:PutObject",
        target_address="aws_s3_bucket.orders",
        scope="arn:aws:s3:::orders/public/<script>secret</script>/*",
        reason_code="policy_condition_unresolved",
        evidence_state=OperationGapEvidenceState.CONDITIONAL,
        provenance=(
            OperationGapProvenance(
                "aws_iam_role.orders_task",
                OperationGapEvidenceKind.POLICY_DOCUMENT,
                ("inline_policy", 0, "policy"),
            ),
        ),
    )
    return AnalysisResult(
        title="Gap-only dashboard",
        analyzed_file="plan.json",
        analyzed_path="plan.json",
        inventory=ResourceInventory(provider="aws", resources=[]),
        findings=[],
        trust_boundaries=[],
        operation_gaps=OperationGapResults((_GAP_FAMILY,), (gap,) if include_gap else ()),
    )


@unittest.skipUnless(FASTAPI_DEPS_AVAILABLE, "dashboard dependencies are not installed")
class DashboardAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(dashboard_app)

    def test_create_app_does_not_analyze_demo_fixtures_eagerly(self) -> None:
        with mock.patch.object(
            dashboard_main.TfStride, "analyze_plan", side_effect=AssertionError("unexpected analysis")
        ):
            app = dashboard_main.create_app()

        self.assertEqual(app.title, "tfSTRIDE Dashboard")

    def test_openapi_generation_does_not_analyze_demo_fixtures(self) -> None:
        with mock.patch.object(
            dashboard_main.TfStride, "analyze_plan", side_effect=AssertionError("unexpected analysis")
        ):
            app = dashboard_main.create_app()
            payload = app.openapi()

        self.assertIn("/api/analyze", payload["paths"])

    def test_index_page_renders_upload_form(self) -> None:
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Analyze plan", response.text)
        self.assertIn("Terraform plan JSON", response.text)
        self.assertIn(">Demos<", response.text)
        self.assertNotIn("Built-in scenarios", response.text)

    def test_scenarios_page_defaults_to_aws_demo_gallery(self) -> None:
        response = self.client.get("/scenarios")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Built-in scenarios", response.text)
        self.assertIn('href="http://testserver/scenarios?provider=aws"', response.text)
        self.assertIn('href="http://testserver/scenarios?provider=gcp"', response.text)
        self.assertIn("provider=azure", response.text)
        self.assertIn('class="scenario-provider-link scenario-provider-link-active"', response.text)
        self.assertIn('data-provider="aws"', response.text)
        self.assertNotIn('data-provider="gcp"', response.text)
        self.assertNotIn('data-provider="azure"', response.text)
        self.assertIn("ECS / Fargate", response.text)
        self.assertIn("Nightmare Plan", response.text)
        self.assertNotIn("Mixed GCP Inventory", response.text)
        self.assertNotIn("GCP Serverless", response.text)
        self.assertIn("Run built-in report", response.text)

    def test_scenarios_page_filters_to_gcp_demo_gallery(self) -> None:
        response = self.client.get("/scenarios?provider=gcp")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Built-in scenarios", response.text)
        self.assertIn('class="scenario-provider-link scenario-provider-link-active"', response.text)
        self.assertIn('data-provider="gcp"', response.text)
        self.assertNotIn('data-provider="aws"', response.text)
        self.assertNotIn('data-provider="azure"', response.text)
        self.assertIn("Mixed GCP Inventory", response.text)
        self.assertIn("GCP Serverless", response.text)
        self.assertNotIn("ECS / Fargate", response.text)
        self.assertNotIn("Mixed AWS Plan", response.text)

    def test_scenarios_page_filters_to_azure_demo_gallery(self) -> None:
        response = self.client.get("/scenarios?provider=azure")

        self.assertEqual(response.status_code, 200)
        self.assertIn('class="scenario-provider-link scenario-provider-link-active"', response.text)
        self.assertIn('data-provider="azure"', response.text)
        self.assertNotIn('data-provider="aws"', response.text)
        self.assertNotIn('data-provider="gcp"', response.text)
        self.assertIn("Safe Azure Storage", response.text)
        self.assertIn("Azure Storage Exposure", response.text)
        self.assertIn("Mixed Azure Inventory", response.text)
        self.assertIn("Azure Nightmare Plan", response.text)
        self.assertNotIn("Mixed AWS Plan", response.text)
        self.assertNotIn("GCP Serverless", response.text)

    def test_scenarios_page_falls_back_to_catalog_default_for_unknown_provider(self) -> None:
        response = self.client.get("/scenarios?provider=not-registered")

        self.assertEqual(response.status_code, 200)
        self.assertIn('data-provider="aws"', response.text)
        self.assertNotIn('data-provider="azure"', response.text)

    def test_scenario_provider_navigation_is_derived_from_catalog_data(self) -> None:
        scenarios = dashboard_scenarios.get_demo_scenarios(dashboard_app, dashboard_app.state.engine)

        self.assertEqual(
            [
                (provider.provider, provider.display_name)
                for provider in dashboard_scenarios.scenario_providers(scenarios)
            ],
            [("aws", "AWS"), ("gcp", "GCP"), ("azure", "Azure")],
        )

    def test_api_analyze_returns_versioned_json_contract(self) -> None:
        with FIXTURE_PATH.open("rb") as fixture_file:
            response = self.client.post(
                "/api/analyze",
                data={"title": "Dashboard Test"},
                files={"plan": (FIXTURE_PATH.name, fixture_file, "application/json")},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["kind"], "tfstride-report")
        self.assertEqual(payload["version"], "1.3")
        self.assertEqual(payload["resource_sensitivity"]["basis"], "resource_class_assumption")
        self.assertEqual(payload["title"], "Dashboard Test")
        self.assertEqual(payload["analyzed_file"], FIXTURE_PATH.name)
        self.assertEqual(payload["analyzed_path"], FIXTURE_PATH.name)
        self.assertIn("analysis_coverage", payload)
        self.assertTrue(payload["findings"])

    def test_coverage_context_derives_useful_fallback_from_legacy_payload(self) -> None:
        payload = deepcopy(dashboard_routes.API_REPORT_EXAMPLE)
        payload.pop("analysis_coverage")
        payload["summary"]["normalized_resources"] = 23
        payload["summary"]["unsupported_resources"] = 1
        payload["inventory"]["unsupported_resources"] = ["aws_cloudwatch_log_group.processor"]
        payload["findings"] = [
            {
                "fingerprint": "sha256:test",
                "title": "Database is reachable from overly permissive sources",
                "rule_id": "aws-database-permissive-ingress",
                "category": "Information Disclosure",
                "severity": "high",
                "affected_resources": ["aws_db_instance.app"],
                "trust_boundary_id": None,
                "rationale": "Test finding.",
                "recommended_mitigation": "Test mitigation.",
                "evidence": [],
                "severity_reasoning": None,
            }
        ]

        context = dashboard_view_models._coverage_context(payload)

        self.assertEqual(
            context["unsupported_resource_types"],
            [{"resource_type": "aws_cloudwatch_log_group", "count": 1}],
        )
        self.assertEqual(
            context["finding_counts_by_rule"],
            [{"rule_id": "aws-database-permissive-ingress", "count": 1}],
        )

    def test_coverage_context_uses_provider_specific_unsupported_empty_message(self) -> None:
        payload = deepcopy(dashboard_routes.API_REPORT_EXAMPLE)

        payload["inventory"]["provider"] = "gcp"
        gcp_context = dashboard_view_models._coverage_context(payload)

        payload["inventory"]["provider"] = "azure"
        azure_context = dashboard_view_models._coverage_context(payload)

        payload["inventory"]["provider"] = "custom"
        custom_context = dashboard_view_models._coverage_context(payload)

        self.assertEqual(
            gcp_context["unsupported_resource_types_empty_message"],
            "No unsupported GCP resource types were encountered.",
        )
        self.assertEqual(
            azure_context["unsupported_resource_types_empty_message"],
            "No unsupported Azure resource types were encountered.",
        )
        self.assertEqual(
            custom_context["unsupported_resource_types_empty_message"],
            "No unsupported resource types were encountered.",
        )

    def test_html_gap_only_report_explains_unassessed_path_without_finding_severity(self) -> None:
        with mock.patch.object(dashboard_app.state.engine, "analyze_plan", return_value=_dashboard_gap_result()):
            response = self.client.post(
                "/analyze",
                files={"plan": ("plan.json", b"{}", "application/json")},
            )

        self.assertEqual(response.status_code, 200)
        gap_section = response.text.split('id="analysis-gaps"', 1)[1].split('class="content-grid"', 1)[0]
        gap_text = " ".join(gap_section.split())
        self.assertIn('href="#analysis-gaps"', response.text)
        self.assertIn(
            "No security findings were recorded, but relevant modeled relationships remain unassessed.", gap_text
        )
        self.assertIn("1 analysis gap across 1 modeled resource.", gap_text)
        self.assertIn('<details class="gap-resource">', gap_section)
        self.assertIn('<details class="gap-operation">', gap_section)
        self.assertIn("aws_ecs_task_definition.orders", gap_section)
        self.assertIn("s3:PutObject", gap_section)
        self.assertIn("aws_s3_bucket.orders", gap_section)
        self.assertIn("policy_condition_unresolved", gap_section)
        self.assertIn("Review the condition at the referenced policy source", gap_section)
        self.assertIn("aws_iam_role.orders_task", gap_section)
        self.assertIn("inline_policy.0.policy", gap_section)
        self.assertIn("&lt;script&gt;secret&lt;/script&gt;", gap_section)
        self.assertNotIn("<script>secret</script>", response.text)
        self.assertNotIn("finding-high", gap_section)

    def test_zero_gap_report_does_not_claim_every_operation_was_assessed(self) -> None:
        with mock.patch.object(
            dashboard_app.state.engine, "analyze_plan", return_value=_dashboard_gap_result(include_gap=False)
        ):
            response = self.client.post(
                "/analyze",
                files={"plan": ("plan.json", b"{}", "application/json")},
            )

        self.assertEqual(response.status_code, 200)
        gap_section = response.text.split('id="analysis-gaps"', 1)[1].split('class="content-grid"', 1)[0]
        gap_text = " ".join(gap_section.split())
        self.assertIn("No operation gaps were reported by the 1 analysis family that ran.", gap_text)
        self.assertIn("This does not establish complete authorization coverage.", gap_section)
        self.assertNotIn("relevant modeled relationships remain unassessed", gap_section)

    def test_filtered_findings_do_not_hide_remaining_operation_gaps(self) -> None:
        result = _dashboard_gap_result()
        result.filter_summary = {
            "total_findings": 1,
            "active_findings": 0,
            "suppressed_findings": 1,
            "baselined_findings": 0,
            "suppressions_path": None,
            "baseline_path": None,
        }
        with mock.patch.object(dashboard_app.state.engine, "analyze_plan", return_value=result):
            response = self.client.post(
                "/analyze",
                files={"plan": ("plan.json", b"{}", "application/json")},
            )

        self.assertEqual(response.status_code, 200)
        gap_section = response.text.split('id="analysis-gaps"', 1)[1].split('class="content-grid"', 1)[0]
        self.assertIn("No active security findings remain after filtering", gap_section)
        self.assertIn("relevant modeled relationships remain unassessed", gap_section)
        self.assertNotIn("No security findings were recorded", gap_section)

    def test_legacy_report_without_gap_field_shows_coverage_unavailable(self) -> None:
        payload = deepcopy(dashboard_routes.API_REPORT_EXAMPLE)
        payload.pop("operation_gaps")

        context = dashboard_view_models._operation_gap_context(payload)

        self.assertEqual(context["operation_gap_count"], "—")
        self.assertFalse(context["operation_gap_data_available"])
        self.assertEqual(context["operation_gap_resources"], [])

    def test_gap_scope_and_safe_provenance_survive_all_formats_without_internal_values(self) -> None:
        sentinels = ("POLICY-BODY-PRIVATE", "SECRET-VALUE-PRIVATE", "ARBITRARY-METADATA-PRIVATE")

        @dataclass(frozen=True)
        class InternalGap(OperationGap):
            policy_body: str = sentinels[0]
            secret_value: str = sentinels[1]
            arbitrary_metadata: dict[str, str] = field(default_factory=lambda: {"raw": sentinels[2]}, compare=False)

        @dataclass(frozen=True)
        class InternalProvenance(OperationGapProvenance):
            condition_value: str = sentinels[1]

        result = _dashboard_gap_result()
        original = result.operation_gaps.records[0]
        gap = InternalGap(
            family=original.family,
            resource_address=original.resource_address,
            relationship=original.relationship,
            reason_code=original.reason_code,
            evidence_state=original.evidence_state,
            operation=original.operation,
            target_address=original.target_address,
            scope=original.scope,
            provenance=(
                InternalProvenance(
                    "aws_iam_role.orders_task",
                    OperationGapEvidenceKind.POLICY_DOCUMENT,
                    ("inline_policy", 0, "policy"),
                ),
            ),
        )
        result.operation_gaps = OperationGapResults((_GAP_FAMILY,), (gap,))

        json_report = render_json(result)
        markdown = render_markdown(result)
        sarif = render_sarif(result)
        with mock.patch.object(dashboard_app.state.engine, "analyze_plan", return_value=result):
            response = self.client.post(
                "/analyze",
                files={"plan": ("plan.json", b"{}", "application/json")},
            )

        self.assertEqual(response.status_code, 200)
        json_payload = json.loads(json_report)
        sarif_run = json.loads(sarif)["runs"][0]
        json_gap = json_payload["operation_gaps"]["records"][0]
        sarif_gap = sarif_run["results"][0]["properties"]
        self.assertEqual(sarif_run["properties"]["resource_sensitivity"], json_payload["resource_sensitivity"])
        self.assertEqual(json_payload["resource_sensitivity"]["basis"], "resource_class_assumption")
        self.assertEqual(json_payload["resource_sensitivity"]["data_contents_state"], "not_assessed")
        self.assertIn(json_payload["resource_sensitivity"]["explanation"], markdown)
        self.assertIn(json_payload["resource_sensitivity"]["explanation"], response.text)
        self.assertEqual(json_gap["scope"], original.scope)
        self.assertEqual(sarif_gap["scope"], original.scope)
        self.assertEqual(sarif_gap["provenance"], json_gap["provenance"])
        self.assertEqual(json_gap["provenance"][0]["field_path"], ["inline_policy", 0, "policy"])
        self.assertIn("Evidence location: `aws_iam_role.orders_task.inline_policy[0].policy`", markdown)
        self.assertIn("arn:aws:s3:::orders/public/", markdown)
        self.assertIn("inline_policy.0.policy", response.text)
        self.assertIn("&lt;script&gt;secret&lt;/script&gt;", response.text)
        for output in (json_report, markdown, sarif, response.text):
            for sentinel in sentinels:
                with self.subTest(sentinel=sentinel):
                    self.assertNotIn(sentinel, output)

    def test_api_docs_hide_topbar_and_schema_models(self) -> None:
        response = self.client.get("/api/docs")

        self.assertEqual(response.status_code, 200)
        self.assertIn("/openapi.json", response.text)
        self.assertIn("defaultModelsExpandDepth", response.text)
        self.assertIn(".swagger-ui .topbar", response.text)
        self.assertIn("section.models", response.text)
        self.assertIn('a[href$="/openapi.json"]', response.text)

    def test_openapi_spec_route_is_available(self) -> None:
        response = self.client.get("/openapi.json")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("/api/analyze", payload["paths"])
        self.assertIn("/demo/{scenario_id}", payload["paths"])
        self.assertNotIn("/scenarios", payload["paths"])
        self.assertEqual(
            payload["paths"]["/api/analyze"]["post"]["summary"],
            "Analyze Terraform plan JSON",
        )
        self.assertEqual(
            payload["paths"]["/api/analyze"]["post"]["responses"]["200"]["content"]["application/json"]["example"][
                "kind"
            ],
            "tfstride-report",
        )
        self.assertIn("multipart/form-data", payload["paths"]["/api/analyze"]["post"]["requestBody"]["content"])
        self.assertEqual(
            payload["paths"]["/api/analyze"]["post"]["responses"]["422"]["content"]["application/json"]["example"][
                "detail"
            ][0]["loc"],
            ["body", "plan"],
        )
        self.assertIn("ValidationErrorResponseModel", payload["components"]["schemas"])

    def test_html_analyze_renders_finding_content(self) -> None:
        with FIXTURE_PATH.open("rb") as fixture_file:
            response = self.client.post(
                "/analyze",
                data={"title": "Dashboard Test"},
                files={"plan": (FIXTURE_PATH.name, fixture_file, "application/json")},
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Dashboard Test", response.text)
        self.assertIn("Database is reachable from overly permissive sources", response.text)
        self.assertIn("JSON report", response.text)
        self.assertIn(FIXTURE_PATH.name, response.text)
        self.assertNotIn(str(FIXTURE_PATH), response.text)
        self.assertIn("Report sections", response.text)
        self.assertIn('href="#findings"', response.text)
        self.assertIn('href="#coverage"', response.text)
        self.assertIn("Analysis coverage", response.text)
        self.assertIn("Audit trail for this run", response.text)
        self.assertIn("Sensitive resource labels are assumptions based on resource class", response.text)
        self.assertIn("aws_cloudwatch_log_group", response.text)
        self.assertIn("aws-database-permissive-ingress", response.text)

    def test_html_analyze_renders_nightmare_fixture(self) -> None:
        with NIGHTMARE_FIXTURE_PATH.open("rb") as fixture_file:
            response = self.client.post(
                "/analyze",
                data={"title": "Nightmare Dashboard Test"},
                files={"plan": (NIGHTMARE_FIXTURE_PATH.name, fixture_file, "application/json")},
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Nightmare Dashboard Test", response.text)
        self.assertIn("Object storage is publicly accessible", response.text)
        self.assertIn("policy statements", response.text)

    def test_demo_route_renders_baseline_fixture_report(self) -> None:
        response = self.client.get("/demo/baseline")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Baseline Plan Demo", response.text)
        self.assertIn(BASELINE_FIXTURE_PATH.name, response.text)
        self.assertIn("IAM policy grants wildcard privileges", response.text)

    def test_demo_route_renders_gcp_inventory_fixture_report(self) -> None:
        response = self.client.get("/demo/gcp-scaffold")

        self.assertEqual(response.status_code, 200)
        self.assertIn("GCP Inventory Demo", response.text)
        self.assertIn(GCP_FIXTURE_PATH.name, response.text)
        self.assertIn("google_compute_instance.web", response.text)
        self.assertIn("Internet-exposed GCP compute instance permits broad ingress", response.text)
        self.assertIn("GCP support covers a curated set", response.text)

    def test_gcp_safe_demo_uses_provider_specific_unsupported_empty_state(self) -> None:
        response = self.client.get("/demo/gcp-safe")

        self.assertEqual(response.status_code, 200)
        self.assertIn("No unsupported GCP resource types were encountered.", response.text)
        self.assertNotIn("No unsupported AWS resource types were encountered.", response.text)

    def test_demo_route_renders_azure_storage_findings_and_unsupported_resource(self) -> None:
        response = self.client.get("/demo/azure-storage")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Azure Storage Exposure Demo", response.text)
        self.assertIn(AZURE_STORAGE_FIXTURE_PATH.name, response.text)
        self.assertIn("Azure Storage account permits Shared Key authorization", response.text)
        self.assertIn("Azure Storage container is publicly accessible", response.text)
        self.assertIn("azurerm_storage_share", response.text)
        self.assertIn("Unsupported resource skipped: azurerm_storage_share.legacy", response.text)

    def test_demo_route_renders_mixed_azure_inventory_and_coverage(self) -> None:
        response = self.client.get("/demo/azure-inventory")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Azure Inventory Demo", response.text)
        self.assertIn(AZURE_FIXTURE_PATH.name, response.text)
        self.assertIn("Internet-exposed Azure virtual machine permits broad ingress", response.text)
        self.assertIn("Azure Storage container is publicly accessible", response.text)
        self.assertIn("Azure Key Vault allows unrestricted public network access", response.text)
        self.assertIn("Azure Key Vault purge protection is disabled", response.text)
        self.assertIn("azurerm_key_vault", response.text)
        self.assertIn("azurerm_kubernetes_cluster", response.text)

    def test_demo_route_renders_azure_nightmare_fixture(self) -> None:
        response = self.client.get("/demo/azure-nightmare")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Azure Nightmare Plan Demo", response.text)
        self.assertIn(AZURE_NIGHTMARE_FIXTURE_PATH.name, response.text)
        self.assertIn("azurerm_windows_virtual_machine.admin", response.text)
        self.assertIn("Azure Storage container is publicly accessible", response.text)
        self.assertIn("azurerm_key_vault", response.text)
        self.assertIn("azurerm_kubernetes_cluster", response.text)

    def test_azure_safe_demo_uses_provider_specific_unsupported_empty_state(self) -> None:
        response = self.client.get("/demo/azure-safe")

        self.assertEqual(response.status_code, 200)
        self.assertIn(AZURE_SAFE_FIXTURE_PATH.name, response.text)
        self.assertIn("No unsupported Azure resource types were encountered.", response.text)
        self.assertNotIn("No unsupported AWS resource types were encountered.", response.text)

    def test_html_upload_auto_detects_and_renders_azure_plan(self) -> None:
        with AZURE_STORAGE_FIXTURE_PATH.open("rb") as fixture_file:
            response = self.client.post(
                "/analyze",
                data={"title": "Azure Upload Test"},
                files={"plan": (AZURE_STORAGE_FIXTURE_PATH.name, fixture_file, "application/json")},
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Azure Upload Test", response.text)
        self.assertIn("Azure Storage account allows unrestricted public network access", response.text)
        self.assertIn("azurerm_storage_share", response.text)

    def test_demo_route_renders_ecs_fargate_fixture_report(self) -> None:
        response = self.client.get("/demo/ecs-fargate")

        self.assertEqual(response.status_code, 200)
        self.assertIn("ECS / Fargate Demo", response.text)
        self.assertIn(ECS_FARGATE_FIXTURE_PATH.name, response.text)
        self.assertIn("aws_ecs_service.app", response.text)

    def test_demo_route_returns_not_found_for_unknown_scenario(self) -> None:
        response = self.client.get("/demo/not-a-scenario")

        self.assertEqual(response.status_code, 404)

    def test_api_rejects_empty_uploads(self) -> None:
        response = self.client.post(
            "/api/analyze",
            data={"title": "Empty Upload"},
            files={"plan": ("empty.json", b"", "application/json")},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {
                "kind": "tfstride-error",
                "message": "Upload a non-empty Terraform plan JSON file.",
            },
        )

    def test_api_rejects_invalid_plan_without_internal_error_details(self) -> None:
        response = self.client.post(
            "/api/analyze",
            data={"title": "Invalid Upload"},
            files={"plan": ("invalid.json", b"{", "application/json")},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {
                "kind": "tfstride-error",
                "message": dashboard_uploads.INVALID_PLAN_UPLOAD_MESSAGE,
            },
        )
        self.assertNotIn("tfstride-dashboard", response.text)
        self.assertNotIn("Expecting", response.text)

    def test_html_analyze_rejects_invalid_plan_without_internal_error_details(self) -> None:
        response = self.client.post(
            "/analyze",
            data={"title": "Invalid Upload"},
            files={"plan": ("invalid.json", b"{", "application/json")},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(dashboard_uploads.INVALID_PLAN_UPLOAD_MESSAGE, response.text)
        self.assertNotIn("tfstride-dashboard", response.text)
        self.assertNotIn("Expecting", response.text)

    def test_healthz_returns_ok(self) -> None:
        response = self.client.get("/healthz")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})


if __name__ == "__main__":
    unittest.main()
