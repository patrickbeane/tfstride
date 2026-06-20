from __future__ import annotations

import importlib.util
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock

FASTAPI_DEPS_AVAILABLE = all(
    importlib.util.find_spec(name) is not None for name in ("fastapi", "httpx2", "jinja2", "multipart")
)

if FASTAPI_DEPS_AVAILABLE:
    from fastapi.testclient import TestClient

    from apps.dashboard import main as dashboard_main
    from apps.dashboard import routes as dashboard_routes
    from apps.dashboard import uploads as dashboard_uploads
    from apps.dashboard import view_models as dashboard_view_models
    from apps.dashboard.main import app as dashboard_app


ROOT = Path(__file__).resolve().parents[1]
BASELINE_FIXTURE_PATH = ROOT / "fixtures" / "aws" / "sample_aws_baseline_plan.json"
ECS_FARGATE_FIXTURE_PATH = ROOT / "fixtures" / "aws" / "sample_aws_ecs_fargate_plan.json"
FIXTURE_PATH = ROOT / "fixtures" / "aws" / "sample_aws_plan.json"
GCP_FIXTURE_PATH = ROOT / "fixtures" / "gcp" / "sample_gcp_plan.json"
SAFE_FIXTURE_PATH = ROOT / "fixtures" / "aws" / "sample_aws_safe_plan.json"
NIGHTMARE_FIXTURE_PATH = ROOT / "fixtures" / "aws" / "sample_aws_nightmare_plan.json"


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
        self.assertIn('class="scenario-provider-link scenario-provider-link-active"', response.text)
        self.assertIn('data-provider="aws"', response.text)
        self.assertNotIn('data-provider="gcp"', response.text)
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
        self.assertIn("Mixed GCP Inventory", response.text)
        self.assertIn("GCP Serverless", response.text)
        self.assertNotIn("ECS / Fargate", response.text)
        self.assertNotIn("Mixed AWS Plan", response.text)

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
        self.assertEqual(payload["version"], "1.1")
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
        self.assertIn("GCP support currently provides initial inventory normalization", response.text)

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
