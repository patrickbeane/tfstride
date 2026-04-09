from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


FASTAPI_DEPS_AVAILABLE = all(
    importlib.util.find_spec(name) is not None
    for name in ("fastapi", "httpx", "jinja2", "multipart")
)

if FASTAPI_DEPS_AVAILABLE:
    from fastapi.testclient import TestClient

    from apps.dashboard.main import app as dashboard_app


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_plan.json"
SAFE_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_safe_plan.json"
NIGHTMARE_FIXTURE_PATH = ROOT / "fixtures" / "sample_aws_nightmare_plan.json"


@unittest.skipUnless(FASTAPI_DEPS_AVAILABLE, "dashboard dependencies are not installed")
class DashboardAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(dashboard_app)

    def test_index_page_renders_upload_form(self) -> None:
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Analyze plan", response.text)
        self.assertIn("Terraform plan JSON", response.text)
        self.assertIn("Built-in scenarios", response.text)
        self.assertIn("Nightmare Plan", response.text)

    def test_api_analyze_returns_versioned_json_contract(self) -> None:
        with FIXTURE_PATH.open("rb") as fixture_file:
            response = self.client.post(
                "/api/analyze",
                data={"title": "Dashboard Test"},
                files={"plan": (FIXTURE_PATH.name, fixture_file, "application/json")},
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["kind"], "cloud-threat-model-report")
        self.assertEqual(payload["version"], "1.1")
        self.assertEqual(payload["title"], "Dashboard Test")
        self.assertEqual(payload["analyzed_file"], FIXTURE_PATH.name)
        self.assertTrue(payload["findings"])

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

    def test_html_analyze_renders_nightmare_fixture(self) -> None:
        with NIGHTMARE_FIXTURE_PATH.open("rb") as fixture_file:
            response = self.client.post(
                "/analyze",
                data={"title": "Nightmare Dashboard Test"},
                files={"plan": (NIGHTMARE_FIXTURE_PATH.name, fixture_file, "application/json")},
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Nightmare Dashboard Test", response.text)
        self.assertIn("Public object storage allows internet reads", response.text)
        self.assertIn("policy statements", response.text)

    def test_demo_route_renders_safe_fixture_report(self) -> None:
        response = self.client.get("/demo/safe")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Safe Plan Demo", response.text)
        self.assertIn(SAFE_FIXTURE_PATH.name, response.text)
        self.assertIn("IAM policy grants wildcard privileges", response.text)

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
                "kind": "cloud-threat-model-error",
                "message": "Upload a non-empty Terraform plan JSON file.",
            },
        )

    def test_healthz_returns_ok(self) -> None:
        response = self.client.get("/healthz")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})


if __name__ == "__main__":
    unittest.main()
