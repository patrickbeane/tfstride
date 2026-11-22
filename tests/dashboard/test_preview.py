from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from tests.helpers.paths import FIXTURES_DIR
from tfstride.app import TfStride
from tfstride.input.terraform_plan import TerraformPlanLoadError
from tfstride.reporting.json_report import build_json_report_payload

FASTAPI_DEPS_AVAILABLE = all(
    importlib.util.find_spec(name) is not None for name in ("fastapi", "httpx2", "jinja2", "multipart")
)

if FASTAPI_DEPS_AVAILABLE:
    from fastapi.testclient import TestClient

    from apps.dashboard.main import create_app
    from apps.dashboard.preview import build_demo_preview, get_demo_preview


@unittest.skipUnless(FASTAPI_DEPS_AVAILABLE, "dashboard dependencies are not installed")
class DashboardPreviewTests(unittest.TestCase):
    def test_preview_is_an_excerpt_of_the_existing_demo_report(self) -> None:
        engine = TfStride()
        preview = build_demo_preview(engine)
        self.assertIsNotNone(preview)
        assert preview is not None
        payload = build_json_report_payload(
            engine.analyze_plan(FIXTURES_DIR / preview.scenario.fixture_name, title=preview.scenario.report_title)
        )

        self.assertEqual(preview.scenario.scenario_id, "ecs-fargate")
        self.assertEqual(preview.summary, payload["summary"])
        self.assertEqual(preview.findings, tuple(payload["findings"][:2]))
        self.assertIn(preview.boundary, payload["trust_boundaries"])
        self.assertEqual(preview.observations, tuple(payload["observations"][:1]))
        self.assertEqual(preview.observed_controls, len(payload["observations"]))
        self.assertEqual(preview.operation_gaps, len(payload["operation_gaps"]["records"]))
        self.assertEqual(
            preview.unresolved_references, payload["analysis_coverage"]["references"]["unresolved_reference_count"]
        )

    def test_landing_analyzes_only_the_preview_once_per_application(self) -> None:
        app = create_app()
        with (
            TestClient(app) as client,
            mock.patch.object(app.state.engine, "analyze_plan", wraps=app.state.engine.analyze_plan) as analyze,
        ):
            first = client.get("/")
            second = client.get("/")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.text, second.text)
        analyze.assert_called_once()
        self.assertEqual(analyze.call_args.args[0].name, "sample_aws_ecs_fargate_plan.json")
        self.assertFalse(hasattr(app.state, "demo_scenarios"))

    def test_missing_or_invalid_preview_fixture_does_not_break_upload_page(self) -> None:
        with TemporaryDirectory() as directory, mock.patch.object(TfStride, "analyze_plan") as analyze:
            self.assertIsNone(build_demo_preview(TfStride(), fixtures_dir=Path(directory)))
            analyze.assert_not_called()

        with mock.patch.object(TfStride, "analyze_plan", side_effect=TerraformPlanLoadError("invalid fixture")):
            app = create_app()
            with TestClient(app) as client:
                response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn('name="plan"', response.text)
        self.assertIsNone(app.state.demo_preview)

    def test_unavailable_preview_is_cached_without_affecting_other_apps(self) -> None:
        first_app, second_app = create_app(), create_app()
        with mock.patch("apps.dashboard.preview.build_demo_preview", return_value=None) as build:
            for app in (first_app, first_app, second_app):
                self.assertIsNone(get_demo_preview(app, app.state.engine))
        self.assertEqual(build.call_count, 2)
