from __future__ import annotations

import importlib.util
import unittest
from copy import deepcopy
from dataclasses import replace
from html.parser import HTMLParser
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
    from apps.dashboard.uploads import MAX_UPLOAD_BYTES


class _ElementsById(HTMLParser):
    def __init__(self, html: str) -> None:
        super().__init__()
        self.elements: dict[str, dict[str, str | None]] = {}
        self.feed(html)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        identifier = attributes.get("id")
        if identifier:
            self.elements[identifier] = attributes


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

    def test_workspace_renders_real_evidence_and_existing_report_destinations(self) -> None:
        app = create_app()
        with TestClient(app) as client:
            response = client.get("/")
        preview = app.state.demo_preview

        self.assertIn(f'data-preview-metric="findings">{preview.summary["active_findings"]}</dd>', response.text)
        self.assertIn(f'data-preview-metric="boundaries">{preview.summary["trust_boundaries"]}</dd>', response.text)
        self.assertIn(f'data-preview-metric="controls">{preview.observed_controls}</dd>', response.text)
        for finding in preview.findings:
            self.assertIn(finding["title"], response.text)
            self.assertIn(finding["rule_id"], response.text)
            self.assertIn(finding["evidence"][0]["values"][0], response.text)
        self.assertIn(preview.boundary["target"], response.text.replace("<wbr>", ""))
        self.assertIn(preview.boundary["boundary_type"], response.text)
        self.assertIn(preview.observations[0]["title"], response.text)
        for section in ("findings", "analysis-gaps", "raw-outputs"):
            self.assertIn(f'href="http://testserver/demo/{preview.scenario.scenario_id}#{section}"', response.text)
        for provider in ("aws", "azure", "gcp"):
            self.assertIn(f'href="http://testserver/scenarios?provider={provider}"', response.text)
        self.assertNotIn(str(FIXTURES_DIR), response.text)

    def test_workspace_keeps_native_upload_contract_labels_and_privacy_notice(self) -> None:
        with TestClient(create_app()) as client:
            response = client.get("/")
        elements = _ElementsById(response.text).elements
        form = elements["plan-upload"]
        upload = elements["plan-file"]
        title = elements["report-title"]

        self.assertEqual(form["action"], "http://testserver/analyze")
        self.assertEqual(form["method"], "post")
        self.assertEqual(form["enctype"], "multipart/form-data")
        self.assertEqual(int(form["data-max-upload-bytes"]), MAX_UPLOAD_BYTES)
        self.assertEqual((upload["type"], upload["name"]), ("file", "plan"))
        self.assertIn("required", upload)
        self.assertNotIn("disabled", upload)
        self.assertNotIn("hidden", upload)
        self.assertIn('for="plan-file"', response.text)
        self.assertEqual(title["name"], "title")
        self.assertNotIn("required", title)
        self.assertEqual(elements["upload-status"]["role"], "status")
        self.assertEqual(elements["upload-error"]["role"], "alert")
        self.assertEqual(elements["main-content"]["tabindex"], "-1")
        text = " ".join(response.text.split())
        for message in ("temporary files on this server, then deleted", "never retained", "forwarded to third parties"):
            self.assertIn(message, text)
        self.assertIn("No cloud API calls", text)

    def test_preview_escapes_engine_text_including_evidence(self) -> None:
        preview = build_demo_preview(TfStride())
        assert preview is not None
        finding = deepcopy(preview.findings[0])
        hostile_text = "<script>alert(1)</script>"
        finding["title"] = hostile_text
        finding["affected_resources"] = [hostile_text]
        finding["evidence"][0]["values"] = [hostile_text]
        with mock.patch("apps.dashboard.routes.get_demo_preview", return_value=replace(preview, findings=(finding,))):
            with TestClient(create_app()) as client:
                response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(hostile_text, response.text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", response.text)

    def test_invalid_upload_preserves_title_and_returns_an_accessible_retry_form(self) -> None:
        title = '<production> & "review"'
        with TestClient(create_app()) as client:
            client.get("/")
            response = client.post(
                "/analyze", data={"title": title}, files={"plan": ("invalid.json", b"{", "application/json")}
            )
        elements = _ElementsById(response.text).elements

        self.assertEqual(response.status_code, 400)
        self.assertEqual(elements["report-title"]["value"], title)
        self.assertEqual(elements["server-error"]["role"], "alert")
        self.assertEqual(elements["server-error"]["tabindex"], "-1")
        self.assertIn("Choose a file again to retry.", response.text)
        self.assertIn("ECS / Fargate", response.text)
        self.assertNotIn(title, response.text)
